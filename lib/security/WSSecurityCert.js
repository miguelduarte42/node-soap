"use strict";

var optional = require("optional");
var fs = require('fs');
var path = require('path');
var ejs = require('ejs');
var SignedXml = require('xml-crypto').SignedXml;
var uuid = require('node-uuid');
var crypto = require('crypto');
var wsseSecurityHeaderTemplate = ejs.compile(fs.readFileSync(path.join(__dirname, 'templates', 'wsse-security-header.ejs')).toString());
var wsseSecurityTokenTemplate = ejs.compile(fs.readFileSync(path.join(__dirname, 'templates', 'wsse-security-token.ejs')).toString());

function addMinutes(date, minutes) {
  return new Date(date.getTime() + minutes * 60000);
}

function dateStringForSOAP(date) {
  return date.getUTCFullYear() + '-' + ('0' + (date.getUTCMonth() + 1)).slice(-2) + '-' +
    ('0' + date.getUTCDate()).slice(-2) + 'T' + ('0' + date.getUTCHours()).slice(-2) + ":" +
    ('0' + date.getUTCMinutes()).slice(-2) + ":" + ('0' + date.getUTCSeconds()).slice(-2) + "Z";
}

function generateCreated() {
  return dateStringForSOAP(new Date());
}

function generateExpires() {
  return dateStringForSOAP(addMinutes(new Date(), 10));
}

function insertStr(src, dst, pos) {
  return [dst.slice(0, pos), src, dst.slice(pos)].join('');
}

function generateId() {
  return uuid.v4().replace(/-/gm, '');
}

function WSSecurityCert() {
  var privatePEM, publicP12PEM, keyPassword, encoding;
  if (arguments.length === 1) {
    privatePEM = arguments[0].privateKey;
    publicP12PEM = arguments[0].publicKey;
    keyPassword = arguments[0].keyPassword;
    encoding = arguments[0].encoding;
    this._username = arguments[0].username;
    this._password = arguments[0].password;
  } else {
    privatePEM = arguments[0];
    publicP12PEM = arguments[1];
    keyPassword = arguments[2];
    encoding = arguments[3];
  }
  this.privateKey = crypto.createPrivateKey({
    key: privatePEM,
    passphrase: keyPassword,
    //encoding
  });
  this.publicP12PEM = publicP12PEM.toString().replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '').replace(/(\r\n|\n|\r)/gm, '');

  this.signer = new SignedXml();
  this.signer.signingKey = this.privateKey.export({
    format: 'pem',
    type: 'pkcs1'
  });
  this.x509Id = "x509-" + generateId();

  var references = ["http://www.w3.org/2001/10/xml-exc-c14n#"];

  this.signer.addReference("//*[local-name(.)='Body']", references);
  this.signer.addReference("//*[local-name(.)='Timestamp']", references);
  this.signer.addReference("//*[local-name(.)='EBS']", references);
  this.signer.addReference("//*[local-name(.)='IDP']", references);

  var _this = this;
  this.signer.keyInfoProvider = {};
  this.signer.keyInfoProvider.getKeyInfo = function (key) {
    return wsseSecurityTokenTemplate({x509Id: _this.x509Id});
  };
}

WSSecurityCert.prototype.postProcess = function (xml) {
  this.created = generateCreated();
  this.expires = generateExpires();

  var secHeader = wsseSecurityHeaderTemplate({
    binaryToken: this.publicP12PEM,
    created: this.created,
    expires: this.expires,
    username: this._username,
    password: this._password,
    id: this.x509Id
  });

  var xmlWithSec = insertStr(secHeader, xml, xml.indexOf('</soap:Header>'));

  //console.log(xmlWithSec);
  this.signer.computeSignature(xmlWithSec);

  var result = insertStr(this.signer.getSignatureXml(), xmlWithSec, xmlWithSec.indexOf('</wsse:Security>'));

  //result = result.split('<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />').join('<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces PrefixList="soap ebs idp wsse wsu xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" /></Transform>');

  //var inclusiveXml = '<ec:InclusiveNamespaces PrefixList="SOAP-ENV ebs idp hcv" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" />';
  //result = insertStr(inclusiveXml, result, result.indexOf('<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">'));

//  console.log(require('pretty-data').pd.xml(this.signer.getSignatureXml()));

  return result;
};

module.exports = WSSecurityCert;
