var crypto = require('crypto');
var AuthenticatorData = require('./authenticatordata');
var cbor = require('cbor');
var cose2jwk = require('cose-to-jwk');


exports.parse = function(attStmt) {
  var att = {
    algorithm: attStmt.alg,
    trustPath: [],
    signature: attStmt.sig
  };
  if (attStmt.x5c) {
    attStmt.x5c.forEach(function(c) {
      var cert = new crypto.X509Certificate(c);
      att.trustPath.push(cert);
    });
  }
  return att;
};

exports.verify = function(attStmt, authData, hash) {
  var att = this.parse(attStmt);
  console.log(att);
  var data = Buffer.concat([authData, hash]);
  
  var authenticatorData = AuthenticatorData.parse(authData, true, false);
  console.log(authenticatorData)
  
  if (att.trustPath.length > 0) {
    var ok = crypto.createVerify('sha256').update(data).verify(att.trustPath[0].publicKey, att.signature);
    if (!ok) { return false; }
    
    // TODO: Valid FIDO OID is aaguid in cert
    
    // TODO: Return trust path of `x5c` chain and 'basic' type (or CA???)
    
    return {
      type: undefined,
      trustPath: att.trustPath
    };
  } else {
    var cwk = cbor.decodeFirstSync(authenticatorData.attestedCredentialData.credentialPublicKey);
    if (att.algorithm != cwk.get(3)) {
      throw new Error('Packed attestation algorithm must match algorithm of credential public key');
    }
    
    var jwk = cose2jwk(authenticatorData.attestedCredentialData.credentialPublicKey);
    var key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    var ok = crypto.createVerify('sha256').update(data).verify(key, att.signature);
    if (!ok) { return false; }
    return {
      type: 'self',
      trustPath: att.trustPath
    };
  }
  
  
  //var attestnCert = att
  
  //var signature = base64url.toBuffer(response.signature);
  
  //var ok = crypto.createVerify('sha256').update(data).verify(publicKey, signature);
  
}