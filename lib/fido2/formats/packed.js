var AuthenticatorData = require('../authenticatordata');
var cbor = require('cbor');
var cose2jwk = require('cose-to-jwk');
var crypto = require('crypto');

exports.verify = function(attStmt, authData, hash) {
  var att = this.parse(attStmt);
  var data = Buffer.concat([authData, hash]);
  
  if (att.trustPath.length > 0) {
    var ok = crypto.createVerify('sha256').update(data).verify(att.trustPath[0].publicKey, att.signature);
    if (!ok) { return false; }
    
    // TODO: Verify id-fido-gen-ce-aaguid extension in attestation cert.
    // TODO: Verify that cert meets requirements
    
    return {
      type: undefined,
      format: 'packed',
      trustPath: att.trustPath
    };
  } else {
    var authenticatorData = AuthenticatorData.parse(authData, true, false);
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
      format: 'packed',
      trustPath: att.trustPath
    };
  }
};

exports.parse = function(attStmt) {
  var att = {
    algorithm: attStmt.alg,
    signature: attStmt.sig,
    trustPath: []
  };
  if (attStmt.x5c) {
    attStmt.x5c.forEach(function(c) {
      var cert = new crypto.X509Certificate(c);
      att.trustPath.push(cert);
    });
  }
  return att;
};
