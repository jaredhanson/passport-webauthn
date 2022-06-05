var AuthenticatorData = require('../authenticatordata');
var crypto = require('crypto');

// https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation
exports.verify = function(attStmt, authData, hash) {
  var att = this.parse(attStmt);
  var attCert = att.trustPath[0];
  if (attCert.publicKey.asymmetricKeyType != 'ec') {
    throw new TypeError('FIDO U2F attestation certificate public key must be an EC key');
  }
  if (attCert.publicKey.asymmetricKeyDetails.namedCurve != 'prime256v1') {
    throw new TypeError('FIDO U2F attestation certificate public key must be an EC key over P-256 curve');
  }
  
  var data = AuthenticatorData.parse(authData, true, true);
  
  // Convert credential public key to uncompressed ECC key format.
  var x = data.attestedCredentialData.credentialPublicKey.get(-2);
  if (x.length != 32) {
    throw new TypeError('FIDO U2F credential public key must have 32-byte X coordinate');
  }
  var y = data.attestedCredentialData.credentialPublicKey.get(-3);
  if (y.length != 32) {
    throw new TypeError('FIDO U2F credential public key must have 32-byte Y coordinate');
  }
  
  var publicKeyU2F = Buffer.concat([Buffer.from([0x04]), x, y]);
  var verificationData = Buffer.concat([Buffer.from([0x00]), data.rpIdHash, hash,
                                       data.attestedCredentialData.credentialId,
                                       publicKeyU2F]);
  var ok = crypto.createVerify('sha256').update(verificationData).verify(attCert.publicKey, att.signature);
  if (!ok) { return false; }
  return {
    type: undefined,
    format: 'fido-u2f',
    trustPath: att.trustPath
  };
};

exports.parse = function(attStmt) {
  if (attStmt.x5c.length != 1) {
    throw new TypeError('FIDO U2F attestation must have a single element certificate chain');
  }
  
  var cert = new crypto.X509Certificate(attStmt.x5c[0]);
  return {
    signature: attStmt.sig,
    trustPath: [ cert ]
  };
};
