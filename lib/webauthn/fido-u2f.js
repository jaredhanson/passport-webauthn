var crypto = require('crypto');
var AuthenticatorData = require('./authenticatordata');


exports.parse = function(attStmt) {
  // TODO: Verify that x5c has only one element
  
  var cert = new crypto.X509Certificate(attStmt.x5c[0]);
  return {
    cert: [ cert ],
    signature: attStmt.sig
  };
};

exports.verify = function(attStmt, authData, hash) {
  console.log('VERIFY FIDO U2F');
  
  var att = this.parse(attStmt);
  console.log(att);
  
  
  var data = AuthenticatorData.parse(authData, true, true);
  console.log(data)
  
  var x = data.attestedCredentialData.credentialPublicKey.get(-2);
  console.log(x);
  console.log(x.length);
  
  if (x.length != 32) {
    throw new Error('wrong size');
  }
  
  var y = data.attestedCredentialData.credentialPublicKey.get(-3);
  console.log(y);
  console.log(y.length);
  
  
  var publicKeyU2F = Buffer.concat([Buffer.from([0x04]), x, y]);
  console.log(publicKeyU2F);
  
  var verificationData = Buffer.concat([Buffer.from([0x00]), data.rpIdHash, hash,
                                       data.attestedCredentialData.credentialId,
                                       publicKeyU2F]);
  console.log(verificationData);
  
  var ok = crypto.createVerify('sha256').update(verificationData).verify(att.cert[0].publicKey, att.signature);
  console.log('VALID? ' + ok);
};
