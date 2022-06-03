var crypto = require('crypto');
var AuthenticatorData = require('./authenticatordata');
var cose2jwk = require('cose-to-jwk');


exports.parse = function(attStmt) {
  //console.log('PARSE PACKED');
  //console.log(attStmt);
  
  var attestation = {
    alg: attStmt.alg,
    signature: attStmt.sig
  };
  
  if (attStmt.x5c) {
    attestation.chain = []
    attStmt.x5c.forEach(function(c) {
      var cert = new crypto.X509Certificate(c);
      attestation.chain.push(cert);
    });
  }
  
  return attestation;
};

exports.verify = function(attStmt, authData, hash) {
  console.log('VERIFY PACKED');
  console.log(attStmt);
  console.log(authData);
  
  var att = this.parse(attStmt);
  var data = Buffer.concat([authData, hash]);
  
  console.log(att);
  
  var authenticatorData = AuthenticatorData.parse(authData, true, false);
  console.log(authenticatorData)
  
  if (att.chain) {
    console.log('VERIFY IT!');
    
    var ok = crypto.createVerify('sha256').update(data).verify(att.chain[0].publicKey, att.signature);
    console.log('VALID? ' + ok);
    
    // TODO: Valid FIDO OID is aaguid in cert
    
    // TODO: Return trust path of `x5c` chain and 'basic' type (or CA???)
    
  } else {
    console.log('self attested...');
    
    // TODO: Validate alg matches public key alg
    
    var jwk = cose2jwk(authenticatorData.attestedCredentialData.credentialPublicKey);
    
    var key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    console.log(key);
    
    var ok = crypto.createVerify('sha256').update(data).verify(key, att.signature);
    console.log('VALID? ' + ok);
    
    // TODO: Return empty trust path and self attestation type
  }
  
  
  //var attestnCert = att
  
  //var signature = base64url.toBuffer(response.signature);
  
  //var ok = crypto.createVerify('sha256').update(data).verify(publicKey, signature);
  
}