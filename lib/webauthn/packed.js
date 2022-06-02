var crypto = require('crypto');


exports.parse = function(attStmt) {
  //console.log('PARSE PACKED');
  //console.log(attStmt);
  
  var attestation = {
    alg: attStmt,
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
