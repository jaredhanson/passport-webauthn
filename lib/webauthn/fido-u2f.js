var crypto = require('crypto');


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
  
};
