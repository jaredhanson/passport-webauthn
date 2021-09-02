var crypto = require('crypto');


exports.parse = function(obj) {
  console.log('PARSE FIDO U2F');
  console.log(obj);
  
  var cert = new crypto.X509Certificate(obj.x5c[0]);
  console.log(cert);
  console.log(cert.toString());
  
  
};
