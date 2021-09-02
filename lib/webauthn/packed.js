var crypto = require('crypto');


exports.parse = function(obj) {
  console.log('PARSE PACKED');
  console.log(obj);
  
  if (obj.x5c) {
    obj.x5c.forEach(function(c) {
      var cert = new crypto.X509Certificate(obj.x5c[0]);
      console.log(cert);
      console.log(cert.toString());
    });
    
    
  }
  
  
};
