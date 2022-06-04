var crypto = require('crypto');
var base64url = require('base64url');

//var uid = require('uid2');


function SessionStore() {
  
}

SessionStore.prototype.challenge = function(req, cb) {
  console.log('CHALLENGE IT');
  
  crypto.randomBytes(16, function(err, buf) {
    if (err) { return cb(err); }
    
    var chal = base64url.encode(buf);
    console.log(chal);
    
    return cb(null, buf);
  });
}

SessionStore.prototype.verify = function(req, cb) {
  
}


module.exports = SessionStore;
