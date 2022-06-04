var crypto = require('crypto');
var base64url = require('base64url');


function SessionStore(options) {
  options = options || {};
  this._key = options.key || 'webauthn';
}

SessionStore.prototype.challenge = function(req, cb) {
  console.log('CHALLENGE IT');
  
  var self = this;
  crypto.randomBytes(16, function(err, buf) {
    if (err) { return cb(err); }
    
    var chal = base64url.encode(buf);
    console.log(chal);
    
    req.session[self._key] = {
      challenge: base64url.encode(buf)
    };
    return cb(null, buf);
  });
}

SessionStore.prototype.verify = function(req, challenge, cb) {
  console.log('VERIFY IT!');
  console.log(challenge);
  console.log(req.session);
  
  var self = this;
  
  process.nextTick(function() {
    var data = req.session[self._key];
    delete req.session[self._key];
  
    if (!data) {
      return cb(null, false, { message: 'Unable to verify authentication challenge.' });
    }
    if (!data.challenge) {
      return cb(null, false, { message: 'Unable to verify authentication challenge.' });
    }
  
    var expectedChallenge = base64url.toBuffer(data.challenge);
  
    console.log('expected');
    console.log(expectedChallenge)
  
    if (Buffer.compare(expectedChallenge, challenge) !== 0) {
      console.log('NOT OK!');
      return cb(null, false, { message: 'Invalid challenge.' });
    }
  
    console.log('OK!');
    return cb(null, true);
  });
}


module.exports = SessionStore;
