var crypto = require('crypto');
var base64url = require('base64url');


function SessionStore(options) {
  options = options || {};
  this._key = options.key || 'webauthn';
}

SessionStore.prototype.challenge = function(req, cb) {
  if (!req.session) { return cb(new Error('WebAuthn authentication requires session support. Did you forget to use express-session middleware?')); }
  
  var self = this;
  crypto.randomBytes(16, function(err, buf) {
    if (err) { return cb(err); }
    req.session[self._key] = {
      challenge: base64url.encode(buf)
    };
    return cb(null, buf);
  });
}

SessionStore.prototype.verify = function(req, challenge, cb) {
  if (!req.session) { return cb(new Error('WebAuthn authentication requires session support. Did you forget to use express-session middleware?')); }
  
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
    if (Buffer.compare(expectedChallenge, challenge) !== 0) {
      return cb(null, false, { message: 'Invalid challenge.' });
    }
    return cb(null, true);
  });
}


module.exports = SessionStore;