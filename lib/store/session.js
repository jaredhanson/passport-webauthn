var crypto = require('crypto');
var base64url = require('base64url');
var clone = require('clone');


function SessionStore(options) {
  options = options || {};
  this._key = options.key || 'webauthn';
}

SessionStore.prototype.challenge = function(req, info, cb) {
  if (typeof info == 'function') {
    cb = info;
    info = undefined;
  }
  info = info || {};
  
  if (!req.session) { return cb(new Error('WebAuthn authentication requires session support. Did you forget to use express-session middleware?')); }
  
  var self = this;
  crypto.randomBytes(16, function(err, buf) {
    if (err) { return cb(err); }
    req.session[self._key] = {
      challenge: base64url.encode(buf)
    };
    if (info.user) {
      var user = clone(info.user);
      if (user.id) {
        user.id = base64url.encode(user.id);
      }
      req.session[self._key].user = user;
    }
    return cb(null, buf);
  });
}

SessionStore.prototype.verify = function(req, challenge, cb) {
  if (!req.session) { return cb(new Error('WebAuthn authentication requires session support. Did you forget to use express-session middleware?')); }
  
  var self = this;
  process.nextTick(function() {
    var info = req.session[self._key];
    delete req.session[self._key];
    
    if (!info) {
      return cb(null, false, { message: 'Unable to verify authentication challenge.' });
    }
    if (!info.challenge) {
      return cb(null, false, { message: 'Unable to verify authentication challenge.' });
    }
    
    var expectedChallenge = base64url.toBuffer(info.challenge);
    if (Buffer.compare(expectedChallenge, challenge) !== 0) {
      return cb(null, false, { message: 'Invalid challenge.' });
    }
    delete info.challenge;
    
    if (info.user && info.user.id) {
      info.user.id = base64url.toBuffer(info.user.id);
    }
    return cb(null, true, info);
  });
}


module.exports = SessionStore;
