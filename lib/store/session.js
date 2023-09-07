var crypto = require('crypto');
var base64url = require('base64url');
var clone = require('clone');


/**
 * Create a new `SessionChallengeStore` object.
 *
 * @classdesc This challenge store stores challenges in the session.
 *
 * See {@link https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges Security Considerations}
 * of the Web Authentication specification for more information.
 *
 * @public
 * @class
 * @param {Object} [options]
 * @param {string} [options.key='webauthn'] - Determines what property ("key")
 *          on the session data where WebAuthn challenge data is located.  The
 *          challenge is stored and read from `req.session[key]`.
 *
 * @example
 * var SessionChallengeStore = require('passport-fido2-webauthn').SessionChallengeStore;
 *
 * var store = new SessionChallengeStore();
 */
function SessionStore(options) {
  options = options || {};
  this._key = options.key || 'webauthn';
}

/**
 * Create and store a challenge.
 *
 * @public
 * @param {http.IncomingMessage} req - The Node.js {@link https://nodejs.org/api/http.html#class-httpincomingmessage `IncomingMessage`}
 *          object.
 * @param {Object} [info]
 * @param {Function} callback
 * @param {Error} callback.err
 * @param {Buffer} callback.buf
 */
SessionStore.prototype.challenge = function(req, info, cb) {
  if (typeof info == 'function') {
    cb = info;
    info = undefined;
  }
  info = info || {};
  
  if (!req.session) { return cb(new Error('WebAuthn authentication requires session support. Did you forget to use express-session middleware?')); }
  
  var self = this;
  // Generate 16 bytes of random data, which has enough entropy to make guessing
  // attacks infeasable, thus preventing replay attacks.  This length is
  // recommended by the Web Authentication specification.
  //
  // Note that this challenge store implementation stores the challenge in the
  // session, which also introduces additional entropy.  Furthermore, any replay
  // attacks would be confined to the session itself.
  crypto.randomBytes(16, function(err, buf) {
    if (err) { return cb(err); }
    req.session[self._key] = {
      challenge: base64url.encode(buf)
    };
    // Store user context of this challenge.  This functionality is used when
    // creating a new account with the intent of registering a public key as the
    // sole credential used to authenticate, thus eliminating the need for a
    // password or other less secure credentials.
    //
    // In this case, a user handle can be generated and the associated profile
    // information can be temporarily saved in the session.  Subsequently, when
    // response is received registering the credential, the user handle and
    // profile information will be loaded from the session and then written to
    // permanent storage.  This avoids creating abandoned user records that lack
    // credentials in cases where creating a public key credential fails or is
    // denied.
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
