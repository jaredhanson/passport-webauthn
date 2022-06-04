/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , base64url = require('base64url')
  , crypto = require('crypto')
  , util = require('util')
  , cose2jwk = require('cose-to-jwk')
  , jwk2pem = require('jwk-to-pem')
  , Attestation = require('./fido2/attestation')
  , AuthenticatorData = require('./fido2/authenticatordata')
  , fidou2f = require('./fido2/formats/fido-u2f')
  , packed = require('./fido2/formats/packed')
  , safetynet = require('./fido2/formats/android-safetynet')
  , utils = require('./utils')
  , url = require('url')

var USER_PRESENT = 0x01;
var USER_VERIFIED = 0x04;


function Strategy(options, verify, verifySignCount, register) {
  if (typeof options == 'function') {
    register = verifySignCount;
    verifySignCount = verify;
    verify = options;
    options = {};
  }
  if (typeof register == 'undefined') {
    register = verifySignCount;
    verifySignCount = undefined;
  }
  
  passport.Strategy.call(this);
  this.name = 'webauthn';
  this._attestationFormats = options.attestationFormats || require('./fido2/formats');
  this._verify = verify;
  this._verifySignCount = verifySignCount;
  this._register = register;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req, options) {
  //console.log('WEBAUTHN AUTHENTICATE!');
  //console.log(req.body);
  //console.log('---');
  
  // FIXME: Pull id from authData.credentialId
  var id = req.body.id;
  var response = req.body.response;
  var clientDataJSON = base64url.decode(response.clientDataJSON);
  var clientData = JSON.parse(clientDataJSON);
  
  // TODO: Verify challenge
  
  // Verify that the origin contained in client data matches the origin of this
  // app (which is the relying party).
  var origin = utils.originalOrigin(req);
  if (origin !== clientData.origin) {
    return this.fail({ message: 'Origin mismatch' }, 403);
  }
  
  // TODO: verify token binding
  
  var rpID = url.parse(origin).hostname;
  var rpIdHash = crypto.createHash('sha256').update(rpID).digest();
  
  // TODO: verify response.userHandle (???? HOW ???)
  
  var self = this;
  
  if (clientData.type === 'webauthn.get') {
    // https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion
    
    // TODO: Verify that credentials was in allowedCredentials, if set
    
    // Obtain the user handle, so that it can be passed to the verify function.
    var userHandle = null;
    if (response.userHandle) {
      userHandle = base64url.decode(response.userHandle);
    }
    
    // FIXME: should user handle always be available for first-factor auth???  seems like it
    
    var b_authenticatorData = base64url.toBuffer(response.authenticatorData);
    var authenticatorData = AuthenticatorData.parse(b_authenticatorData);
    
    // TODO: Support appID extension for rpIdHash
    
    // Verify that the RP ID hash contained in authenticator data matches the
    // hash of this app's (which is the relying party) RP ID.
    if (!rpIdHash.equals(authenticatorData.rpIdHash)) {
      return this.fail({ message: 'RP ID hash mismatch' }, 403);
    }
    
    // Verify that the user present bit is set in authenticator data flags.
    if (!(authenticatorData.flags & USER_PRESENT)) {
      return this.fail({ message: 'User not present' }, 403);
    }
    
    // TODO: Verify extensions
    
    var flags = {
      userPresent: !!(authenticatorData.flags & USER_PRESENT),
      userVerified: !!(authenticatorData.flags & USER_VERIFIED)
    };
    
    function verified(err, user, publicKey, info) {
      var hash = crypto.createHash('sha256').update(clientDataJSON).digest();
      var data = Buffer.concat([b_authenticatorData, hash]);
      var signature = base64url.toBuffer(response.signature);
    
      var ok = crypto.createVerify('sha256').update(data).verify(publicKey, signature);
      if (!ok) {
        return self.fail({ message: 'Invalid signature' }, 403);
      }
      
      if (authenticatorData.signCount && (info && info.signCount)) {
        self._verifySignCount(id, authenticatorData.signCount, info.signCount, function(err, ok) {
          if (err) { return self.error(err); }
          if (!ok) { return self.fail({ message: 'Cloned authenticator detected' }, 403); }
          self.success(user, info);
        });
      } else {
        self.success(user, info);
      }
    }
    
    try {
      if (self._passReqToCallback) {
        var arity = self._verify.length;
        switch (arity) {
        case 5:
          return this._verify(req, id, userHandle, flags, verified);
        case 4:
          return this._verify(req, id, userHandle, verified);
        default:
          return this._verify(req, id, verified);
        }
      } else {
        var arity = self._verify.length;
        switch (arity) {
        case 4:
          return this._verify(id, userHandle, flags, verified);
        case 3:
          return this._verify(id, userHandle, verified);
        default:
          return this._verify(id, verified);
        }
      }
    } catch (ex) {
      return self.error(ex);
    }
  } else if (clientData.type === 'webauthn.create') {
    // https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
    
    var b_attestation = base64url.toBuffer(response.attestationObject);
    var attestation = Attestation.parse(b_attestation);
    var authenticatorData = AuthenticatorData.parse(attestation.authData, true, false);
    
    if (!rpIdHash.equals(authenticatorData.rpIdHash)) {
      return this.fail({ message: 'RP ID hash mismatch' }, 403);
    }
    
    if (!(authenticatorData.flags & USER_PRESENT)) {
      return this.fail({ message: 'User not present' }, 403);
    }
    
    var flags = {
      userPresent: !!(authenticatorData.flags & USER_PRESENT),
      userVerified: !!(authenticatorData.flags & USER_VERIFIED)
    };
    
    // TODO: Verify alg is allowed
    
    // TODO: Verify extensions
    
    var format = this._attestationFormats[attestation.fmt];
    if (!format) {
      return this.fail({ message: 'Unsupported attestation format: ' + attestation.fmt }, 400);
    }
    
    var hash = crypto.createHash('sha256').update(clientDataJSON).digest();
    var vAttestation;
    try {
      vAttestation = format.verify(attestation.attStmt, attestation.authData, hash);
    } catch (ex) {
      return this.fail({ message: ex.message }, 400);
    }
    
    var jwk = cose2jwk(authenticatorData.attestedCredentialData.credentialPublicKey);
    var pem = jwk2pem(jwk);
    
    function registered(err, user, info) {
      if (err) { return self.error(err); }
      if (!user) { return self.fail(info); }
      self.success(user, info);
    }
    
    try {
      if (self._passReqToCallback) {
        // TODO
        //this._verify(req, username, password, verified);
      } else {
        // TODO: Need to serialize a user with the challenge, and pass it here for continuation.
        
        // TODO: pass flags object, including user verification booleans
        // TODO: pass sign count here
        // FIXME: Pull id from authData.credentialId
        
        var arity = self._register.length;
        switch (arity) {
        case 7:
          return this._register(id, pem, flags, authenticatorData.signCount, response.transports, vAttestation, registered);
        case 6:
          return this._register(id, pem, flags, authenticatorData.signCount, response.transports, registered);
        case 5:
          return this._register(id, pem, flags, authenticatorData.signCount, registered);
        case 4:
          return this._register(id, pem, flags, registered);
        default:
          return this._register(id, pem, registered);
        }
      }
    } catch (ex) {
      return self.error(ex);
    }
  } else {
    return this.fail({ message: 'Unsupported response type: ' + clientData.type }, 400);
  }
};

// https://www.w3.org/TR/webauthn/#authenticator-data
function parseAuthenticatorData(buffer) {
  var rpIdHash = buffer.slice(0, 32);
  var flags = buffer.slice(32, 33);
  var signCount = buffer.slice(33, 37);

  // TODO: parse attestedCredentialData, if present
  // TODO: parse extensions, if present

  return {
    rpIdHash: rpIdHash,
    flags: flags[0],
    signCount: signCount.readUInt32BE(0)
  };
}


module.exports = Strategy;
