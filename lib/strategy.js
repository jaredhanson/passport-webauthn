/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , url = require('url')
  , crypto = require('crypto')
  , cose2jwk = require('cose-to-jwk')
  , jwk2pem = require('jwk-to-pem')
  , base64url = require('base64url')
  , util = require('util')
  , utils = require('./utils')
  , Attestation = require('./fido2/attestation')
  , AuthenticatorData = require('./fido2/authenticatordata')
  , SessionStore = require('./store/session');

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
  this._store = options.store || new SessionStore();
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req, options) {
  var response = req.body.response;
  var clientDataJSON = base64url.decode(response.clientDataJSON);
  var clientData = JSON.parse(clientDataJSON);
  
  var self = this;
  
  function validated(err, ok, ctx) {
    if (err) { return self.error(err); }
    if (!ok) {
      return self.fail(ctx, 403);
    }
    ctx = ctx || {};
  
    // Verify that the origin contained in client data matches the origin of this
    // app (which is the relying party).
    var origin = utils.originalOrigin(req);
    if (origin !== clientData.origin) {
      return self.fail({ message: 'Origin mismatch' }, 403);
    }
  
    // TODO: Verify the state of Token Binding for the TLS connection over which
    // the attestation was obtained.
    
    var rpID = url.parse(origin).hostname;
    var rpIdHash = crypto.createHash('sha256').update(rpID).digest();
  
    if (clientData.type === 'webauthn.get') {
      // https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion
    
      // TODO: Verify that credentials was in allowedCredentials, if set
      
      var userHandle = null;
      if (response.userHandle) {
        userHandle = base64url.toBuffer(response.userHandle);
      }
      
      if (!ctx.user) {
        // If the user was not identified before the authentication ceremony was
        // initiated, response.userHandle must be present.
        //
        // NOTE: User handle being set should imply resident keys (???)
        if (!userHandle) { return self.fail({ message: 'User handle not set' }, 403); };
      } else {
        if (userHandle && (Buffer.compare(ctx.user.id, userHandle) != 0)) {
          // If the user was identified before the authentication ceremony was
          // initiated, if response.userHandle is present, it must map to the
          // same user.
          return self.fail({ message: 'User handle does not map to user' }, 403);
        }
      }
      
      var b_authenticatorData = base64url.toBuffer(response.authenticatorData);
      var authenticatorData = AuthenticatorData.parse(b_authenticatorData);
    
      // TODO: Support appID extension for rpIdHash
    
      // Verify that the RP ID hash contained in authenticator data matches the
      // hash of this app's (which is the relying party) RP ID.
      if (!rpIdHash.equals(authenticatorData.rpIdHash)) {
        return self.fail({ message: 'RP ID hash mismatch' }, 403);
      }
    
      // Verify that the user present bit is set in authenticator data flags.
      if (!(authenticatorData.flags & USER_PRESENT)) {
        return self.fail({ message: 'User not present' }, 403);
      }
    
      // TODO: Verify that extensions are as expected.
    
      var id = req.body.id;
      var flags = {
        userPresent: !!(authenticatorData.flags & USER_PRESENT),
        userVerified: !!(authenticatorData.flags & USER_VERIFIED)
      };
    
      function verified(err, user, publicKey, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(publicKey); }
        
        var hash = crypto.createHash('sha256').update(clientDataJSON).digest();
        var data = Buffer.concat([b_authenticatorData, hash]);
        var signature = base64url.toBuffer(response.signature);
    
        // Verify that the signature is valid.
        var ok = crypto.createVerify('sha256').update(data).verify(publicKey, signature);
        if (!ok) {
          return self.fail({ message: 'Invalid signature' }, 403);
        }
      
        // If the application desires, allow it to process the signature counter
        // in order to detect cloned authenticators and incorporate this
        // information into risk scoring.
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
            return self._verify(req, id, userHandle, flags, verified);
          default:
            return self._verify(req, id, userHandle, verified);
          }
        } else {
          var arity = self._verify.length;
          switch (arity) {
          case 4:
            return self._verify(id, userHandle, flags, verified);
          default:
            return self._verify(id, userHandle, verified);
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
    
      // Verify that the RP ID hash contained in authenticator data matches the
      // hash of this app's (which is the relying party) RP ID.
      if (!rpIdHash.equals(authenticatorData.rpIdHash)) {
        return self.fail({ message: 'RP ID hash mismatch' }, 403);
      }
    
      // Verify that the user present bit is set in authenticator data flags.
      if (!(authenticatorData.flags & USER_PRESENT)) {
        return self.fail({ message: 'User not present' }, 403);
      }
    
      // TODO: Verify alg is allowed
    
      // TODO: Verify that extensions are as expected.
    
      var format = self._attestationFormats[attestation.fmt];
      if (!format) {
        return self.fail({ message: 'Unsupported attestation format: ' + attestation.fmt }, 400);
      }
    
      // Verify that the attestation statement conveys a valid attestation signature.
      var hash = crypto.createHash('sha256').update(clientDataJSON).digest();
      var vAttestation;
      try {
        vAttestation = format.verify(attestation.attStmt, attestation.authData, hash);
      } catch (ex) {
        return self.fail({ message: ex.message }, 400);
      }
    
      var credentialId = base64url.encode(authenticatorData.attestedCredentialData.credentialId);
      var jwk = cose2jwk(authenticatorData.attestedCredentialData.credentialPublicKey);
      var pem = jwk2pem(jwk);
      var flags = {
        userPresent: !!(authenticatorData.flags & USER_PRESENT),
        userVerified: !!(authenticatorData.flags & USER_VERIFIED)
      };
    
      function registered(err, user, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(info); }
        self.success(user, info);
      }
    
      try {
        if (self._passReqToCallback) {
          // TODO
          //self._verify(req, username, password, verified);
        } else {
          var arity = self._register.length;
          switch (arity) {
          case 8:
            return self._register(ctx.user, credentialId, pem, flags, authenticatorData.signCount, response.transports, vAttestation, registered);
          case 7:
            return self._register(ctx.user, credentialId, pem, flags, authenticatorData.signCount, response.transports, registered);
          case 6:
            return self._register(ctx.user, credentialId, pem, flags, authenticatorData.signCount, registered);
          case 5:
            return self._register(ctx.user, credentialId, pem, flags, registered);
          default:
            return self._register(ctx.user, credentialId, pem, registered);
          }
        }
      } catch (ex) {
        return self.error(ex);
      }
    } else {
      return self.fail({ message: 'Unsupported response type: ' + clientData.type }, 400);
    }
  }
  
  // Verify that the challenge (aka nonce) received from the client equals the
  // challenge sent.
  var challenge = base64url.toBuffer(clientData.challenge);
  this._store.verify(req, challenge, validated);
};

module.exports = Strategy;
