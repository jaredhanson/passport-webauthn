/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , base64url = require('base64url')
  , crypto = require('crypto')
  , util = require('util')
  , cose2jwk = require('cose-to-jwk')
  , jwk2pem = require('jwk-to-pem')
  , Attestation = require('./webauthn/attestation')
  , AuthenticatorData = require('./webauthn/authenticatordata')
  , fidou2f = require('./webauthn/fido-u2f')
  , packed = require('./webauthn/packed')
  , utils = require('./utils')
  , url = require('url')

var USER_PRESENT = 0x01;
var USER_VERIFIED = 0x04;


function Strategy(options, verify, register) {
  if (typeof options == 'function') {
    register = verify;
    verify = options;
    options = {};
  }
  
  passport.Strategy.call(this);
  this.name = 'webauthn';
  this._verify = verify;
  this._register = register;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req, options) {
  console.log('WEBAUTHN AUTHENTICATE!');
  console.log(req.body);
  console.log('---');
  //return;
  
  // FIXME: Pull id from authData.credentialId
  var id = req.body.id;
  var response = req.body.response;
  var clientDataJSON = base64url.decode(response.clientDataJSON);
  var clientData = JSON.parse(clientDataJSON);
  
  console.log(clientData);
  
  // https://www.w3.org/TR/webauthn/#verifying-assertion
  
  // TODO: Verify challenge
  
  var origin = utils.originalOrigin(req);
  if (origin !== clientData.origin) {
    return this.fail({ message: 'Non-matching origin: ' + clientData.origin }, 400);
  }
  
  // TODO: verify token binding
  
  var rpID = url.parse(origin).hostname;
  
  var rpIdHash = crypto.createHash('sha256').update(rpID).digest();
  
  
  // TODO: verify response.userHandle (???? HOW ???)
  
  
  
  var self = this;
  
  if (clientData.type === 'webauthn.get') {
    // TODO: Verify that credentials was in allowedCredentials
    
    // https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion
    
    
    var userHandle = null;
    if (response.userHandle) {
      userHandle = base64url.decode(response.userHandle);
      console.log(userHandle);
    }
    
    var b_authenticatorData = base64url.toBuffer(response.authenticatorData);
    var authenticatorData = AuthenticatorData.parse(b_authenticatorData);
    
    console.log(authenticatorData);
    
    if (!rpIdHash.equals(authenticatorData.rpIdHash)) {
      return this.fail({ message: 'Non-matching RP ID hash' }, 400);
    }
    
    if (!(authenticatorData.flags & USER_PRESENT)) {
      return this.fail({ message: 'User not present during authentication' }, 400);
    }
    
    // TODO: Option to check user verification (or pass it to verify callback)
    
    // TODO: Verify extensions
    
    function verified(err, user, publicKey) {
      var hash = crypto.createHash('sha256').update(clientDataJSON).digest();
      var data = Buffer.concat([b_authenticatorData, hash]);
      var signature = base64url.toBuffer(response.signature);
    
      var ok = crypto.createVerify('sha256').update(data).verify(publicKey, signature);
      if (!ok) {
        return self.fail({ message: 'Invalid signature' });
      }
      self.success(user);
    }
    
    
    console.log('VERIFYING!!!');
    
    try {
      if (self._passReqToCallback) {
        // TODO
        //this._verify(req, username, password, verified);
      } else {
        
        var arity = self._verify.length;
        switch (arity) {
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
    console.log('register!');
    
    // https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
    
    
    var b_attestation = base64url.toBuffer(response.attestationObject);
    var attestation = Attestation.parse(b_attestation);
    console.log(attestation);
    
    var authenticatorData = AuthenticatorData.parse(attestation.authData, true, false);
    console.log(authenticatorData)
    
    if (!rpIdHash.equals(authenticatorData.rpIdHash)) {
      return this.fail({ message: 'Non-matching RP ID hash' }, 400);
    }
    
    if (!(authenticatorData.flags & USER_PRESENT)) {
      return this.fail({ message: 'User not present during registration' }, 400);
    }
    
    var flags = {
      userPresent: !!(authenticatorData.flags & USER_PRESENT),
      userVerified: !!(authenticatorData.flags & USER_VERIFIED)
    };
    
    // TODO: Verify alg is allowed
    
    // TODO: Verify extensions
    
    // TODO: Verify attestation statement
    
    var jwk = cose2jwk(authenticatorData.attestedCredentialData.credentialPublicKey);
    console.log(jwk)
    
    var pem = jwk2pem(jwk);
    console.log(pem);
    
    switch (attestation.fmt) {
    case 'fido-u2f':
      fidou2f.parse(attestation.attStmt);
      break;
    case 'packed':
      packed.parse(attestation.attStmt);
      break;
    }
    
    
    console.log('HERE!');
    
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
