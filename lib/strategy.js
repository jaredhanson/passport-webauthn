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
    var b_authenticatorData = base64url.toBuffer(response.authenticatorData);
    var authenticatorData = AuthenticatorData.parse(b_authenticatorData);
    
    // TODO: Verify rpIdHash??
    
    console.log(authenticatorData)
    
    function verified(err, user, publicKey) {
      var signature = base64url.toBuffer(response.signature);
  
      var hash = crypto.createHash('sha256').update(clientDataJSON).digest();
      var data = Buffer.concat([b_authenticatorData, hash]);
    
      var ok = crypto.createVerify('sha256').update(data).verify(publicKey, signature);
      
      if (!ok) {
        return self.fail({ message: 'Invalid signature' });
      }
    
      self.success(user);
    }
    
    
    
    try {
      if (self._passReqToCallback) {
        // TODO
        //this._verify(req, username, password, verified);
      } else {
        this._verify(id, verified);
      }
    } catch (ex) {
      return self.error(ex);
    }
    
    
  } else if (clientData.type === 'webauthn.create') {
    console.log('!CREATE!');
    
    https://www.w3.org/TR/webauthn-1/#registering-a-new-credential
    
    var self = this;
    
    var b_attestation = base64url.toBuffer(response.attestationObject);
    var attestation = Attestation.parse(b_attestation);
    console.log(attestation);
    
    var authenticatorData = AuthenticatorData.parse(attestation.authData, true, false);
    console.log(authenticatorData)
    
    if (!rpIdHash.equals(authenticatorData.rpIdHash)) {
      return this.fail({ message: 'Non-matching RP ID hash' }, 400);
    }
    
    
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
    
    
    // TODO: Compare authData credentialID with that in body.id
    
    function registered(err, user) {
      console.log('REGISTERED!');
      console.log(err)
      console.log(user);
      
      self.success(user);
    }
    
    
    try {
      if (self._passReqToCallback) {
        // TODO
        //this._verify(req, username, password, verified);
      } else {
        this._register(id, pem, registered);
      }
    } catch (ex) {
      return self.error(ex);
    }
    
  } else {
    return this.fail({ message: 'Unsupported response type: ' + clientData.type }, 400);
  }
  
  
  
  return;
  
  var authenticatorDataBuffer = base64url.toBuffer(response.authenticatorData);
  var authenticatorData = parseAuthenticatorData(authenticatorDataBuffer);
  console.log(authenticatorData);
  
  
  if (!(authenticatorData.flags & USER_PRESENT)) {
    return this.fail({ message: 'User not present during authentication' }, 400);
  }
  
  // TODO: Verify user verified, if necessary
  
  console.log('verify it...');
  
  var self = this;
  
  function verified(err, user, publicKey) {
    console.log('VERIFIED!');
    console.log(err)
    console.log(user);
    console.log(publicKey)
    
    return;
  
    var signature = base64url.toBuffer(response.signature);
  
    var hash = crypto.createHash('sha256').update(clientDataBuffer).digest();
    var data = Buffer.concat([authenticatorDataBuffer, hash]);
    
    var ok = crypto.createVerify('sha256').update(data).verify(publicKey, signature);
    
    console.log('OK? ' + ok);
    
    if (!ok) {
      return this.fail({ message: 'Invalid signature' });
    }
    
    self.success(user);
  }
  
  try {
    if (self._passReqToCallback) {
      // TODO
      //this._verify(req, username, password, verified);
    } else {
      this._verify(id, verified);
    }
  } catch (ex) {
    return self.error(ex);
  }
  
  /*
{ rpIdHash:
   <Buffer 49 96 0d e5 88 0e 8c 68 74 34 17 0f 64 76 60 5b 8f e4 ae b9 a2 86 32 c7 99 5c f3 ba 83 1d 97 63>,
  flagsBuf: <Buffer 01>,
  flags: 1,
  counter: 21,
  counterBuf: <Buffer 00 00 00 15> }
  */
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
