/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , base64url = require('base64url')
  , crypto = require('crypto')
  , util = require('util')

var USER_PRESENT = 0x01;


function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  
  passport.Strategy.call(this);
  this.name = 'webauthn';
  this._verify = verify;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req, options) {
  console.log('WEBAUTHN AUTHENTICATE!');
  console.log(req.body);
  
  var id = req.body.id;
  var response = req.body.response;
  var clientDataBuffer = base64url.decode(response.clientDataJSON);
  var clientData = JSON.parse(clientDataBuffer);
  
  console.log(clientData);
  
  // https://www.w3.org/TR/webauthn/#verifying-assertion
  
  if (clientData.type != 'webauthn.get') {
    return this.fail({ message: 'Unsupported response type: ' + clientData.type }, 400);
  }
  // TODO: Verify challenge
  // TODO: verify origin
  // TODO: verify token binding
  
  // TODO: verify response.userHandle (???? HOW ???)
  
  
  
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
