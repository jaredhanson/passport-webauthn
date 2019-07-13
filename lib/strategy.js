/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , base64url = require('base64url')
  , util = require('util')

function Strategy(options, verify) {
  passport.Strategy.call(this);
  this.name = 'webauthn';
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req, options) {
  console.log('WEBAUTHN AUTHENTICATE!');
  console.log(req.body);
  
  var response = req.body.response;
  var clientData = JSON.parse(base64url.decode(response.clientDataJSON));
  
  console.log(clientData);
  
  // https://www.w3.org/TR/webauthn/#verifying-assertion
  
  if (clientData.type != 'webauthn.get') {
    return this.fail({ message: 'Unsupported response type: ' + clientData.type }, 400);
  }
  // TODO: Verify challenge
  // TODO: verify origin
  // TODO: verify token binding
  
  // TODO: verify response.userHandle (???? HOW ???)
  
  console.log('verify it...');
  
  var authenticatorData = parseAuthenticatorData(base64url.toBuffer(response.authenticatorData));
  console.log(authenticatorData);
  
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
  let rpIdHash      = buffer.slice(0, 32);
  let flagsBuf      = buffer.slice(32, 33);
  let flags         = flagsBuf[0];
  let counterBuf    = buffer.slice(33, 37);
  let counter       = counterBuf.readUInt32BE(0);

  return {rpIdHash, flagsBuf, flags, counter, counterBuf}
}


module.exports = Strategy;
