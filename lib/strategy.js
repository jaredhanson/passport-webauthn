/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
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
  
  
};

module.exports = Strategy;
