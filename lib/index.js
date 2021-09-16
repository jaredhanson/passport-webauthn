/**
 * Module dependencies.
 */
var Strategy = require('./strategy')
  , Strategy2 = require('./strategy2');


/**
 * Expose `Strategy` directly from package.
 */
exports = module.exports = Strategy;

/**
 * Export constructors.
 */
exports.Strategy = Strategy;
exports.MFAStrategy =
exports.Strategy2 = Strategy2;

exports.webauthn = require('./webauthn');
