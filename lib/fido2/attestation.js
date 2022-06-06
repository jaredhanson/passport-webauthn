var cbor = require('cbor');

exports.parse = function(buffer) {
  return cbor.decodeFirstSync(buffer);
};
