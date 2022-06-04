var jws = require('jws');
var crypto = require('crypto');

// https://developer.android.com/training/safetynet/attestation.html
exports.verify = function(attStmt, authData, hash) {
  var att = this.parse(attStmt);
  
  // Verify that the nonce attribute in the payload of response is identical to
  // the Base64 encoding of the SHA-256 hash of the concatenation of authData
  // and hash.
  var nonce = crypto.createHash('sha256').update(Buffer.concat([authData, hash])).digest('base64');
  if (att.response.nonce !== nonce) {
    return false;
  }
  // Verify the signature of the attestation response.
  var ok = jws.verify(attStmt.response, 'RS256', att.trustPath[0].publicKey);
  if (!ok) { return false; }
  
  return {
    type: 'basic',
    format: 'android-safetynet',
    response: att.response,
    trustPath: att.trustPath
  };
};

exports.parse = function(attStmt) {
  var response = jws.decode(attStmt.response, { json: true });
  
  return {
    version: attStmt.ver,
    response: response.payload,
    trustPath: response.header.x5c.map(function(c) {
      return new crypto.X509Certificate(Buffer.from(c.toString(), 'base64'));
    })
  };
};
