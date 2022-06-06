var cbor = require('cbor');

exports.USER_PRESENT = 0x01;
exports.USER_VERIFIED = 0x04;
exports.ATTESTED_CREDENTIAL_DATA_INCLUDED = 0x40;
exports.EXTENSIONS_INCLUDED = 0x80;


exports.parse = function(buffer, parseACD, parseCPK) {
  parseACD = parseACD !== undefined ? parseACD : true;
  parseCPK = parseCPK !== undefined ? parseCPK : true;
  
  var rpIdHash = buffer.slice(0, 32);
  var flags = buffer.slice(32, 33);
  var signCount = buffer.slice(33, 37);
  var pos, len;
  
  // TODO: attested credential data
  // TODO: extensions
  
  var authData = {
    rpIdHash: rpIdHash,
    flags: flags[0],
    signCount: signCount.readUInt32BE(0)
  };
  
  if ((authData.flags & exports.ATTESTED_CREDENTIAL_DATA_INCLUDED) && parseACD) {
    authData.attestedCredentialData = {
      aaguid: buffer.slice(37, 53)
    };
    
    len = buffer.slice(53, 55);
    len = len.readUInt16BE(0);
    authData.attestedCredentialData.credentialId = buffer.slice(55, 55 + len);
    pos = 55 + len;
    
    // TODO: Determine length of key, so extensions can be parsed, if any
    if (parseCPK) {
      var publicKey = cbor.decodeFirstSync(buffer.slice(pos));
      authData.attestedCredentialData.credentialPublicKey = publicKey;
    } else {
      authData.attestedCredentialData.credentialPublicKey = buffer.slice(pos);
    }
  }
  
  if (authData.flags & exports.EXTENSIONS_INCLUDED) {
    authData.extensions = {}
  }
  
  return authData;
};
