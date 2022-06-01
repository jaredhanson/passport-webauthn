var chai = require('chai');
var sinon = require('sinon');
var Strategy = require('../lib/strategy');


describe('Strategy', function() {
  
  it('should be named webauthn', function() {
    var strategy = new Strategy(function(){});
    
    expect(strategy.name).to.equal('webauthn');
  });
  
  
  it('should register a YubiKey 5C with no attestation', function(done) {
    var strategy = new Strategy(function(){}, function(id, publicKey, cb) {
      expect(id).to.equal('n90ZI-FwPA9HT5jtZins33Rtae1Zz1zLnoDR9yCj5Jwz2PB6fJR0KCPZehORB-ht48mRfbcA512cnDyfbQQ0OQ');
      expect(publicKey).to.equal(
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEp+ZH3WpsBVUojVZ1D1BufQoSMplI\n' +
'VbiKl+g4PojQCflkt+eEtwaQkv2aRTTLMVHr0gucag7QbOA0m/WyFtuXIg==\n' +
'-----END PUBLIC KEY-----\n'
      );
      return cb(null, { id: '248289761001' });
    });
  
    chai.passport.use(strategy)
      .request(function(req) {
        req.connection = {};
        req.headers.host = 'localhost:3000';
        req.body = {
          "rawId": "n90ZI-FwPA9HT5jtZins33Rtae1Zz1zLnoDR9yCj5Jwz2PB6fJR0KCPZehORB-ht48mRfbcA512cnDyfbQQ0OQ",
          "response": {
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAOgAAAAAAAAAAAAAAAAAAAAAAQJ_dGSPhcDwPR0-Y7WYp7N90bWntWc9cy56A0fcgo-ScM9jwenyUdCgj2XoTkQfobePJkX23AOddnJw8n20ENDmlAQIDJiABIVggp-ZH3WpsBVUojVZ1D1BufQoSMplIVbiKl-g4PojQCfkiWCBkt-eEtwaQkv2aRTTLMVHr0gucag7QbOA0m_WyFtuXIg",
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTVRJek5BIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
          },
          "id": "n90ZI-FwPA9HT5jtZins33Rtae1Zz1zLnoDR9yCj5Jwz2PB6fJR0KCPZehORB-ht48mRfbcA512cnDyfbQQ0OQ",
          "type": "public-key"
        };
        
      })
      .success(function(user, info) {
        expect(user).to.deep.equal({ id: '248289761001' });
        expect(info).to.be.undefined;
        done();
      })
      .error(done)
      .authenticate();
  }); // should register a YubiKey 5C with no attestation
  
  it('should register a YubiKey 4 with no attestation via level 3', function(done) {
    var strategy = new Strategy(function(){}, function(id, publicKey, cb) {
      
      expect(id).to.equal('12T-jjmoUpVJ-1z7Bx-OYFo-MxDj8_xbne6iytC9scwbBjutzSUNdK9wphc4oNnmPqSbp-6UDba3ztUrAy2dcw');
      expect(publicKey).to.equal(
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEc42HZW7iW+hIXF90W5wgxeKu4M8Q\n' +
'zMwC4eHnaO2CifIVgKhxEZbVZ5ANWVwXmhXodN7R05KQtar4HlCTg1WUrg==\n' +
'-----END PUBLIC KEY-----\n'
      );
      return cb(null, { id: '248289761001' });
    });
  
    chai.passport.use(strategy)
      .request(function(req) {
        req.connection = {};
        req.headers.host = 'localhost:3000';
        req.body = {
          "rawId": "12T-jjmoUpVJ-1z7Bx-OYFo-MxDj8_xbne6iytC9scwbBjutzSUNdK9wphc4oNnmPqSbp-6UDba3ztUrAy2dcw",
          "response": {
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQNdk_o45qFKVSftc-wcfjmBaPjMQ4_P8W53uosrQvbHMGwY7rc0lDXSvcKYXOKDZ5j6km6fulA22t87VKwMtnXOlAQIDJiABIVggc42HZW7iW-hIXF90W5wgxeKu4M8QzMwC4eHnaO2CifIiWCAVgKhxEZbVZ5ANWVwXmhXodN7R05KQtar4HlCTg1WUrg",
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTVRJek5BIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0",
            "transports": [ "usb" ]
          },
          "authenticatorAttachment": "cross-platform",
          "id": "12T-jjmoUpVJ-1z7Bx-OYFo-MxDj8_xbne6iytC9scwbBjutzSUNdK9wphc4oNnmPqSbp-6UDba3ztUrAy2dcw",
          "type": "public-key"
        };
        
      })
      .success(function(user, info) {
        expect(user).to.deep.equal({ id: '248289761001' });
        expect(info).to.be.undefined;
        done();
      })
      .error(done)
      .authenticate();
  }); // should register a YubiKey 4 with no attestation via level 3
  
});