var chai = require('chai');
var sinon = require('sinon');
var Strategy = require('../lib/strategy');


describe('Strategy', function() {
  
  it('should be named webauthn', function() {
    var strategy = new Strategy(function(){});
    
    expect(strategy.name).to.equal('webauthn');
  });
  
  it('should verify credential', function(done) {
    var strategy = new Strategy(function(id, cb) {
      expect(id).to.equal('JYrR3EvvQJNqG0i_OwJckOkbzq4YJWviotG4hig9wA_Qdxm-eBEHfsYqBJKTtXMasL-RD9CFOlcag48icK3E8Q');
      var publicKey =
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/6j9N8S3dBWutrvVJBB3MrU5uipV\n' +
'D8+rZ0GboVEJMPT3HZmICG/06CAPSqcDchP+qLa0N8Tvp9FSmguCnvLtZg==\n' +
'-----END PUBLIC KEY-----\n';
      return cb(null, { id: '248289761001' }, publicKey);
    }, function(){});
    
    chai.passport.use(strategy)
      .request(function(req) {
        req.connection = {};
        req.headers.host = 'localhost:3000';
        req.body = {
          rawId: 'JYrR3EvvQJNqG0i_OwJckOkbzq4YJWviotG4hig9wA_Qdxm-eBEHfsYqBJKTtXMasL-RD9CFOlcag48icK3E8Q',
          response: {
            authenticatorData: 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAANw',
            signature: 'MEYCIQDfGFxZvtHzGZUzfgxIjD4BaF1YF8BKOSGwk-rVkydv3wIhAOZn4lufNS5zptLpfHf-6YPcauXW5MJW_UVnVIHvPzGD',
            userHandle: null,
            clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiTlRZM09BIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0'
          },
          id: 'JYrR3EvvQJNqG0i_OwJckOkbzq4YJWviotG4hig9wA_Qdxm-eBEHfsYqBJKTtXMasL-RD9CFOlcag48icK3E8Q',
          type: 'public-key'
        };
      })
      .success(function(user, info) {
        expect(user).to.deep.equal({ id: '248289761001' });
        expect(info).to.be.undefined;
        done();
      })
      .error(done)
      .authenticate();
  }); // should verify credential
  
  it('should verify Google Chrome on Mac OS X without Touch ID via level 3', function(done) {
    var strategy = new Strategy(function(id, cb) {
      expect(id).to.equal('iFxmcVm7eyw5q34uNELR_lSs4pyeL8CJrHN8ZZanOTrn5JxIMS7Z1Km-ZA');
      var publicKey =
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESo+uMzzeOSkrHdJFfK98BdlhtydB\n' +
'sYCSfcQItYWDgr7qFbPLcRIiuS3ejIa4iFHAe01oslaURGWUxtby39TpQA==\n' +
'-----END PUBLIC KEY-----\n';
      return cb(null, { id: '248289761001' }, publicKey);
    }, function(){});
  
    chai.passport.use(strategy)
      .request(function(req) {
        req.connection = {};
        req.headers.host = 'localhost:3000';
        req.body = {
          "rawId": "iFxmcVm7eyw5q34uNELR_lSs4pyeL8CJrHN8ZZanOTrn5JxIMS7Z1Km-ZA",
          "response": {
            "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA",
            "signature": "MEYCIQCCKxA70welhqy9PZH-sLj09VtYRIkA9w-MryjXfIOc5QIhAOUIqjOk8jkH-vP50sCxRXSb6ZG-iT6bgheMxDHB3JqM",
            "userHandle": "NA",
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiTVRJek5BIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
          },
          "authenticatorAttachment": "platform",
          "id": "iFxmcVm7eyw5q34uNELR_lSs4pyeL8CJrHN8ZZanOTrn5JxIMS7Z1Km-ZA",
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
  }); // should verify Google Chrome on Mac OS X without Touch ID via level 3
  
  it('should verify YubiKey 4 via level 3', function(done) {
    var strategy = new Strategy(function(id, cb) {
      expect(id).to.equal('VjXl8fuJXIAqLg-BVrR5oeLLfee6gBGKXdMxo6xtMySugJfU2HNvTJk84T1DgFYtJDpDrwL2Bg_QM4xQwVAutA');
      var publicKey =
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaLB+Aejtfh9S/i+iU1IfvQswbRlS\n' +
'EGu/tcXrRjnscbMNflAnHVHDeb4PzlexGEjGgrsZiuLmlq+ZTOJjOsGOeQ==\n' +
'-----END PUBLIC KEY-----\n';
      return cb(null, { id: '248289761001' }, publicKey);
    }, function(){});
  
    chai.passport.use(strategy)
      .request(function(req) {
        req.connection = {};
        req.headers.host = 'localhost:3000';
        req.body = {
          "rawId": "VjXl8fuJXIAqLg-BVrR5oeLLfee6gBGKXdMxo6xtMySugJfU2HNvTJk84T1DgFYtJDpDrwL2Bg_QM4xQwVAutA",
          "response": {
            "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAUA",
            "signature": "MEUCICG43QV-jSPIChOZOCh3KO07dtM32dBXFBBOlk34m4BIAiEAp7iRKyhglWg7m8OezNieFOzxZdRl42FyDaXq6jbt45g",
            "userHandle": null,
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiTVRJek5BIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
          },
          "authenticatorAttachment": null,
          "id": "VjXl8fuJXIAqLg-BVrR5oeLLfee6gBGKXdMxo6xtMySugJfU2HNvTJk84T1DgFYtJDpDrwL2Bg_QM4xQwVAutA",
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
  }); // should verify YubiKey 4 via level 3
  
  it('should register YubiKey 5C with no attestation', function(done) {
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
  }); // should register YubiKey 5C with no attestation
  
  it('registering a valid credential from YubiKey 5C with direct attestation in fido-u2f format', function(done) {
    var strategy = new Strategy(function(){}, function(id, publicKey, cb) {
      expect(id).to.equal('JYrR3EvvQJNqG0i_OwJckOkbzq4YJWviotG4hig9wA_Qdxm-eBEHfsYqBJKTtXMasL-RD9CFOlcag48icK3E8Q');
      expect(publicKey).to.equal(
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/6j9N8S3dBWutrvVJBB3MrU5uipV\n' +
'D8+rZ0GboVEJMPT3HZmICG/06CAPSqcDchP+qLa0N8Tvp9FSmguCnvLtZg==\n' +
'-----END PUBLIC KEY-----\n'
      );
      return cb(null, { id: '248289761001' });
    });
  
    chai.passport.use(strategy)
      .request(function(req) {
        req.connection = {};
        req.headers.host = 'localhost:3000';
        req.body = {
          "rawId": "JYrR3EvvQJNqG0i_OwJckOkbzq4YJWviotG4hig9wA_Qdxm-eBEHfsYqBJKTtXMasL-RD9CFOlcag48icK3E8Q",
          "response": {
            "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgX6Gu-qQl37z3nTm2wNRwuoTnAvNYg0CeQnCVU25Hd6kCIQDtbKMA-pYZsb2yAM8fHb4EPP8hENE2pvPfGJ3IKIC-bmN4NWOBWQLBMIICvTCCAaWgAwIBAgIEGKxGwDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNDEzOTQzNDg4MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeeo7LHxJcBBiIwzSP-tg5SkxcdSD8QC-hZ1rD4OXAwG1Rs3Ubs_K4-PzD4Hp7WK9Jo1MHr03s7y-kqjCrutOOqNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC5RwCAQEEBAMCBSAwIQYLKwYBBAGC5RwBAQQEEgQQy2lIHo_3QDmT7AonKaFUqDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCXnQOX2GD4LuFdMRx5brr7Ivqn4ITZurTGG7tX8-a0wYpIN7hcPE7b5IND9Nal2bHO2orh_tSRKSFzBY5e4cvda9rAdVfGoOjTaCW6FZ5_ta2M2vgEhoz5Do8fiuoXwBa1XCp61JfIlPtx11PXm5pIS2w3bXI7mY0uHUMGvxAzta74zKXLslaLaSQibSKjWKt9h-SsXy4JGqcVefOlaQlJfXL1Tga6wcO0QTu6Xq-Uw7ZPNPnrpBrLauKDd202RlN4SP7ohL3d9bG6V5hUz_3OusNEBZUn5W3VmPj1ZnFavkMB3RkRMOa58MZAORJT4imAPzrvJ0vtv94_y71C6tZ5aGF1dGhEYXRhWMRJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0EAAAAAAAAAAAAAAAAAAAAAAAAAAABAJYrR3EvvQJNqG0i_OwJckOkbzq4YJWviotG4hig9wA_Qdxm-eBEHfsYqBJKTtXMasL-RD9CFOlcag48icK3E8aUBAgMmIAEhWCD_qP03xLd0Fa62u9UkEHcytTm6KlUPz6tnQZuhUQkw9CJYIPcdmYgIb_ToIA9KpwNyE_6otrQ3xO-n0VKaC4Ke8u1m",
            "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJNVEl6TkEiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"
          },
          "id": "JYrR3EvvQJNqG0i_OwJckOkbzq4YJWviotG4hig9wA_Qdxm-eBEHfsYqBJKTtXMasL-RD9CFOlcag48icK3E8Q",
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
  });
  
  it('should register Google Chrome on Mac OS X without Touch ID with no attestation via level 3', function(done) {
    var strategy = new Strategy(function(){}, function(id, publicKey, cb) {
      
      expect(id).to.equal('noMuGuaaVLubAVjuS6Z2BYrrBpajYhtjnFgvSjk0IV1LJeVrupbpnw');
      expect(publicKey).to.equal(
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErujwiSbsh53HcaC4ohSuid5DvZbr\n' +
'AONRIXCYQTX0UFH6pVdJ7FZ7j/obBTXN9FNNK9neay4OjrmUM9oyI9VQKw==\n' +
'-----END PUBLIC KEY-----\n'
      );
      return cb(null, { id: '248289761001' });
    });
  
    chai.passport.use(strategy)
      .request(function(req) {
        req.connection = {};
        req.headers.host = 'localhost:3000';
        req.body = {
          "rawId": "noMuGuaaVLubAVjuS6Z2BYrrBpajYhtjnFgvSjk0IV1LJeVrupbpnw",
          "response": {
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVisSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAKJ6DLhrmmlS7mwFY7kumdgWK6waWo2IbY5xYL0o5NCFdSyXla7qW6Z-lAQIDJiABIVggrujwiSbsh53HcaC4ohSuid5DvZbrAONRIXCYQTX0UFEiWCD6pVdJ7FZ7j_obBTXN9FNNK9neay4OjrmUM9oyI9VQKw",
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTVRJek5BIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ",
            "transports": [ "internal" ]
          },
          "authenticatorAttachment": "platform",
          "id": "noMuGuaaVLubAVjuS6Z2BYrrBpajYhtjnFgvSjk0IV1LJeVrupbpnw",
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
  }); // should register Google Chrome on Mac OS X without Touch ID with no attestation via level 3
  
  it('should register YubiKey 4 with no attestation via level 3', function(done) {
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
  }); // should register YubiKey 4 with no attestation via level 3
  
});
