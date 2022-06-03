var chai = require('chai');
var sinon = require('sinon');
var Strategy = require('../lib/strategy');


describe('Strategy', function() {
  
  it('should be named webauthn', function() {
    var strategy = new Strategy(function(){});
    
    expect(strategy.name).to.equal('webauthn');
  });
  
  it('should verify credential', function(done) {
    chai.passport.use(new Strategy(function(id, cb) {
      expect(id).to.equal('JYrR3EvvQJNqG0i_OwJckOkbzq4YJWviotG4hig9wA_Qdxm-eBEHfsYqBJKTtXMasL-RD9CFOlcag48icK3E8Q');
      var publicKey =
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/6j9N8S3dBWutrvVJBB3MrU5uipV\n' +
'D8+rZ0GboVEJMPT3HZmICG/06CAPSqcDchP+qLa0N8Tvp9FSmguCnvLtZg==\n' +
'-----END PUBLIC KEY-----\n';
      return cb(null, { id: '248289761001' }, publicKey);
    }, function(){}))
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
    chai.passport.use(new Strategy(function(id, cb) {
      expect(id).to.equal('iFxmcVm7eyw5q34uNELR_lSs4pyeL8CJrHN8ZZanOTrn5JxIMS7Z1Km-ZA');
      var publicKey =
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESo+uMzzeOSkrHdJFfK98BdlhtydB\n' +
'sYCSfcQItYWDgr7qFbPLcRIiuS3ejIa4iFHAe01oslaURGWUxtby39TpQA==\n' +
'-----END PUBLIC KEY-----\n';
      return cb(null, { id: '248289761001' }, publicKey);
    }, function(){}))
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
  
  it('should verify Google Chrome on Mac OS X without Touch ID using user handle via level 3', function(done) {
    chai.passport.use(new Strategy(function(id, userHandle, cb) {
      expect(id).to.equal('iFxmcVm7eyw5q34uNELR_lSs4pyeL8CJrHN8ZZanOTrn5JxIMS7Z1Km-ZA');
      expect(userHandle).to.equal('4');
      var publicKey =
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESo+uMzzeOSkrHdJFfK98BdlhtydB\n' +
'sYCSfcQItYWDgr7qFbPLcRIiuS3ejIa4iFHAe01oslaURGWUxtby39TpQA==\n' +
'-----END PUBLIC KEY-----\n';
      return cb(null, { id: '248289761001' }, publicKey);
    }, function(){}))
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
  }); // should verify Google Chrome on Mac OS X without Touch ID using user handle via level 3
  
  it('should verify Google Chrome on Mac OS X without Touch ID using user handle and flags via level 3', function(done) {
    chai.passport.use(new Strategy(function(id, userHandle, flags, cb) {
      expect(id).to.equal('iFxmcVm7eyw5q34uNELR_lSs4pyeL8CJrHN8ZZanOTrn5JxIMS7Z1Km-ZA');
      expect(userHandle).to.equal('4');
      expect(flags).to.deep.equal({
        userPresent: true,
        userVerified: true
      });
      var publicKey =
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESo+uMzzeOSkrHdJFfK98BdlhtydB\n' +
'sYCSfcQItYWDgr7qFbPLcRIiuS3ejIa4iFHAe01oslaURGWUxtby39TpQA==\n' +
'-----END PUBLIC KEY-----\n';
      return cb(null, { id: '248289761001' }, publicKey);
    }, function(){}))
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
  }); // should verify Google Chrome on Mac OS X without Touch ID using user handle and flags via level 3
  
  it('should verify YubiKey 4 via level 3', function(done) {
    chai.passport.use(new Strategy(function(id, cb) {
      expect(id).to.equal('VjXl8fuJXIAqLg-BVrR5oeLLfee6gBGKXdMxo6xtMySugJfU2HNvTJk84T1DgFYtJDpDrwL2Bg_QM4xQwVAutA');
      var publicKey =
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaLB+Aejtfh9S/i+iU1IfvQswbRlS\n' +
'EGu/tcXrRjnscbMNflAnHVHDeb4PzlexGEjGgrsZiuLmlq+ZTOJjOsGOeQ==\n' +
'-----END PUBLIC KEY-----\n';
      return cb(null, { id: '248289761001' }, publicKey);
    }, function(){}))
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
  
  it('should verify YubiKey 4 using user handle via level 3', function(done) {
    chai.passport.use(new Strategy(function(id, userHandle, cb) {
      expect(id).to.equal('VjXl8fuJXIAqLg-BVrR5oeLLfee6gBGKXdMxo6xtMySugJfU2HNvTJk84T1DgFYtJDpDrwL2Bg_QM4xQwVAutA');
      expect(userHandle).to.be.null;
      var publicKey =
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaLB+Aejtfh9S/i+iU1IfvQswbRlS\n' +
'EGu/tcXrRjnscbMNflAnHVHDeb4PzlexGEjGgrsZiuLmlq+ZTOJjOsGOeQ==\n' +
'-----END PUBLIC KEY-----\n';
      return cb(null, { id: '248289761001' }, publicKey);
    }, function(){}))
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
  }); // should verify YubiKey 4 using user handle via level 3
  
  it('should verify YubiKey 4 using user handle and flags via level 3', function(done) {
    chai.passport.use(new Strategy(function(id, userHandle, flags, cb) {
      expect(id).to.equal('VjXl8fuJXIAqLg-BVrR5oeLLfee6gBGKXdMxo6xtMySugJfU2HNvTJk84T1DgFYtJDpDrwL2Bg_QM4xQwVAutA');
      expect(userHandle).to.be.null;
      expect(flags).to.deep.equal({
        userPresent: true,
        userVerified: false
      });
      var publicKey =
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaLB+Aejtfh9S/i+iU1IfvQswbRlS\n' +
'EGu/tcXrRjnscbMNflAnHVHDeb4PzlexGEjGgrsZiuLmlq+ZTOJjOsGOeQ==\n' +
'-----END PUBLIC KEY-----\n';
      return cb(null, { id: '248289761001' }, publicKey);
    }, function(){}))
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
  }); // should verify YubiKey 4 using user handle and flags via level 3
  
  it('should verify YubiKey 4 signature counter via level 3', function(done) {
    function verifySignCount(id, signCount, storedSignCount, cb) {
      expect(id).to.equal('VjXl8fuJXIAqLg-BVrR5oeLLfee6gBGKXdMxo6xtMySugJfU2HNvTJk84T1DgFYtJDpDrwL2Bg_QM4xQwVAutA');
      expect(signCount).to.equal(80);
      expect(storedSignCount).to.equal(79);
      return cb(null, true);
    }
    var verifySignCountSpy = sinon.spy(verifySignCount);
    
    chai.passport.use(new Strategy(function(id, cb) {
      expect(id).to.equal('VjXl8fuJXIAqLg-BVrR5oeLLfee6gBGKXdMxo6xtMySugJfU2HNvTJk84T1DgFYtJDpDrwL2Bg_QM4xQwVAutA');
      var publicKey =
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaLB+Aejtfh9S/i+iU1IfvQswbRlS\n' +
'EGu/tcXrRjnscbMNflAnHVHDeb4PzlexGEjGgrsZiuLmlq+ZTOJjOsGOeQ==\n' +
'-----END PUBLIC KEY-----\n';
      return cb(null, { id: '248289761001' }, publicKey, { signCount: 79 });
    }, verifySignCountSpy, function(){}))
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
        expect(info).to.deep.equal({ signCount: 79 });
        expect(verifySignCountSpy).to.have.been.called;
        done();
      })
      .error(done)
      .authenticate();
  }); // should verify YubiKey 4 signature counter via level 3
  
  it('should fail when origin does not match', function(done) {
    chai.passport.use(new Strategy(function(id, cb) {
      expect(id).to.equal('iFxmcVm7eyw5q34uNELR_lSs4pyeL8CJrHN8ZZanOTrn5JxIMS7Z1Km-ZA');
      var publicKey =
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESo+uMzzeOSkrHdJFfK98BdlhtydB\n' +
'sYCSfcQItYWDgr7qFbPLcRIiuS3ejIa4iFHAe01oslaURGWUxtby39TpQA==\n' +
'-----END PUBLIC KEY-----\n';
      return cb(null, { id: '248289761001' }, publicKey);
    }, function(){}))
      .request(function(req) {
        req.connection = {};
        req.headers.host = 'localhost:3999';
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
      .fail(function(challenge, status) {
        expect(challenge).to.deep.equal({ message: 'Origin mismatch' });
        expect(status).to.equal(403);
        done();
      })
      .error(done)
      .authenticate();
  }); // should fail when origin does not match
  
  it('should fail when signature is invalid', function(done) {
    chai.passport.use(new Strategy(function(id, cb) {
      expect(id).to.equal('iFxmcVm7eyw5q34uNELR_lSs4pyeL8CJrHN8ZZanOTrn5JxIMS7Z1Km-ZA');
      var publicKey =
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESo+uMzzeOSkrHdJFfK98BdlhtydB\n' +
'sYCSfcQItYWDgr7qFbPLcRIiuS3ejIa4iFHAe01oslaURGWUxtby39TpQA==\n' +
'-----END PUBLIC KEY-----\n';
      return cb(null, { id: '248289761001' }, publicKey);
    }, function(){}))
      .request(function(req) {
        req.connection = {};
        req.headers.host = 'localhost:3000';
        req.body = {
          "rawId": "iFxmcVm7eyw5q34uNELR_lSs4pyeL8CJrHN8ZZanOTrn5JxIMS7Z1Km-ZA",
          "response": {
            "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA",
            "signature": "XEYCIQCCKxA70welhqy9PZH-sLj09VtYRIkA9w-MryjXfIOc5QIhAOUIqjOk8jkH-vP50sCxRXSb6ZG-iT6bgheMxDHB3JqM",
            "userHandle": "NA",
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiTVRJek5BIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
          },
          "authenticatorAttachment": "platform",
          "id": "iFxmcVm7eyw5q34uNELR_lSs4pyeL8CJrHN8ZZanOTrn5JxIMS7Z1Km-ZA",
          "type": "public-key"
        };
      })
      .fail(function(challenge, status) {
        expect(challenge).to.deep.equal({ message: 'Invalid signature' });
        expect(status).to.equal(403);
        done();
      })
      .error(done)
      .authenticate();
  }); // should fail when signature is invalid
  
  it('should fail when signature counter is less than or equal to stored sign count', function(done) {
    function verifySignCount(id, signCount, storedSignCount, cb) {
      expect(id).to.equal('VjXl8fuJXIAqLg-BVrR5oeLLfee6gBGKXdMxo6xtMySugJfU2HNvTJk84T1DgFYtJDpDrwL2Bg_QM4xQwVAutA');
      expect(signCount).to.equal(80);
      expect(storedSignCount).to.equal(81);
      return cb(null, false);
    }
    var verifySignCountSpy = sinon.spy(verifySignCount);
    
    chai.passport.use(new Strategy(function(id, cb) {
      expect(id).to.equal('VjXl8fuJXIAqLg-BVrR5oeLLfee6gBGKXdMxo6xtMySugJfU2HNvTJk84T1DgFYtJDpDrwL2Bg_QM4xQwVAutA');
      var publicKey =
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaLB+Aejtfh9S/i+iU1IfvQswbRlS\n' +
'EGu/tcXrRjnscbMNflAnHVHDeb4PzlexGEjGgrsZiuLmlq+ZTOJjOsGOeQ==\n' +
'-----END PUBLIC KEY-----\n';
      return cb(null, { id: '248289761001' }, publicKey, { signCount: 81 });
    }, verifySignCountSpy, function(){}))
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
      .fail(function(challenge, status) {
        expect(challenge).to.deep.equal({ message: 'Cloned authenticator detected' });
        expect(status).to.equal(403);
        done();
      })
      .error(done)
      .authenticate();
  }); // should fail when signature counter is less than or equal to stored sign count
  
  it('should register YubiKey 5C with no attestation', function(done) {
    chai.passport.use(new Strategy(function(){}, function(id, publicKey, cb) {
      expect(id).to.equal('n90ZI-FwPA9HT5jtZins33Rtae1Zz1zLnoDR9yCj5Jwz2PB6fJR0KCPZehORB-ht48mRfbcA512cnDyfbQQ0OQ');
      expect(publicKey).to.equal(
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEp+ZH3WpsBVUojVZ1D1BufQoSMplI\n' +
'VbiKl+g4PojQCflkt+eEtwaQkv2aRTTLMVHr0gucag7QbOA0m/WyFtuXIg==\n' +
'-----END PUBLIC KEY-----\n'
      );
      return cb(null, { id: '248289761001' });
    }))
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
  
  it('should register YubiKey 5C with no attestation using flags', function(done) {
    chai.passport.use(new Strategy(function(){}, function(id, publicKey, flags, cb) {
      expect(id).to.equal('n90ZI-FwPA9HT5jtZins33Rtae1Zz1zLnoDR9yCj5Jwz2PB6fJR0KCPZehORB-ht48mRfbcA512cnDyfbQQ0OQ');
      expect(publicKey).to.equal(
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEp+ZH3WpsBVUojVZ1D1BufQoSMplI\n' +
'VbiKl+g4PojQCflkt+eEtwaQkv2aRTTLMVHr0gucag7QbOA0m/WyFtuXIg==\n' +
'-----END PUBLIC KEY-----\n'
      );
      expect(flags).to.deep.equal({
        userPresent: true,
        userVerified: false
      });
      return cb(null, { id: '248289761001' });
    }))
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
  }); // should register YubiKey 5C with no attestation using flags
  
  it('should register YubiKey 5C with no attestation using flags and signature counter', function(done) {
    chai.passport.use(new Strategy(function(){}, function(id, publicKey, flags, signCount, cb) {
      expect(id).to.equal('n90ZI-FwPA9HT5jtZins33Rtae1Zz1zLnoDR9yCj5Jwz2PB6fJR0KCPZehORB-ht48mRfbcA512cnDyfbQQ0OQ');
      expect(publicKey).to.equal(
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEp+ZH3WpsBVUojVZ1D1BufQoSMplI\n' +
'VbiKl+g4PojQCflkt+eEtwaQkv2aRTTLMVHr0gucag7QbOA0m/WyFtuXIg==\n' +
'-----END PUBLIC KEY-----\n'
      );
      expect(flags).to.deep.equal({
        userPresent: true,
        userVerified: false
      });
      expect(signCount).to.equal(58);
      return cb(null, { id: '248289761001' });
    }))
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
  }); // should register YubiKey 5C with no attestation using flags and signature counter
  
  it('should register YubiKey 5C with attestation in FIDO U2F format', function(done) {
    chai.passport.use(new Strategy(function(){}, function(id, publicKey, flags, signCount, transports, attestation, cb) {
      expect(id).to.equal('JYrR3EvvQJNqG0i_OwJckOkbzq4YJWviotG4hig9wA_Qdxm-eBEHfsYqBJKTtXMasL-RD9CFOlcag48icK3E8Q');
      expect(publicKey).to.equal(
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/6j9N8S3dBWutrvVJBB3MrU5uipV\n' +
'D8+rZ0GboVEJMPT3HZmICG/06CAPSqcDchP+qLa0N8Tvp9FSmguCnvLtZg==\n' +
'-----END PUBLIC KEY-----\n'
      );
      
      expect(attestation.type).to.be.undefined;
      expect(attestation.trustPath.length).to.equal(1);
      expect(attestation.trustPath[0].issuer).to.equal('CN=Yubico U2F Root CA Serial 457200631');
      expect(attestation.trustPath[0].subject).to.equal('C=SE\nO=Yubico AB\nOU=Authenticator Attestation\nCN=Yubico U2F EE Serial 413943488');
      expect(attestation.trustPath[0].serialNumber).to.equal('18AC46C0');
      expect(attestation.trustPath[0].fingerprint).to.equal('E7:D0:92:BA:19:2F:DB:BB:2F:36:55:28:32:D6:16:12:69:71:A2:69');
      
      return cb(null, { id: '248289761001' });
    }))
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
  }); // should register YubiKey 5C with attestation in FIDO U2F format
  
  it('should register Soft U2F with attestation in FIDO U2F format', function(done) {
    chai.passport.use(new Strategy(function(){}, function(id, publicKey, flags, signCount, transports, attestation, cb) {
      expect(id).to.equal('GU0lmsssQL3nKuu3Q5YtBTVfTLUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
      expect(publicKey).to.equal(
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMXwd2qrp2AidRk9IBDeAxxEUU43g\n' +
'V+dShmc0kKQoWOhxDyslVXoA1M7RYzrpFrGWEK3z1Hk9Wso1GeUBnPrXJQ==\n' +
'-----END PUBLIC KEY-----\n'
      );
      
      expect(attestation.type).to.be.undefined;
      expect(attestation.trustPath.length).to.equal(1);
      expect(attestation.trustPath[0].issuer).to.equal('CN=Soft U2F\nO=GitHub Inc.\nOU=Security');
      expect(attestation.trustPath[0].subject).to.equal('CN=Soft U2F\nO=GitHub Inc.\nOU=Security');
      expect(attestation.trustPath[0].serialNumber).to.equal('01');
      expect(attestation.trustPath[0].fingerprint).to.equal('D6:45:25:FF:AE:7C:57:C3:7A:90:4D:E0:83:BE:05:BC:ED:C7:F9:32');
      return cb(null, { id: '248289761001' });
    }))
      .request(function(req) {
        req.connection = {};
        req.headers.host = 'localhost:3000';
        req.body = {
          "rawId": "GU0lmsssQL3nKuu3Q5YtBTVfTLUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          "response": {
            "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEYwRAIgTM7jGmhOvbujIW0oDFiGKq5BjB31_Vg7oncdXCUmEJMCIGxBoeX20y-Ai01Mma1nhSle4lOEuK-TRzvwo2A7MwevY3g1Y4FZAYIwggF-MIIBJKADAgECAgEBMAoGCCqGSM49BAMCMDwxETAPBgNVBAMMCFNvZnQgVTJGMRQwEgYDVQQKDAtHaXRIdWIgSW5jLjERMA8GA1UECwwIU2VjdXJpdHkwHhcNMTcwNzI2MjAwOTA4WhcNMjcwNzI0MjAwOTA4WjA8MREwDwYDVQQDDAhTb2Z0IFUyRjEUMBIGA1UECgwLR2l0SHViIEluYy4xETAPBgNVBAsMCFNlY3VyaXR5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9pyrJBRLtO-H9w8jHFzU9XgErPjgxrKz41IYPYA5H2vSedJqTINkdObC2iOT_6wdUDRsXCOQZVeTPsuT_27e0aMXMBUwEwYLKwYBBAGC5RwCAQEEBAMCAwgwCgYIKoZIzj0EAwIDSAAwRQIhAP4iHZe46uoSu59CFIUPSBdlteCVk16ho9ZtD7FvOfciAiBk19wvXGw4Kvdl9XhqObCxSpdFKO993yECFRuIStRBemhhdXRoRGF0YVjKSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAARhlNJZrLLEC95yrrt0OWLQU1X0y1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAClAQIDJiABIVggMXwd2qrp2AidRk9IBDeAxxEUU43gV-dShmc0kKQoWOgiWCBxDyslVXoA1M7RYzrpFrGWEK3z1Hk9Wso1GeUBnPrXJQ",
            "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJNVEl6TkEiLCJjbGllbnRFeHRlbnNpb25zIjp7fSwiaGFzaEFsZ29yaXRobSI6IlNIQS0yNTYiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"
          },
          "id": "GU0lmsssQL3nKuu3Q5YtBTVfTLUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
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
  }); // should register Soft U2F with attestation in FIDO U2F format
  
  it('should register Touch ID with no attestation via level 2', function(done) {
    chai.passport.use(new Strategy(function(){}, function(id, publicKey, cb) {
      expect(id).to.equal('Abqu4O_U5dE71w4TuJ-zW1IrpdCgZftpnR-hKqfTWheMc8SZIaky7qXAyiDzPSqRtPUC');
      expect(publicKey).to.equal(
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElmqTyDG7IwXwGEjJV2zQD5gKpupH\n' +
'dUnzimUr4dJAREBxQhyQUM9A5/K8AT6lrgbpTXvoIQEuZ6w1+eLAE4lbJA==\n' +
'-----END PUBLIC KEY-----\n'
      );
      return cb(null, { id: '248289761001' });
    }))
      .request(function(req) {
        req.connection = {};
        req.headers.host = 'localhost:3000';
        req.body = {
          "rawId": "Abqu4O_U5dE71w4TuJ-zW1IrpdCgZftpnR-hKqfTWheMc8SZIaky7qXAyiDzPSqRtPUC",
          "response": {
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVi3SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFYTEXGq3OAAI1vMYKZIsLJfHwVQMAMwG6ruDv1OXRO9cOE7ifs1tSK6XQoGX7aZ0foSqn01oXjHPEmSGpMu6lwMog8z0qkbT1AqUBAgMmIAEhWCCWapPIMbsjBfAYSMlXbNAPmAqm6kd1SfOKZSvh0kBEQCJYIHFCHJBQz0Dn8rwBPqWuBulNe-ghAS5nrDX54sATiVsk",
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTVRJek5BIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ",
            "transports": [ "internal" ]
          },
          "id": "Abqu4O_U5dE71w4TuJ-zW1IrpdCgZftpnR-hKqfTWheMc8SZIaky7qXAyiDzPSqRtPUC",
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
  }); // should register Touch ID with no attestation via level 2
  
  it('should register Touch ID with no attestation using flags and signature counter via level 2', function(done) {
    chai.passport.use(new Strategy(function(){}, function(id, publicKey, flags, signCount, cb) {
      expect(id).to.equal('Abqu4O_U5dE71w4TuJ-zW1IrpdCgZftpnR-hKqfTWheMc8SZIaky7qXAyiDzPSqRtPUC');
      expect(publicKey).to.equal(
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElmqTyDG7IwXwGEjJV2zQD5gKpupH\n' +
'dUnzimUr4dJAREBxQhyQUM9A5/K8AT6lrgbpTXvoIQEuZ6w1+eLAE4lbJA==\n' +
'-----END PUBLIC KEY-----\n'
      );
      expect(flags).to.deep.equal({
        userPresent: true,
        userVerified: true
      });
      expect(signCount).to.equal(1630607130);
      return cb(null, { id: '248289761001' });
    }))
      .request(function(req) {
        req.connection = {};
        req.headers.host = 'localhost:3000';
        req.body = {
          "rawId": "Abqu4O_U5dE71w4TuJ-zW1IrpdCgZftpnR-hKqfTWheMc8SZIaky7qXAyiDzPSqRtPUC",
          "response": {
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVi3SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFYTEXGq3OAAI1vMYKZIsLJfHwVQMAMwG6ruDv1OXRO9cOE7ifs1tSK6XQoGX7aZ0foSqn01oXjHPEmSGpMu6lwMog8z0qkbT1AqUBAgMmIAEhWCCWapPIMbsjBfAYSMlXbNAPmAqm6kd1SfOKZSvh0kBEQCJYIHFCHJBQz0Dn8rwBPqWuBulNe-ghAS5nrDX54sATiVsk",
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTVRJek5BIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ",
            "transports": [ "internal" ]
          },
          "id": "Abqu4O_U5dE71w4TuJ-zW1IrpdCgZftpnR-hKqfTWheMc8SZIaky7qXAyiDzPSqRtPUC",
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
  }); // should register Touch ID with no attestation using flags and signature counter via level 2
  
  it('should register Touch ID with attestation in packed format via level 2', function(done) {
    chai.passport.use(new Strategy(function(){}, function(id, publicKey, flags, signCount, transports, attestation, cb) {
      expect(id).to.equal('AIJBqkpwDr_4baNTt2_u_kG-sGqZnr4WZ63y911uY9qB6u6JTcB-9MQkyQzruTOBRi9vKluqAZqBWio2tFem-SgrUD7RI7i_Bpajs5N6uG_cCdycJwE-4Xjt');
      expect(publicKey).to.equal(
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwK1LFo9PmBhEPW/LCaEZMRKh8UAQ\n' +
'woQeUORJDXHXglTFEiUWB4qw52KN/aeRYuqb6jDTY1oIsQlgm1WwFcxIxA==\n' +
'-----END PUBLIC KEY-----\n'
      );
      expect(attestation).to.deep.equal({
        type: 'self',
        trustPath: []
      });
      return cb(null, { id: '248289761001' });
    }))
      .request(function(req) {
        req.headers.host = 'localhost:3000';
        req.connection = {};
        req.user = { id: '500' };
        
        req.body = {
          "rawId": "AIJBqkpwDr_4baNTt2_u_kG-sGqZnr4WZ63y911uY9qB6u6JTcB-9MQkyQzruTOBRi9vKluqAZqBWio2tFem-SgrUD7RI7i_Bpajs5N6uG_cCdycJwE-4Xjt",
          "response": {
            "attestationObject": "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIhAKNUl2n5uMyTfhC4Sxn7884NTkBM01z5FWu_M-iUkddUAiBTdF11L7ajh9TfmBAJmeQXxU3_WKSUa37Mu_Za_cq7gWhhdXRoRGF0YVjeSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFXW8RXK3OAAI1vMYKZIsLJfHwVQMAWgCCQapKcA6_-G2jU7dv7v5BvrBqmZ6-Fmet8vddbmPageruiU3AfvTEJMkM67kzgUYvbypbqgGagVoqNrRXpvkoK1A-0SO4vwaWo7OTerhv3AncnCcBPuF47aUBAgMmIAEhWCDArUsWj0-YGEQ9b8sJoRkxEqHxQBDChB5Q5EkNcdeCVCJYIMUSJRYHirDnYo39p5Fi6pvqMNNjWgixCWCbVbAVzEjE",
            "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJNVEl6TkEiLCJleHRyYV9rZXlzX21heV9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
            "transports": [ "internal" ]
          },
          "id": "AIJBqkpwDr_4baNTt2_u_kG-sGqZnr4WZ63y911uY9qB6u6JTcB-9MQkyQzruTOBRi9vKluqAZqBWio2tFem-SgrUD7RI7i_Bpajs5N6uG_cCdycJwE-4Xjt",
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
  }); // should register Touch ID with attestation in packed format via level 2
  
  it('should register YubiKey 5C with attestation in packed format via level 2', function(done) {
    chai.passport.use(new Strategy(function(){}, function(id, publicKey, flags, signCount, transports, attestation, cb) {
      expect(id).to.equal('i18s3M25qA39Y6vOXR2_TOCglKz8kxFHHzx6Jpnk_Y9THMVBV85Vnd5IyjtNpFIS6Sp_ssg4ZJtAW6UARMStUQ');
      expect(publicKey).to.equal(
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETRaVPaJos8YJakatxjOVMPS+49GC\n' +
'RqQlUaVoVKm7XTAciKioZJxh8i9dm8znJlMwnEeqDP5BNwonyqfTBTnC6Q==\n' +
'-----END PUBLIC KEY-----\n'
      );
      
      expect(attestation.type).to.be.undefined;
      expect(attestation.trustPath.length).to.equal(1);
      expect(attestation.trustPath[0].issuer).to.equal('CN=Yubico U2F Root CA Serial 457200631');
      expect(attestation.trustPath[0].subject).to.equal('C=SE\nO=Yubico AB\nOU=Authenticator Attestation\nCN=Yubico U2F EE Serial 413943488');
      expect(attestation.trustPath[0].serialNumber).to.equal('18AC46C0');
      expect(attestation.trustPath[0].fingerprint).to.equal('E7:D0:92:BA:19:2F:DB:BB:2F:36:55:28:32:D6:16:12:69:71:A2:69');
      
      return cb(null, { id: '248289761001' });
    }))
      .request(function(req) {
        req.headers.host = 'localhost:3000';
        req.connection = {};
        req.body = {
          "rawId": "i18s3M25qA39Y6vOXR2_TOCglKz8kxFHHzx6Jpnk_Y9THMVBV85Vnd5IyjtNpFIS6Sp_ssg4ZJtAW6UARMStUQ",
          "response": {
            "attestationObject": "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAKB_lCbNBN3KHdrygHJY33EFqjBOcXJ_BgXonuVq1yMDAiEAuBAkFQ_vj_9rShhlogJLrEaTjXvOO7SsvAcwneTaJNJjeDVjgVkCwTCCAr0wggGloAMCAQICBBisRsAwDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMG4xCzAJBgNVBAYTAlNFMRIwEAYDVQQKDAlZdWJpY28gQUIxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xJzAlBgNVBAMMHll1YmljbyBVMkYgRUUgU2VyaWFsIDQxMzk0MzQ4ODBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHnqOyx8SXAQYiMM0j_rYOUpMXHUg_EAvoWdaw-DlwMBtUbN1G7PyuPj8w-B6e1ivSaNTB69N7O8vpKowq7rTjqjbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS43MBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEMtpSB6P90A5k-wKJymhVKgwDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAl50Dl9hg-C7hXTEceW66-yL6p-CE2bq0xhu7V_PmtMGKSDe4XDxO2-SDQ_TWpdmxztqK4f7UkSkhcwWOXuHL3WvawHVXxqDo02gluhWef7WtjNr4BIaM-Q6PH4rqF8AWtVwqetSXyJT7cddT15uaSEtsN21yO5mNLh1DBr8QM7Wu-Myly7JWi2kkIm0io1irfYfkrF8uCRqnFXnzpWkJSX1y9U4GusHDtEE7ul6vlMO2TzT566Qay2rig3dtNkZTeEj-6IS93fWxuleYVM_9zrrDRAWVJ-Vt1Zj49WZxWr5DAd0ZETDmufDGQDkSU-IpgD867ydL7b_eP8u9QurWeWhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAPstpSB6P90A5k-wKJymhVKgAQItfLNzNuagN_WOrzl0dv0zgoJSs_JMRRx88eiaZ5P2PUxzFQVfOVZ3eSMo7TaRSEukqf7LIOGSbQFulAETErVGlAQIDJiABIVggTRaVPaJos8YJakatxjOVMPS-49GCRqQlUaVoVKm7XTAiWCAciKioZJxh8i9dm8znJlMwnEeqDP5BNwonyqfTBTnC6Q",
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTVRJek5BIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ",
            "transports": [ "usb" ]
          },
          "id": "i18s3M25qA39Y6vOXR2_TOCglKz8kxFHHzx6Jpnk_Y9THMVBV85Vnd5IyjtNpFIS6Sp_ssg4ZJtAW6UARMStUQ",
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
  }); // should register YubiKey 5C with attestation in packed format via level 2
  
  it('should register Google Chrome on Mac OS X without Touch ID with no attestation via level 3', function(done) {
    chai.passport.use(new Strategy(function(){}, function(id, publicKey, cb) {
      expect(id).to.equal('noMuGuaaVLubAVjuS6Z2BYrrBpajYhtjnFgvSjk0IV1LJeVrupbpnw');
      expect(publicKey).to.equal(
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErujwiSbsh53HcaC4ohSuid5DvZbr\n' +
'AONRIXCYQTX0UFH6pVdJ7FZ7j/obBTXN9FNNK9neay4OjrmUM9oyI9VQKw==\n' +
'-----END PUBLIC KEY-----\n'
      );
      return cb(null, { id: '248289761001' });
    }))
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
  
  it('should register Google Chrome on Mac OS X without Touch ID with no attestation using flags, signature counter, and transports via level 3', function(done) {
    chai.passport.use(new Strategy(function(){}, function(id, publicKey, flags, signCount, transports, cb) {
      expect(id).to.equal('noMuGuaaVLubAVjuS6Z2BYrrBpajYhtjnFgvSjk0IV1LJeVrupbpnw');
      expect(publicKey).to.equal(
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErujwiSbsh53HcaC4ohSuid5DvZbr\n' +
'AONRIXCYQTX0UFH6pVdJ7FZ7j/obBTXN9FNNK9neay4OjrmUM9oyI9VQKw==\n' +
'-----END PUBLIC KEY-----\n'
      );
      expect(flags).to.deep.equal({
        userPresent: true,
        userVerified: true
      });
      expect(signCount).to.equal(0);
      expect(transports).to.deep.equal([ 'internal' ]);
      return cb(null, { id: '248289761001' });
    }))
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
    chai.passport.use(new Strategy(function(){}, function(id, publicKey, cb) {
      expect(id).to.equal('12T-jjmoUpVJ-1z7Bx-OYFo-MxDj8_xbne6iytC9scwbBjutzSUNdK9wphc4oNnmPqSbp-6UDba3ztUrAy2dcw');
      expect(publicKey).to.equal(
'-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEc42HZW7iW+hIXF90W5wgxeKu4M8Q\n' +
'zMwC4eHnaO2CifIVgKhxEZbVZ5ANWVwXmhXodN7R05KQtar4HlCTg1WUrg==\n' +
'-----END PUBLIC KEY-----\n'
      );
      return cb(null, { id: '248289761001' });
    }))
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
