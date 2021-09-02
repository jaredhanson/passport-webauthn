/* global describe, it */

var chai = require('chai')
  , sinon = require('sinon')
  , Strategy = require('../lib/strategy');


describe('Strategy', function() {
  
  describe('verifying a valid credential', function() {
    var verify = sinon.spy(function(id, cb) {
      var publicKey = '-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/6j9N8S3dBWutrvVJBB3MrU5uipV\n' +
'D8+rZ0GboVEJMPT3HZmICG/06CAPSqcDchP+qLa0N8Tvp9FSmguCnvLtZg==\n' +
'-----END PUBLIC KEY-----\n';
      
      return cb(null, { id: '500' }, publicKey);
    });
    
    var strategy = new Strategy(verify);
    var user;
    
    before(function(done) {
      chai.passport(strategy)
        .success(function(u) {
          user = u;
          done();
        })
        .req(function(req) {
          req.headers.host = 'localhost:3000';
          req.connection = {};
          
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
        .authenticate();
    });
    
    it('should verify assertion', function() {
      expect(verify).to.be.calledWith('JYrR3EvvQJNqG0i_OwJckOkbzq4YJWviotG4hig9wA_Qdxm-eBEHfsYqBJKTtXMasL-RD9CFOlcag48icK3E8Q');
    });
    
    it('should supply user', function() {
      expect(user).to.deep.equal({ id: '500' });
    });
  });
  
});
