/* global describe, it */

var chai = require('chai')
  , sinon = require('sinon')
  , Strategy = require('../lib/strategy');


describe.skip('Strategy2', function() {
  
  
  
  describe('registering a valid credential from TouchID with direct attestation in packed format', function() {
    var verify = sinon.spy(function(id, cb) {
    });
    var register = sinon.spy(function(user, id, publicKey, cb) {
      return cb(null, true);
    });
  
    var strategy = new Strategy(verify, register);
    var user;
  
    before(function(done) {
      chai.passport(strategy)
        .success(function(u) {
          user = u;
          done();
        })
        .error(function(err) {
          console.log(err);
        })
        .req(function(req) {
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
        .authenticate();
    });
  
    it('should register credential', function() {
      var publicKey = '-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwK1LFo9PmBhEPW/LCaEZMRKh8UAQ\n' +
'woQeUORJDXHXglTFEiUWB4qw52KN/aeRYuqb6jDTY1oIsQlgm1WwFcxIxA==\n' +
'-----END PUBLIC KEY-----\n';
      
      expect(register).to.be.calledWith({ id: '500' }, 'AIJBqkpwDr_4baNTt2_u_kG-sGqZnr4WZ63y911uY9qB6u6JTcB-9MQkyQzruTOBRi9vKluqAZqBWio2tFem-SgrUD7RI7i_Bpajs5N6uG_cCdycJwE-4Xjt', publicKey);
    });
  
    it('should supply user', function() {
      expect(user).to.deep.equal({ id: '500' });
    });
    
    it('should not call verify', function() {
      expect(verify).to.not.have.been.called;
    });
  });

});
