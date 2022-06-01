/* global describe, it */

var chai = require('chai')
  , sinon = require('sinon')
  , Strategy = require('../lib/strategy');


describe.skip('Strategy2', function() {
  
  describe('registering a valid credential from Soft U2F', function() {
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
            "rawId": "GU0lmsssQL3nKuu3Q5YtBTVfTLUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "response": {
              "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEYwRAIgTM7jGmhOvbujIW0oDFiGKq5BjB31_Vg7oncdXCUmEJMCIGxBoeX20y-Ai01Mma1nhSle4lOEuK-TRzvwo2A7MwevY3g1Y4FZAYIwggF-MIIBJKADAgECAgEBMAoGCCqGSM49BAMCMDwxETAPBgNVBAMMCFNvZnQgVTJGMRQwEgYDVQQKDAtHaXRIdWIgSW5jLjERMA8GA1UECwwIU2VjdXJpdHkwHhcNMTcwNzI2MjAwOTA4WhcNMjcwNzI0MjAwOTA4WjA8MREwDwYDVQQDDAhTb2Z0IFUyRjEUMBIGA1UECgwLR2l0SHViIEluYy4xETAPBgNVBAsMCFNlY3VyaXR5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9pyrJBRLtO-H9w8jHFzU9XgErPjgxrKz41IYPYA5H2vSedJqTINkdObC2iOT_6wdUDRsXCOQZVeTPsuT_27e0aMXMBUwEwYLKwYBBAGC5RwCAQEEBAMCAwgwCgYIKoZIzj0EAwIDSAAwRQIhAP4iHZe46uoSu59CFIUPSBdlteCVk16ho9ZtD7FvOfciAiBk19wvXGw4Kvdl9XhqObCxSpdFKO993yECFRuIStRBemhhdXRoRGF0YVjKSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAARhlNJZrLLEC95yrrt0OWLQU1X0y1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAClAQIDJiABIVggMXwd2qrp2AidRk9IBDeAxxEUU43gV-dShmc0kKQoWOgiWCBxDyslVXoA1M7RYzrpFrGWEK3z1Hk9Wso1GeUBnPrXJQ",
              "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJNVEl6TkEiLCJjbGllbnRFeHRlbnNpb25zIjp7fSwiaGFzaEFsZ29yaXRobSI6IlNIQS0yNTYiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"
            },
            "id": "GU0lmsssQL3nKuu3Q5YtBTVfTLUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "type": "public-key"
          };
        })
        .authenticate();
    });
  
    it('should register credential', function() {
      var publicKey = '-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMXwd2qrp2AidRk9IBDeAxxEUU43g\n' +
'V+dShmc0kKQoWOhxDyslVXoA1M7RYzrpFrGWEK3z1Hk9Wso1GeUBnPrXJQ==\n' +
'-----END PUBLIC KEY-----\n';
      
      expect(register).to.be.calledWith({ id: '500' }, 'GU0lmsssQL3nKuu3Q5YtBTVfTLUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', publicKey);
    });
  
    it('should supply user', function() {
      expect(user).to.deep.equal({ id: '500' });
    });
    
    it('should not call verify', function() {
      expect(verify).to.not.have.been.called;
    });
  });
  
  describe('registering a valid credential from TouchID with no attestation', function() {
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
        .authenticate();
    });
  
    it('should register credential', function() {
      var publicKey = '-----BEGIN PUBLIC KEY-----\n' +
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElmqTyDG7IwXwGEjJV2zQD5gKpupH\n' +
'dUnzimUr4dJAREBxQhyQUM9A5/K8AT6lrgbpTXvoIQEuZ6w1+eLAE4lbJA==\n' +
'-----END PUBLIC KEY-----\n';
      
      expect(register).to.be.calledWith({ id: '500' }, 'Abqu4O_U5dE71w4TuJ-zW1IrpdCgZftpnR-hKqfTWheMc8SZIaky7qXAyiDzPSqRtPUC', publicKey);
    });
  
    it('should supply user', function() {
      expect(user).to.deep.equal({ id: '500' });
    });
    
    it('should not call verify', function() {
      expect(verify).to.not.have.been.called;
    });
  });
  
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
