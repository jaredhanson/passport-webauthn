var chai = require('chai');

chai.use(require('sinon-chai'));
chai.use(require('chai-passport-strategy'));

global.expect = chai.expect;
