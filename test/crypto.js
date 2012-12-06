// Load modules

var Chai = require('chai');
var Oz = process.env.TEST_COV ? require('../lib-cov') : require('../lib');


// Declare internals

var internals = {};


// Test shortcuts

var expect = Chai.expect;


describe('Crypto', function () {

    describe('#generateKey', function() {

        it('returns an error when password is missing', function(done) {

            Oz.crypto.generateKey(null, null, function(err) {

                expect(err).to.be.instanceOf(Error);
                done();
            });
        });

        it('returns an error when options are missing', function(done) {

            Oz.crypto.generateKey('password', null, function(err) {

                expect(err).to.be.instanceOf(Error);
                done();
            });
        });

        it('returns an error when an unknown algorithm is specified', function(done) {

            Oz.crypto.generateKey('password', { algorithm: 'unknown' }, function(err) {

                expect(err).to.be.instanceOf(Error);
                done();
            });
        });

        it('returns an error when no salt or salt bits are provided', function(done) {

            var options = {
                algorithm: 'sha256',
                iterations: 2
            };

            Oz.crypto.generateKey('password', options, function(err) {

                expect(err).to.be.instanceOf(Error);
                done();
            });
        });

        it('returns the key when valid algorithm and salt provided', function(done) {

            var options = {
                algorithm: 'sha256',
                salt: 'test',
                iterations: 2
            };

            Oz.crypto.generateKey('password', options, function(err, result) {

                expect(err).to.not.exist;
                expect(result).to.exist;
                done();
            });
        });
    });
});