// Load modules

var expect = require('chai').expect;
var Crypto = process.env.TEST_COV ? require('../lib-cov/crypto') : require('../lib/crypto');


describe('Crypto', function () {

    describe('#generateKey', function() {

        it('returns an error when password is missing', function(done) {

            Crypto.generateKey(null, null, function(err) {

                expect(err).to.be.instanceOf(Error);
                done();
            });
        });

        it('returns an error when options are missing', function(done) {

            Crypto.generateKey('password', null, function(err) {

                expect(err).to.be.instanceOf(Error);
                done();
            });
        });

        it('returns an error when an unknown algorithm is specified', function(done) {

            Crypto.generateKey('password', { algorithm: 'unknown' }, function(err) {

                expect(err).to.be.instanceOf(Error);
                done();
            });
        });

        it('returns an error when no salt or salt bits are provided', function(done) {

            var options = {
                algorithm: 'sha256',
                iterations: 2
            };

            Crypto.generateKey('password', options, function(err) {

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

            Crypto.generateKey('password', options, function(err, result) {

                expect(err).to.not.exist;
                expect(result).to.exist;
                done();
            });
        });
    });
});