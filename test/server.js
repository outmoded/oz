// Load modules

var Lab = require('lab');
var Oz = require('../lib');


// Declare internals

var internals = {};


// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;


describe('Server', function () {

    describe('#authenticate', function () {

        it('returns an error on missing password', function (done) {

            Oz.server.authenticate(null, null, {}, function (err, ticket, ext) {

                expect(err).to.exist;
                expect(err.message).to.equal('Invalid encryption password');
                done();
            });
        });
    });
});

