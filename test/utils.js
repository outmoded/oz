// Load modules

var Chai = require('chai');
var Oz = require('../lib');
var Package = require('../package.json');


// Declare internals

var internals = {};


// Test shortcuts

var expect = Chai.expect;


describe('Utils', function() {

    describe('#version', function() {

        it('returns the correct package version number', function(done) {

            expect(Oz.utils.version()).to.equal(Package.version);
            done();
        });
    });
});