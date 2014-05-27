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


describe('Client', function () {

    describe('#header', function () {

        it('', function (done) {

            var app = {
                id: 'social',
                scope: ['a', 'b', 'c'],
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'sha256'
            };

            var header = Oz.client.header('http://example.com/oz/app', 'POST', app, {}).field;
            expect(header).to.exist;
            done();
        });
    });
});