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


describe('Settings', function () {

    describe('#set', function () {

        it('should override default values using (group, settings)', function (done) {

            var ttl = Oz.settings.ticket.ttl;
            var secretBytes = Oz.settings.ticket.secretBytes;
            Oz.settings.set('ticket', { ttl: ttl + 100 });
            expect(Oz.settings.ticket.ttl).to.equal(ttl + 100);
            expect(Oz.settings.ticket.secretBytes).to.equal(secretBytes);
            done();
        });

        it('should override default values using (tree)', function (done) {

            var ttl = Oz.settings.ticket.ttl;
            var secretBytes = Oz.settings.ticket.secretBytes;
            Oz.settings.set({ ticket: { ttl: ttl + 100 } });
            expect(Oz.settings.ticket.ttl).to.equal(ttl + 100);
            expect(Oz.settings.ticket.secretBytes).to.equal(secretBytes);
            done();
        });
    });
});


