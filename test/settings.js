// Load modules

var Chai = require('chai');
var Oz = process.env.TEST_COV ? require('../lib-cov') : require('../lib');


// Declare internals

var internals = {};


// Test shortcuts

var expect = Chai.expect;


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


