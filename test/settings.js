// Load modules

var expect = require('chai').expect;
var should = require('should');
var Oz = process.env.TEST_COV ? require('../lib-cov/oz') : require('../lib/oz');


describe('Settings', function () {

    describe('#set', function () {

        it('should override default values using (group, settings)', function (done) {

            var ttl = Oz.settings.ticket.ttl;
            var secretBits = Oz.settings.ticket.secretBits;
            Oz.settings.set('ticket', { ttl: ttl + 100 });
            Oz.settings.ticket.ttl.should.equal(ttl + 100);
            Oz.settings.ticket.secretBits.should.equal(secretBits);
            done();
        });

        it('should override default values using (tree)', function (done) {

            var ttl = Oz.settings.ticket.ttl;
            var secretBits = Oz.settings.ticket.secretBits;
            Oz.settings.set({ ticket: { ttl: ttl + 100 } });
            Oz.settings.ticket.ttl.should.equal(ttl + 100);
            Oz.settings.ticket.secretBits.should.equal(secretBits);
            done();
        });
    });
});


