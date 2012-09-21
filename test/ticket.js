var assert = require('assert');
var should = require('should');
var sinon = require('sinon');
var Oz = require('../lib/oz');


describe('oz', function () {

    describe('#issue', function () {

        it('should construct a valid ticket', function (done) {

            var app = {
                id: '123',                  // Client id
                ttl: 5 * 60 * 1000,         // 5 min
                scope: ['a', 'b']           // Client scope
            };

            var user = {
                id: '456'                   // User id
            };

            var options = {
                ttl: 60 * 1000,             // 1 min
                ext: 'welcome',             // Server-specific extension data
                scope: ['b']                // Ticket-specific scope
            };

            var ts = Date.now();
            Oz.Ticket.issue(app, user, options, function (err, ticket) {

                should.not.exist(err);

                Oz.Ticket.parse(ticket.ticket, function (err, object) {

                    should.not.exist(err);
                    object.ext.should.equal('welcome');
                    done();
                });
            });
        });
    });
});


