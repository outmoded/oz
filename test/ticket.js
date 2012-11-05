var assert = require('assert');
var should = require('should');
var sinon = require('sinon');
var Oz = require('../lib/oz');


describe('Ticket', function () {

    describe('#issue', function () {

        it('should construct a valid ticket', function (done) {

            var encryptionPassword = 'welcome!';

            var app = {
                id: '123',                  // App id
                ttl: 5 * 60 * 1000,         // 5 min
                scope: ['a', 'b']           // App scope
            };

            var user = {
                id: '456'                   // User id
            };

            var options = {
                ttl: 60 * 1000,             // 1 min
                ext: 'welcome',             // Server-specific extension data
                scope: ['b']                // Ticket-specific scope
            };

            Oz.Ticket.issue(app, user, encryptionPassword, options, function (err, ticket) {

                should.not.exist(err);

                Oz.Ticket.parse(ticket.id, encryptionPassword, function (err, object) {

                    should.not.exist(err);
                    object.ext.should.equal('welcome');
                    done();
                });
            });
        });
    });
});


