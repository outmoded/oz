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
                id: '456',                  // User id
                grant: 's81u29n1812'        // Grant
            };

            var options = {
                ttl: 60 * 1000,             // 1 min
                scope: ['b'],               // Ticket-specific scope
                ext: {                      // Server-specific extension data
                    x: 'welcome',
                    'private': 123
                }
            };

            Oz.Ticket.issue(app, user, encryptionPassword, options, function (err, envelope) {

                should.not.exist(err);
                envelope.ext.x.should.equal('welcome');
                should.not.exist(envelope.ext.private);

                Oz.Ticket.parse(envelope.id, encryptionPassword, function (err, ticket) {

                    should.not.exist(err);
                    ticket.ext.x.should.equal('welcome');
                    ticket.ext.private.should.equal(123);
                    done();
                });
            });
        });
    });
});


