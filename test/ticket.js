var assert = require('assert');
var should = require('should');
var sinon = require('sinon');
var Oz = require('../lib/oz');


describe('Ticket', function () {

    describe('#issue', function () {

        it('should construct a valid ticket', function (done) {

            var encryptionPassword = 'welcome!';

            var app = {
                id: '123'
            };

            var grant = {
                id: 's81u29n1812',
                user: '456',
                exp: Date.now() + 5000,
                scope: ['a', 'b']
            };

            var options = {
                ttl: 10 * 60 * 1000,
                scope: ['b'],
                ext: {
                    x: 'welcome',
                    'private': 123
                }
            };

            Oz.Ticket.issue(app, grant, encryptionPassword, options, function (err, envelope) {

                should.not.exist(err);
                envelope.ext.x.should.equal('welcome');
                envelope.exp.should.equal(grant.exp);
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


