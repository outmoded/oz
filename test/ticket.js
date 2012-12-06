// Load modules

var Chai = require('chai');
var Oz = process.env.TEST_COV ? require('../lib-cov') : require('../lib');


// Declare internals

var internals = {};


// Test shortcuts

var expect = Chai.expect;


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

            Oz.ticket.issue(app, grant, encryptionPassword, options, function (err, envelope) {

                expect(err).to.not.exist;
                expect(envelope.ext.x).to.equal('welcome');
                expect(envelope.exp).to.equal(grant.exp);
                expect(envelope.ext.private).to.not.exist;

                Oz.ticket.parse(envelope.id, encryptionPassword, function (err, ticket) {

                    expect(err).to.not.exist;
                    expect(ticket.ext.x).to.equal('welcome');
                    expect(ticket.ext.private).to.equal(123);

                    Oz.ticket.reissue(ticket, encryptionPassword, {}, function (err, envelope2) {

                        expect(envelope2.ext.x).to.equal('welcome');
                        expect(envelope2.id).to.not.equal(envelope.id);
                        done();
                    });
                });
            });
        });
    });
});


