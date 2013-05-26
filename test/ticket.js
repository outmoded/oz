// Load modules

var Hawk = require('hawk');
var Hoek = require('hoek');
var Iron = require('iron');
var Cryptiles = require('cryptiles');
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
                exp: Hawk.utils.now() + 5000,
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

                Oz.ticket.parse(envelope.id, encryptionPassword, {}, function (err, ticket) {

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

    describe('#rsvp', function () {

        it('errors on random fail', function (done) {

            var orig = Cryptiles.randomString;
            Cryptiles.randomString = function (size) {

                Cryptiles.randomString = orig;
                return new Error('fake');
            };

            Oz.ticket.generate({}, 'password', {}, function (err, ticket) {

                expect(err).to.exist;
                expect(err.message).to.equal('fake');
                done();
            });
        });

        it('errors on missing password', function (done) {

            Oz.ticket.generate({}, null, {}, function (err, ticket) {

                expect(err).to.exist;
                expect(err.message).to.equal('Empty password');
                done();
            });
        });

        it('errors on wrong password', function (done) {

            var encryptionPassword = 'welcome!';

            var app = {
                id: '123'
            };

            var grant = {
                id: 's81u29n1812',
                user: '456',
                exp: Hawk.utils.now() + 5000,
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

            Oz.ticket.issue(app, grant, 'password', options, function (err, envelope) {

                expect(err).to.not.exist;

                Oz.ticket.parse(envelope.id, 'x', {}, function (err, ticket) {

                    expect(err).to.exist;
                    expect(err.message).to.equal('Bad hmac value');
                    done();
                });
            });
        });
    });

    describe('#rsvp', function () {

        it('constructs a valid rsvp', function (done) {

            var encryptionPassword = 'welcome!';

            var app = {
                id: '123'                   // App id
            };

            var grant = {
                id: 's81u29n1812'           // Grant
            };

            Oz.ticket.rsvp(app, grant, encryptionPassword, {}, function (err, envelope) {

                expect(err).to.not.exist;

                Oz.ticket.parse(envelope, encryptionPassword, {}, function (err, object) {

                    expect(err).to.not.exist;
                    expect(object.app).to.equal(app.id);
                    expect(object.grant).to.equal(grant.id);
                    done();
                });
            });
        });

        it('fails to construct a valid rsvp due to bad Iron options', function (done) {

            var encryptionPassword = 'welcome!';

            var app = {
                id: '123'                   // App id
            };

            var grant = {
                id: 's81u29n1812'           // Grant
            };

            var iron = Hoek.clone(Iron.defaults);
            iron.encryption = null;

            Oz.ticket.rsvp(app, grant, encryptionPassword, { iron: iron }, function (err, envelope) {

                expect(err).to.exist;
                expect(err.message).to.equal('Bad options');
                done();
            });
        });
    });
});


