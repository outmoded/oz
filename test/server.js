// Load modules

var Lab = require('lab');
var Hawk = require('hawk');
var Oz = require('../lib');


// Declare internals

var internals = {};


// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;


describe('Server', function () {

    describe('#authenticate', function () {

        it('returns an error on missing password', function (done) {

            Oz.server.authenticate(null, null, {}, function (err, ticket, ext) {

                expect(err).to.exist;
                expect(err.message).to.equal('Invalid encryption password');
                done();
            });
        });

        var encryptionPassword = 'welcome!';

        var app = {
            id: '123'
        };

        it('authenticates a request', function (done) {

            var grant = {
                id: 's81u29n1812',
                user: '456',
                exp: Hawk.utils.now() + 5000,
                scope: ['a', 'b']
            };

            Oz.ticket.issue(app, grant, encryptionPassword, {}, function (err, envelope) {

                expect(err).to.not.exist;

                var req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', envelope).field
                    }
                };

                Oz.server.authenticate(req, encryptionPassword, {}, function (err, ticket, ext) {

                    expect(err).to.not.exist;
                    done();
                });
            });
        });

        it('fails to authenticate a request with bad password', function (done) {

            var grant = {
                id: 's81u29n1812',
                user: '456',
                exp: Hawk.utils.now() + 5000,
                scope: ['a', 'b']
            };

            Oz.ticket.issue(app, grant, encryptionPassword, {}, function (err, envelope) {

                expect(err).to.not.exist;

                var req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', envelope).field
                    }
                };

                Oz.server.authenticate(req, 'x', {}, function (err, ticket, ext) {

                    expect(err).to.exist;
                    expect(err.message).to.equal('Bad hmac value');
                    done();
                });
            });
        });

        it('fails to authenticate a request with expired ticket', function (done) {

            var grant = {
                id: 's81u29n1812',
                user: '456',
                exp: Hawk.utils.now() - 5000,
                scope: ['a', 'b']
            };

            Oz.ticket.issue(app, grant, encryptionPassword, {}, function (err, envelope) {

                expect(err).to.not.exist;

                var req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', envelope).field
                    }
                };

                Oz.server.authenticate(req, encryptionPassword, {}, function (err, ticket, ext) {

                    expect(err).to.exist;
                    expect(err.message).to.equal('Expired ticket');
                    done();
                });
            });
        });

        it('fails to authenticate a request with mismatching app id', function (done) {

            var grant = {
                id: 's81u29n1812',
                user: '456',
                exp: Hawk.utils.now() + 5000,
                scope: ['a', 'b']
            };

            Oz.ticket.issue(app, grant, encryptionPassword, {}, function (err, envelope) {

                expect(err).to.not.exist;

                envelope.app = '567';
                var req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', envelope).field
                    }
                };

                Oz.server.authenticate(req, encryptionPassword, {}, function (err, ticket, ext) {

                    expect(err).to.exist;
                    expect(err.message).to.equal('Mismatching application id');
                    done();
                });
            });
        });

        it('fails to authenticate a request with mismatching dlg id', function (done) {

            var grant = {
                id: 's81u29n1812',
                user: '456',
                exp: Hawk.utils.now() + 5000,
                scope: ['a', 'b']
            };

            Oz.ticket.issue(app, grant, encryptionPassword, {}, function (err, envelope) {

                expect(err).to.not.exist;

                envelope.dlg = '567';
                var req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', envelope).field
                    }
                };

                Oz.server.authenticate(req, encryptionPassword, {}, function (err, ticket, ext) {

                    expect(err).to.exist;
                    expect(err.message).to.equal('Mismatching delegated application id');
                    done();
                });
            });
        });
    });
});

