// Load modules

var Hawk = require('hawk');
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


describe('Oz', function () {

    it('runs a full authorization flow', function (done) {

        var encryptionPassword = 'password';

        var apps = {
            social: {
                id: 'social',
                scope: ['a', 'b', 'c'],
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'sha256'
            },
            network: {
                id: 'network',
                scope: ['b', 'x'],
                key: 'witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi',
                algorithm: 'sha256'
            }
        };

        // The app requests an app ticket using Hawk authentication

        var req = {
            method: 'POST',
            url: '/oz/app',
            headers: {
                host: 'example.com',
                authorization: Hawk.client.header('http://example.com/oz/app', 'POST', { credentials: apps['social'] }).field
            }
        };

        var options = {
            encryptionPassword: encryptionPassword,
            loadAppFunc: function (id, callback) {

                callback(null, apps[id]);
            }
        };

        Oz.endpoints.app(req, null, options, function (err, appTicket) {

            expect(err).to.not.exist;

            // The app refreshes its own ticket

            req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', appTicket).field
                }
            };

            Oz.endpoints.reissue(req, {}, options, function (err, reAppTicket) {

                expect(err).to.not.exist;

                // The user is redirected to the server, logs in, and grant app access, resulting in an rsvp

                var grant = {
                    id: 'a1b2c3d4e5f6g7h8i9j0',
                    app: reAppTicket.app,
                    user: 'john',
                    exp: Hawk.utils.now() + 60000
                };

                Oz.ticket.rsvp(apps['social'], grant, encryptionPassword, {}, function (err, rsvp) {

                    expect(err).to.not.exist;

                    // After granting app access, the user returns to the app with the rsvp

                    options.loadGrantFunc = function (id, callback) {

                        var ext = {
                            public: 'everybody knows',
                            private: 'the the dice are loaded'
                        };

                        callback(null, grant, ext);
                    };

                    // The app exchanges the rsvp for a ticket

                    var payload = { rsvp: rsvp };

                    req = {
                        method: 'POST',
                        url: '/oz/rsvp',
                        headers: {
                            host: 'example.com',
                            authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', reAppTicket).field
                        }
                    };

                    Oz.endpoints.rsvp(req, payload, options, function (err, ticket) {

                        expect(err).to.not.exist;

                        // The app reissues the ticket with delegation to another app

                        payload = {
                            issueTo: apps.network.id,
                            scope: ['a']
                        };

                        req = {
                            method: 'POST',
                            url: '/oz/reissue',
                            headers: {
                                host: 'example.com',
                                authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', ticket).field
                            }
                        };

                        Oz.endpoints.reissue(req, payload, options, function (err, delegatedTicket) {

                            expect(err).to.not.exist;

                            // The other app reissues their ticket

                            req = {
                                method: 'POST',
                                url: '/oz/reissue',
                                headers: {
                                    host: 'example.com',
                                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', delegatedTicket).field
                                }
                            };

                            Oz.endpoints.reissue(req, {}, options, function (err, reissuedDelegatedTicket) {

                                expect(err).to.not.exist;
                                done();
                            });
                        });
                    });
                });
            });
        });
    });
});


