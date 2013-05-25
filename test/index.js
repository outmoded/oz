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

    var basicHeader = function (username, password) {

        return 'Basic ' + (new Buffer(username + ':' + password, 'utf8')).toString('base64');
    };

    it('runs a full authorization flow', function (done) {

        var encryptionPassword = 'password';

        var apps = {
            social: {
                id: 'social',
                scope: ['a', 'b', 'c'],
                secret: 'secret1'
            },
            network: {
                id: 'network',
                scope: ['b', 'x'],
                secret: 'secret2'
            },
            third: {
                id: 'third',
                scope: ['b', 'x'],
                secret: 'secret3'
            }
        };

        // The app requests an app ticket using Basic authentication

        var req = {
            headers: {
                authorization: basicHeader(apps['social'].id, apps['social'].secret)
            }
        };

        var options = {
            encryptionPassword: encryptionPassword,
            loadAppFunc: function (id, callback) {

                callback(apps[id]);
            }
        };

        Oz.endpoints.app(req, null, options, function (err, appTicket) {

            expect(err).to.not.exist;

            // The user is redirected to the server, logs in, and grant app access, resulting in an rsvp

            var grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
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

                    callback(grant, ext);
                };

                // The app exchanges the rsvp for a ticket

                var payload = { rsvp: rsvp };

                req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, function (err, ticket) {

                    expect(err).to.not.exist;

                    // The app reissues the ticket with delegation to another app

                    payload = {
                        issueTo: apps.network.id
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


