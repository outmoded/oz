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

        // Request an app ticket

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
            }
        };

        var req = {
            headers: {
                authorization: basicHeader(apps['social'].id, apps['social'].secret)
            }
        };

        var options = {
            encryptionPassword: encryptionPassword
        };

        options.loadAppFunc = function (id, callback) {

            callback(apps[id]);
        };

        Oz.endpoints.app(req, null, options, function (err, appTicket) {

            expect(err).to.not.exist;

            // The user logs into the server and grant app access, resulting in an rsvp

            var grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Hawk.utils.now() + 60000
            };

            Oz.rsvp.issue(apps['social'], grant, encryptionPassword, function (err, rsvp) {

                expect(err).to.not.exist;

                // After granting app access, the user returns to the app with the rsvp

                options.loadGrantFunc = function (id, callback) {

                    var ext = {
                        public: 'everybody knows',
                        private: 'the the dice are loaded'
                    };

                    callback(grant, ext);
                };

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

                    // Refresh the ticket

                    var otherApp = {
                    };

                    payload = {
                        issueTo: otherApp.id
                    };

                    Oz.endpoints.reissue(req, payload, options, function (err, ticket) {

                        done();
                    });
                });
            });
        });
    });
});


