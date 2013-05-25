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


describe('Endpoints', function () {

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

    it('fails on invalid app request (bad credentials)', function (done) {

        // The app requests an app ticket using Basic authentication

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

                callback(null, apps.network);
            }
        };

        Oz.endpoints.app(req, null, options, function (err, appTicket) {

            expect(err).to.exist;
            done();
        });
    });
});


