// Load modules

var Utils = require('./utils');
var Crypto = require('./crypto');
var Settings = require('./settings');


// Declare internals

var internals = {};


/*
    // The requesting application

    var app = {
        id: '123',                  // Application id
    };

    // The resource owner

    var user = {
        id: '456',                  // User id
        grant: 'd832d9283hd9823dh'  // Persitant identifier used to issue additional tickets or revoke access
    };
*/

exports.issue = function (app, user, encryptionPassword, callback) {

    Utils.assert(app && app.id, 'Invalid application object');
    Utils.assert(user && user.id && user.grant, 'Invalid user object');
    Utils.assert(encryptionPassword, 'Invalid encryption password');

    // Construct envelope

    var envelope = {
        app: app.id,
        exp: Date.now() + Settings.rsvp.ttl,
        user: user.id,
        grant: user.grant
    };
    
    // Stringify and encrypt

    Crypto.seal(envelope, encryptionPassword, Settings.ticket, function (err, sealed) {

        if (err) {
            return callback(err);
        }

        var rsvp = sealed;
        return callback(null, rsvp);
    });
};


// Parse ticket id

exports.parse = function (rsvp, encryptionPassword, callback) {

    Utils.assert(encryptionPassword, 'Invalid encryption password');

    Crypto.unseal(rsvp, encryptionPassword, Settings.ticket, callback);
};


