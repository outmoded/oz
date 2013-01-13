// Load modules

var Boom = require('boom');
var Iron = require('iron');
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

    var grant = {
        id: 'd832d9283hd9823dh'     // Persitant identifier used to issue additional tickets or revoke access
    };
*/

exports.issue = function (app, grant, encryptionPassword, callback) {

    Utils.toss(app && app.id, Boom.internal('Invalid application object'), callback);
    Utils.toss(grant && grant.id, Boom.internal('Invalid grant object'), callback);
    Utils.toss(encryptionPassword, Boom.internal('Invalid encryption password'), callback);

    // Construct envelope

    var envelope = {
        app: app.id,
        exp: Date.now() + Settings.rsvp.ttl,
        grant: grant.id
    };
    
    // Stringify and encrypt

    Iron.seal(envelope, encryptionPassword, Settings.ticket, function (err, sealed) {

        if (err) {
            return callback(err);
        }

        var rsvp = sealed;
        return callback(null, rsvp);
    });
};


// Parse ticket id

exports.parse = function (rsvp, encryptionPassword, callback) {

    Utils.toss(encryptionPassword, Boom.internal('Invalid encryption password'), callback);

    Iron.unseal(rsvp, encryptionPassword, Settings.ticket, callback);
};