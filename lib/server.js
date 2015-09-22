// Load modules

var Boom = require('boom');
var Hoek = require('hoek');
var Hawk = require('hawk');
var Ticket = require('./ticket');


// Declare internals

var internals = {};


// Validate an incoming request

exports.authenticate = function (req, encryptionPassword, options, callback) {

    return exports._authenticate(req, encryptionPassword, true, options, callback);
};


exports._authenticate = function (req, encryptionPassword, checkExpiration, options, callback) {

    Hoek.assert(encryptionPassword, 'Invalid encryption password');
    Hoek.assert(options, 'Invalid options object');

    // Hawk credentials lookup method

    var credentialsFunc = function (id, credsCallback) {

        // Parse ticket id

        Ticket.parse(id, encryptionPassword, options.ticket || {}, function (err, ticket) {

            if (err) {
                return credsCallback(err);
            }

            // Check expiration

            if (checkExpiration &&
                ticket.exp <= Hawk.utils.now()) {

                return credsCallback(Hawk.utils.unauthorized('Expired ticket', { reason: 'expired' }));
            }

            return credsCallback(null, ticket);
        });
    };

    // Hawk authentication

    Hawk.server.authenticate(req, credentialsFunc, options.hawk || {}, function (err, credentials, artifacts) {

        if (err) {
            return callback(err);
        }

        // Check application

        if (credentials.app !== artifacts.app) {
            return callback(Hawk.utils.unauthorized('Mismatching application id'));
        }

        if ((credentials.dlg || artifacts.dlg) &&
            credentials.dlg !== artifacts.dlg) {

            return callback(Hawk.utils.unauthorized('Mismatching delegated application id'));
        }

        // Return result

        return callback(null, credentials, artifacts);
    });
};
