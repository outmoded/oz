// Load modules

var Boom = require('boom');
var Hawk = require('hawk');
var Ticket = require('./ticket');


// Declare internals

var internals = {};


// Validate an incoming request

exports.authenticate = function (req, encryptionPassword, options, callback) {

    if (!encryptionPassword) {
        return callback(Boom.internal('Invalid encryption password'));
    }

    var credentialsFunc = function (id, credCallback) {

        // Parse ticket id

        Ticket.parse(id, encryptionPassword, options, function (err, ticket) {

            if (err) {
                return credCallback(err);
            }

            // Check expiration

            if (ticket.exp <= Hawk.utils.now()) {
                return credCallback(Hawk.utils.unauthorized('Expired ticket'));
            }

            return credCallback(null, ticket);
        });
    };

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

