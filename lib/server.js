// Load modules

var Boom = require('boom');
var Hawk = require('hawk');
var Ticket = require('./ticket');


// Declare internals

var internals = {};


// Validate an incoming request

exports.authenticate = function (req, encryptionPassword, options, callback) {

    Hawk.server.authenticate(req, exports.credentialsFunc(encryptionPassword, options), options.hawk || {}, function (err, credentials, artifacts) {

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


// Hawk credentialsFunc generator

exports.credentialsFunc = function (encryptionPassword, options) {

    Hawk.utils.assert(encryptionPassword, 'Invalid encryption password');

    return function (id, callback) {

        // Parse ticket id

        Ticket.parse(id, encryptionPassword, options, function (err, ticket) {

            if (err) {
                return callback(err);
            }

            // Check expiration

            if (ticket.exp <= Hawk.utils.now()) {
                return callback(Hawk.utils.unauthorized('Expired ticket'));
            }

            return callback(null, ticket);
        });
    };
};
