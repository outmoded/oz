'use strict';

// Load modules

const Hoek = require('hoek');
const Hawk = require('hawk');

const Ticket = require('./ticket');


// Declare internals

const internals = {};


// Validate an incoming request

exports.authenticate = function (req, encryptionPassword, options) {

    return exports._authenticate(req, encryptionPassword, true, options);
};


exports._authenticate = async function (req, encryptionPassword, checkExpiration, options) {

    options = options || {};

    Hoek.assert(encryptionPassword, 'Invalid encryption password');

    // Hawk credentials lookup method

    const credentialsFunc = async function (id) {

        // Parse ticket id

        const ticket = await Ticket.parse(id, encryptionPassword, options.ticket);

        // Check expiration

        if (checkExpiration &&
            ticket.exp <= Hawk.utils.now()) {

            const error = Hawk.utils.unauthorized('Expired ticket');
            error.output.payload.expired = true;
            throw error;
        }

        return ticket;
    };

    // Hawk authentication

    const { credentials, artifacts } = await Hawk.server.authenticate(req, credentialsFunc, options.hawk);

    // Check application

    if (credentials.app !== artifacts.app) {
        throw Hawk.utils.unauthorized('Mismatching application id');
    }

    if ((credentials.dlg || artifacts.dlg) &&
        credentials.dlg !== artifacts.dlg) {

        throw Hawk.utils.unauthorized('Mismatching delegated application id');
    }

    // Return result

    return { ticket: credentials, artifacts };
};
