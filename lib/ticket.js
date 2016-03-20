'use strict';

// Load modules

const Boom = require('boom');
const Cryptiles = require('cryptiles');
const Hawk = require('hawk');
const Hoek = require('hoek');
const Iron = require('iron');
const Scope = require('./scope');


// Declare internals

const internals = {};


internals.defaults = {
    ticketTTL: 60 * 60 * 1000,                          // 1 hour
    rsvpTTL: 1 * 60 * 1000,                             // 1 minute
    keyBytes: 32,                                       // Ticket secret size in bytes
    hmacAlgorithm: 'sha256'
};


/*
    const app = {
        id: '123',                      // Application id
        scope: ['a', 'b']               // Application scope
    };

    const grant = {
        id: 'd832d9283hd9823dh',        // Persistent identifier used to issue additional tickets or revoke access
        user: '456',                    // User id
        exp: 1352535473414,             // Grant expiration
        scope: ['b']                    // Grant scope
    };

    const options = {
        ttl: 60 * 1000,                 // 1 min
        delegate: false,                // Ticket-specific delegation permission (default to true)
        ext: {                          // Server-specific extension data
            public: {                   // Included in the plain ticket
                tos: '0.0.1'
            },
            private: {                  // Included in the encoded ticket
                x: 1
            }
        },
        dlg: '456',                     // Delegating application id
        scope: ['b'],                   // Subset of grant scope to delegate
        iron: {},                       // Override Iron defaults
        keyBytes: 32,                   // Hawk key length
        hmacAlgorithm: 'sha256'         // Hawk algorithm
    };
*/

exports.issue = function (app, grant, encryptionPassword, options, callback) {

    const fail = Hoek.nextTick(callback);

    if (!app || !app.id) {
        return fail(Boom.internal('Invalid application object'));
    }

    if (grant && (!grant.id || !grant.user || !grant.exp)) {
        return fail(Boom.internal('Invalid grant object'));
    }

    if (!encryptionPassword) {
        return fail(Boom.internal('Invalid encryption password'));
    }

    if (!options) {
        return fail(Boom.internal('Invalid options object'));
    }

    const scope = options.scope || (grant && grant.scope) || app.scope || [];
    const error = Scope.validate(scope);
    if (error) {
        return fail(error);
    }

    if (grant &&
        grant.scope &&
        app.scope &&
        !Scope.isSubset(app.scope, grant.scope)) {

        return fail(Boom.internal('Grant scope is not a subset of the application scope'));
    }

    // Construct ticket

    let exp = (Hawk.utils.now() + (options.ttl || internals.defaults.ticketTTL));
    if (grant) {
        exp = Math.min(exp, grant.exp);
    }

    const ticket = {
        exp: exp,
        app: app.id,
        scope: scope
    };

    if (grant) {
        ticket.grant = grant.id;
        ticket.user = grant.user;
    }

    if (options.delegate === false) {           // Defaults to true
        ticket.delegate = false;
    }

    if (options.dlg) {
        ticket.dlg = options.dlg;
    }

    exports.generate(ticket, encryptionPassword, options, callback);
};


// Reissue ticket

/*
    const grant = {
        id: 'd832d9283hd9823dh',        // Persistent identifier used to issue additional tickets or revoke access
        user: '456',                    // User id
        exp: 1352535473414,             // Grant expiration
        scope: ['b']                    // Grant scope
    };

    const options = {
        ttl: 60 * 1000,                 // 1 min
        delegate: false,                // Ticket-specific delegation permission (default to true)
        scope: ['b'],                   // Ticket scope (must be equal or lesser than parent)
        issueTo: '123',                 // Delegated to application id
        ext: {                          // Server-specific extension data
            public: {                   // Included in the plain ticket
                tos: '0.0.1'
            },
            private: {                  // Included in the encoded ticket
                x: 1
            }
        },
        iron: {}                        // Override Iron defaults
        keyBytes: 32,                   // Hawk key length
        hmacAlgorithm: 'sha256'         // Hawk algorithm
    };
*/

exports.reissue = function (parentTicket, grant, encryptionPassword, options, callback) {

    const fail = Hoek.nextTick(callback);

    if (!parentTicket) {
        return fail(Boom.internal('Invalid parent ticket object'));
    }

    if (!encryptionPassword) {
        return fail(Boom.internal('Invalid encryption password'));
    }

    if (!options) {
        return fail(Boom.internal('Invalid options object'));
    }

    if (parentTicket.scope) {
        const error = Scope.validate(parentTicket.scope);
        if (error) {
            return fail(error);
        }
    }

    if (options.scope) {
        const error = Scope.validate(options.scope);
        if (error) {
            return fail(error);
        }

        if (!Scope.isSubset(parentTicket.scope, options.scope)) {
            return fail(Boom.forbidden('New scope is not a subset of the parent ticket scope'));
        }
    }

    if (options.delegate &&
        parentTicket.delegate === false) {

        return fail(Boom.forbidden('Cannot override ticket delegate restriction'));
    }

    if (options.issueTo) {
        if (parentTicket.dlg) {
            return fail(Boom.badRequest('Cannot re-delegate'));
        }

        if (parentTicket.delegate === false) {          // Defaults to true
            return fail(Boom.forbidden('Ticket does not allow delegation'));
        }
    }

    if (grant && (!grant.id || !grant.user || !grant.exp)) {
        return fail(Boom.internal('Invalid grant object'));
    }

    if (grant || parentTicket.grant) {
        if (!grant ||
            !parentTicket.grant ||
            parentTicket.grant !== grant.id) {

            return fail(Boom.internal('Parent ticket grant does not match options.grant'));
        }
    }

    // Construct ticket

    let exp = (Hawk.utils.now() + (options.ttl || internals.defaults.ticketTTL));
    if (grant) {
        exp = Math.min(exp, grant.exp);
    }

    const ticket = {
        exp: exp,
        app: options.issueTo || parentTicket.app,
        scope: options.scope || parentTicket.scope
    };

    if (!options.ext &&
        parentTicket.ext) {

        options = Hoek.shallow(options);
        options.ext = parentTicket.ext;
    }

    if (grant) {
        ticket.grant = grant.id;
        ticket.user = grant.user;
    }

    if (options.issueTo) {
        ticket.dlg = parentTicket.app;
    }
    else if (parentTicket.dlg) {
        ticket.dlg = parentTicket.dlg;
    }

    if (options.delegate === false ||                   // Defaults to true
        parentTicket.delegate === false) {

        ticket.delegate = false;
    }

    exports.generate(ticket, encryptionPassword, options, callback);
};


/*
    // The requesting application

    const app = {
        id: '123',                      // Application id
    };

    // The resource owner

    const grant = {
        id: 'd832d9283hd9823dh'         // Persistent identifier used to issue additional tickets or revoke access
    };

    const options = {
        ttl: 1 * 60 * 10000,            // Rsvp TTL
        dlg: '456',                     // The delegating application id
        scope: ['a'],                   // Subset of grant scope to delegate
        iron: {}                        // Override Iron defaults
    };
*/

exports.rsvp = function (app, grant, encryptionPassword, options, callback) {

    const fail = Hoek.nextTick(callback);

    if (!app || !app.id) {
        return fail(Boom.internal('Invalid application object'));
    }

    if (!grant || !grant.id) {
        return fail(Boom.internal('Invalid grant object'));
    }

    if (!encryptionPassword) {
        return fail(Boom.internal('Invalid encryption password'));
    }

    if (!options) {
        return fail(Boom.internal('Invalid options object'));
    }

    options.ttl = options.ttl || internals.defaults.rsvpTTL;

    // Construct envelope

    const envelope = {
        app: app.id,
        exp: Hawk.utils.now() + options.ttl,
        grant: grant.id
    };

    // Add options for delegation rsvp

    if (options.dlg) {

        const delegateOptions = { dlg: options.dlg };

        if (options.scope) {
            delegateOptions.scope = options.scope;
        }

        envelope.delegate = delegateOptions;
    }

    // Stringify and encrypt

    Iron.seal(envelope, encryptionPassword, options.iron || Iron.defaults, (err, sealed) => {

        if (err) {
            return callback(err);
        }

        const rsvp = sealed;
        return callback(null, rsvp);
    });
};


/*
    const ticket = {

        // Inputs into generate()

        exp:                time in msec
        app:                app id ticket is issued to
        scope:              ticket scope
        grant:              grant id
        user:               user id
        dlg:                app id of the delegating party

        // Added by generate()

        key:                ticket secret key (Hawk)
        algorithm:          ticket hmac algorithm (Hawk)
        id:                 ticket key id (Hawk)
        ext:                application data { public, private }
    };

    const options = {
        iron: {},                       // Override Iron defaults
        keyBytes: 32,                   // Hawk key length
        hmacAlgorithm: 'sha256'         // Hawk algorithm
    };
*/

exports.generate = function (ticket, encryptionPassword, options, callback) {

    const fail = Hoek.nextTick(callback);

    // Generate ticket secret

    const random = Cryptiles.randomString(options.keyBytes || internals.defaults.keyBytes);
    if (random instanceof Error) {
        return fail(random);
    }

    ticket.key = random;
    ticket.algorithm = options.hmacAlgorithm || internals.defaults.hmacAlgorithm;

    // Ext data

    if (options.ext) {
        ticket.ext = {};

        // Explicit copy to avoid unintentional leaking of private data as public or changes to options object

        if (options.ext.public !== undefined) {
            ticket.ext.public = options.ext.public;
        }

        if (options.ext.private !== undefined) {
            ticket.ext.private = options.ext.private;
        }
    }

    // Seal ticket

    Iron.seal(ticket, encryptionPassword, options.iron || Iron.defaults, (err, sealed) => {

        if (err) {
            return callback(err);
        }

        ticket.id = sealed;

        // Hide private ext data

        if (ticket.ext) {
            if (ticket.ext.public !== undefined) {
                ticket.ext = ticket.ext.public;
            }
            else {
                delete ticket.ext;
            }
        }

        return callback(null, ticket);
    });
};


// Parse ticket id

/*
    const options = {
        iron: {}                        // Override Iron defaults
    };
*/

exports.parse = function (id, encryptionPassword, options, callback) {

    const fail = Hoek.nextTick(callback);

    if (!encryptionPassword) {
        return fail(Boom.internal('Invalid encryption password'));
    }

    if (!options) {
        return fail(Boom.internal('Invalid options object'));
    }

    Iron.unseal(id, encryptionPassword, options.iron || Iron.defaults, (err, object) => {

        if (err) {
            return callback(err);
        }

        const ticket = object;
        ticket.id = id;
        return callback(null, ticket);
    });
};
