// Load modules

var Boom = require('boom');
var Cryptiles = require('cryptiles');
var Hawk = require('hawk');
var Hoek = require('hoek');
var Iron = require('iron');
var Scope = require('./scope');


// Declare internals

var internals = {};


internals.defaults = {
    ticketTTL: 60 * 60 * 1000,                          // 1 hour
    rsvpTTL: 1 * 60 * 1000,                             // 1 minute
    keyBytes: 32,                                       // Ticket secret size in bytes
    hmacAlgorithm: 'sha256'
};


/*
    var app = {
        id: '123',                      // Application id
        scope: ['a', 'b']               // Application scope
    };

    var options = {
        ttl: 60 * 1000,                 // 1 min
        grant: {
            id: 'd832d9283hd9823dh',    // Persistent identifier used to issue additional tickets or revoke access
            user: '456',                // User id
            exp: 1352535473414,         // Grant expiration
            scope: ['b']                // Grant scope
        },
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

exports.issue = function (app, encryptionPassword, options, next) {

    if (!app || !app.id) {
        return next(Boom.internal('Invalid application object'));
    }

    var grant = options.grant;
    if (grant && (!grant.id || !grant.user || !grant.exp)) {
        return next(Boom.internal('Invalid grant object'));
    }

    if (!encryptionPassword) {
        return next(Boom.internal('Invalid encryption password'));
    }

    if (!options) {
        return next(Boom.internal('Invalid options object'));
    }

    var scope = (grant && grant.scope) || app.scope || [];
    var error = Scope.validate(scope);
    if (error) {
        return next(error);
    }

    if (grant &&
        grant.scope &&
        app.scope &&
        !Scope.isSubset(app.scope, grant.scope)) {

        return next(Boom.internal('Grant scope is not a subset of the application scope'));
    }

    // Construct ticket

    var exp = (Hawk.utils.now() + (options.ttl || internals.defaults.ticketTTL));
    if (grant) {
        exp = Math.min(exp, grant.exp);
    }

    var ticket = {
        exp: exp,
        app: app.id,
        scope: scope
    };

    if (grant) {
        ticket.grant = grant.id;
        ticket.user = grant.user;
    }

    exports.generate(ticket, encryptionPassword, options, next);
};


// Reissue ticket

/*
    var options = {
        ttl: 60 * 1000,                 // 1 min
        scope: ['b'],                   // Ticket scope (must be equal or lesser than parent)
        grant: {
            id: 'd832d9283hd9823dh',    // Persistent identifier used to issue additional tickets or revoke access
            user: '456',                // User id
            exp: 1352535473414          // Grant expiration
        },
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

exports.reissue = function (parentTicket, encryptionPassword, options, next) {

    if (!parentTicket) {
        return next(Boom.internal('Invalid parent ticket object'));
    }

    if (!encryptionPassword) {
        return next(Boom.internal('Invalid encryption password'));
    }

    if (!options) {
        return next(Boom.internal('Invalid options object'));
    }

    if (options.scope &&
        !Scope.isSubset(parentTicket.scope, options.scope)) {

        return next(Boom.forbidden('New scope is not a subset of the parent ticket scope'));
    }

    if (options.issueTo &&
        parentTicket.dlg) {

        return next(Boom.badRequest('Cannot re-delegate'));
    }

    var grant = options.grant;
    if (grant && (!grant.id || !grant.user || !grant.exp)) {
        return next(Boom.internal('Invalid grant object'));
    }

    if (grant || parentTicket.grant) {
        if (!grant ||
            !parentTicket.grant ||
            parentTicket.grant !== grant.id) {

            return next(Boom.internal('Parent ticket grant does not match options.grant'));
        }
    }

    // Construct ticket

    var exp = (Hawk.utils.now() + (options.ttl || internals.defaults.ticketTTL));
    if (grant) {
        exp = Math.min(exp, grant.exp);
    }

    var ticket = {
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

    exports.generate(ticket, encryptionPassword, options, next);
};


/*
    // The requesting application

    var app = {
        id: '123',                      // Application id
    };

    // The resource owner

    var grant = {
        id: 'd832d9283hd9823dh'         // Persistent identifier used to issue additional tickets or revoke access
    };

    var options = {
        ttl: 1 * 60 * 10000,            // Rsvp TTL
        iron: {}                        // Override Iron defaults
    };
*/

exports.rsvp = function (app, grant, encryptionPassword, options, next) {

    if (!app || !app.id) {
        return next(Boom.internal('Invalid application object'));
    }

    if (!grant || !grant.id) {
        return next(Boom.internal('Invalid grant object'));
    }

    if (!encryptionPassword) {
        return next(Boom.internal('Invalid encryption password'));
    }

    if (!options) {
        return next(Boom.internal('Invalid options object'));
    }

    options.ttl = options.ttl || internals.defaults.rsvpTTL;

    // Construct envelope

    var envelope = {
        app: app.id,
        exp: Hawk.utils.now() + options.ttl,
        grant: grant.id
    };

    // Stringify and encrypt

    Iron.seal(envelope, encryptionPassword, options.iron || Iron.defaults, function (err, sealed) {

        if (err) {
            return next(err);
        }

        var rsvp = sealed;
        return next(null, rsvp);
    });
};


/*
    var ticket = {

        // Inputs into generate()

        exp:                time in msec
        app:                app id ticket is issued to
        scope:              ticket scope
        ext:                application data { public, private }
        grant:              grant id
        user:               user id
        dlg:                app id of the delegating party

        // Added by generate()

        key:                ticket secret key (Hawk)
        algorithm:          ticket hmac algorithm (Hawk)
        id:                 ticket key id (Hawk)
    };

    var options = {
        iron: {},                       // Override Iron defaults
        keyBytes: 32,                   // Hawk key length
        hmacAlgorithm: 'sha256'         // Hawk algorithm
    };
*/

exports.generate = function (ticket, encryptionPassword, options, next) {

    // Generate ticket secret

    var random = Cryptiles.randomString(options.keyBytes || internals.defaults.keyBytes);
    if (random instanceof Error) {
        return next(random);
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

    Iron.seal(ticket, encryptionPassword, options.iron || Iron.defaults, function (err, sealed) {

        if (err) {
            return next(err);
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

        return next(null, ticket);
    });
};


// Parse ticket id

/*
    var options = {
        iron: {}                        // Override Iron defaults
    };
*/

exports.parse = function (id, encryptionPassword, options, next) {

    if (!encryptionPassword) {
        return next(Boom.internal('Invalid encryption password'));
    }

    if (!options) {
        return next(Boom.internal('Invalid options object'));
    }

    Iron.unseal(id, encryptionPassword, options.iron || Iron.defaults, function (err, object) {

        if (err) {
            return next(err);
        }

        var ticket = object;
        ticket.id = id;
        return next(null, ticket);
    });
};
