// Load modules

var Utils = require('./utils');
var Crypto = require('./crypto');
var Settings = require('./settings');


// Declare internals

var internals = {};


/*
    var app = {
        id: '123',                  // Application id
        scope: ['a', 'b'],          // Grant scope
        clockOffset: 0              // MSecs = localtime - remotetime
    };

    var grant = {
        id: 'd832d9283hd9823dh',    // Persitant identifier used to issue additional tickets or revoke access
        user: '456',                // User id
        exp: 1352535473414,         // Grant expiration
        scope: ['b']                // Grant scope
    };

    var options = {
        ttl: 60 * 1000,             // 1 min
        scope: ['b'],               // Ticket scope
        issuedFor: '456',           // Delegated to application id
        ext: {                      // Server-specific extension data
            tos: '0.0.1',
            private: { x: 1 }       // Anything inside 'private' is only included in the encrypted portion
        }
    };
*/

exports.issue = function (app, grant, encryptionPassword, options, callback) {

    Utils.assert(app && app.id, 'Invalid application object');
    Utils.assert(!grant || (grant.id && grant.user && grant.exp), 'Invalid grant object');
    Utils.assert(encryptionPassword, 'Invalid encryption password');
    Utils.assert(options, 'Invalid options object');

    // Construct envelope

    var exp = (Date.now() + (options.ttl || Settings.ticket.ttl));
    if (grant) {
        exp = Math.min(exp, grant.exp);
    }

    var envelope = {
        exp: exp,
        app: options.issuedFor || app.id,
        scope: options.scope || (grant ? grant.scope : null) || app.scope || [],
        offset: app.clockOffset || 0
    };

    if (grant) {
        envelope.user = grant.user;
        envelope.grant = grant.id;
    }

    if (options.issuedFor) {
        envelope.delegatedBy = app.id;
    }

    if (options.ext) {
        envelope.ext = options.ext
    }

    exports.generate(envelope, encryptionPassword, callback);
};


// Reissue ticket

/*
    var options = {
        *scope: ['b'],                   // Ticket scope (must be equal or lesser than original)
        grantExp: 1352535473414,        // Grant expiration timestamp
        *issuedFor: '123'                // Delegated to application id
*/

exports.reissue = function (ticket, encryptionPassword, options, callback) {

    Utils.assert(ticket, 'Invalid original ticket object');
    Utils.assert(encryptionPassword, 'Invalid encryption password');
    Utils.assert(options, 'Invalid options object');

    // Construct envelope

    var exp = (Date.now() + (options.ttl || Settings.ticket.ttl));
    if (options.grantExp) {
        exp = Math.min(exp, options.grantExp);
    }

    var envelope = {
        app: ticket.app,
        scope: ticket.scope,
        exp: exp,
        offset: ticket.offset
    };

    if (ticket.user) {
        envelope.user = ticket.user;
        envelope.grant = ticket.grant;
    }

    if (ticket.delegatedBy) {
        envelope.delegatedBy = ticket.delegatedBy;
    }

    if (ticket.ext) {
        envelope.ext = ticket.ext
    }

    exports.generate(envelope, encryptionPassword, callback);
};


exports.generate = function (envelope, encryptionPassword, callback) {

    // Generate ticket secret

    Crypto.randomBits(Settings.ticket.secretBits, function (err, random) {

        if (err) {
            return callback(err);
        }

        envelope.key = random.toString('hex');
        envelope.algorithm = Settings.ticket.hmacAlgorithm;

        // Seal envelope

        Crypto.seal(envelope, encryptionPassword, Settings.ticket, function (err, sealed) {

            if (err) {
                return callback(err);
            }

            envelope.id = sealed;

            // Hide private ext data

            if (envelope.ext &&
                envelope.ext.private) {

                delete envelope.ext.private;
            }

            return callback(null, envelope);
        });
    });
};


// Parse ticket id

exports.parse = function (id, encryptionPassword, callback) {

    Utils.assert(encryptionPassword, 'Invalid encryption password');

    Crypto.unseal(id, encryptionPassword, Settings.ticket, function (err, object) {

        if (err) {
            return callback(err);
        }

        var ticket = object;
        ticket.id = id;
        return callback(null, ticket);
    });
};


