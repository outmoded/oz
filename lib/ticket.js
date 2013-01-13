// Load modules

var Boom = require('boom');
var Iron = require('iron');
var Cryptiles = require('cryptiles');
var Utils = require('./utils');
var Crypto = require('./crypto');
var Settings = require('./settings');
var Scope = require('./scope');


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
        issueTo: '456',             // Delegated to application id
        ext: {                      // Server-specific extension data
            tos: '0.0.1',
            private: { x: 1 }       // Anything inside 'private' is only included in the encrypted portion
        }
    };
*/

exports.issue = function (app, grant, encryptionPassword, options, callback) {

    Utils.toss(app && app.id, Boom.internal('Invalid application object'), callback);
    Utils.toss(!grant || (grant.id && grant.user && grant.exp), Boom.internal('Invalid grant object'), callback);
    Utils.toss(encryptionPassword, Boom.internal('Invalid encryption password'), callback);
    Utils.toss(options, Boom.internal('Invalid options object'), callback);
    Utils.toss(!options.issueTo || options.issueTo !== app.id, Boom.badRequest('Cannot issue to self'), callback);

    var scope = options.scope || (grant ? grant.scope : null) || app.scope || [];
    Utils.toss(Scope.validate(scope), callback);

    // Construct envelope

    var exp = (Date.now() + (options.ttl || Settings.ticket.ttl));
    if (grant) {
        exp = Math.min(exp, grant.exp);
    }

    var envelope = {
        exp: exp,
        app: options.issueTo || app.id,
        scope: scope,
        offset: app.clockOffset || 0
    };

    if (grant) {
        envelope.grant = grant.id;
        envelope.user = grant.user;
    }

    if (options.issueTo) {
        envelope.delegatedBy = app.id;
    }

    if (options.ext) {
        envelope.ext = options.ext;
    }

    exports.generate(envelope, encryptionPassword, callback);
};


// Reissue ticket

/*
    var options = {
        scope: ['b'],                   // Ticket scope (must be equal or lesser than original)
        grantExp: 1352535473414,        // Grant expiration timestamp
        issueTo: '123'                  // Delegated to application id
*/

exports.reissue = function (ticket, encryptionPassword, options, callback) {

    Utils.toss(ticket, Boom.internal('Invalid original ticket object'), callback);
    Utils.toss(encryptionPassword, Boom.internal('Invalid encryption password'), callback);
    Utils.toss(options, Boom.internal('Invalid options object'), callback);
    Utils.toss(!options.scope || Scope.isSubset(ticket.scope, options.scope), Boom.forbidden('New scope is not a subset of ticket scope'), callback);
    Utils.toss(!options.issueTo || !ticket.delegatedBy, Boom.badRequest('Cannot re-delegate'), callback);

    // Construct envelope

    var exp = (Date.now() + (options.ttl || Settings.ticket.ttl));
    if (options.grantExp) {
        exp = Math.min(exp, options.grantExp);
    }

    var envelope = {
        app: options.issueTo || ticket.app,
        scope: options.scope || ticket.scope,
        exp: exp,
        offset: ticket.offset
    };

    if (ticket.grant) {
        envelope.grant = ticket.grant;
        envelope.user = ticket.user;
    }

    if (options.issueTo) {
        envelope.delegatedBy = ticket.app;
    }
    else if (ticket.delegatedBy) {
        envelope.delegatedBy = ticket.delegatedBy;
    }

    if (options.ext || ticket.ext) {
        envelope.ext = options.ext || ticket.ext;
    }

    exports.generate(envelope, encryptionPassword, callback);
};


exports.generate = function (envelope, encryptionPassword, callback) {

    // Generate ticket secret

    var random = Cryptiles.randomString(Settings.ticket.secretBytes);
    if (random instanceof Error) {
        return callback(random);
    }

    envelope.key = random.toString('hex');
    envelope.algorithm = Settings.ticket.hmacAlgorithm;

    // Seal envelope

    Iron.seal(envelope, encryptionPassword, Settings.ticket, function (err, sealed) {

        if (err) {
            return callback(err);
        }

        envelope.id = sealed;

        // Hide private ext data

        if (envelope.ext &&
            typeof envelope.ext === 'object' &&
            envelope.ext.private) {

            delete envelope.ext.private;
        }

        return callback(null, envelope);
    });
};


// Parse ticket id

exports.parse = function (id, encryptionPassword, callback) {

    Utils.toss(encryptionPassword, Boom.internal('Invalid encryption password'), callback);

    Iron.unseal(id, encryptionPassword, Settings.ticket, function (err, object) {

        if (err) {
            return callback(err);
        }

        var ticket = object;
        ticket.id = id;
        return callback(null, ticket);
    });
};