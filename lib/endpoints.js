// Load modules

var Boom = require('boom');
var Joi = require('joi');
var Hoek = require('hoek');
var Hawk = require('hawk');
var Cryptiles = require('cryptiles');
var Ticket = require('./ticket');
var Server = require('./server');


// Declare internals

var internals = {};


/*
    var options = {
        hawk: {},
        encryptionPassword: 'f84rf84r3hjdf8hw38hr',

        loadAppFunc: function (id, callback) { callback(err, app); },
        loadGrantFunc: function (id, callback) { callback(err, grant, ext); }
    };
*/

// Request an application ticket using Basic authentication

exports.app = function (req, payload, options, callback) {

    Hawk.server.authenticate(req, options.loadAppFunc, options.hawk || {}, function (err, credentials, artifacts) {

        if (err) {
            return callback(err);
        }

        // Issue application ticket

        Ticket.issue(credentials, null, options.encryptionPassword, {}, callback);
    });
};


// Request a ticket reissue using the authenticating ticket

exports.reissue = function (req, payload, options, callback) {

    var validate = function () {

        var schema = {
            issueTo: Joi.types.String(),
            scope: Joi.types.Array().includes(Joi.types.String()).emptyOk()
        };

        var error = Joi.validate(payload, schema);
        if (error) {
            return callback(Boom.badRequest(error.message));
        }

        internals.authenticate(req, 'any', options, function (err, ticket) {

            if (err) {
                return callback(err);
            }

            load(ticket);
        });
    };

    var load = function (ticket) {

        // Load ticket

        options.loadAppFunc(ticket.app, function (err, app) {

            if (err || !app) {
                return callback(err || Hawk.utils.unauthorized('Invalid application'));
            }

            if (!ticket.grant) {
                return reissue(ticket, app);
            }

            options.loadGrantFunc(ticket.grant, function (err, grant, ext) {

                if (err ||
                    !grant ||
                    (grant.app !== ticket.app && grant.app !== ticket.dlg) ||
                    grant.user !== ticket.user ||
                    !grant.exp ||
                    grant.exp <= Hawk.utils.now()) {

                    return callback(err || Hawk.utils.unauthorized('Invalid grant'));
                }

                return reissue(ticket, app, grant, ext);
            });
        });
    };

    var reissue = function (ticket, app, grant, ext) {

        var ticketOptions = {};

        if (grant) {
            ticketOptions.grantExp = grant.exp;
        }

        if (payload.issueTo) {
            // TODO: Check if the app has permission to delegate or redelegate
            ticketOptions.issueTo = payload.issueTo;
        }

        if (payload.scope) {
            ticketOptions.scope = payload.scope;
        }

        if (ext) {
            ticketOptions.ext = ext;
        }

        Ticket.reissue(ticket, options.encryptionPassword, ticketOptions, callback);
    };

    validate();
};


exports.rsvp = function (req, payload, options, callback) {

    var schema = {
        rsvp: Joi.types.String().required()
    };

    var error = Joi.validate(payload, schema);
    if (error) {
        return callback(Boom.badRequest(error.message));
    }

    internals.authenticate(req, 'app', options, function (err, ticket) {

        if (err) {
            return callback(err);
        }

        Ticket.parse(payload.rsvp, options.encryptionPassword, function (err, envelope) {

            if (err) {
                return callback(err);
            }

            if (envelope.app !== ticket.app) {
                return callback(Boom.forbidden('Mismatching ticket and rsvp apps'));
            }

            var now = Hawk.utils.now();

            if (envelope.exp <= now) {
                return callback(Boom.forbidden('Expired rsvp'));
            }

            options.loadGrantFunc(envelope.grant, function (err, grant, ext) {

                if (err ||
                    !grant ||
                    grant.app !== ticket.app ||
                    !grant.exp ||
                    grant.exp <= now) {

                    return callback(err || Boom.forbidden('Invalid grant'));
                }

                options.loadAppFunc(grant.app, function (err, app) {

                    if (err || !app) {
                        return callback(err || Boom.forbidden('Invalid application identifier or secret'));
                    }

                    var ticketOptions = {};
                    if (ext) {
                        ticketOptions.ext = ext;
                    }

                    Ticket.issue(app, grant, options.encryptionPassword, ticketOptions, callback);
                });
            });
        });
    });
};


// Ticket authentication

internals.authenticate = function (req, entity, options, callback) {

    Server.authenticate(req, options.encryptionPassword, options.hawk || {}, function (err, ticket, ext) {

        if (err) {
            return callback(err);
        }

        // Entity: any

        if (entity === 'any') {
            return callback(null, ticket);
        }

        // Entity: required

        if (entity === 'user') {
            if (!ticket.user) {
                return callback(Hawk.utils.unauthorized('Application ticket cannot be used on a user endpoint'));
            }

            return callback(null, ticket);
        }

        // Entity: none

        if (entity === 'app') {
            if (ticket.user) {
                return callback(Hawk.utils.unauthorized('User ticket cannot be used on an application endpoint'));
            }

            return callback(null, ticket);
        }

        // Entity: unknown

        return callback(Boom.internal('Unknown endpoint entity mode'));
    });
};


