// Load modules

var Boom = require('boom');
var Joi = require('joi');
var Utils = require('./utils');
var Rsvp = require('./rsvp');
var Ticket = require('./ticket');
var Request = require('./request');


// Declare internals

var internals = {};


/*
    var options = {
        isHttps: true,
        encryptionPassword: 'f84rf84r3hjdf8hw38hr',

        loadAppFunc: function (id, callback) { callback(app); },
        loadGrantFunc: function (id, callback) { callback(grant, ext); }
    };
*/

// Request an applicaiton ticket using Basic authentication

exports.app = function (req, payload, options, callback) {

    // Parse Basic authentication

    var creds = internals.basicAuth(req);
    if (creds instanceof Error) {
        return callback(creds);
    }

    // Load application

    options.loadAppFunc(creds.username, function (app) {

        if (!app) {
            return callback(Boom.unauthorized('Invalid application identifier or secret', 'Basic'));
        }

        // Validate application secret

        if ((app.secret || '') !== (creds.password || '')) {
            return callback(Boom.unauthorized('Invalid application identifier or secret', 'Basic'));
        }

        // Issue application ticket

        Ticket.issue(app, null, options.encryptionPassword, {}, callback);
    });
};


// Request a ticket reissue using the authenticating ticket

exports.reissue = function (req, payload, options, callback) {

    var schema = {
        issueTo: Joi.Types.String(),
        scope: Joi.Types.Array().includes(Joi.Types.String())//.emptyOk()
    };

    var load = function (ticket) {

        // Load ticket

        options.loadAppFunc(ticket.app, function (app) {

            if (!app) {
                return callback(Boom.unauthorized('Invalid application', 'Oz'));
            }

            if (!ticket.grant) {
                return reissue(ticket, app);
            }

            options.loadGrantFunc(ticket.grant, function (grant, ext) {

                if (!grant ||
                    grant.app !== ticket.app ||
                    grant.user !== ticket.user ||
                    !grant.exp ||
                    grant.exp <= Date.now()) {

                    return callback(Boom.unauthorized('Invalid grant', 'Oz'));
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
            // TODO: Check if the app has permission to delegate
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

    Joi.validate(payload, schema, function (err) {

        if (err) {
            return callback(Boom.badRequest(err.message));
        }

        internals.authenticate(req, 'any', options, function (err, ticket) {

            if (err) {
                return callback(err);
            }

            load(ticket);
        });
    });
};


exports.rsvp = function (req, payload, options, callback) {

    var schema = {
        rsvp: Joi.Types.String().required()
    };

    Joi.validate(payload, schema, function (err) {

        if (err) {
            return callback(Boom.badRequest(err.message));
        }

        internals.authenticate(req, 'app', options, function (err, ticket) {

            if (err) {
                return callback(err);
            }

            Rsvp.parse(payload.rsvp, options.encryptionPassword, function (err, envelope) {

                if (err) {
                    return callback(err);
                }

                if (envelope.app !== ticket.app) {
                    return callback(Boom.forbidden('Mismatching ticket and rsvp apps'));
                }

                var now = Date.now();

                if (envelope.exp <= now) {
                    return callback(Boom.forbidden('Expired rsvp'));
                }

                options.loadGrantFunc(envelope.grant, function (grant, ext) {

                    if (!grant ||
                        grant.app !== ticket.app ||
                        !grant.exp ||
                        grant.exp <= now) {

                        return callback(Boom.forbidden('Invalid grant'));
                    }

                    options.loadAppFunc(grant.app, function (app) {

                        if (!app) {
                            return callback(Boom.forbidden('Invalid application identifier or secret'));
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
    });
};


// Ticket authentication

internals.authenticate = function (req, entity, options, callback) {

    Request.authenticate(req, options.encryptionPassword, { isHttps: options.isHttps }, function (err, ticket, ext) {

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
                return callback(Boom.unauthorized('Application ticket cannot be used on a user endpoint', 'Oz'));
            }

            return callback(null, ticket);
        }

        // Entity: none

        if (entity === 'app') {
            if (ticket.user) {
                return callback(Boom.unauthorized('User ticket cannot be used on an application endpoint', 'Oz'));
            }

            return callback(null, ticket);
        }

        // Entity: unknown

        return callback(Boom.internal('Unknown endpoint entity mode'));
    });
};


// Basic authentication

internals.basicAuth = function (req) {

    var authorization = req.headers.authorization;
    if (!authorization) {
        return Boom.unauthorized('Request missing authentication', 'Basic');
    }

    var parts = authorization.split(/\s+/);
    if (parts.length !== 2) {
        return Boom.unauthorized('Bad HTTP authentication header format: ' + authorization, 'Basic');
    }

    if (parts[0].toLowerCase() !== 'basic') {
        return Boom.unauthorized('Incorrect HTTP authentication scheme: ' + parts[0], 'Basic');
    }

    var credentials = new Buffer(parts[1], 'base64').toString().split(':');
    return { username: credentials[0], password: credentials[1] };
};