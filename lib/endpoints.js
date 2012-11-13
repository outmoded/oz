// Load modules

var Joi = require('joi');
var Utils = require('./utils');
var Err = require('./error');
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
        return callback(new Err('invalid_request', 'Bad application authentication'));
    }

    // Load application

    options.loadAppFunc(creds.username, function (app) {

        if (!app) {
            return callback(new Err('invalid_client', 'Invalid application identifier or secret'));
        }

        // Validate application secret

        if ((app.secret || '') !== (creds.password || '')) {
            return callback(new Err('invalid_client', 'Invalid application identifier or secret'));
        }

        // Issue application ticket

        Ticket.issue(app, null, options.encryptionPassword, {}, function (err, envelope) {

            if (err) {
                return callback(new Err('invalid_client', 'Failed to issue ticket: ' + err));
            }

            return callback(null, envelope);
        });
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
                return callback(new Err('invalid_client', 'Invalid application identifier or secret'));
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

                    return callback(new Err('invalid_client', 'Invalid grant'));
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

        Ticket.reissue(ticket, options.encryptionPassword, ticketOptions, function (err, envelope) {

            if (err) {
                return callback(err);
            }

            return callback(null, envelope);
        });
    };

    Joi.validate(payload, schema, function (err) {

        if (err) {
            return callback(new Error(err.message));
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
            return callback(new Error(err.message));
        }

        internals.authenticate(req, 'app', options, function (err, ticket) {

            if (err) {
                return callback(err);
            }

            Rsvp.parse(payload.rsvp, options.encryptionPassword, function (err, envelope) {

                if (err) {
                    return callback(new Err('invalid_client', 'Invalid rsvp: ' + err));
                }

                if (envelope.app !== ticket.app) {
                    return callback(new Err('invalid_client', 'Mismatching ticket and rsvp apps'));
                }

                var now = Date.now();

                if (envelope.exp <= now) {
                    return callback(new Err('invalid_client', 'Expired rsvp'));
                }

                options.loadGrantFunc(envelope.grant, function (grant, ext) {

                    if (!grant ||
                        grant.app !== ticket.app ||
                        !grant.exp ||
                        grant.exp <= now) {

                        return callback(new Err('invalid_client', 'Invalid grant'));
                    }

                    options.loadAppFunc(grant.app, function (app) {

                        if (!app) {
                            return callback(new Err('invalid_client', 'Invalid application identifier or secret'));
                        }

                        var ticketOptions = {};
                        if (ext) {
                            ticketOptions.ext = ext;
                        }

                        Ticket.issue(app, grant, options.encryptionPassword, ticketOptions, function (err, envelope) {

                            if (err) {
                                return callback(new Err('invalid_client', 'Failed to issue ticket: ' + err));
                            }

                            return callback(null, envelope);
                        });
                    });
                });
            });
        });
    });
};


// Ticket authentication

internals.authenticate = function (req, entity, options, callback) {

    Request.authenticate(req, options.encryptionPassword, { isHttps: options.isHttps }, function (err, ticket, attributes) {

        if (err) {
//          res.setHeader('WWW-Authenticate', err.wwwAuthenticateHeader);
            return callback(err);
        }

        // Entity: any

        if (entity === 'any') {
            return callback(null, ticket);
        }

        // Entity: required

        if (entity === 'user') {
            if (!ticket.user) {
                return callback(new Error('Application ticket cannot be used on a user endpoint'));
            }

            return callback(null, ticket);
        }

        // Entity: none

        if (entity === 'app') {
            if (ticket.user) {
                return callback(new Error('User ticket cannot be used on an application endpoint'));
            }

            return callback(null, ticket);
        }

        // Entity: unknown

        return callback(new Error('Unknown endpoint entity mode'));
    });
};


// Basic authentication

internals.basicAuth = function (req) {

    var authorization = req.headers.authorization;
    if (!authorization) {
        return new Error('Request missing authentication');
    }

    var parts = authorization.split(/\s+/);
    if (parts.length !== 2) {
        return new Error('Bad HTTP authentication header format: ' + authorization);
    }

    if (parts[0].toLowerCase() !== 'basic') {
        return new Error('Incorrect HTTP authentication scheme: ' + parts[0]);
    }

    var credentials = new Buffer(parts[1], 'base64').toString().split(':');
    return { username: credentials[0], password: credentials[1] };
};
