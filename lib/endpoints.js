'use strict';

// Load modules

const Boom = require('boom');
const Joi = require('joi');
const Hoek = require('hoek');
const Hawk = require('hawk');
const Ticket = require('./ticket');
const Server = require('./server');


// Declare internals

const internals = {
    schema: {}
};


/*
    const options = {
        encryptionPassword: 'f84rf84r3hjdf8hw38hr',
        hawk: {},
        ticket: {},

        loadAppFunc: function (id, callback) { callback(err, app); },
        loadGrantFunc: function (id, callback) { callback(err, grant, ext); }
    };
*/

// Request an application ticket using Hawk authentication

exports.app = function (req, payload, options, callback) {

    Hawk.server.authenticate(req, options.loadAppFunc, options.hawk || {}, (err, credentials, artifacts) => {

        if (err) {
            return callback(err);
        }

        // Issue application ticket

        Ticket.issue(credentials, null, options.encryptionPassword, options.ticket || {}, callback);
    });
};


// Request a ticket reissue using the authenticating ticket

internals.schema.reissue = Joi.object({
    issueTo: Joi.string(),
    scope: Joi.array().items(Joi.string())
});

exports.reissue = function (req, payload, options, callback) {

    payload = payload || {};

    const validate = () => {

        const error = Joi.validate(payload, internals.schema.reissue).error;
        if (error) {
            return callback(Boom.badRequest(error.message));
        }

        Server._authenticate(req, options.encryptionPassword, false, options, (err, ticket, artifacts) => {

            if (err) {
                return callback(err);
            }

            // Load ticket

            options.loadAppFunc(ticket.app, (err, app) => {

                if (err) {
                    return callback(err);
                }

                if (!app) {
                    return callback(Hawk.utils.unauthorized('Invalid application'));
                }

                if (payload.issueTo &&
                    !app.delegate) {

                    return callback(Boom.forbidden('Application has no delegation rights'));
                }

                // Application ticket

                if (!ticket.grant) {
                    return reissue(ticket, app);
                }

                // User ticket

                options.loadGrantFunc(ticket.grant, (err, grant, ext) => {

                    if (err) {
                        return callback(err);
                    }

                    if (!grant ||
                        (grant.app !== ticket.app && grant.app !== ticket.dlg) ||
                        grant.user !== ticket.user ||
                        !grant.exp ||
                        grant.exp <= Hawk.utils.now()) {

                        return callback(Hawk.utils.unauthorized('Invalid grant'));
                    }

                    return reissue(ticket, app, grant, ext);
                });
            });
        });
    };

    const reissue = (ticket, app, grant, ext) => {

        const ticketOptions = Hoek.shallow(options.ticket || {});

        if (ext) {
            ticketOptions.ext = ext;
        }

        if (payload.issueTo) {
            ticketOptions.issueTo = payload.issueTo;
        }

        if (payload.scope) {
            ticketOptions.scope = payload.scope;
        }

        Ticket.reissue(ticket, grant, options.encryptionPassword, ticketOptions, callback);
    };

    validate();
};


internals.schema.rsvp = Joi.object({
    rsvp: Joi.string().required()
});


exports.rsvp = function (req, payload, options, callback) {

    if (!payload) {
        return callback(Boom.badRequest('Missing required payload'));
    }

    const error = Joi.validate(payload, internals.schema.rsvp).error;
    if (error) {
        return callback(Boom.badRequest(error.message));
    }

    Server.authenticate(req, options.encryptionPassword, options, (err, ticket, artifacts) => {

        if (err) {
            return callback(err);
        }

        if (ticket.user) {
            return callback(Hawk.utils.unauthorized('User ticket cannot be used on an application endpoint'));
        }

        Ticket.parse(payload.rsvp, options.encryptionPassword, options.ticket || {}, (err, envelope) => {

            if (err) {
                return callback(err);
            }

            if (envelope.app !== ticket.app) {
                return callback(Boom.forbidden('Mismatching ticket and rsvp apps'));
            }

            const now = Hawk.utils.now();

            if (envelope.exp <= now) {
                return callback(Boom.forbidden('Expired rsvp'));
            }

            options.loadGrantFunc(envelope.grant, (err, grant, ext) => {

                if (err) {
                    return callback(err);
                }

                if (!grant ||
                    grant.app !== ticket.app ||
                    !grant.exp ||
                    grant.exp <= now) {

                    return callback(Boom.forbidden('Invalid grant'));
                }

                options.loadAppFunc(grant.app, (err, app) => {

                    if (err) {
                        return callback(err);
                    }

                    if (!app) {
                        return callback(Boom.forbidden('Invalid application'));
                    }

                    let ticketOptions = options.ticket || {};
                    if (ext) {
                        ticketOptions = Hoek.shallow(ticketOptions);
                        ticketOptions.ext = ext;
                    }

                    Ticket.issue(app, grant, options.encryptionPassword, ticketOptions, callback);
                });
            });
        });
    });
};
