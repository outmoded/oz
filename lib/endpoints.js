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

        loadAppFunc: async function (id) { return app; },
        loadGrantFunc: async function (id) { return { grant, ext }; }
    };
*/

// Request an application ticket using Hawk authentication

exports.app = async function (req, payload, options) {

    const { credentials } = await Hawk.server.authenticate(req, options.loadAppFunc, options.hawk);
    return Ticket.issue(credentials, null, options.encryptionPassword, options.ticket);
};


// Request a ticket reissue using the authenticating ticket

internals.schema.reissue = Joi.object({
    issueTo: Joi.string(),
    scope: Joi.array().items(Joi.string())
});


exports.reissue = async function (req, payload, options) {

    payload = payload || {};

    await internals.validate('reissue', payload);

    const { ticket } = await Server._authenticate(req, options.encryptionPassword, false, options);

    // Load ticket

    const app = await options.loadAppFunc(ticket.app);
    if (!app) {
        throw Hawk.utils.unauthorized('Invalid application');
    }

    if (payload.issueTo &&
        !app.delegate) {

        throw Boom.forbidden('Application has no delegation rights');
    }


    const reissue = (grant, ext) => {

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

        return Ticket.reissue(ticket, grant, options.encryptionPassword, ticketOptions);
    };

    // Application ticket

    if (!ticket.grant) {
        return reissue();
    }

    // User ticket

    const { grant, ext } = await options.loadGrantFunc(ticket.grant);

    if (!grant ||
        (grant.app !== ticket.app && grant.app !== ticket.dlg) ||
        grant.user !== ticket.user ||
        !grant.exp ||
        grant.exp <= Hawk.utils.now()) {

        throw Hawk.utils.unauthorized('Invalid grant');
    }

    return reissue(grant, ext);
};


internals.schema.rsvp = Joi.object({
    rsvp: Joi.string().required()
});


exports.rsvp = async function (req, payload, options) {

    if (!payload) {
        throw Boom.badRequest('Missing required payload');
    }

    await internals.validate('rsvp', payload);

    const { ticket } = await Server.authenticate(req, options.encryptionPassword, options);

    if (ticket.user) {
        throw Hawk.utils.unauthorized('User ticket cannot be used on an application endpoint');
    }

    const envelope = await Ticket.parse(payload.rsvp, options.encryptionPassword, options.ticket);

    if (envelope.app !== ticket.app) {
        throw Boom.forbidden('Mismatching ticket and rsvp apps');
    }

    const now = Hawk.utils.now();

    if (envelope.exp <= now) {
        throw Boom.forbidden('Expired rsvp');
    }

    const grantResult = await options.loadGrantFunc(envelope.grant);
    if (!grantResult) {
        throw Boom.forbidden('Invalid grant');
    }

    const { grant, ext } = grantResult;
    if (!grant ||
        grant.app !== ticket.app ||
        !grant.exp ||
        grant.exp <= now) {

        throw Boom.forbidden('Invalid grant');
    }

    const app = await options.loadAppFunc(grant.app);
    if (!app) {
        throw Boom.forbidden('Invalid application');
    }

    let ticketOptions = options.ticket || {};
    if (ext) {
        ticketOptions = Hoek.shallow(ticketOptions);
        ticketOptions.ext = ext;
    }

    return Ticket.issue(app, grant, options.encryptionPassword, ticketOptions);
};


internals.validate = async function (type, payload) {

    try {
        await Joi.validate(payload, internals.schema[type]);
    }
    catch (err) {
        throw Boom.badRequest(`Invalid request payload: ${Hoek.escapeHtml(err.details[0].message.replace(/"/g, ''))}`, err);
    }
};
