'use strict';

// Load modules

const Boom = require('boom');
const Hawk = require('hawk');
const Hoek = require('hoek');
const Wreck = require('wreck');


// Declare internals

const internals = {
    defaults: {
        endpoints: {
            app: '/oz/app',
            reissue: '/oz/reissue'
        }
    }
};


// Generate header

exports.header = function (uri, method, ticket, options = {}) {

    const settings = Hoek.shallow(options);
    settings.credentials = ticket;
    settings.app = ticket.app;
    settings.dlg = ticket.dlg;

    return Hawk.client.header(uri, method, settings);
};


exports.Connection = internals.Connection = class {

    constructor(options) {

        this.settings = Hoek.applyToDefaults(internals.defaults, options);
        this._appTicket = null;
    }

    async request(path, ticket, options = {}) {

        const method = options.method || 'GET';
        const { code, result } = await this._request(method, path, options.payload, ticket);

        if (code !== 401 ||
            !result ||
            !result.expired) {

            return { code, result, ticket };
        }

        // Try to reissue ticket

        const reissued = await this.reissue(ticket);

        // Try resource again and pass back the ticket reissued (when not app)

        const { code: rCode, result: rResult } = await this._request(method, path, options.payload, reissued);
        return { result: rResult, code: rCode, ticket: reissued };
    }

    async app(path, options = {}) {

        if (!this._appTicket) {
            await this._requestAppTicket();
        }

        const response = await this.request(path, this._appTicket, options);
        this._appTicket = response.ticket;                                          // In case ticket was refreshed
        return response;
    }

    async reissue(ticket) {

        const { code, result: reissued } = await this._request('POST', this.settings.endpoints.reissue, null, ticket);

        if (code !== 200) {
            throw Boom.internal(reissued.message);
        }

        return reissued;
    }

    async _request(method, path, payload, ticket) {

        const body = (payload !== null ? JSON.stringify(payload) : null);
        const uri = this.settings.uri + path;
        const headers = {};

        if (typeof payload === 'object') {
            headers['content-type'] = 'application/json';
        }

        const { header, artifacts } = exports.header(uri, method, ticket);
        headers.Authorization = header;

        const response = await Wreck.request(method, uri, { headers, payload: body });
        const result = await Wreck.read(response, { json: true });

        await Hawk.client.authenticate(response, ticket, artifacts);
        return { code: response.statusCode, result };
    }

    async _requestAppTicket() {

        const uri = this.settings.uri + this.settings.endpoints.app;
        const { header } = exports.header(uri, 'POST', this.settings.credentials);

        const response = await Wreck.request('POST', uri, { headers: { Authorization: header } });
        const ticket = await Wreck.read(response, { json: true });                  // Always read to drain the stream

        if (response.statusCode !== 200) {
            throw Boom.internal('Client registration failed with unexpected response', { code: response.statusCode, payload: ticket });
        }

        this._appTicket = ticket;
    }
};
