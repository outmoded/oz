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

exports.header = function (uri, method, ticket, options) {

    const settings = Hoek.shallow(options || {});
    settings.credentials = ticket;
    settings.app = ticket.app;
    settings.dlg = ticket.dlg;

    return Hawk.client.header(uri, method, settings);
};


exports.Connection = internals.Connection = function (options) {

    this.settings = Hoek.applyToDefaults(internals.defaults, options);
    this._appTicket = null;
};


internals.Connection.prototype.request = function (path, ticket, options, callback) {

    const method = options.method || 'GET';
    this._request(method, path, options.payload, ticket, (err, result, code) => {

        if (err) {
            return callback(err);
        }

        if (code !== 401 ||
            !result ||
            !result.expired) {

            return callback(null, result, code, ticket);
        }

        // Try to reissue ticket

        this.reissue(ticket, (refreshError, reissued) => {

            if (refreshError) {
                return callback(err);       // Pass original request error
            }

            // Try resource again and pass back the ticket reissued (when not app)

            this._request(method, path, options.payload, reissued, (err, result2, code2) => {

                return callback(err, result2, code2, reissued);
            });
        });
    });
};


internals.Connection.prototype.app = function (path, options, callback) {

    const finalize = (err, result, code, ticket) => {

        if (err) {
            return callback(err);
        }

        this._appTicket = ticket;           // In case ticket was refreshed
        return callback(null, result, code, ticket);
    };

    if (this._appTicket) {
        return this.request(path, this._appTicket, options, finalize);
    }

    this._requestAppTicket((err) => {

        if (err) {
            return finalize(err);
        }

        return this.request(path, this._appTicket, options, finalize);
    });
};


internals.Connection.prototype.reissue = function (ticket, callback) {

    this._request('POST', this.settings.endpoints.reissue, null, ticket, (err, result, code) => {

        if (err) {
            return callback(err);
        }

        if (code !== 200) {
            return callback(Boom.internal(result.message));
        }

        return callback(null, result);
    });
};


internals.Connection.prototype._request = function (method, path, payload, ticket, callback) {

    const body = (payload !== null ? JSON.stringify(payload) : null);
    const uri = this.settings.uri + path;
    const headers = {};

    if (typeof payload === 'object') {
        headers['content-type'] = 'application/json';
    }

    const header = exports.header(uri, method, ticket);
    headers.Authorization = header.field;

    Wreck.request(method, uri, { headers: headers, payload: body }, (err, response) => {

        if (err) {
            return callback(err);
        }

        Wreck.read(response, { json: true }, (err, result) => {

            if (err) {
                return callback(err);
            }

            Hawk.client.authenticate(response, ticket, header.artifacts, {}, (err, attributes) => {

                return callback(err, result, response.statusCode);
            });
        });
    });
};


internals.Connection.prototype._requestAppTicket = function (callback) {

    const uri = this.settings.uri + this.settings.endpoints.app;
    const header = exports.header(uri, 'POST', this.settings.credentials);
    Wreck.request('POST', uri, { headers: { Authorization: header.field } }, (err, response) => {

        if (err) {
            return callback(err);
        }

        Wreck.read(response, { json: true }, (err, result) => {

            if (err) {
                return callback(err);
            }

            if (response.statusCode !== 200) {
                return callback(Boom.internal('Client registration failed with unexpected response', { code: response.statusCode, payload: result }));
            }

            this._appTicket = result;
            return callback();
        });
    });
};
