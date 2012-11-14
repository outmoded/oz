// Load modules

var Http = require('http');
var NodeUtil = require('util');
var Utils = require('./utils');


// Declare internals

var internals = {};


exports = module.exports = internals.Error = function (code, message) {

    Utils.assert(this.constructor === internals.Error, 'Error must be instantiated using new');
    Utils.assert(code >= 400, 'Error code must be 4xx or 5xx');

    Error.call(this);

    this.code = code;
    this.message = message;
    this.headers = null;

    return this;
};

NodeUtil.inherits(internals.Error, Error);


internals.Error.prototype.toResponse = function () {

    var response = {
        code: this.code,
        payload: {
            error: Http.STATUS_CODES[this.code] || 'Unknown',
            code: this.code,
            message: this.message
        },
        headers: this.headers
        // contentType: 'application/json'
    };

    for (var d in this) {
        if (this.hasOwnProperty(d) &&
            !response.payload.hasOwnProperty(d)) {

            response.payload[d] = this[d];
        }
    }

    return response;
};


// Utilities

internals.Error.badRequest = function (message) {

    return new internals.Error(400, message);
};


internals.Error.unauthorized = function (message, scheme) {

    var err = new internals.Error(401, message);

    scheme = scheme || 'Oz';
    err.headers = { 'WWW-Authenticate': scheme + (scheme === 'Oz' && message ? ' error="' + Utils.escapeHeaderAttribute(message) + '"' : '') };

    return err;
};


internals.Error.forbidden = function (message) {

    return new internals.Error(403, message);
};


internals.Error.notFound = function (message) {

    return new internals.Error(404, message);
};


internals.Error.internal = function (message, data) {

    var format = function () {

        var response = {
            code: 500,
            payload: {
                error: Http.STATUS_CODES[500],
                code: 500,
                message: 'An internal server error occurred'                // Hide actual error from user
            }
        };

        return response;
    };

    var err = new internals.Error(500, message, { toResponse: format });
    err.trace = Utils.callStack(1);
    err.data = data;
    return err;
};