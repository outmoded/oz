// Load modules

var Http = require('http');
var NodeUtil = require('util');
var Utils = require('./utils');


// Declare internals

var internals = {};


internals.codes = {
    invalid_request: 400,
    invalid_client: 401,
    invalid_grant: 400,
    unauthorized_client: 401,
    unsupported_grant_type: 400,
    invalid_scope: 403,
    access_denied: 401,
    unsupported_response_type: 400,
    server_error: 500,
    temporarily_unavailable: 503
};


exports = module.exports = internals.Error = function (code, message) {

    Utils.assert(this.constructor === internals.Error, 'Error must be instantiated using new');
    Utils.assert(internals.codes[code], 'Unknown error code: ' + code);

    Error.call(this);

    this.code = code;
    this.message = message;

    return this;
};

NodeUtil.inherits(internals.Error, Error);


internals.Error.prototype.toResponse = function () {

    var httpCode = internals.codes[this.code];
    var response = {
        code: httpCode,
        payload: {
            error: Http.STATUS_CODES[httpCode] || 'Unknown',
            code: this.code,
            message: this.message
        }
    };

    for (var d in this) {
        if (this.hasOwnProperty(d) &&
            !response.payload.hasOwnProperty(d)) {

            response.payload[d] = this[d];
        }
    }

    return response;
};



