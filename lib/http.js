// Load modules

var Utils = require('./utils');
var Crypto = require('./crypto');
var Ticket = require('./ticket');
var Request = require('./request');
var Settings = require('./settings')


// Declare internals

var internals = {};


// Validate an incoming request
// options: see Request.parse()

exports.authenticate = function (req, options, callback) {

    var now = Date.now();

    // Parse HTTP Authorization header

    if (!req.headers.authorization) {
        return callback(new Error('Request missing authorization header'));
    }

    var attributes = exports.parseHeader(req.headers.authorization);

    // Verify MAC authentication scheme

    if (attributes instanceof Error) {
        return callback(attributes);
    }

    // Verify required header attributes

    if (!attributes.ticket ||
        !attributes.ts ||
        !attributes.mac) {

        return callback(new Error('Missing authentication attributes in Authorization header field'));
    }

    // Parse request

    var request = Request.parse(req, options);
    if (request instanceof Error) {
        return callback(request);
    }

    // Parse ticket

    Ticket.parse(attributes.ticket, function (err, ticket) {

        if (err) {
            return callback(err);
        }

        // Validate MAC

        if (!Request.validate(request, attributes, ticket)) {
            return callback(new Error('Invalid request MAC'));
        }

        // Check timestamp

        if (Math.abs(now - ticket.offset - attributes.ts) >= Settings.ticket.timestampWindow) {
            return callback(new Error('Request includes stale timestamp'));
        }

        // Return result

        return callback(null, ticket, attributes);
    });
};


// Extract attributes from OZ header (strict)

exports.parseHeader = function (header) {

    // Authorization: OZ ticket="asdlaskjdlaksjdlaksjd", ts="1348191870082", ext="", mac=""

    var headerRegex = /^[Oo][Zz]\s+(.*)$/;
    var headerParts = headerRegex.exec(header);

    if (!headerParts ||
        headerParts.length !== 2 ||
        !headerParts[1]) {

        // Invalid header format
        return (new Error('Wrong authentication scheme'));
    }

    var attributes = {};

    var attributesRegex = /(ticket|ts|ext|mac)="([^"\\]*)"\s*(?:,\s*|$)/g;
    var verify = headerParts[1].replace(attributesRegex, function ($0, $1, $2) {

        if (attributes[$1] === undefined) {
            attributes[$1] = $2;
            return '';
        }
    });

    if (verify) {                               // verify will be empty on full match
        // Did not match all parts
        return (new Error('Authorization header field includes unknown attributes'));
    }

    return attributes;
};


// Generate an Authorization header

exports.formatHeader = function (attributes, ticket, mac) {

    // Construct header

    return 'OZ ticket="' + ticket + '", ts="' + attributes.ts + (attributes.ext ? '", ext="' + attributes.ext : '') + '", mac="' + mac + '"';
};


