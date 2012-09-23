// Load modules

var Url = require('url');
var Crypto = require('./crypto');
var Ticket = require('./ticket');
var Settings = require('./settings')


// Declare internals

var internals = {};


// MAC request

/*
    var request = {
        method: 'GET',
        resource: '/path?query',
        host: 'example.com',
        port: 80
    };

    var attributes = {
        ts: 1348170630020               // Date.now()
        ext: 'app data'                 // Server-specific extension data (string)
    };
*/

exports.mac = function (request, attributes, ticket) {

    var normalized = ticket.id + '\n' +
                     ticket.app + '\n' +
                     attributes.ts + '\n' +
                     request.method.toUpperCase() + '\n' +
                     request.resource + '\n' +
                     request.host.toLowerCase() + '\n' +
                     request.port + '\n' +
                     (attributes.ext || '') + '\n';

    var mac = Crypto.hmacKey(ticket.key, ticket.algorithm, normalized);
    return mac;
};


exports.validateMac = function (request, attributes, ticket) {

    var mac = exports.mac(request, attributes, ticket);
    return mac === attributes.mac;
};


/*
    var options = {
        hostHeader: X-Forwarded-Host,           // Alternative host header modified by proxies
        isHttps: false                          // Used to determine default port if not present in Host header, defaults to false
    };
*/

exports.parse = function (req, options) {

    // Obtain host and port information

    var hostHeader = (options.hostHeader ? req.headers[options.hostHeader.toLowerCase()] : req.headers.host);
    if (!hostHeader) {
        return (new Error('Missing Host header field'));
    }

    var hostHeaderRegex = /^(?:(?:\r\n)?[\t ])*([^:]+)(?::(\d+))*(?:(?:\r\n)?[\t ])*$/; // Does not support IPv6
    var hostParts = hostHeaderRegex.exec(hostHeader);

    if (!hostParts ||
        hostParts.length <= 2 ||
        !hostParts[1]) {

        return (new Error('Invalid Host header field'));
    }

    var host = hostParts[1];
    var port = hostParts[2] || (options.isHttps ? 443 : 80);

    // Parse URI

    var uri = Url.parse(req.url);
    var resource = uri.pathname + (uri.search || '');

    var request = {
        method: req.method.toLowerCase(),
        resource: resource,
        host: host,
        port: port
    };

    return request;
};


// Validate an incoming request
// options: see exports.parse()

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

    if (!attributes.id ||
        !attributes.app ||
        !attributes.ts ||
        !attributes.mac) {

        return callback(new Error('Missing authentication attributes in Authorization header field'));
    }

    // Parse request

    var request = exports.parse(req, options);
    if (request instanceof Error) {
        return callback(request);
    }

    // Parse ticket id

    Ticket.parse(attributes.id, function (err, ticket) {

        if (err) {
            return callback(err);
        }
        
        // Check application
        
        if (ticket.app !== attributes.app) {
            return callback(new Error('Mismatching application id'));
        }

        // Validate MAC

        if (!exports.validateMac(request, attributes, ticket)) {
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

    // Authorization: Oz id="asdlaskjdlaksjdlaksjd", app="123423234", ts="1348191870082", ext="", mac=""

    var headerRegex = /^[Oo][Zz]\s+(.*)$/;
    var headerParts = headerRegex.exec(header);

    if (!headerParts ||
        headerParts.length !== 2 ||
        !headerParts[1]) {

        // Invalid header format
        return (new Error('Wrong authentication scheme'));
    }

    var attributes = {};

    var attributesRegex = /(id|app|ts|ext|mac)="([^"\\]*)"\s*(?:,\s*|$)/g;
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

exports.formatHeader = function (attributes, id, app, mac) {

    // Construct header

    return 'Oz id="' + id + '", app="' + app + '", ts="' + attributes.ts + (attributes.ext ? '", ext="' + attributes.ext : '') + '", mac="' + mac + '"';
};


