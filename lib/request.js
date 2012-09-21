// Load modules

var Crypto = require('./crypto');


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

    var normalized = attributes.ts + '\n' +
                     request.method.toUpperCase() + '\n' +
                     request.resource + '\n' +
                     request.host.toLowerCase() + '\n' +
                     request.port + '\n' +
                     (attributes.ext || '') + '\n';

    var mac = Crypto.hmacPassword(ticket.key, ticket.algorithm, normalized);
    return mac;
};


exports.validate = function (request, attributes, ticket) {

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

    var uri = URL.parse(URI);
    var resource = uri.pathname + (uri.search || '');

    var request = {
        method: req.method.toLowerCase(),
        resource: resource,
        host: host,
        port: port
    };

    return request;
};

