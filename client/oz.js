/*
    HTTP Oz Authentication Scheme
    Copyright (c) 2012, Eran Hammer <eran@hueniverse.com>
    MIT Licensed
*/


// Declare namespaces

var Oz = {
    internals: {}
};

Oz.request = Oz.Request = {};


/*
    var request = {
        method: 'GET',

        uri: 'http://example.com/path?query',

        // OR

        resource: '/path?query',
        host: 'example.com',
        port: 80
    };

    var attributes = {
        ts: 1348170630020               // Date.now()
        ext: 'app data'                 // Server-specific extension data (string)
    };
*/

Oz.request.mac = function (request, ticket, attributes) {

    if (request.uri) {
        var uri = Oz.internals.parseUri(request.uri);
        request.host = uri.host;
        request.port = uri.port;
        request.resource = uri.resource;
    }

    var normalized = ticket.id + '\n' +
                     ticket.app + '\n' +
                     (attributes.dlg || '') + '\n' +
                     attributes.ts + '\n' +
                     request.method.toUpperCase() + '\n' +
                     request.resource + '\n' +
                     request.host.toLowerCase() + '\n' +
                     request.port + '\n' +
                     (attributes.ext || '');

    var mac = Oz.macMessage(normalized, ticket).replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
    return mac;
};


Oz.request.formatHeader = function (attributes, id, app, mac) {

    return 'Oz id="' + id + '", app="' + Oz.internals.escapeHeaderAttribute(app) + '", ts="' + attributes.ts + (attributes.ext ? '", ext="' + Oz.internals.escapeHeaderAttribute(attributes.ext) : '') + (attributes.dlg ? '", dlg="' + Oz.internals.escapeHeaderAttribute(attributes.dlg) : '') + '", mac="' + mac + '"';
};


Oz.request.generateHeader = function (request, ticket, attributes) {

    attributes = attributes || { ts: Date.now() };
    if (ticket.delegatedBy && !attributes.dlg) {
        attributes.dlg = ticket.delegatedBy;
    }

    var mac = Oz.request.mac(request, ticket, attributes);
    var header = Oz.request.formatHeader(attributes, ticket.id, ticket.app, mac);
    return header;
};


// Use Oz credentials to MAC a message

Oz.macMessage = function (message, ticket) {

    // Check request

    if (!ticket.key ||
        !ticket.algorithm) {

        // Invalid ticket object
        return '';
    }

    // Set hash algorithm

    var hashFunc;
    switch (ticket.algorithm) {
        case 'sha256': hashFunc = Crypto.SHA256; break;
        default: return '';                                         // Error: Unknown algorithm
    }

    // Sign normalized request string

    return Crypto.util.bytesToBase64(Crypto.HMAC(hashFunc, Oz.internals.utf8Encode(message), ticket.key, { asBytes: true }));
};


// Escape header attribute value

Oz.internals.escapeHeaderAttribute = function (attribute) {

    return attribute.replace(/\\/g, '\\\\').replace(/\"/g, '\\"');
};


// Based on: parseURI 1.2.2
// http://blog.stevenlevithan.com/archives/parseuri
// (c) Steven Levithan <stevenlevithan.com>
// MIT License

Oz.internals.parseUri = function (input) {

    var keys = ['source', 'scheme', 'authority', 'userInfo', 'user', 'password', 'host', 'port', 'resource', 'relative', 'pathname', 'directory', 'file', 'query', 'fragment'];

    var uriRegex = /^(?:([^:\/?#]+):)?(?:\/\/((?:(([^:@]*)(?::([^:@]*))?)?@)?([^:\/?#]*)(?::(\d*))?))?(((((?:[^?#\/]*\/)*)([^?#]*))(?:\?([^#]*))?)(?:#(.*))?)/;
    var uriByNumber = uriRegex.exec(input);
    var uri = {};

    var i = 15;
    while (i--) {

        uri[keys[i]] = uriByNumber[i] || '';
    }

    if (uri.port === null ||
        uri.port === '') {

        uri.port = (uri.scheme.toLowerCase() === 'http' ? '80' : (uri.scheme.toLowerCase() === 'https' ? '443' : ''));
    }

    return uri;
};


// Based on: Crypto-JS v2.0.0
// Copyright (c) 2009, Jeff Mott. All rights reserved.
// http://code.google.com/p/crypto-js/
// http://code.google.com/p/crypto-js/wiki/License

(function () { var c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'; var d = window.Crypto = {}; var a = d.util = { rotl: function (h, g) { return (h << g) | (h >>> (32 - g)) }, rotr: function (h, g) { return (h << (32 - g)) | (h >>> g) }, endian: function (h) { if (h.constructor === Number) { return a.rotl(h, 8) & 16711935 | a.rotl(h, 24) & 4278255360 } for (var g = 0; g < h.length; g++) { h[g] = a.endian(h[g]) } return h }, randomBytes: function (h) { for (var g = []; h > 0; h--) { g.push(Math.floor(Math.random() * 256)) } return g }, bytesToWords: function (h) { for (var k = [], j = 0, g = 0; j < h.length; j++, g += 8) { k[g >>> 5] |= h[j] << (24 - g % 32) } return k }, wordsToBytes: function (i) { for (var h = [], g = 0; g < i.length * 32; g += 8) { h.push((i[g >>> 5] >>> (24 - g % 32)) & 255) } return h }, bytesToHex: function (g) { for (var j = [], h = 0; h < g.length; h++) { j.push((g[h] >>> 4).toString(16)); j.push((g[h] & 15).toString(16)) } return j.join('') }, hexToBytes: function (h) { for (var g = [], i = 0; i < h.length; i += 2) { g.push(parseInt(h.substr(i, 2), 16)) } return g }, bytesToBase64: function (h) { if (typeof btoa === 'function') { return btoa(e.bytesToString(h)) } for (var g = [], l = 0; l < h.length; l += 3) { var m = (h[l] << 16) | (h[l + 1] << 8) | h[l + 2]; for (var k = 0; k < 4; k++) { if (l * 8 + k * 6 <= h.length * 8) { g.push(c.charAt((m >>> 6 * (3 - k)) & 63)) } else { g.push('=') } } } return g.join('') }, base64ToBytes: function (h) { if (typeof atob === 'function') { return e.stringToBytes(atob(h)) } h = h.replace(/[^A-Z0-9+\/]/ig, ''); for (var g = [], j = 0, k = 0; j < h.length; k = ++j % 4) { if (k === 0) { continue } g.push(((c.indexOf(h.charAt(j - 1)) & (Math.pow(2, -2 * k + 8) - 1)) << (k * 2)) | (c.indexOf(h.charAt(j)) >>> (6 - k * 2))) } return g } }; d.mode = {}; var b = d.charenc = {}; var f = b.UTF8 = { stringToBytes: function (g) { return e.stringToBytes(unescape(encodeURIComponent(g))) }, bytesToString: function (g) { return decodeURIComponent(escape(e.bytesToString(g))) } }; var e = b.Binary = { stringToBytes: function (j) { for (var g = [], h = 0; h < j.length; h++) { g.push(j.charCodeAt(h)) } return g }, bytesToString: function (g) { for (var j = [], h = 0; h < g.length; h++) { j.push(String.fromCharCode(g[h])) } return j.join('') } } })(); (function () { var g = Crypto, b = g.util, c = g.charenc, f = c.UTF8, e = c.Binary; var a = [1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298]; var d = g.SHA256 = function (j, h) { var i = b.wordsToBytes(d._sha256(j)); return h && h.asBytes ? i : h && h.asString ? e.bytesToString(i) : b.bytesToHex(i) }; d._sha256 = function (q) { if (q.constructor === String) { q = f.stringToBytes(q) } var y = b.bytesToWords(q), z = q.length * 8, r = [1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225], s = [], K, J, I, G, F, E, D, C, B, A, p, o; y[z >> 5] |= 128 << (24 - z % 32); y[((z + 64 >> 9) << 4) + 15] = z; for (var B = 0; B < y.length; B += 16) { K = r[0]; J = r[1]; I = r[2]; G = r[3]; F = r[4]; E = r[5]; D = r[6]; C = r[7]; for (var A = 0; A < 64; A++) { if (A < 16) { s[A] = y[A + B] } else { var n = s[A - 15], u = s[A - 2], M = ((n << 25) | (n >>> 7)) ^ ((n << 14) | (n >>> 18)) ^ (n >>> 3), L = ((u << 15) | (u >>> 17)) ^ ((u << 13) | (u >>> 19)) ^ (u >>> 10); s[A] = M + (s[A - 7] >>> 0) + L + (s[A - 16] >>> 0) } var t = F & E ^ ~F & D, k = K & J ^ K & I ^ J & I, x = ((K << 30) | (K >>> 2)) ^ ((K << 19) | (K >>> 13)) ^ ((K << 10) | (K >>> 22)), v = ((F << 26) | (F >>> 6)) ^ ((F << 21) | (F >>> 11)) ^ ((F << 7) | (F >>> 25)); p = (C >>> 0) + v + t + (a[A]) + (s[A] >>> 0); o = x + k; C = D; D = E; E = F; F = G + p; G = I; I = J; J = K; K = p + o } r[0] += K; r[1] += J; r[2] += I; r[3] += G; r[4] += F; r[5] += E; r[6] += D; r[7] += C } return r }; d._blocksize = 16 })();
(function () { var e = Crypto, a = e.util, b = e.charenc, d = b.UTF8, c = b.Binary; e.HMAC = function (l, m, k, h) { if (m.constructor === String) { m = d.stringToBytes(m) } if (k.constructor === String) { k = d.stringToBytes(k) } if (k.length > l._blocksize * 4) { k = l(k, { asBytes: true }) } var g = k.slice(0), n = k.slice(0); for (var j = 0; j < l._blocksize * 4; j++) { g[j] ^= 92; n[j] ^= 54 } var f = l(g.concat(l(n.concat(m), { asBytes: true })), { asBytes: true }); return h && h.asBytes ? f : h && h.asString ? c.bytesToString(f) : a.bytesToHex(f) } })();


// Adapted from http://www.webtoolkit.info/javascript-url-decode-encode.html

Oz.internals.utf8Encode = function (string) {

    string = string.replace(/\r\n/g, '\n');
    var utfString = '';

    for (var i = 0, il = string.length; i < il; ++i) {

        var chr = string.charCodeAt(i);
        if (chr < 128) {

            utfString += String.fromCharCode(chr);
        }
        else if ((chr > 127) && (chr < 2048)) {

            utfString += String.fromCharCode((chr >> 6) | 192);
            utfString += String.fromCharCode((chr & 63) | 128);
        }
        else {

            utfString += String.fromCharCode((chr >> 12) | 224);
            utfString += String.fromCharCode(((chr >> 6) & 63) | 128);
            utfString += String.fromCharCode((chr & 63) | 128);
        }
    }

    return utfString;
};
