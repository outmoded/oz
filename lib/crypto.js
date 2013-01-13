// Load modules

var Crypto = require('crypto');


// Declare internals

var internals = {};


// HMAC using a key
// options: see exports.generateKey()

exports.hmacKey = function (key, algorithm, data) {

    var hmac = Crypto.createHmac(algorithm, key).update(data);
    var digest = hmac.digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
    return digest;
};


