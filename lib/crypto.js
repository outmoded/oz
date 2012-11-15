// Load modules

var Crypto = require('crypto');
var Utils = require('./utils');
var Err = require('./error');


// Declare internals

var internals = {};


// Algorithm configuration

internals.algorithms = {

    'aes-128-ctr': { keyBits: 128, ivBits: 128 },
    'aes-256-cbc': { keyBits: 256, ivBits: 128 },
    'sha256': { keyBits: 256 }
};


// Generate a  cryptographically strong pseudo-random data

exports.randomBits = function (bits, callback) {

    var bytes = Math.ceil(bits / 8);
    Crypto.randomBytes(bytes, function (err, buffer) {

        if (err) {
            return callback(err);
        }

        return callback(null, buffer);
    });
};


// Generate a unique encryption key

/*
    var options =  {
        saltBits: 256,                                  // Ignored if salt is set
        salt: '4d8nr9q384nr9q384nr93q8nruq9348run',
        algorithm: 'aes-128-ctr',
        iterations: 1,
        iv: 'sdfsdfsdfsdfscdrgercgesrcgsercg'           // Optional
    };
*/

exports.generateKey = function (password, options, callback) {

    if (!password) {
        return callback(Err.internal('Empty password'));
    }

    if (!options ||
        typeof options !== 'object') {

        return callback(Err.internal('Bad options'));
    }

    var algorithm = internals.algorithms[options.algorithm];
    if (!algorithm) {
        return callback(Err.internal('Unknown algorithm: ' + options.algorithm));
    }

    var generate = function () {

        if (options.salt) {
            generateKey(options.salt);
        }
        else if (options.saltBits) {
            generateSalt();
        }
        else {
            return callback(Err.internal('Missing salt or saltBits options'));
        }
    };

    var generateSalt = function () {

        exports.randomBits(options.saltBits, function (err, randomSalt) {

            if (err) {
                return callback(err);
            }

            var salt = randomSalt.toString('hex');
            generateKey(salt);
        });
    };

    var generateKey = function (salt) {

        Crypto.pbkdf2(password, salt, options.iterations, algorithm.keyBits / 8, function (err, derivedKey) {

            if (err) {
                return callback(err);
            }

            var result = {
                key: derivedKey,
                salt: salt
            };

            if (algorithm.ivBits &&
                !options.iv) {

                exports.randomBits(algorithm.ivBits, function (err, randomIv) {

                    if (err) {
                        return callback(err);
                    }

                    result.iv = randomIv.toString('binary');
                    return callback(null, result);
                });
            }
            else {
                if (options.iv) {
                    result.iv = options.iv;
                }
                return callback(null, result);
            }
        });
    };

    generate();
};


// Encrypt data
// options: see exports.generateKey()

exports.encrypt = function (password, options, data, callback) {

    exports.generateKey(password, options, function (err, key) {

        if (err) {
            return callback(err);
        }

        var cipher = Crypto.createCipheriv(options.algorithm, key.key, key.iv);
        var enc = cipher.update(data, 'utf8', 'binary');
        enc += cipher.final('binary');

        callback(null, enc, key);
    });
};


// Decrypt data
// options: see exports.generateKey()

exports.decrypt = function (password, options, data, callback) {

    exports.generateKey(password, options, function (err, key) {

        if (err) {
            return callback(err);
        }

        var decipher = Crypto.createDecipheriv(options.algorithm, key.key, key.iv);
        var dec = decipher.update(data, 'binary', 'utf8');
        dec += decipher.final('utf8');

        callback(null, dec);
    });
};


// HMAC using a password
// options: see exports.generateKey()

exports.hmacPassword = function (password, options, data, callback) {

    exports.generateKey(password, options, function (err, key) {

        if (err) {
            return callback(err);
        }

        var hmac = Crypto.createHmac(options.algorithm, key.key).update(data);
        var digest = hmac.digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');

        var result = {
            digest: digest,
            salt: key.salt
        };

        return callback(null, result);
    });
};


// HMAC using a key
// options: see exports.generateKey()

exports.hmacKey = function (key, algorithm, data) {

    var hmac = Crypto.createHmac(algorithm, key).update(data);
    var digest = hmac.digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
    return digest;
};


// Encrypt and HMAC an object

exports.seal = function (object, encryptionPassword, options, callback) {

    var objectString = JSON.stringify(object);

    exports.encrypt(encryptionPassword, options.encryptionKey, objectString, function (err, encrypted, key) {

        if (err) {
            return callback(err);
        }

        // Base64url the encrypted value

        var encryptedB64 = Utils.base64urlEncode(encrypted);
        var iv = Utils.base64urlEncode(key.iv);
        var macBaseString = key.salt + ':' + iv + ':' + encryptedB64;

        // Mac the combined values

        var hmac = exports.hmacPassword(encryptionPassword, options.integrityKey, macBaseString, function (err, mac) {

            if (err) {
                return callback(err);
            }

            // Put it all together

            var sealed = mac.salt + ':' + mac.digest + ':' + macBaseString;        // hmac-salt:hmac:encryption-salt:encryption-iv:encrypted
            return callback(null, sealed);
        });
    });
};


// Decrypt and validate sealed string

exports.unseal = function (sealed, encryptionPassword, options, callback) {

    // Break string into components

    var parts = sealed.split(':');
    if (parts.length !== 5) {
        return callback(Err.internal('Incorrect number of sealed components'));
    }

    var hmacSalt = parts[0];
    var hmac = parts[1];
    var encryptionSalt = parts[2];
    var encryptionIv = parts[3];
    var encryptedB64 = parts[4];
    var macBaseString = encryptionSalt + ':' + encryptionIv + ':' + encryptedB64;

    // Check hmac

    var macOptions = Utils.clone(options.integrityKey);
    macOptions.salt = hmacSalt;

    exports.hmacPassword(encryptionPassword, macOptions, macBaseString, function (err, mac) {

        if (err) {
            return callback(err);
        }

        if (hmac !== mac.digest) {
            return callback(Err.internal('Bad hmac value'));
        }

        // Decrypt

        var encrypted = Utils.base64urlDecode(encryptedB64);

        if (encrypted instanceof Error) {
            return callback(encrypted);
        }

        var decryptOptions = Utils.clone(options.encryptionKey);
        decryptOptions.salt = encryptionSalt;
        decryptOptions.iv = Utils.base64urlDecode(encryptionIv);

        exports.decrypt(encryptionPassword, decryptOptions, encrypted, function (err, decrypted) {

            // Parse JSON

            var object = null;
            try {
                object = JSON.parse(decrypted);
            }
            catch (err) {
                return callback(Err.internal('Failed parsing sealed object JSON: ' + err.message));
            }

            return callback(null, object);
        });
    });
};