// Load modules

var Utils = require('./utils');
var Crypto = require('./crypto');
var Settings = require('./settings');


// Declare internals

var internals = {};


/*
    var app = {
        id: '123',                  // Client id
        ttl: 5 * 60 * 1000,         // 5 min
        scope: ['a', 'b']           // Client scope
    };

    var user = {
        id: '456'                   // User id
    };

    var options = {
        ttl: 60 * 1000,             // 1 min
        clockOffset: 0,             // MSecs = localtime - remotetime
        ext: { tos: '0.0.1' },      // Server-specific extension data
        scope: ['b']                // Ticket-specific scope
    };
*/

exports.issue = function (app, user, options, callback) {

    Utils.assert(app && app.id, 'Invalid application object');

    options = options || {};

    // Generate ticket secret

    Crypto.randomBits(Settings.ticket.secretBits, function (err, random) {

        if (err) {
            return callback(err);
        }

        // Construct ticket

        var ttl = options.ttl || app.ttl || Settings.ticket.ttl;

        var ticket = {
            key: random.toString('hex'),
            algorithm: Settings.ticket.hmacAlgorithm,
            app: app.id,
            scope: options.scope || app.scope || [],
            exp: Date.now() + ttl,
            offset: options.clockOffset || 0
        };

        if (user) {
            ticket.user = user.id;
        }

        if (options.ext) {
            ticket.ext = options.ext
        }

        // Stringify and encrypt

        var ticketString = JSON.stringify(ticket);

        Crypto.encrypt(Settings.ticket.encryptionPassword, Settings.ticket.encryptionKey, ticketString, function (err, encrypted, key) {

            if (err) {
                return callback(err);
            }

            // Base64url the encrypted value

            var encryptedB64 = Utils.base64urlEncode(encrypted);
            var iv = Utils.base64urlEncode(key.iv);
            var macBaseString = key.salt + ':' + iv + ':' + encryptedB64;

            // Mac the combined values

            var hmac = Crypto.hmacPassword(Settings.ticket.encryptionPassword, Settings.ticket.integrityKey, macBaseString, function (err, mac) {

                if (err) {
                    return callback(err);
                }

                // Put it all together

                var id = mac.salt + ':' + mac.digest + ':' + macBaseString;        // hmac-salt:hmac:encryption-salt:encryption-iv:encrypted
                ticket.id = id;
                return callback(null, ticket);
            });
        });
    });
};


// Parse ticket id

exports.parse = function (id, callback) {

    // Break string into components

    var parts = id.split(':');
    if (parts.length !== 5) {
        return callback(new Error('Incorrect number of ticket id components'));
    }

    var hmacSalt = parts[0];
    var hmac = parts[1];
    var encryptionSalt = parts[2];
    var encryptionIv = parts[3];
    var encryptedB64 = parts[4];
    var macBaseString = encryptionSalt + ':' + encryptionIv + ':' + encryptedB64;

    // Check hmac

    var macOptions = Utils.clone(Settings.ticket.integrityKey);
    macOptions.salt = hmacSalt;

    Crypto.hmacPassword(Settings.ticket.encryptionPassword, macOptions, macBaseString, function (err, mac) {

        if (err) {
            return callback(err);
        }

        if (hmac !== mac.digest) {
            return callback(new Error('Bad hmac value'));
        }

        // Decrypt ticket id

        var encrypted = Utils.base64urlDecode(encryptedB64);

        if (encrypted instanceof Error) {
            return callback(encrypted);
        }

        var decryptOptions = Utils.clone(Settings.ticket.encryptionKey);
        decryptOptions.salt = encryptionSalt;
        decryptOptions.iv = Utils.base64urlDecode(encryptionIv);

        Crypto.decrypt(Settings.ticket.encryptionPassword, decryptOptions, encrypted, function (err, decrypted) {

            // Parse JSON into ticket

            var ticket = null;
            try {
                ticket = JSON.parse(decrypted);
            }
            catch (err) {
                return callback(new Error('Failed parsing ticket JSON: ' + err.message));
            }

            ticket.id = id;
            return callback(null, ticket);
        });
    });
};


