// Load modules


// Declare internals

var internals = {};


exports.ticket = {
    ttl: 60 * 60 * 1000,                                // 1 hour
    secretBits: 256,                                    // Ticket secret size in bits

    encryptionKey: {
        saltBits: 256,
        //        algorithm: 'aes-128-ctr',             // Requires node 0.9.x
        algorithm: 'aes-256-cbc',
        iterations: 1
    },

    integrityKey: {
        saltBits: 256,
        algorithm: 'sha256',
        iterations: 1
    },

    encryptionPassword: 'example',
    hmacAlgorithm: 'sha256',
    timestampWindow: 5 * 60 * 1000                      // +/- 5m window for timestamp clock shit
};
