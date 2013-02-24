// Load modules

var Hoek = require('hoek');
var Iron = require('iron');


// Declare internals

var internals = {};


exports.ticket = {
    ttl: 60 * 60 * 1000,                                // 1 hour
    secretBytes: 32,                                    // Ticket secret size in bytes
    hmacAlgorithm: 'sha256',
    timestampWindow: 5 * 60 * 1000                      // +/- 5m window for timestamp clock shift
};

Hoek.merge(exports.ticket, Iron.defaults);


exports.rsvp = {
    ttl: 1 * 60 * 1000                                  // 1 minute
};


exports.set = function (arg1, arg2) {     // (group, settings) OR (tree)

    Hoek.assert(arguments.length === 1 || arguments.length === 2, 'Incorrect number of arguments');
    Hoek.assert(arguments.length === 1 || (typeof arguments[0] === 'string' && typeof arguments[1] === 'object'), 'Bad arguments type when used as set(group, settings)');
    Hoek.assert(arguments.length === 2 || typeof arguments[0] === 'object', 'Bad arguments type when used as set(tree)');

    var groups = (arguments.length === 1 ? Object.keys(arguments[0]) : [arguments[0]]);
    var settings = arguments[0];
    if (arguments.length === 2) {
        settings = {};
        settings[arguments[0]] = arguments[1];
    }

    for (var i in groups) {
        var group = groups[i];

        Hoek.assert(['ticket'].indexOf(group) !== -1, 'Unknown settings group: ' + group);
        Hoek.merge(exports[group], settings[group]);
    }
};