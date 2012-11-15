// Load modules

var Crypto = require('crypto');
var Hoek = require('hoek');


// Declare internals

var internals = {};


// Import Hoek Utilities

internals.import = function () {

    for (var i in Hoek) {
        if (Hoek.hasOwnProperty(i)) {
            exports[i] = Hoek[i];
        }
    }
};

internals.import();


// oz version

exports.version = function () {

    return exports.loadPackage(__dirname + '/..').version;
};
