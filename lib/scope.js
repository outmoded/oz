// Load modules

var Utils = require('./utils');


// Declare internals

var internals = {};


// Ensure scope is an array of unique strings

exports.validate = function (scope) {

    if (!scope) {
        return new Error('null scope');
    }

    if (scope instanceof Array === false) {
        return new Error('scope not instance of Array');
    }

    var hash = {};
    for (var i = 0, il = scope.length; i < il; ++i) {
        if (!scope[i]) {
            return new Error('scope includes null or empty string value');
        }

        if (typeof scope[i] !== 'string') {
            return new Error('scope item is not a string');
        }

        if (hash[scope[i]]) {
            return new Error('scope includes duplicated item');
        }

        hash[scope[i]] = true;
    }

    return true;
};


// Check is one scope is a subset of another

exports.isSubset = function (scope, subset) {

    if (scope.length < subset.length) {
        return false;
    }

    var common = Utils.intersect(scope, subset);
    return common.length === subset.length;
};

