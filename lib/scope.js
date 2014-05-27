// Load modules

var Boom = require('boom');
var Hoek = require('hoek');


// Declare internals

var internals = {};


// Ensure scope is an array of unique strings

exports.validate = function (scope) {

    if (!scope) {
        return Boom.internal('null scope');
    }

    if (scope instanceof Array === false) {
        return Boom.internal('scope not instance of Array');
    }

    var hash = {};
    for (var i = 0, il = scope.length; i < il; ++i) {
        if (!scope[i]) {
            return Boom.badRequest('scope includes null or empty string value');
        }

        if (typeof scope[i] !== 'string') {
            return Boom.badRequest('scope item is not a string');
        }

        if (hash[scope[i]]) {
            return Boom.badRequest('scope includes duplicated item');
        }

        hash[scope[i]] = true;
    }

    return null;
};


// Check is one scope is a subset of another

exports.isSubset = function (scope, subset) {

    if (scope.length < subset.length) {
        return false;
    }

    var common = Hoek.intersect(scope, subset);
    return common.length === subset.length;
};