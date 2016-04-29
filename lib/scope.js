'use strict';

// Load modules

const Boom = require('boom');
const Hoek = require('hoek');


// Declare internals

const internals = {};


// Ensure scope is an array of unique strings

exports.validate = function (scope) {

    if (!scope) {
        return Boom.internal('null scope');
    }

    if (scope instanceof Array === false) {
        return Boom.internal('scope not instance of Array');
    }

    const hash = {};
    for (let i = 0; i < scope.length; ++i) {
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

    if (!scope) {
        return false;
    }

    if (scope.length < subset.length) {
        return false;
    }

    const common = Hoek.intersect(scope, subset);
    return common.length === subset.length;
};


// Check is two scope arrays are the same

exports.isEqual = function (one, two) {

    if (one === two) {
        return true;
    }

    if (!one ||
        !two) {

        return false;
    }

    if (one.length !== two.length) {
        return false;
    }

    const common = Hoek.intersect(one, two);
    return common.length === one.length;
};
