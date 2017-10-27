'use strict';

// Load modules

const Code = require('code');
const Lab = require('lab');
const Oz = require('../lib');


// Declare internals

const internals = {};


// Test shortcuts

const lab = exports.lab = Lab.script();
const describe = lab.experiment;
const it = lab.test;
const expect = Code.expect;


describe('Scope', () => {

    describe('validate()', () => {

        it('should return null for valid scope', () => {

            const scope = ['a', 'b', 'c'];
            expect(() => Oz.scope.validate(scope)).to.not.throw();
        });

        it('should return error when scope is null', () => {

            expect(() => Oz.scope.validate(null)).to.throw();
        });

        it('should return error when scope is not an array', () => {

            expect(() => Oz.scope.validate({})).to.throw();
        });

        it('should return error when scope contains non-string values', () => {

            const scope = ['a', 'b', 1];
            expect(() => Oz.scope.validate(scope)).to.throw();
        });

        it('should return error when scope contains duplicates', () => {

            const scope = ['a', 'b', 'b'];
            expect(() => Oz.scope.validate(scope)).to.throw();
        });

        it('should return error when scope contains empty strings', () => {

            const scope = ['a', 'b', ''];
            expect(() => Oz.scope.validate(scope)).to.throw();
        });
    });

    describe('isSubset()', () => {

        it('should return true when scope is a subset', () => {

            const scope = ['a', 'b', 'c'];
            const subset = ['a', 'c'];
            const isSubset = Oz.scope.isSubset(scope, subset);
            expect(isSubset).to.equal(true);
        });

        it('should return false when scope is not a subset', () => {

            const scope = ['a'];
            const subset = ['a', 'c'];
            const isSubset = Oz.scope.isSubset(scope, subset);
            expect(isSubset).to.equal(false);
        });

        it('should return false when scope is not a subset but equal length', () => {

            const scope = ['a', 'b'];
            const subset = ['a', 'c'];
            const isSubset = Oz.scope.isSubset(scope, subset);
            expect(isSubset).to.equal(false);
        });

        it('should return false when scope is not a subset due to duplicates', () => {

            const scope = ['a', 'c', 'c', 'd'];
            const subset = ['a', 'c', 'c'];
            const isSubset = Oz.scope.isSubset(scope, subset);
            expect(isSubset).to.equal(false);
        });
    });

    describe('isEqual()', () => {

        it('compares scopes', () => {

            const scope = ['a', 'b', 'c'];
            expect(Oz.scope.isEqual(null, null)).to.equal(true);
            expect(Oz.scope.isEqual(scope, scope)).to.equal(true);
            expect(Oz.scope.isEqual(null, scope)).to.equal(false);
            expect(Oz.scope.isEqual(scope, null)).to.equal(false);
            expect(Oz.scope.isEqual(scope, [])).to.equal(false);
            expect(Oz.scope.isEqual([], scope)).to.equal(false);
            expect(Oz.scope.isEqual(scope, ['a', 'b', 'c'])).to.equal(true);
            expect(Oz.scope.isEqual(scope, ['a', 'c', 'd'])).to.equal(false);
            expect(Oz.scope.isEqual(['a', 'b', 'c'], scope)).to.equal(true);
            expect(Oz.scope.isEqual(['a', 'c', 'd'], scope)).to.equal(false);
        });
    });
});


