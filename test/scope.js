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

        it('should return null for valid scope', (done) => {

            const scope = ['a', 'b', 'c'];
            const err = Oz.scope.validate(scope);
            expect(err).to.equal(null);
            done();
        });

        it('should return error when scope is null', (done) => {

            const err = Oz.scope.validate(null);
            expect(err).to.exist();
            done();
        });

        it('should return error when scope is not an array', (done) => {

            const err = Oz.scope.validate({});
            expect(err).to.exist();
            done();
        });

        it('should return error when scope contains non-string values', (done) => {

            const scope = ['a', 'b', 1];
            const err = Oz.scope.validate(scope);
            expect(err).to.exist();
            done();
        });

        it('should return error when scope contains duplicates', (done) => {

            const scope = ['a', 'b', 'b'];
            const err = Oz.scope.validate(scope);
            expect(err).to.exist();
            done();
        });

        it('should return error when scope contains empty strings', (done) => {

            const scope = ['a', 'b', ''];
            const err = Oz.scope.validate(scope);
            expect(err).to.exist();
            done();
        });
    });

    describe('isSubset()', () => {

        it('should return true when scope is a subset', (done) => {

            const scope = ['a', 'b', 'c'];
            const subset = ['a', 'c'];
            const isSubset = Oz.scope.isSubset(scope, subset);
            expect(isSubset).to.equal(true);
            done();
        });

        it('should return false when scope is not a subset', (done) => {

            const scope = ['a'];
            const subset = ['a', 'c'];
            const isSubset = Oz.scope.isSubset(scope, subset);
            expect(isSubset).to.equal(false);
            done();
        });

        it('should return false when scope is not a subset but equal length', (done) => {

            const scope = ['a', 'b'];
            const subset = ['a', 'c'];
            const isSubset = Oz.scope.isSubset(scope, subset);
            expect(isSubset).to.equal(false);
            done();
        });

        it('should return false when scope is not a subset due to duplicates', (done) => {

            const scope = ['a', 'c', 'c', 'd'];
            const subset = ['a', 'c', 'c'];
            const isSubset = Oz.scope.isSubset(scope, subset);
            expect(isSubset).to.equal(false);
            done();
        });
    });

    describe('isEqual()', () => {

        it('compares scopes', (done) => {

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

            done();
        });
    });
});


