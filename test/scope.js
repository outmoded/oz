// Load modules

var Chai = require('chai');
var Oz = process.env.TEST_COV ? require('../lib-cov') : require('../lib');


// Declare internals

var internals = {};


// Test shortcuts

var expect = Chai.expect;


describe('Scope', function () {

    describe('#validate', function () {

        it('should return true for valid scope', function (done) {

            var scope = ['a', 'b', 'c'];
            var err = Oz.scope.validate(scope);
            expect(err).to.equal(true);
            done();
        });

        it('should return error when scope is null', function (done) {

            var err = Oz.scope.validate(null);
            expect(err).to.exist;
            done();
        });

        it('should return error when scope is not an array', function (done) {

            var err = Oz.scope.validate({});
            expect(err).to.exist;
            done();
        });

        it('should return error when scope contains non-string values', function (done) {

            var scope = ['a', 'b', 1];
            var err = Oz.scope.validate(scope);
            expect(err).to.exist;
            done();
        });

        it('should return error when scope contains duplicates', function (done) {

            var scope = ['a', 'b', 'b'];
            var err = Oz.scope.validate(scope);
            expect(err).to.exist;
            done();
        });

        it('should return error when scope contains empty strings', function (done) {

            var scope = ['a', 'b', ''];
            var err = Oz.scope.validate(scope);
            expect(err).to.exist;
            done();
        });
    });

    describe('#isSubset', function () {

        it('should return true when scope is a subset', function (done) {

            var scope = ['a', 'b', 'c'];
            var subset = ['a', 'c'];
            var isSubset = Oz.scope.isSubset(scope, subset);
            expect(isSubset).to.equal(true);
            done();
        });

        it('should return false when scope is not a subset', function (done) {

            var scope = ['a'];
            var subset = ['a', 'c'];
            var isSubset = Oz.scope.isSubset(scope, subset);
            expect(isSubset).to.equal(false);
            done();
        });

        it('should return false when scope is not a subset but equal length', function (done) {

            var scope = ['a', 'b'];
            var subset = ['a', 'c'];
            var isSubset = Oz.scope.isSubset(scope, subset);
            expect(isSubset).to.equal(false);
            done();
        });

        it('should return false when scope is not a subset due to duplicates', function (done) {

            var scope = ['a', 'c', 'c', 'd'];
            var subset = ['a', 'c', 'c'];
            var isSubset = Oz.scope.isSubset(scope, subset);
            expect(isSubset).to.equal(false);
            done();
        });
    });
});


