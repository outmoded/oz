var expect = require('chai').expect;
var assert = require('assert');
var should = require('should');
var sinon = require('sinon');
var Oz = process.env.TEST_COV ? require('../lib-cov/oz') : require('../lib/oz');


describe('RSVP', function () {

    describe('#issue', function () {

        it('should construct a valid rsvp', function (done) {

            var encryptionPassword = 'welcome!';

            var app = {
                id: '123'                   // App id
            };

            var grant = {
                id: 's81u29n1812'           // Grant
            };

            Oz.rsvp.issue(app, grant, encryptionPassword, function (err, envelope) {

                should.not.exist(err);

                Oz.rsvp.parse(envelope, encryptionPassword, function (err, object) {

                    should.not.exist(err);
                    object.app.should.equal(app.id);
                    object.grant.should.equal(grant.id);
                    done();
                });
            });
        });
    });
});


