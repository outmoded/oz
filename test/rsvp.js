var assert = require('assert');
var should = require('should');
var sinon = require('sinon');
var Oz = require('../lib/oz');


describe('RSVP', function () {

    describe('#issue', function () {

        it('should construct a valid rsvp', function (done) {

            var encryptionPassword = 'welcome!';

            var app = {
                id: '123'                   // App id
            };

            var user = {
                id: '456',                  // User id
                grant: 's81u29n1812'        // Grant
            };

            Oz.rsvp.issue(app, user, encryptionPassword, function (err, envelope) {

                should.not.exist(err);

                Oz.rsvp.parse(envelope, encryptionPassword, function (err, object) {

                    should.not.exist(err);
                    object.app.should.equal(app.id);
                    object.user.should.equal(user.id);
                    object.grant.should.equal(user.grant);
                    done();
                });
            });
        });
    });
});


