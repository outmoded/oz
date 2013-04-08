// Load modules

var Iron = require('iron');
var Lab = require('lab');
var Oz = require('../lib');


// Declare internals

var internals = {};


// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;


describe('RSVP', function () {

    describe('#issue', function () {

        it('constructs a valid rsvp', function (done) {

            var encryptionPassword = 'welcome!';

            var app = {
                id: '123'                   // App id
            };

            var grant = {
                id: 's81u29n1812'           // Grant
            };

            Oz.rsvp.issue(app, grant, encryptionPassword, function (err, envelope) {

                expect(err).to.not.exist;

                Oz.rsvp.parse(envelope, encryptionPassword, function (err, object) {

                    expect(err).to.not.exist;
                    expect(object.app).to.equal(app.id);
                    expect(object.grant).to.equal(grant.id);
                    done();
                });
            });
        });

        it('fails to construct a valid rsvp due to bad Iron options', function (done) {

            var encryptionPassword = 'welcome!';

            var app = {
                id: '123'                   // App id
            };

            var grant = {
                id: 's81u29n1812'           // Grant
            };

            Oz.settings.set('ticket', { encryption: null });

            Oz.rsvp.issue(app, grant, encryptionPassword, function (err, envelope) {

                Oz.settings.set('ticket', { encryption: Iron.defaults.encryption });

                expect(err).to.exist;
                expect(err.message).to.equal('Bad options');
                done();
            });
        });
    });
});


