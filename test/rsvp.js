// Load modules

var Chai = require('chai');
var Oz = process.env.TEST_COV ? require('../lib-cov') : require('../lib');


// Declare internals

var internals = {};


// Test shortcuts

var expect = Chai.expect;


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

                expect(err).to.not.exist

                Oz.rsvp.parse(envelope, encryptionPassword, function (err, object) {

                    expect(err).to.not.exist;
                    expect(object.app).to.equal(app.id);
                    expect(object.grant).to.equal(grant.id);
                    done();
                });
            });
        });
    });
});


