// Load modules

var Code = require('code');
var Cryptiles = require('cryptiles');
var Hoek = require('hoek');
var Iron = require('iron');
var Lab = require('lab');
var Oz = require('../lib');


// Declare internals

var internals = {};


// Test shortcuts

var lab = exports.lab = Lab.script();
var describe = lab.experiment;
var it = lab.test;
var expect = Code.expect;


describe('Ticket', function () {

    describe('issue()', function () {

        it('should construct a valid ticket', function (done) {

            var encryptionPassword = 'welcome!';

            var app = {
                id: '123',
                scope: ['a', 'b']
            };

            var grant = {
                id: 's81u29n1812',
                user: '456',
                exp: Oz.hawk.utils.now() + 5000,
                scope: ['a']
            };

            var options = {
                ttl: 10 * 60 * 1000,
                ext: {
                    public: {
                        x: 'welcome'
                    },
                    private: {
                        x: 123
                    }
                }
            };

            Oz.ticket.issue(app, grant, encryptionPassword, options, function (err, envelope) {

                expect(err).to.not.exist();
                expect(envelope.ext).to.deep.equal({ x: 'welcome' });
                expect(envelope.exp).to.equal(grant.exp);
                expect(envelope.scope).to.deep.equal(['a']);

                Oz.ticket.parse(envelope.id, encryptionPassword, {}, function (err, ticket) {

                    expect(err).to.not.exist();
                    expect(ticket.ext).to.deep.equal(options.ext);

                    Oz.ticket.reissue(ticket, grant, encryptionPassword, {}, function (err, envelope2) {

                        expect(err).to.not.exist();
                        expect(envelope.ext).to.deep.equal({ x: 'welcome' });
                        expect(envelope2.id).to.not.equal(envelope.id);
                        done();
                    });
                });
            });
        });

        it('errors on missing app', function (done) {

            Oz.ticket.issue(null, null, 'password', {}, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid application object');
                done();
            });
        });

        it('errors on invalid app', function (done) {

            Oz.ticket.issue({}, null, 'password', {}, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid application object');
                done();
            });
        });

        it('errors on invalid grant (missing id)', function (done) {

            Oz.ticket.issue({ id: 'abc' }, {}, 'password', {}, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid grant object');
                done();
            });
        });

        it('errors on invalid grant (missing user)', function (done) {

            Oz.ticket.issue({ id: 'abc' }, { id: '123' }, 'password', {}, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid grant object');
                done();
            });
        });

        it('errors on invalid grant (missing exp)', function (done) {

            Oz.ticket.issue({ id: 'abc' }, { id: '123', user: 'steve' }, 'password', {}, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid grant object');
                done();
            });
        });

        it('errors on invalid grant (scope outside app)', function (done) {

            Oz.ticket.issue({ id: 'abc', scope: ['a'] }, { id: '123', user: 'steve', exp: 1442690715989, scope: ['b'] }, 'password', {}, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Grant scope is not a subset of the application scope');
                done();
            });
        });

        it('errors on invalid app scope', function (done) {

            Oz.ticket.issue({ id: 'abc', scope: 'a' }, null, 'password', {}, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('scope not instance of Array');
                done();
            });
        });

        it('errors on invalid password', function (done) {

            Oz.ticket.issue({ id: 'abc' }, null, '', {}, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid encryption password');
                done();
            });
        });

        it('errors on invalid options', function (done) {

            Oz.ticket.issue({ id: 'abc' }, null, 'password', null, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid options object');
                done();
            });
        });
    });

    describe('reissue()', function () {

        it('sets delegate to false', function (done) {

            var encryptionPassword = 'welcome!';

            var app = {
                id: '123'
            };

            Oz.ticket.issue(app, null, encryptionPassword, {}, function (err, envelope) {

                expect(err).to.not.exist();

                Oz.ticket.parse(envelope.id, encryptionPassword, {}, function (err, ticket) {

                    expect(err).to.not.exist();

                    Oz.ticket.reissue(ticket, null, encryptionPassword, { issueTo: '345', delegate: false }, function (err, envelope2) {

                        expect(err).to.not.exist();
                        expect(envelope2.delegate).to.be.false();
                        done();
                    });
                });
            });
        });

        it('errors on issueTo when delegate is not allowed', function (done) {

            var encryptionPassword = 'welcome!';

            var app = {
                id: '123'
            };

            var options = {
                delegate: false
            };

            Oz.ticket.issue(app, null, encryptionPassword, options, function (err, envelope) {

                expect(err).to.not.exist();
                expect(envelope.delegate).to.be.false();

                Oz.ticket.parse(envelope.id, encryptionPassword, {}, function (err, ticket) {

                    expect(err).to.not.exist();

                    Oz.ticket.reissue(ticket, null, encryptionPassword, { issueTo: '345' }, function (err, envelope2) {

                        expect(err).to.exist();
                        expect(err.message).to.equal('Ticket does not allow delegation');
                        done();
                    });
                });
            });
        });

        it('errors on delegate override', function (done) {

            var encryptionPassword = 'welcome!';

            var app = {
                id: '123'
            };

            var options = {
                delegate: false
            };

            Oz.ticket.issue(app, null, encryptionPassword, options, function (err, envelope) {

                expect(err).to.not.exist();
                expect(envelope.delegate).to.be.false();

                Oz.ticket.parse(envelope.id, encryptionPassword, {}, function (err, ticket) {

                    expect(err).to.not.exist();

                    Oz.ticket.reissue(ticket, null, encryptionPassword, { delegate: true }, function (err, envelope2) {

                        expect(err).to.exist();
                        expect(err.message).to.equal('Cannot override ticket delegate restriction');
                        done();
                    });
                });
            });
        });

        it('errors on missing parent ticket', function (done) {

            Oz.ticket.reissue(null, null, 'password', {}, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid parent ticket object');
                done();
            });
        });

        it('errors on missing password', function (done) {

            Oz.ticket.reissue({}, null, '', {}, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid encryption password');
                done();
            });
        });

        it('errors on missing options', function (done) {

            Oz.ticket.reissue({}, null, 'password', null, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid options object');
                done();
            });
        });

        it('errors on missing parent scope', function (done) {

            Oz.ticket.reissue({}, null, 'password', { scope: ['a'] }, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('New scope is not a subset of the parent ticket scope');
                done();
            });
        });

        it('errors on invalid parent scope', function (done) {

            Oz.ticket.reissue({ scope: 'a' }, null, 'password', { scope: ['a'] }, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('scope not instance of Array');
                done();
            });
        });

        it('errors on invalid options scope', function (done) {

            Oz.ticket.reissue({ scope: ['a'] }, null, 'password', { scope: 'a' }, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('scope not instance of Array');
                done();
            });
        });

        it('errors on invalid grant (missing id)', function (done) {

            Oz.ticket.reissue({}, {}, 'password', {}, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid grant object');
                done();
            });
        });

        it('errors on invalid grant (missing user)', function (done) {

            Oz.ticket.reissue({}, { id: 'abc' }, 'password', {}, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid grant object');
                done();
            });
        });

        it('errors on invalid grant (missing exp)', function (done) {

            Oz.ticket.reissue({}, { id: 'abc', user: 'steve' }, 'password', {}, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid grant object');
                done();
            });
        });

        it('errors on options.issueTo and ticket.dlg conflict', function (done) {

            Oz.ticket.reissue({ dlg: '123' }, null, 'password', { issueTo: '345' }, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Cannot re-delegate');
                done();
            });
        });

        it('errors on mismatching grants (missing grant)', function (done) {

            Oz.ticket.reissue({ grant: '123' }, null, 'password', {}, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Parent ticket grant does not match options.grant');
                done();
            });
        });

        it('errors on mismatching grants (missing parent)', function (done) {

            Oz.ticket.reissue({}, { id: '123', user: 'steve', exp: 1442690715989 }, 'password', {}, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Parent ticket grant does not match options.grant');
                done();
            });
        });

        it('errors on mismatching grants (different)', function (done) {

            Oz.ticket.reissue({ grant: '234' }, { id: '123', user: 'steve', exp: 1442690715989 }, 'password', {}, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Parent ticket grant does not match options.grant');
                done();
            });
        });
    });

    describe('rsvp()', function () {

        it('errors on missing app', function (done) {

            Oz.ticket.rsvp(null, { id: '123' }, 'password', {}, function (err, rsvp) {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid application object');
                done();
            });
        });

        it('errors on invalid app', function (done) {

            Oz.ticket.rsvp({}, { id: '123' }, 'password', {}, function (err, rsvp) {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid application object');
                done();
            });
        });

        it('errors on missing grant', function (done) {

            Oz.ticket.rsvp({ id: '123' }, null, 'password', {}, function (err, rsvp) {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid grant object');
                done();
            });
        });

        it('errors on invalid grant', function (done) {

            Oz.ticket.rsvp({ id: '123' }, {}, 'password', {}, function (err, rsvp) {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid grant object');
                done();
            });
        });

        it('errors on missing password', function (done) {

            Oz.ticket.rsvp({ id: '123' }, { id: '123' }, '', {}, function (err, rsvp) {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid encryption password');
                done();
            });
        });

        it('errors on missing options', function (done) {

            Oz.ticket.rsvp({ id: '123' }, { id: '123' }, 'password', null, function (err, rsvp) {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid options object');
                done();
            });
        });

        it('constructs a valid rsvp', function (done) {

            var encryptionPassword = 'welcome!';

            var app = {
                id: '123'                   // App id
            };

            var grant = {
                id: 's81u29n1812'           // Grant
            };

            Oz.ticket.rsvp(app, grant, encryptionPassword, {}, function (err, envelope) {

                expect(err).to.not.exist();

                Oz.ticket.parse(envelope, encryptionPassword, {}, function (err, object) {

                    expect(err).to.not.exist();
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

            var iron = Hoek.clone(Iron.defaults);
            iron.encryption = null;

            Oz.ticket.rsvp(app, grant, encryptionPassword, { iron: iron }, function (err, envelope) {

                expect(err).to.exist();
                expect(err.message).to.equal('Bad options');
                done();
            });
        });
    });

    describe('generate()', function () {

        it('errors on random fail', function (done) {

            var orig = Cryptiles.randomString;
            Cryptiles.randomString = function (size) {

                Cryptiles.randomString = orig;
                return new Error('fake');
            };

            Oz.ticket.generate({}, 'password', {}, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('fake');
                done();
            });
        });

        it('errors on missing password', function (done) {

            Oz.ticket.generate({}, null, {}, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Empty password');
                done();
            });
        });

        it('generates a ticket with only public ext', function (done) {

            var input = {};
            Oz.ticket.generate(input, 'password', { ext: { public: { x: 1 } } }, function (err, ticket) {

                expect(ticket.ext.x).to.equal(1);
                done();
            });
        });

        it('generates a ticket with only private ext', function (done) {

            var input = {};
            Oz.ticket.generate(input, 'password', { ext: { private: { x: 1 } } }, function (err, ticket) {

                expect(ticket.ext).to.not.exist();
                done();
            });
        });

        it('overrides hawk options', function (done) {

            var input = {};
            Oz.ticket.generate(input, 'password', { keyBytes: 10, hmacAlgorithm: 'something' }, function (err, ticket) {

                expect(ticket.key).to.have.length(10);
                expect(ticket.algorithm).to.equal('something');
                done();
            });
        });
    });

    describe('parse()', function () {

        it('errors on wrong password', function (done) {

            var encryptionPassword = 'welcome!';

            var app = {
                id: '123'
            };

            var grant = {
                id: 's81u29n1812',
                user: '456',
                exp: Oz.hawk.utils.now() + 5000,
                scope: ['a', 'b']
            };

            var options = {
                ttl: 10 * 60 * 1000
            };

            Oz.ticket.issue(app, grant, 'password', options, function (err, envelope) {

                expect(err).to.not.exist();

                Oz.ticket.parse(envelope.id, 'x', {}, function (err, ticket) {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Bad hmac value');
                    done();
                });
            });
        });

        it('errors on missing password', function (done) {

            Oz.ticket.parse('abc', '', {}, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid encryption password');
                done();
            });
        });

        it('errors on missing options', function (done) {

            Oz.ticket.parse('abc', 'password', null, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid options object');
                done();
            });
        });
    });
});


