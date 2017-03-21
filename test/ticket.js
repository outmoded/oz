'use strict';

// Load modules

const Code = require('code');
const Cryptiles = require('cryptiles');
const Hoek = require('hoek');
const Iron = require('iron');
const Lab = require('lab');
const Oz = require('../lib');


// Declare internals

const internals = {};


// Test shortcuts

const lab = exports.lab = Lab.script();
const describe = lab.experiment;
const it = lab.test;
const expect = Code.expect;


describe('Ticket', () => {

    const password = 'a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough';

    describe('issue()', () => {

        it('should construct a valid ticket', (done) => {

            const app = {
                id: '123',
                scope: ['a', 'b']
            };

            const grant = {
                id: 's81u29n1812',
                user: '456',
                exp: Oz.hawk.utils.now() + 5000,
                scope: ['a']
            };

            const options = {
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

            Oz.ticket.issue(app, grant, password, options, (err, envelope) => {

                expect(err).to.not.exist();
                expect(envelope.ext).to.equal({ x: 'welcome' });
                expect(envelope.exp).to.equal(grant.exp);
                expect(envelope.scope).to.equal(['a']);

                Oz.ticket.parse(envelope.id, password, {}, (err, ticket) => {

                    expect(err).to.not.exist();
                    expect(ticket.ext).to.equal(options.ext);

                    Oz.ticket.reissue(ticket, grant, password, {}, (err, envelope2) => {

                        expect(err).to.not.exist();
                        expect(envelope.ext).to.equal({ x: 'welcome' });
                        expect(envelope2.id).to.not.equal(envelope.id);
                        done();
                    });
                });
            });
        });

        it('errors on missing app', (done) => {

            Oz.ticket.issue(null, null, password, {}, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid application object');
                done();
            });
        });

        it('errors on invalid app', (done) => {

            Oz.ticket.issue({}, null, password, {}, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid application object');
                done();
            });
        });

        it('errors on invalid grant (missing id)', (done) => {

            Oz.ticket.issue({ id: 'abc' }, {}, password, {}, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid grant object');
                done();
            });
        });

        it('errors on invalid grant (missing user)', (done) => {

            Oz.ticket.issue({ id: 'abc' }, { id: '123' }, password, {}, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid grant object');
                done();
            });
        });

        it('errors on invalid grant (missing exp)', (done) => {

            Oz.ticket.issue({ id: 'abc' }, { id: '123', user: 'steve' }, password, {}, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid grant object');
                done();
            });
        });

        it('errors on invalid grant (scope outside app)', (done) => {

            Oz.ticket.issue({ id: 'abc', scope: ['a'] }, { id: '123', user: 'steve', exp: 1442690715989, scope: ['b'] }, password, {}, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Grant scope is not a subset of the application scope');
                done();
            });
        });

        it('errors on invalid app scope', (done) => {

            Oz.ticket.issue({ id: 'abc', scope: 'a' }, null, password, {}, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('scope not instance of Array');
                done();
            });
        });

        it('errors on invalid password', (done) => {

            Oz.ticket.issue({ id: 'abc' }, null, '', {}, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid encryption password');
                done();
            });
        });

        it('errors on invalid options', (done) => {

            Oz.ticket.issue({ id: 'abc' }, null, password, null, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid options object');
                done();
            });
        });
    });

    describe('reissue()', () => {

        it('sets delegate to false', (done) => {

            const app = {
                id: '123'
            };

            Oz.ticket.issue(app, null, password, {}, (err, envelope) => {

                expect(err).to.not.exist();

                Oz.ticket.parse(envelope.id, password, {}, (err, ticket) => {

                    expect(err).to.not.exist();

                    Oz.ticket.reissue(ticket, null, password, { issueTo: '345', delegate: false }, (err, envelope2) => {

                        expect(err).to.not.exist();
                        expect(envelope2.delegate).to.be.false();
                        done();
                    });
                });
            });
        });

        it('errors on issueTo when delegate is not allowed', (done) => {

            const app = {
                id: '123'
            };

            const options = {
                delegate: false
            };

            Oz.ticket.issue(app, null, password, options, (err, envelope) => {

                expect(err).to.not.exist();
                expect(envelope.delegate).to.be.false();

                Oz.ticket.parse(envelope.id, password, {}, (err, ticket) => {

                    expect(err).to.not.exist();

                    Oz.ticket.reissue(ticket, null, password, { issueTo: '345' }, (err, envelope2) => {

                        expect(err).to.exist();
                        expect(err.message).to.equal('Ticket does not allow delegation');
                        done();
                    });
                });
            });
        });

        it('errors on delegate override', (done) => {

            const app = {
                id: '123'
            };

            const options = {
                delegate: false
            };

            Oz.ticket.issue(app, null, password, options, (err, envelope) => {

                expect(err).to.not.exist();
                expect(envelope.delegate).to.be.false();

                Oz.ticket.parse(envelope.id, password, {}, (err, ticket) => {

                    expect(err).to.not.exist();

                    Oz.ticket.reissue(ticket, null, password, { delegate: true }, (err, envelope2) => {

                        expect(err).to.exist();
                        expect(err.message).to.equal('Cannot override ticket delegate restriction');
                        done();
                    });
                });
            });
        });

        it('errors on missing parent ticket', (done) => {

            Oz.ticket.reissue(null, null, password, {}, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid parent ticket object');
                done();
            });
        });

        it('errors on missing password', (done) => {

            Oz.ticket.reissue({}, null, '', {}, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid encryption password');
                done();
            });
        });

        it('errors on missing options', (done) => {

            Oz.ticket.reissue({}, null, password, null, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid options object');
                done();
            });
        });

        it('errors on missing parent scope', (done) => {

            Oz.ticket.reissue({}, null, password, { scope: ['a'] }, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('New scope is not a subset of the parent ticket scope');
                done();
            });
        });

        it('errors on invalid parent scope', (done) => {

            Oz.ticket.reissue({ scope: 'a' }, null, password, { scope: ['a'] }, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('scope not instance of Array');
                done();
            });
        });

        it('errors on invalid options scope', (done) => {

            Oz.ticket.reissue({ scope: ['a'] }, null, password, { scope: 'a' }, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('scope not instance of Array');
                done();
            });
        });

        it('errors on invalid grant (missing id)', (done) => {

            Oz.ticket.reissue({}, {}, password, {}, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid grant object');
                done();
            });
        });

        it('errors on invalid grant (missing user)', (done) => {

            Oz.ticket.reissue({}, { id: 'abc' }, password, {}, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid grant object');
                done();
            });
        });

        it('errors on invalid grant (missing exp)', (done) => {

            Oz.ticket.reissue({}, { id: 'abc', user: 'steve' }, password, {}, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid grant object');
                done();
            });
        });

        it('errors on options.issueTo and ticket.dlg conflict', (done) => {

            Oz.ticket.reissue({ dlg: '123' }, null, password, { issueTo: '345' }, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Cannot re-delegate');
                done();
            });
        });

        it('errors on mismatching grants (missing grant)', (done) => {

            Oz.ticket.reissue({ grant: '123' }, null, password, {}, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Parent ticket grant does not match options.grant');
                done();
            });
        });

        it('errors on mismatching grants (missing parent)', (done) => {

            Oz.ticket.reissue({}, { id: '123', user: 'steve', exp: 1442690715989 }, password, {}, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Parent ticket grant does not match options.grant');
                done();
            });
        });

        it('errors on mismatching grants (different)', (done) => {

            Oz.ticket.reissue({ grant: '234' }, { id: '123', user: 'steve', exp: 1442690715989 }, password, {}, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Parent ticket grant does not match options.grant');
                done();
            });
        });
    });

    describe('rsvp()', () => {

        it('errors on missing app', (done) => {

            Oz.ticket.rsvp(null, { id: '123' }, password, {}, (err, rsvp) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid application object');
                done();
            });
        });

        it('errors on invalid app', (done) => {

            Oz.ticket.rsvp({}, { id: '123' }, password, {}, (err, rsvp) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid application object');
                done();
            });
        });

        it('errors on missing grant', (done) => {

            Oz.ticket.rsvp({ id: '123' }, null, password, {}, (err, rsvp) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid grant object');
                done();
            });
        });

        it('errors on invalid grant', (done) => {

            Oz.ticket.rsvp({ id: '123' }, {}, password, {}, (err, rsvp) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid grant object');
                done();
            });
        });

        it('errors on missing password', (done) => {

            Oz.ticket.rsvp({ id: '123' }, { id: '123' }, '', {}, (err, rsvp) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid encryption password');
                done();
            });
        });

        it('errors on missing options', (done) => {

            Oz.ticket.rsvp({ id: '123' }, { id: '123' }, password, null, (err, rsvp) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid options object');
                done();
            });
        });

        it('constructs a valid rsvp', (done) => {

            const app = {
                id: '123'                   // App id
            };

            const grant = {
                id: 's81u29n1812'           // Grant
            };

            Oz.ticket.rsvp(app, grant, password, {}, (err, envelope) => {

                expect(err).to.not.exist();

                Oz.ticket.parse(envelope, password, {}, (err, object) => {

                    expect(err).to.not.exist();
                    expect(object.app).to.equal(app.id);
                    expect(object.grant).to.equal(grant.id);
                    done();
                });
            });
        });

        it('fails to construct a valid rsvp due to bad Iron options', (done) => {

            const app = {
                id: '123'                   // App id
            };

            const grant = {
                id: 's81u29n1812'           // Grant
            };

            const iron = Hoek.clone(Iron.defaults);
            iron.encryption = null;

            Oz.ticket.rsvp(app, grant, password, { iron }, (err, envelope) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Bad options');
                done();
            });
        });
    });

    describe('delegateRsvp()', () => {

        it('errors on invalid delegating app', (done) => {

            Oz.ticket.delegateRsvp({ id: '123' }, null, null, null, password, {}, (err, rsvp) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid delegating application object');
                done();
            });
        });
    });

    describe('generate()', () => {

        it('errors on random fail', (done) => {

            const orig = Cryptiles.randomString;
            Cryptiles.randomString = function (size) {

                Cryptiles.randomString = orig;
                return new Error('fake');
            };

            Oz.ticket.generate({}, password, {}, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('fake');
                done();
            });
        });

        it('errors on missing password', (done) => {

            Oz.ticket.generate({}, null, {}, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Empty password');
                done();
            });
        });

        it('generates a ticket with only public ext', (done) => {

            const input = {};
            Oz.ticket.generate(input, password, { ext: { public: { x: 1 } } }, (err, ticket) => {

                expect(err).to.not.exist();
                expect(ticket.ext.x).to.equal(1);
                done();
            });
        });

        it('generates a ticket with only private ext', (done) => {

            const input = {};
            Oz.ticket.generate(input, password, { ext: { private: { x: 1 } } }, (err, ticket) => {

                expect(err).to.not.exist();
                expect(ticket.ext).to.not.exist();
                done();
            });
        });

        it('overrides hawk options', (done) => {

            const input = {};
            Oz.ticket.generate(input, password, { keyBytes: 10, hmacAlgorithm: 'something' }, (err, ticket) => {

                expect(err).to.not.exist();
                expect(ticket.key).to.have.length(10);
                expect(ticket.algorithm).to.equal('something');
                done();
            });
        });
    });

    describe('parse()', () => {

        it('errors on wrong password', (done) => {

            const app = {
                id: '123'
            };

            const grant = {
                id: 's81u29n1812',
                user: '456',
                exp: Oz.hawk.utils.now() + 5000,
                scope: ['a', 'b']
            };

            const options = {
                ttl: 10 * 60 * 1000
            };

            Oz.ticket.issue(app, grant, password, options, (err, envelope) => {

                expect(err).to.not.exist();

                Oz.ticket.parse(envelope.id, 'a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough_x', {}, (err, ticket) => {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Bad hmac value');
                    done();
                });
            });
        });

        it('errors on missing password', (done) => {

            Oz.ticket.parse('abc', '', {}, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid encryption password');
                done();
            });
        });

        it('errors on missing options', (done) => {

            Oz.ticket.parse('abc', password, null, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid options object');
                done();
            });
        });
    });
});
