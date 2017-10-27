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

const { describe, it } = exports.lab = Lab.script();
const expect = Code.expect;


describe('Ticket', () => {

    const password = 'a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough';

    describe('issue()', () => {

        it('should construct a valid ticket', async () => {

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

            const envelope = await Oz.ticket.issue(app, grant, password, options);
            expect(envelope.ext).to.equal({ x: 'welcome' });
            expect(envelope.exp).to.equal(grant.exp);
            expect(envelope.scope).to.equal(['a']);

            const ticket = await Oz.ticket.parse(envelope.id, password);
            expect(ticket.ext).to.equal(options.ext);

            const envelope2 = await Oz.ticket.reissue(ticket, grant, password);
            expect(envelope.ext).to.equal({ x: 'welcome' });
            expect(envelope2.id).to.not.equal(envelope.id);
        });

        it('errors on missing app', () => {

            expect(() => Oz.ticket.issue(null, null, password)).to.throw('Invalid application object');
        });

        it('errors on invalid app', () => {

            expect(() => Oz.ticket.issue({}, null, password)).to.throw('Invalid application object');
        });

        it('errors on invalid grant (missing id)', () => {

            expect(() => Oz.ticket.issue({ id: 'abc' }, {}, password)).to.throw('Invalid grant object');
        });

        it('errors on invalid grant (missing user)', () => {

            expect(() => Oz.ticket.issue({ id: 'abc' }, { id: '123' }, password)).to.throw('Invalid grant object');
        });

        it('errors on invalid grant (missing exp)', () => {

            expect(() => Oz.ticket.issue({ id: 'abc' }, { id: '123', user: 'steve' }, password)).to.throw('Invalid grant object');
        });

        it('errors on invalid grant (scope outside app)', () => {

            expect(() => Oz.ticket.issue({ id: 'abc', scope: ['a'] }, { id: '123', user: 'steve', exp: 1442690715989, scope: ['b'] }, password)).to.throw('Grant scope is not a subset of the application scope');
        });

        it('errors on invalid app scope', () => {

            expect(() => Oz.ticket.issue({ id: 'abc', scope: 'a' }, null, password)).to.throw('scope not instance of Array');
        });

        it('errors on invalid password', () => {

            expect(() => Oz.ticket.issue({ id: 'abc' }, null, '')).to.throw('Invalid encryption password');
        });
    });

    describe('reissue()', () => {

        it('sets delegate to false', async () => {

            const app = {
                id: '123'
            };

            const envelope = await Oz.ticket.issue(app, null, password);
            const ticket = await Oz.ticket.parse(envelope.id, password);

            const envelope2 = await Oz.ticket.reissue(ticket, null, password, { issueTo: '345', delegate: false });
            expect(envelope2.delegate).to.be.false();
        });

        it('errors on issueTo when delegate is not allowed', async () => {

            const app = {
                id: '123'
            };

            const options = {
                delegate: false
            };

            const envelope = await Oz.ticket.issue(app, null, password, options);
            expect(envelope.delegate).to.be.false();

            const ticket = await Oz.ticket.parse(envelope.id, password);
            expect(() => Oz.ticket.reissue(ticket, null, password, { issueTo: '345' })).to.throw('Ticket does not allow delegation');
        });

        it('errors on delegate override', async () => {

            const app = {
                id: '123'
            };

            const options = {
                delegate: false
            };

            const envelope = await Oz.ticket.issue(app, null, password, options);
            expect(envelope.delegate).to.be.false();

            const ticket = await Oz.ticket.parse(envelope.id, password);
            expect(() => Oz.ticket.reissue(ticket, null, password, { delegate: true })).to.throw('Cannot override ticket delegate restriction');
        });

        it('errors on missing parent ticket', () => {

            expect(() => Oz.ticket.reissue(null, null, password)).to.throw('Invalid parent ticket object');
        });

        it('errors on missing password', () => {

            expect(() => Oz.ticket.reissue({}, null, '')).to.throw('Invalid encryption password');
        });

        it('errors on missing parent scope', () => {

            expect(() => Oz.ticket.reissue({}, null, password, { scope: ['a'] })).to.throw('New scope is not a subset of the parent ticket scope');
        });

        it('errors on invalid parent scope', () => {

            expect(() => Oz.ticket.reissue({ scope: 'a' }, null, password, { scope: ['a'] })).to.throw('scope not instance of Array');
        });

        it('errors on invalid options scope', () => {

            expect(() => Oz.ticket.reissue({ scope: ['a'] }, null, password, { scope: 'a' })).to.throw('scope not instance of Array');
        });

        it('errors on invalid grant (missing id)', () => {

            expect(() => Oz.ticket.reissue({}, {}, password)).to.throw('Invalid grant object');
        });

        it('errors on invalid grant (missing user)', () => {

            expect(() => Oz.ticket.reissue({}, { id: 'abc' }, password)).to.throw('Invalid grant object');
        });

        it('errors on invalid grant (missing exp)', () => {

            expect(() => Oz.ticket.reissue({}, { id: 'abc', user: 'steve' }, password)).to.throw('Invalid grant object');
        });

        it('errors on options.issueTo and ticket.dlg conflict', () => {

            expect(() => Oz.ticket.reissue({ dlg: '123' }, null, password, { issueTo: '345' })).to.throw('Cannot re-delegate');
        });

        it('errors on mismatching grants (missing grant)', () => {

            expect(() => Oz.ticket.reissue({ grant: '123' }, null, password)).to.throw('Parent ticket grant does not match options.grant');
        });

        it('errors on mismatching grants (missing parent)', () => {

            expect(() => Oz.ticket.reissue({}, { id: '123', user: 'steve', exp: 1442690715989 }, password)).to.throw('Parent ticket grant does not match options.grant');
        });

        it('errors on mismatching grants (different)', () => {

            expect(() => Oz.ticket.reissue({ grant: '234' }, { id: '123', user: 'steve', exp: 1442690715989 }, password)).to.throw('Parent ticket grant does not match options.grant');
        });
    });

    describe('rsvp()', () => {

        it('errors on missing app', () => {

            expect(() => Oz.ticket.rsvp(null, { id: '123' }, password)).to.throw('Invalid application object');
        });

        it('errors on invalid app', () => {

            expect(() => Oz.ticket.rsvp({}, { id: '123' }, password)).to.throw('Invalid application object');
        });

        it('errors on missing grant', () => {

            expect(() => Oz.ticket.rsvp({ id: '123' }, null, password)).to.throw('Invalid grant object');
        });

        it('errors on invalid grant', () => {

            expect(() => Oz.ticket.rsvp({ id: '123' }, {}, password)).to.throw('Invalid grant object');
        });

        it('errors on missing password', () => {

            expect(() => Oz.ticket.rsvp({ id: '123' }, { id: '123' }, '')).to.throw('Invalid encryption password');
        });

        it('constructs a valid rsvp', async () => {

            const app = {
                id: '123'                   // App id
            };

            const grant = {
                id: 's81u29n1812'           // Grant
            };

            const envelope = await Oz.ticket.rsvp(app, grant, password);
            const object = await Oz.ticket.parse(envelope, password);
            expect(object.app).to.equal(app.id);
            expect(object.grant).to.equal(grant.id);
        });

        it('fails to construct a valid rsvp due to bad Iron options', async () => {

            const app = {
                id: '123'                   // App id
            };

            const grant = {
                id: 's81u29n1812'           // Grant
            };

            const iron = Hoek.clone(Iron.defaults);
            iron.encryption = null;

            await expect(Oz.ticket.rsvp(app, grant, password, { iron })).to.reject('Bad options');
        });
    });

    describe('generate()', () => {

        it('errors on random fail', async () => {

            const orig = Cryptiles.randomString;
            Cryptiles.randomString = function (size) {

                Cryptiles.randomString = orig;
                throw new Error('fake');
            };

            await expect(Oz.ticket.generate({}, password)).to.reject('fake');
        });

        it('errors on missing password', async () => {

            await expect(Oz.ticket.generate({}, null)).to.reject('Empty password');
        });

        it('generates a ticket with only public ext', async () => {

            const input = {};
            const ticket = await Oz.ticket.generate(input, password, { ext: { public: { x: 1 } } });
            expect(ticket.ext.x).to.equal(1);
        });

        it('generates a ticket with only private ext', async () => {

            const input = {};
            const ticket = await Oz.ticket.generate(input, password, { ext: { private: { x: 1 } } });
            expect(ticket.ext).to.not.exist();
        });

        it('overrides hawk options', async () => {

            const input = {};
            const ticket = await Oz.ticket.generate(input, password, { keyBytes: 10, hmacAlgorithm: 'something' });
            expect(ticket.key).to.have.length(10);
            expect(ticket.algorithm).to.equal('something');
        });
    });

    describe('parse()', () => {

        it('errors on wrong password', async () => {

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

            const envelope = await Oz.ticket.issue(app, grant, password, options);
            await expect(Oz.ticket.parse(envelope.id, 'a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough_x')).to.reject('Bad hmac value');
        });

        it('errors on missing password', async () => {

            await expect(Oz.ticket.parse('abc', '')).to.reject('Invalid encryption password');
        });
    });
});


