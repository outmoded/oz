'use strict';

// Load modules

const Code = require('code');
const Lab = require('lab');
const Oz = require('../lib');


// Declare internals

const internals = {};


// Test shortcuts

const { describe, it } = exports.lab = Lab.script();
const expect = Code.expect;


describe('Server', () => {

    describe('authenticate()', () => {

        it('throws an error on missing password', async () => {

            await expect(Oz.server.authenticate(null, null)).to.reject('Invalid encryption password');
        });

        const encryptionPassword = 'a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough';

        const app = {
            id: '123'
        };

        it('authenticates a request', async () => {

            const grant = {
                id: 's81u29n1812',
                user: '456',
                exp: Oz.hawk.utils.now() + 5000,
                scope: ['a', 'b']
            };

            const envelope = await Oz.ticket.issue(app, grant, encryptionPassword);

            const req = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', envelope).header
                }
            };

            await expect(Oz.server.authenticate(req, encryptionPassword)).to.not.reject();
        });

        it('authenticates a request (hawk options)', async () => {

            const grant = {
                id: 's81u29n1812',
                user: '456',
                exp: Oz.hawk.utils.now() + 5000,
                scope: ['a', 'b']
            };

            const envelope = await Oz.ticket.issue(app, grant, encryptionPassword);

            const req = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    hostx1: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', envelope).header
                }
            };

            await expect(Oz.server.authenticate(req, encryptionPassword, { hawk: { hostHeaderName: 'hostx1' } })).to.not.reject();
        });

        it('fails to authenticate a request with bad password', async () => {

            const grant = {
                id: 's81u29n1812',
                user: '456',
                exp: Oz.hawk.utils.now() + 5000,
                scope: ['a', 'b']
            };

            const envelope = await Oz.ticket.issue(app, grant, encryptionPassword);

            const req = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', envelope).header
                }
            };

            await expect(Oz.server.authenticate(req, 'a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough_x')).to.reject('Bad hmac value');
        });

        it('fails to authenticate a request with expired ticket', async () => {

            const grant = {
                id: 's81u29n1812',
                user: '456',
                exp: Oz.hawk.utils.now() - 5000,
                scope: ['a', 'b']
            };

            const envelope = await Oz.ticket.issue(app, grant, encryptionPassword);

            const req = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', envelope).header
                }
            };

            const err = await expect(Oz.server.authenticate(req, encryptionPassword)).to.reject('Expired ticket');
            expect(err.output.payload.expired).to.be.true();
        });

        it('fails to authenticate a request with mismatching app id', async () => {

            const grant = {
                id: 's81u29n1812',
                user: '456',
                exp: Oz.hawk.utils.now() + 5000,
                scope: ['a', 'b']
            };

            const envelope = await Oz.ticket.issue(app, grant, encryptionPassword);

            envelope.app = '567';
            const req = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', envelope).header
                }
            };

            await expect(Oz.server.authenticate(req, encryptionPassword)).to.reject('Mismatching application id');
        });

        it('fails to authenticate a request with mismatching dlg id', async () => {

            const grant = {
                id: 's81u29n1812',
                user: '456',
                exp: Oz.hawk.utils.now() + 5000,
                scope: ['a', 'b']
            };

            const envelope = await Oz.ticket.issue(app, grant, encryptionPassword);

            envelope.dlg = '567';
            const req = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', envelope).header
                }
            };

            await expect(Oz.server.authenticate(req, encryptionPassword)).to.reject('Mismatching delegated application id');
        });
    });
});
