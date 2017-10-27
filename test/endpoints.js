'use strict';

// Load modules

const Code = require('code');
const Hoek = require('hoek');
const Iron = require('iron');
const Lab = require('lab');
const Oz = require('../lib');


// Declare internals

const internals = {};


// Test shortcuts

const { describe, it, before } = exports.lab = Lab.script();
const expect = Code.expect;


describe('Endpoints', () => {

    const encryptionPassword = 'a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough';

    const apps = {
        social: {
            id: 'social',
            scope: ['a', 'b', 'c'],
            key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
            algorithm: 'sha256'
        },
        network: {
            id: 'network',
            scope: ['b', 'x'],
            key: 'witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi',
            algorithm: 'sha256'
        }
    };

    let appTicket = null;

    before(async () => {

        const req = {
            method: 'POST',
            url: '/oz/app',
            headers: {
                host: 'example.com',
                authorization: Oz.client.header('http://example.com/oz/app', 'POST', apps.social).header
            }
        };

        const options = {
            encryptionPassword,
            loadAppFunc: (id) => apps[id]
        };

        const ticket = await Oz.endpoints.app(req, null, options);
        appTicket = ticket;
    });

    describe('app()', () => {

        it('overrides defaults', async () => {

            const req = {
                method: 'POST',
                url: '/oz/app',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/app', 'POST', apps.social).header
                }
            };

            const options = {
                encryptionPassword,
                loadAppFunc: () => apps.social,
                ticket: {
                    ttl: 10 * 60 * 1000,
                    iron: Iron.defaults
                },
                hawk: {}
            };

            await expect(Oz.endpoints.app(req, null, options)).to.not.reject();
        });

        it('fails on invalid app request (bad credentials)', async () => {

            const req = {
                method: 'POST',
                url: '/oz/app',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/app', 'POST', apps.social).header
                }
            };

            const options = {
                encryptionPassword,
                loadAppFunc: () => apps.network
            };

            await expect(Oz.endpoints.app(req, null, options)).to.reject('Bad mac');
        });
    });

    describe('reissue()', () => {

        it('allows null payload', async () => {

            const req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', appTicket).header
                }
            };

            const options = {
                encryptionPassword,
                loadAppFunc: () => apps.social
            };

            await expect(Oz.endpoints.reissue(req, null, options)).to.not.reject();
        });

        it('overrides defaults', async () => {

            const req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', appTicket).header
                }
            };

            const options = {
                encryptionPassword,
                loadAppFunc: () => apps.social,
                ticket: {
                    ttl: 10 * 60 * 1000,
                    iron: Iron.defaults
                },
                hawk: {}
            };

            await expect(Oz.endpoints.reissue(req, null, options)).to.not.reject();
        });

        it('reissues expired ticket', async () => {

            let req = {
                method: 'POST',
                url: '/oz/app',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/app', 'POST', apps.social).header
                }
            };

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id],
                ticket: {
                    ttl: 5
                }
            };

            const ticket = await Oz.endpoints.app(req, null, options);

            req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', ticket).header
                }
            };

            await Hoek.wait(10);
            await expect(Oz.endpoints.reissue(req, {}, options)).to.not.reject();
        });

        it('fails on app load error', async () => {

            const req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', appTicket).header
                }
            };

            const options = {
                encryptionPassword,
                loadAppFunc: () => {

                    throw new Error('not found');
                }
            };

            await expect(Oz.endpoints.reissue(req, {}, options)).to.reject('not found');
        });

        it('fails on missing app delegation rights', async () => {

            const req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', appTicket).header
                }
            };

            const options = {
                encryptionPassword,
                loadAppFunc: () => apps.social
            };

            await expect(Oz.endpoints.reissue(req, { issueTo: apps.network.id }, options)).to.reject('Application has no delegation rights');
        });

        it('fails on invalid reissue (request params)', async () => {

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id]
            };

            const payload = {
                issueTo: null
            };

            const req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', appTicket).header
                }
            };

            await expect(Oz.endpoints.reissue(req, payload, options)).to.reject('Invalid request payload: issueTo must be a string');
        });

        it('fails on invalid reissue (fails auth)', async () => {

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id]
            };

            const req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', appTicket).header
                }
            };

            options.encryptionPassword = 'a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough_x';
            await expect(Oz.endpoints.reissue(req, {}, options)).to.reject('Bad hmac value');
        });

        it('fails on invalid reissue (invalid app)', async () => {

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id]
            };

            const req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', appTicket).header
                }
            };

            options.loadAppFunc = () => null;
            await expect(Oz.endpoints.reissue(req, {}, options)).to.reject('Invalid application');
        });

        it('fails on invalid reissue (missing grant)', async () => {

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id]
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            const rsvp = await Oz.ticket.rsvp(apps.social, grant, encryptionPassword);

            options.loadGrantFunc = () => ({ grant });

            const payload = { rsvp };

            const req1 = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).header
                }
            };

            const ticket = await Oz.endpoints.rsvp(req1, payload, options);

            const req2 = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', ticket).header
                }
            };

            options.loadGrantFunc = () => ({ grant: null });

            await expect(Oz.endpoints.reissue(req2, {}, options)).to.reject('Invalid grant');
        });

        it('fails on invalid reissue (grant error)', async () => {

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id]
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            const rsvp = await Oz.ticket.rsvp(apps.social, grant, encryptionPassword);

            options.loadGrantFunc = () => ({ grant });

            const payload = { rsvp };

            const req1 = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).header
                }
            };

            const ticket = await Oz.endpoints.rsvp(req1, payload, options);

            const req2 = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', ticket).header
                }
            };

            options.loadGrantFunc = () => {

                throw new Error('what?');
            };

            await expect(Oz.endpoints.reissue(req2, {}, options)).to.reject('what?');
        });

        it('fails on invalid reissue (grant user mismatch)', async () => {

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id]
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            const rsvp = await Oz.ticket.rsvp(apps.social, grant, encryptionPassword);

            options.loadGrantFunc = () => ({ grant });

            const payload = { rsvp };

            const req1 = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).header
                }
            };

            const ticket = await Oz.endpoints.rsvp(req1, payload, options);

            const req2 = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', ticket).header
                }
            };

            options.loadGrantFunc = () => {

                grant.user = 'steve';
                return { grant };
            };

            await expect(Oz.endpoints.reissue(req2, {}, options)).to.reject('Invalid grant');
        });

        it('fails on invalid reissue (grant missing exp)', async () => {

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id]
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            const rsvp = await Oz.ticket.rsvp(apps.social, grant, encryptionPassword);

            options.loadGrantFunc = () => ({ grant });

            const payload = { rsvp };

            const req1 = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).header
                }
            };

            const ticket = await Oz.endpoints.rsvp(req1, payload, options);

            const req2 = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', ticket).header
                }
            };

            options.loadGrantFunc = () => {

                delete grant.exp;
                return { grant };
            };

            await expect(Oz.endpoints.reissue(req2, {}, options)).to.reject('Invalid grant');
        });

        it('fails on invalid reissue (grant app does not match app or dlg)', async () => {

            const applications = {
                social: {
                    id: 'social',
                    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                    algorithm: 'sha256',
                    delegate: true
                },
                network: {
                    id: 'network',
                    key: 'witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi',
                    algorithm: 'sha256'
                }
            };

            // The app requests an app ticket using Oz.hawk authentication

            let req = {
                method: 'POST',
                url: '/oz/app',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/app', 'POST', applications.social).header
                }
            };

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => applications[id]
            };

            const applicationTicket = await Oz.endpoints.app(req, null, options);

            // The user is redirected to the server, logs in, and grant app access, resulting in an rsvp

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: applicationTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            const rsvp = await Oz.ticket.rsvp(applications.social, grant, encryptionPassword);

            // After granting app access, the user returns to the app with the rsvp

            options.loadGrantFunc = () => ({ grant });

            // The app exchanges the rsvp for a ticket

            let payload = { rsvp };

            req = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', applicationTicket).header
                }
            };

            const ticket = await Oz.endpoints.rsvp(req, payload, options);

            // The app reissues the ticket with delegation to another app

            payload = {
                issueTo: applications.network.id
            };

            req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', ticket).header
                }
            };

            const delegatedTicket = await Oz.endpoints.reissue(req, payload, options);

            // The other app reissues their ticket

            req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', delegatedTicket).header
                }
            };

            options.loadGrantFunc = (id) => {

                grant.app = 'xyz';
                return { grant };
            };

            await expect(Oz.endpoints.reissue(req, {}, options)).to.reject('Invalid grant');
        });
    });

    describe('rsvp()', () => {

        it('overrides defaults', async () => {

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id],
                ticket: {
                    iron: Iron.defaults
                }
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            const rsvp = await Oz.ticket.rsvp(apps.social, grant, encryptionPassword);

            options.loadGrantFunc = () => ({ grant });

            const payload = { rsvp };

            const req = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).header
                }
            };

            await expect(Oz.endpoints.rsvp(req, payload, options)).to.not.reject();
        });

        it('errors on invalid authentication', async () => {

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id],
                ticket: {
                    iron: Iron.defaults
                }
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            const rsvp = await Oz.ticket.rsvp(apps.social, grant, encryptionPassword);

            options.loadGrantFunc = () => ({ grant });

            const payload = { rsvp };

            const req = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com'
                }
            };

            await expect(Oz.endpoints.rsvp(req, payload, options)).to.reject();
        });

        it('errors on expired ticket', async () => {

            // App ticket

            let req = {
                method: 'POST',
                url: '/oz/app',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/app', 'POST', apps.social).header
                }
            };

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id],
                ticket: {
                    ttl: 5
                }
            };

            const applicationTicket = await Oz.endpoints.app(req, null, options);

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: applicationTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            const rsvp = await Oz.ticket.rsvp(apps.social, grant, encryptionPassword);

            options.loadGrantFunc = () => ({ grant });

            const payload = { rsvp };

            req = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', applicationTicket).header
                }
            };

            await Hoek.wait(10);
            await expect(Oz.endpoints.rsvp(req, payload, options)).to.reject('Expired ticket');
        });

        it('errors on missing payload', async () => {

            await expect(Oz.endpoints.rsvp({}, null, {})).to.reject('Missing required payload');
        });

        it('fails on invalid rsvp (request params)', async () => {

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id]
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            await Oz.ticket.rsvp(apps.social, grant, encryptionPassword);

            options.loadGrantFunc = () => ({ grant });

            const payload = { rsvp: '' };

            const req = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).header
                }
            };

            await expect(Oz.endpoints.rsvp(req, payload, options)).to.reject('Invalid request payload: rsvp is not allowed to be empty');
        });

        it('fails on invalid rsvp (invalid auth)', async () => {

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id]
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            await Oz.ticket.rsvp(apps.social, grant, encryptionPassword);

            options.loadGrantFunc = () => ({ grant });

            const payload = { rsvp: 'abc' };

            const req = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).header
                }
            };

            await expect(Oz.endpoints.rsvp(req, payload, options)).to.reject('Incorrect number of sealed components');
        });

        it('fails on invalid rsvp (user ticket)', async () => {

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id]
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            const rsvp = await Oz.ticket.rsvp(apps.social, grant, encryptionPassword);

            options.loadGrantFunc = () => ({ grant });

            const body = { rsvp };

            const req1 = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).header
                }
            };

            const ticket1 = await Oz.endpoints.rsvp(req1, body, options);

            const req2 = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', ticket1).header
                }
            };

            await expect(Oz.endpoints.rsvp(req2, body, options)).to.reject('User ticket cannot be used on an application endpoint');
        });

        it('fails on invalid rsvp (mismatching apps)', async () => {

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id]
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            const rsvp = await Oz.ticket.rsvp(apps.network, grant, encryptionPassword);

            options.loadGrantFunc = () => ({ grant });

            const payload = { rsvp };

            const req = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).header
                }
            };

            await expect(Oz.endpoints.rsvp(req, payload, options)).to.reject('Mismatching ticket and rsvp apps');
        });

        it('fails on invalid rsvp (expired rsvp)', async () => {

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id]
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            const rsvp = await Oz.ticket.rsvp(apps.social, grant, encryptionPassword, { ttl: 1 });

            options.loadGrantFunc = () => ({ grant });

            const payload = { rsvp };

            const req = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).header
                }
            };

            await Hoek.wait(10);
            await expect(Oz.endpoints.rsvp(req, payload, options)).to.reject('Expired rsvp');
        });

        it('fails on invalid rsvp (expired grant)', async () => {

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id]
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() - 1000
            };

            const rsvp = await Oz.ticket.rsvp(apps.social, grant, encryptionPassword);

            options.loadGrantFunc = () => ({ grant });

            const payload = { rsvp };

            const req = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).header
                }
            };

            await expect(Oz.endpoints.rsvp(req, payload, options)).to.reject('Invalid grant');
        });

        it('fails on invalid rsvp (missing grant envelope)', async () => {

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id],
                ticket: {
                    iron: Iron.defaults
                }
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            const rsvp = await Oz.ticket.rsvp(apps.social, grant, encryptionPassword);

            options.loadGrantFunc = () => null;

            const payload = { rsvp };

            const req = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).header
                }
            };

            await expect(Oz.endpoints.rsvp(req, payload, options)).to.reject('Invalid grant');
        });

        it('fails on invalid rsvp (missing grant)', async () => {

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id],
                ticket: {
                    iron: Iron.defaults
                }
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            const rsvp = await Oz.ticket.rsvp(apps.social, grant, encryptionPassword);

            options.loadGrantFunc = () => ({ grant: null });

            const payload = { rsvp };

            const req = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).header
                }
            };

            await expect(Oz.endpoints.rsvp(req, payload, options)).to.reject('Invalid grant');
        });

        it('fails on invalid rsvp (grant app mismatch)', async () => {

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id],
                ticket: {
                    iron: Iron.defaults
                }
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            const rsvp = await Oz.ticket.rsvp(apps.social, grant, encryptionPassword);

            options.loadGrantFunc = (id) => {

                grant.app = apps.network.id;
                return { grant };
            };

            const payload = { rsvp };

            const req = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).header
                }
            };

            await expect(Oz.endpoints.rsvp(req, payload, options)).to.reject('Invalid grant');
        });

        it('fails on invalid rsvp (grant missing exp)', async () => {

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id],
                ticket: {
                    iron: Iron.defaults
                }
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            const rsvp = await Oz.ticket.rsvp(apps.social, grant, encryptionPassword);

            options.loadGrantFunc = (id) => {

                delete grant.exp;
                return { grant };
            };

            const payload = { rsvp };

            const req = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).header
                }
            };

            await expect(Oz.endpoints.rsvp(req, payload, options)).to.reject('Invalid grant');
        });

        it('fails on invalid rsvp (grant error)', async () => {

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id],
                ticket: {
                    iron: Iron.defaults
                }
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            const rsvp = await Oz.ticket.rsvp(apps.social, grant, encryptionPassword);

            options.loadGrantFunc = (id) => {

                throw new Error('boom');
            };

            const payload = { rsvp };

            const req = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).header
                }
            };

            await expect(Oz.endpoints.rsvp(req, payload, options)).to.reject('boom');
        });

        it('fails on invalid rsvp (app error)', async () => {

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id],
                ticket: {
                    iron: Iron.defaults
                }
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            const rsvp = await Oz.ticket.rsvp(apps.social, grant, encryptionPassword);

            options.loadGrantFunc = () => ({ grant });

            const payload = { rsvp };

            const req = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).header
                }
            };

            options.loadAppFunc = () => {

                throw new Error('nope');
            };

            await expect(Oz.endpoints.rsvp(req, payload, options)).to.reject('nope');
        });

        it('fails on invalid rsvp (invalid app)', async () => {

            const options = {
                encryptionPassword,
                loadAppFunc: (id) => apps[id]
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            const rsvp = await Oz.ticket.rsvp(apps.social, grant, encryptionPassword);

            options.loadGrantFunc = () => ({ grant });

            const payload = { rsvp };

            const req = {
                method: 'POST',
                url: '/oz/rsvp',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).header
                }
            };

            options.loadAppFunc = () => null;

            await expect(Oz.endpoints.rsvp(req, payload, options)).to.reject('Invalid application');
        });
    });
});
