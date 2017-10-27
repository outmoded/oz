'use strict';

// Load modules

const Http = require('http');

const Code = require('code');
const Hoek = require('hoek');
const Iron = require('iron');
const Lab = require('lab');
const Oz = require('..');
const Wreck = require('wreck');


// Declare internals

const internals = {};


// Test shortcuts

const { describe, it } = exports.lab = Lab.script();
const expect = Code.expect;


describe('Client', () => {

    describe('header()', () => {

        it('generates header', () => {

            const app = {
                id: 'social',
                scope: ['a', 'b', 'c'],
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'sha256'
            };

            const { header } = Oz.client.header('http://example.com/oz/app', 'POST', app, {});
            expect(header).to.exist();
        });
    });

    describe('Connection', () => {

        it('obtains an application ticket and requests resource', async () => {

            const mock = new internals.Mock();
            const uri = await mock.start();

            const connection = new Oz.client.Connection({ uri, credentials: internals.app });
            const { result: result1, code: code1, ticket: ticket1 } = await connection.app('/');
            expect(result1).to.equal('GET /');
            expect(code1).to.equal(200);
            expect(ticket1).to.equal(connection._appTicket);

            const { result: result2, code: code2, ticket: ticket2 } = await connection.request('/resource', ticket1);
            expect(result2).to.equal('GET /resource');
            expect(code2).to.equal(200);
            expect(ticket2).to.equal(ticket1);

            const ticket3 = await connection.reissue(ticket2);
            expect(ticket3).to.not.equal(ticket2);

            const { result: result4, code: code4, ticket: ticket4 } = await connection.request('/resource', ticket3);
            expect(result4).to.equal('GET /resource');
            expect(code4).to.equal(200);
            expect(ticket4).to.equal(ticket3);

            await mock.stop();
        });

        it('errors on payload read fail', async () => {

            const mock = new internals.Mock();
            const uri = await mock.start();

            const connection = new Oz.client.Connection({ uri, credentials: internals.app });

            let count = 0;
            const orig = Wreck.read;
            Wreck.read = function (...args) {

                if (++count === 1) {
                    return orig.apply(Wreck, args);
                }

                Wreck.read = orig;
                return Promise.reject(new Error('fail read'));
            };

            await expect(connection._requestAppTicket()).to.reject();
            await mock.stop();
        });

        it('errors on invalid app response', async () => {

            const mock = new internals.Mock({ failApp: true });
            const uri = await mock.start();

            const connection = new Oz.client.Connection({ uri, credentials: internals.app });
            await expect(connection.app('/')).to.not.reject();
            await mock.stop();
        });

        describe('request()', () => {

            it('automatically refreshes ticket', async () => {

                const mock = new internals.Mock({ ttl: 20 });
                const uri = await mock.start();

                const connection = new Oz.client.Connection({ uri, credentials: internals.app });
                const { result: result1, code: code1, ticket: ticket1 } = await connection.app('/');
                expect(result1).to.equal('GET /');
                expect(code1).to.equal(200);
                expect(ticket1).to.equal(connection._appTicket);

                await Hoek.wait(30);

                const { result: result2, code: code2, ticket: ticket2 } = await connection.request('/resource', ticket1, { method: 'POST' });
                expect(result2).to.equal('POST /resource');
                expect(code2).to.equal(200);
                expect(ticket2).to.not.equal(ticket1);

                await mock.stop();
            });

            it('errors on socket fail', async () => {

                const mock = new internals.Mock();
                const uri = await mock.start();

                const connection = new Oz.client.Connection({ uri, credentials: internals.app });
                const { result: result1, code: code1, ticket: ticket1 } = await connection.app('/');
                expect(result1).to.equal('GET /');
                expect(code1).to.equal(200);
                expect(ticket1).to.equal(connection._appTicket);

                const orig = Wreck.request;
                Wreck.request = function () {

                    Wreck.request = orig;
                    return Promise.reject(new Error('bad socket'));
                };

                await expect(connection.request('/resource', ticket1)).to.reject();
                await mock.stop();
            });

            it('errors on reissue fail', async () => {

                const mock = new internals.Mock({ ttl: 10 });
                const uri = await mock.start();

                const connection = new Oz.client.Connection({ uri, credentials: internals.app });
                const { result: result1, code: code1, ticket: ticket1 } = await connection.app('/');
                expect(result1).to.equal('GET /');
                expect(code1).to.equal(200);
                expect(ticket1).to.equal(connection._appTicket);

                await Hoek.wait(11);        // Expire ticket

                let count = 0;
                const orig = Wreck.request;
                Wreck.request = function (...args) {

                    if (++count === 1) {
                        return orig.apply(Wreck, args);
                    }

                    Wreck.request = orig;
                    return Promise.reject(new Error('bad socket'));
                };

                await expect(connection.request('/resource', ticket1, { method: 'POST' })).to.reject();
                await mock.stop();
            });

            it('does not reissue a 401 without payload', async () => {

                const mock = new internals.Mock({ empty401: true });
                const uri = await mock.start();

                const connection = new Oz.client.Connection({ uri, credentials: internals.app });
                const { result, code } = await connection.app('/');
                expect(code).to.equal(401);
                expect(result).to.equal('');

                await mock.stop();
            });
        });

        describe('app()', () => {

            it('reuses application ticket', async () => {

                const mock = new internals.Mock();
                const uri = await mock.start();

                const connection = new Oz.client.Connection({ uri, credentials: internals.app });
                const { result: result1, code: code1, ticket: ticket1 } = await connection.app('/');
                expect(result1).to.equal('GET /');
                expect(code1).to.equal(200);
                expect(ticket1).to.equal(connection._appTicket);

                const { result: result2, code: code2, ticket: ticket2 } = await connection.app('/resource');
                expect(result2).to.equal('GET /resource');
                expect(code2).to.equal(200);
                expect(ticket2).to.equal(ticket1);

                await mock.stop();
            });

            it('handles app ticket request errors', async () => {

                const mock = new internals.Mock();
                const uri = await mock.start();

                const connection = new Oz.client.Connection({ uri, credentials: internals.app });
                connection._requestAppTicket = (callback) => callback(new Error('failed'));
                await expect(connection.app('/')).to.reject();
                await mock.stop();
            });
        });

        describe('reissue()', () => {

            it('errors on non 200 reissue response', async () => {

                const mock = new internals.Mock({ failRefresh: true });
                const uri = await mock.start();

                const connection = new Oz.client.Connection({ uri, credentials: internals.app });
                const { result, code, ticket } = await connection.app('/');
                expect(result).to.equal('GET /');
                expect(code).to.equal(200);
                expect(ticket).to.equal(connection._appTicket);

                await expect(connection.reissue(ticket)).to.reject();
                await mock.stop();
            });
        });

        describe('_request()', () => {

            it('errors on payload read fail', async () => {

                const mock = new internals.Mock();
                const uri = await mock.start();

                const connection = new Oz.client.Connection({ uri, credentials: internals.app });
                const { ticket: ticket1 } = await connection.app('/');

                let count = 0;
                const orig = Wreck.read;
                Wreck.read = function (...args) {

                    if (++count === 1) {
                        return orig.apply(Wreck, args);
                    }

                    Wreck.read = orig;
                    return Promise.reject(new Error('fail read'));
                };

                await expect(connection._request('GET', '/', null, ticket1)).to.reject();
                await mock.stop();
            });
        });

        describe('_requestAppTicket()', () => {

            it('errors on socket fail', async () => {

                const mock = new internals.Mock();
                const uri = await mock.start();

                const connection = new Oz.client.Connection({ uri, credentials: internals.app });

                const orig = Wreck.request;
                Wreck.request = function () {

                    Wreck.request = orig;
                    return Promise.reject(new Error('bad socket'));
                };

                await expect(connection._requestAppTicket()).to.reject();
                await mock.stop();
            });

            it('errors on redirection', async () => {

                const mock = new internals.Mock();
                const uri = await mock.start();

                const connection = new Oz.client.Connection({ uri, credentials: internals.app });

                const orig = Wreck.request;
                Wreck.request = async (...args) => {

                    Wreck.request = orig;
                    const response = await Wreck.request(...args);
                    response.statusCode = 300;
                    return response;
                };

                await expect(connection._requestAppTicket()).to.reject();
                await mock.stop();
            });
        });
    });
});


internals.app = {
    id: 'social',
    scope: ['a', 'b', 'c'],
    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
    algorithm: 'sha256'
};


internals.Mock = class {

    constructor(options = {}) {

        const settings = {
            encryptionPassword: 'passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpassword',
            loadAppFunc: function (id) {

                return internals.app;
            },
            ticket: {
                ttl: options.ttl || 10 * 60 * 1000,
                iron: Iron.defaults
            },
            hawk: {}
        };

        this.listener = Http.createServer(async (req, res) => {

            const reply = (err, payload, code) => {

                code = code || (err ? err.output.statusCode : 200);
                const headers = (err ? err.output.headers : {});
                headers['Content-Type'] = 'application/json';
                const body = JSON.stringify(err ? err.output.payload : payload);

                res.writeHead(code, headers);
                res.end(body);
            };

            const result = await Wreck.read(req);

            if (req.url === '/oz/app') {
                try {
                    const payload = await Oz.endpoints.app(req, result, settings);
                    return reply(null, payload, 200);
                }
                catch (err) {
                    return reply(err, null, options.failApp ? 400 : 200);
                }
            }

            if (req.url === '/oz/reissue') {
                try {
                    const payload = await Oz.endpoints.reissue(req, result, settings);
                    return reply(null, payload, options.failRefresh ? 400 : 200);
                }
                catch (err) {
                    return reply(err, null, 400);
                }
            }

            if (options.empty401) {
                return reply(null, '', 401);
            }

            try {
                await Oz.server.authenticate(req, settings.encryptionPassword, settings);
                return reply(null, req.method + ' ' + req.url);
            }
            catch (err) {
                return reply(err);
            }
        });
    };

    start() {

        return new Promise((resolve) => {

            this.listener.listen(0, 'localhost', () => {

                const address = this.listener.address();
                return resolve('http://localhost:' + address.port);
            });
        });
    }

    stop() {

        return new Promise((resolve) => this.listener.close(resolve));
    }
};
