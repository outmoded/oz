'use strict';

// Load modules

const Http = require('http');
const Code = require('code');
const Iron = require('iron');
const Lab = require('lab');
const Oz = require('..');
const Wreck = require('wreck');


// Declare internals

const internals = {};


// Test shortcuts

const lab = exports.lab = Lab.script();
const describe = lab.experiment;
const it = lab.test;
const expect = Code.expect;


describe('Client', () => {

    describe('header()', () => {

        it('', (done) => {

            const app = {
                id: 'social',
                scope: ['a', 'b', 'c'],
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'sha256'
            };

            const header = Oz.client.header('http://example.com/oz/app', 'POST', app, {}).field;
            expect(header).to.exist();
            done();
        });
    });

    describe('Connection', () => {

        it('obtains an application ticket and requests resource', (done) => {

            const mock = new internals.Mock();
            mock.start((uri) => {

                const connection = new Oz.client.Connection({ uri, credentials: internals.app });
                connection.app('/', {}, (err, result1, code1, ticket1) => {

                    expect(err).to.not.exist();
                    expect(result1).to.equal('GET /');
                    expect(code1).to.equal(200);
                    expect(ticket1).to.equal(connection._appTicket);

                    connection.request('/resource', ticket1, {}, (err, result2, code2, ticket2) => {

                        expect(err).to.not.exist();
                        expect(result2).to.equal('GET /resource');
                        expect(code2).to.equal(200);
                        expect(ticket2).to.equal(ticket1);

                        connection.reissue(ticket2, (err, ticket3) => {

                            expect(err).to.not.exist();
                            expect(ticket3).to.not.equal(ticket2);

                            connection.request('/resource', ticket3, {}, (err, result4, code4, ticket4) => {

                                expect(err).to.not.exist();
                                expect(result4).to.equal('GET /resource');
                                expect(code4).to.equal(200);
                                expect(ticket4).to.equal(ticket3);

                                mock.stop(done);
                            });
                        });
                    });
                });
            });
        });

        describe('request()', () => {

            it('automatically refreshes ticket', (done) => {

                const mock = new internals.Mock({ ttl: 20 });
                mock.start((uri) => {

                    const connection = new Oz.client.Connection({ uri, credentials: internals.app });
                    connection.app('/', {}, (err, result1, code1, ticket1) => {

                        expect(err).to.not.exist();
                        expect(result1).to.equal('GET /');
                        expect(code1).to.equal(200);
                        expect(ticket1).to.equal(connection._appTicket);

                        setTimeout(() => {

                            connection.request('/resource', ticket1, { method: 'POST' }, (err, result2, code2, ticket2) => {

                                expect(err).to.not.exist();
                                expect(result2).to.equal('POST /resource');
                                expect(code2).to.equal(200);
                                expect(ticket2).to.not.equal(ticket1);

                                mock.stop(done);
                            });
                        }, 30);
                    });
                });
            });

            it('errors on socket fail', { parallel: false }, (done) => {

                const mock = new internals.Mock();
                mock.start((uri) => {

                    const connection = new Oz.client.Connection({ uri, credentials: internals.app });
                    connection.app('/', {}, (err, result1, code1, ticket1) => {

                        expect(err).to.not.exist();
                        expect(result1).to.equal('GET /');
                        expect(code1).to.equal(200);
                        expect(ticket1).to.equal(connection._appTicket);

                        const orig = Wreck.request;
                        Wreck.request = function (method, path, options, callback) {

                            Wreck.request = orig;
                            return callback(new Error('bad socket'));
                        };

                        connection.request('/resource', ticket1, {}, (err, result2, code2, ticket2) => {

                            expect(err).to.exist();
                            mock.stop(done);
                        });
                    });
                });
            });

            it('errors on reissue fail', { parallel: false }, (done) => {

                const mock = new internals.Mock({ ttl: 10 });
                mock.start((uri) => {

                    const connection = new Oz.client.Connection({ uri, credentials: internals.app });
                    connection.app('/', {}, (err, result1, code1, ticket1) => {

                        expect(err).to.not.exist();
                        expect(result1).to.equal('GET /');
                        expect(code1).to.equal(200);
                        expect(ticket1).to.equal(connection._appTicket);

                        setTimeout(() => {

                            let count = 0;
                            const orig = Wreck.request;
                            Wreck.request = function (method, path, options, callback) {

                                if (++count === 1) {
                                    return orig.apply(Wreck, arguments);
                                }

                                Wreck.request = orig;
                                return callback(new Error('bad socket'));
                            };

                            connection.request('/resource', ticket1, { method: 'POST' }, (err, result2, code2, ticket2) => {

                                expect(err).to.not.exist();
                                mock.stop(done);
                            });
                        }, 11);
                    });
                });
            });

            it('does not reissue a 401 without payload', (done) => {

                const mock = new internals.Mock({ empty401: true });
                mock.start((uri) => {

                    const connection = new Oz.client.Connection({ uri, credentials: internals.app });
                    connection.app('/', {}, (err, result, code, ticket) => {

                        expect(err).to.not.exist();
                        expect(result).to.equal('');
                        expect(code).to.equal(401);

                        mock.stop(done);
                    });
                });
            });
        });

        describe('app()', () => {

            it('reuses application ticket', (done) => {

                const mock = new internals.Mock();
                mock.start((uri) => {

                    const connection = new Oz.client.Connection({ uri, credentials: internals.app });
                    connection.app('/', {}, (err, result1, code1, ticket1) => {

                        expect(err).to.not.exist();
                        expect(result1).to.equal('GET /');
                        expect(code1).to.equal(200);
                        expect(ticket1).to.equal(connection._appTicket);

                        connection.app('/resource', {}, (err, result2, code2, ticket2) => {

                            expect(err).to.not.exist();
                            expect(result2).to.equal('GET /resource');
                            expect(code2).to.equal(200);
                            expect(ticket2).to.equal(ticket1);

                            mock.stop(done);
                        });
                    });
                });
            });

            it('handles app ticket request errors', { parallel: false }, (done) => {

                const mock = new internals.Mock();
                mock.start((uri) => {

                    const connection = new Oz.client.Connection({ uri, credentials: internals.app });
                    connection._requestAppTicket = (callback) => callback(new Error('failed'));
                    connection.app('/', {}, (err, result1, code1, ticket1) => {

                        expect(err).to.exist();
                        mock.stop(done);
                    });
                });
            });
        });

        describe('reissue()', () => {

            it('errors on non 200 reissue response', (done) => {

                const mock = new internals.Mock({ failRefresh: true });
                mock.start((uri) => {

                    const connection = new Oz.client.Connection({ uri, credentials: internals.app });
                    connection.app('/', {}, (err, result1, code1, ticket1) => {

                        expect(err).to.not.exist();
                        expect(result1).to.equal('GET /');
                        expect(code1).to.equal(200);
                        expect(ticket1).to.equal(connection._appTicket);

                        connection.reissue(ticket1, (err, ticket2) => {

                            expect(err).to.exist();
                            mock.stop(done);
                        });
                    });
                });
            });
        });

        describe('_request()', () => {

            it('errors on payload read fail', { parallel: false }, (done) => {

                const mock = new internals.Mock();
                mock.start((uri) => {

                    const connection = new Oz.client.Connection({ uri, credentials: internals.app });
                    connection.app('/', {}, (err, result1, code1, ticket1) => {

                        expect(err).to.not.exist();

                        let count = 0;
                        const orig = Wreck.read;
                        Wreck.read = function (req, options, callback) {

                            if (++count === 1) {
                                return orig.apply(Wreck, arguments);
                            }

                            Wreck.read = orig;
                            return callback(new Error('fail read'));
                        };

                        connection._request('GET', '/', null, ticket1, (err, result2, code2) => {

                            expect(err).to.exist();
                            mock.stop(done);
                        });
                    });
                });
            });
        });

        describe('_requestAppTicket()', () => {

            it('errors on socket fail', { parallel: false }, (done) => {

                const mock = new internals.Mock();
                mock.start((uri) => {

                    const connection = new Oz.client.Connection({ uri, credentials: internals.app });

                    const orig = Wreck.request;
                    Wreck.request = function (method, path, options, callback) {

                        Wreck.request = orig;
                        return callback(new Error('bad socket'));
                    };

                    connection._requestAppTicket((err, ticket) => {

                        expect(err).to.exist();
                        mock.stop(done);
                    });
                });
            });
        });

        it('errors on payload read fail', { parallel: false }, (done) => {

            const mock = new internals.Mock();
            mock.start((uri) => {

                const connection = new Oz.client.Connection({ uri, credentials: internals.app });

                let count = 0;
                const orig = Wreck.read;
                Wreck.read = function (req, options, callback) {

                    if (++count === 1) {
                        return orig.apply(Wreck, arguments);
                    }

                    Wreck.read = orig;
                    return callback(new Error('fail read'));
                };

                connection._requestAppTicket((err, ticket) => {

                    expect(err).to.exist();
                    mock.stop(done);
                });
            });
        });

        it('errors on invalid app response', (done) => {

            const mock = new internals.Mock({ failApp: true });
            mock.start((uri) => {

                const connection = new Oz.client.Connection({ uri, credentials: internals.app });
                connection.app('/', {}, (err, result1, code1, ticket1) => {

                    expect(err).to.exist();
                    mock.stop(done);
                });
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

    constructor(options) {

        options = options || {};

        const settings = {
            encryptionPassword: 'passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpassword',
            loadAppFunc: function (id, callback) {

                callback(null, internals.app);
            },
            ticket: {
                ttl: options.ttl || 10 * 60 * 1000,
                iron: Iron.defaults
            },
            hawk: {}
        };

        this.listener = Http.createServer((req, res) => {

            const reply = (err, payload, code) => {

                code = code || (err ? err.output.statusCode : 200);
                const headers = (err ? err.output.headers : {});
                headers['Content-Type'] = 'application/json';
                const body = JSON.stringify(err ? err.output.payload : payload);

                res.writeHead(code, headers);
                res.end(body);
            };

            Wreck.read(req, {}, (err, result) => {

                expect(err).to.not.exist();

                if (req.url === '/oz/app') {
                    return Oz.endpoints.app(req, result, settings, (err, payload) => {

                        return reply(err, payload, options.failApp ? 400 : 200);
                    });
                }

                if (req.url === '/oz/reissue') {
                    return Oz.endpoints.reissue(req, result, settings, (err, payload) => {

                        return reply(err, payload, options.failRefresh ? 400 : 200);
                    });
                }

                Oz.server.authenticate(req, settings.encryptionPassword, settings, (err, credentials, artifacts) => {

                    if (options.empty401) {
                        return reply(null, '', 401);
                    }

                    return reply(err, req.method + ' ' + req.url);
                });
            });
        });
    };

    start(callback) {

        this.listener.listen(0, 'localhost', () => {

            const address = this.listener.address();
            return callback('http://localhost:' + address.port);
        });
    }

    stop(callback) {

        return this.listener.close(callback);
    }
};
