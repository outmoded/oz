'use strict';

// Load modules

const Code = require('code');
const Lab = require('lab');
const Oz = require('../lib');


// Declare internals

const internals = {};


// Test shortcuts

const lab = exports.lab = Lab.script();
const describe = lab.experiment;
const it = lab.test;
const expect = Code.expect;


describe('Server', () => {

    describe('authenticate()', () => {

        it('throws an error on missing password', (done) => {

            expect(() => {

                Oz.server.authenticate(null, null, {}, () => { });
            }).to.throw('Invalid encryption password');
            done();
        });

        const encryptionPassword = 'welcome!';

        const app = {
            id: '123'
        };

        it('authenticates a request', (done) => {

            const grant = {
                id: 's81u29n1812',
                user: '456',
                exp: Oz.hawk.utils.now() + 5000,
                scope: ['a', 'b']
            };

            Oz.ticket.issue(app, grant, encryptionPassword, {}, (err, envelope) => {

                expect(err).to.not.exist();

                const req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', envelope).field
                    }
                };

                Oz.server.authenticate(req, encryptionPassword, {}, (err, credentials, artifacts) => {

                    expect(err).to.not.exist();
                    done();
                });
            });
        });

        it('authenticates a request (hawk options)', (done) => {

            const grant = {
                id: 's81u29n1812',
                user: '456',
                exp: Oz.hawk.utils.now() + 5000,
                scope: ['a', 'b']
            };

            Oz.ticket.issue(app, grant, encryptionPassword, {}, (err, envelope) => {

                expect(err).to.not.exist();

                const req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        hostx1: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', envelope).field
                    }
                };

                Oz.server.authenticate(req, encryptionPassword, { hawk: { hostHeaderName: 'hostx1' } }, (err, credentials, artifacts) => {

                    expect(err).to.not.exist();
                    done();
                });
            });
        });

        it('fails to authenticate a request with bad password', (done) => {

            const grant = {
                id: 's81u29n1812',
                user: '456',
                exp: Oz.hawk.utils.now() + 5000,
                scope: ['a', 'b']
            };

            Oz.ticket.issue(app, grant, encryptionPassword, {}, (err, envelope) => {

                expect(err).to.not.exist();

                const req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', envelope).field
                    }
                };

                Oz.server.authenticate(req, 'x', {}, (err, credentials, artifacts) => {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Bad hmac value');
                    done();
                });
            });
        });

        it('fails to authenticate a request with expired ticket', (done) => {

            const grant = {
                id: 's81u29n1812',
                user: '456',
                exp: Oz.hawk.utils.now() - 5000,
                scope: ['a', 'b']
            };

            Oz.ticket.issue(app, grant, encryptionPassword, {}, (err, envelope) => {

                expect(err).to.not.exist();

                const req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', envelope).field
                    }
                };

                Oz.server.authenticate(req, encryptionPassword, {}, (err, credentials, artifacts) => {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Expired ticket');
                    expect(err.output.payload.expired).to.be.true();
                    done();
                });
            });
        });

        it('fails to authenticate a request with mismatching app id', (done) => {

            const grant = {
                id: 's81u29n1812',
                user: '456',
                exp: Oz.hawk.utils.now() + 5000,
                scope: ['a', 'b']
            };

            Oz.ticket.issue(app, grant, encryptionPassword, {}, (err, envelope) => {

                expect(err).to.not.exist();

                envelope.app = '567';
                const req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', envelope).field
                    }
                };

                Oz.server.authenticate(req, encryptionPassword, {}, (err, credentials, artifacts) => {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Mismatching application id');
                    done();
                });
            });
        });

        it('fails to authenticate a request with mismatching dlg id', (done) => {

            const grant = {
                id: 's81u29n1812',
                user: '456',
                exp: Oz.hawk.utils.now() + 5000,
                scope: ['a', 'b']
            };

            Oz.ticket.issue(app, grant, encryptionPassword, {}, (err, envelope) => {

                expect(err).to.not.exist();

                envelope.dlg = '567';
                const req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', envelope).field
                    }
                };

                Oz.server.authenticate(req, encryptionPassword, {}, (err, credentials, artifacts) => {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Mismatching delegated application id');
                    done();
                });
            });
        });
    });
});
