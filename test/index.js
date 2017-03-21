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


describe('Oz', () => {

    it('runs a full authorization flow', (done) => {

        const encryptionPassword = 'a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough';

        const apps = {
            social: {
                id: 'social',
                scope: ['a', 'b', 'c'],
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'sha256',
                delegate: true
            },
            network: {
                id: 'network',
                scope: ['b', 'x'],
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
                authorization: Oz.client.header('http://example.com/oz/app', 'POST', apps.social).field
            }
        };

        const options = {
            encryptionPassword,
            loadAppFunc: function (id, callback) {

                callback(null, apps[id]);
            }
        };

        Oz.endpoints.app(req, null, options, (err, appTicket) => {

            expect(err).to.not.exist();

            // The app refreshes its own ticket

            req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', appTicket).field
                }
            };

            Oz.endpoints.reissue(req, {}, options, (err, reAppTicket) => {

                expect(err).to.not.exist();

                // The user is redirected to the server, logs in, and grant app access, resulting in an rsvp

                const grant = {
                    id: 'a1b2c3d4e5f6g7h8i9j0',
                    app: reAppTicket.app,
                    user: 'john',
                    exp: Oz.hawk.utils.now() + 60000
                };

                Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, (err, rsvp) => {

                    expect(err).to.not.exist();

                    // After granting app access, the user returns to the app with the rsvp

                    options.loadGrantFunc = function (id, callback) {

                        const ext = {
                            public: 'everybody knows',
                            private: 'the the dice are loaded'
                        };

                        callback(null, grant, ext);
                    };

                    // The app exchanges the rsvp for a ticket

                    let payload = { rsvp };

                    req = {
                        method: 'POST',
                        url: '/oz/rsvp',
                        headers: {
                            host: 'example.com',
                            authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', reAppTicket).field
                        }
                    };

                    Oz.endpoints.rsvp(req, payload, options, (err, ticket) => {

                        expect(err).to.not.exist();

                        // The app reissues the ticket with delegation to another app

                        payload = {
                            issueTo: apps.network.id,
                            scope: ['a']
                        };

                        req = {
                            method: 'POST',
                            url: '/oz/reissue',
                            headers: {
                                host: 'example.com',
                                authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', ticket).field
                            }
                        };

                        Oz.endpoints.reissue(req, payload, options, (err, delegatedTicket) => {

                            expect(err).to.not.exist();

                            // The other app reissues their ticket

                            req = {
                                method: 'POST',
                                url: '/oz/reissue',
                                headers: {
                                    host: 'example.com',
                                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', delegatedTicket).field
                                }
                            };

                            Oz.endpoints.reissue(req, {}, options, (err, reissuedDelegatedTicket) => {

                                expect(err).to.not.exist();
                                done();
                            });
                        });
                    });
                });
            });
        });
    });

    it('runs a full authorization flow using rsvp-based access delegation', (done) => {

        const encryptionPassword = 'a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough';

        const apps = {
            social: {
                id: 'social',
                scope: ['a', 'b', 'c'],
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'sha256',
                delegate: true
            },
            network: {
                id: 'network',
                scope: ['b', 'x'],
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
                authorization: Oz.client.header('http://example.com/oz/app', 'POST', apps.social).field
            }
        };

        const options = {
            encryptionPassword: encryptionPassword,
            loadAppFunc: function (id, callback) {

                callback(null, apps[id]);
            }
        };

        Oz.endpoints.app(req, null, options, (err, appTicket) => {

            expect(err).to.not.exist();

            // The app refreshes its own ticket

            req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', appTicket).field
                }
            };

            Oz.endpoints.reissue(req, {}, options, (err, reAppTicket) => {

                expect(err).to.not.exist();

                // The user is redirected to the server, logs in, and grant app access, resulting in an rsvp

                const grant = {
                    id: 'a1b2c3d4e5f6g7h8i9j0',
                    app: reAppTicket.app,
                    user: 'john',
                    exp: Oz.hawk.utils.now() + 60000
                };

                Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, (err, rsvp) => {

                    expect(err).to.not.exist();

                    // After granting app access, the user returns to the app with the rsvp

                    options.loadGrantFunc = function (id, callback) {

                        const ext = {
                            public: 'everybody knows',
                            private: 'the the dice are loaded'
                        };

                        callback(null, grant, ext);
                    };

                    // The app exchanges the rsvp for a ticket

                    let payload = { rsvp: rsvp };

                    req = {
                        method: 'POST',
                        url: '/oz/rsvp',
                        headers: {
                            host: 'example.com',
                            authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', reAppTicket).field
                        }
                    };

                    Oz.endpoints.rsvp(req, payload, options, (err, ticket) => {

                        expect(err).to.not.exist();

                        // The app requests an rsvp to delegate the ticket to another app

                        payload = {
                            delegateTo: apps.network.id,
                            scope: ['a']
                        };

                        req = {
                            method: 'POST',
                            url: '/oz/delegate',
                            headers: {
                                host: 'example.com',
                                authorization: Oz.client.header('http://example.com/oz/delegate', 'POST', ticket).field
                            }
                        };

                        Oz.endpoints.delegate(req, payload, options, (err, delegate) => {

                            expect(err).to.not.exist();

                            // The other app requests an app ticket

                            req = {
                                method: 'POST',
                                url: '/oz/app',
                                headers: {
                                    host: 'example.com',
                                    authorization: Oz.client.header('http://example.com/oz/app', 'POST', apps.network).field
                                }
                            };

                            Oz.endpoints.app(req, null, options, (err, otherAppTicket) => {

                                expect(err).to.not.exist();

                                // The other app exchanges the rsvp for a delegated user ticket

                                payload = { rsvp: delegate.rsvp };

                                req = {
                                    method: 'POST',
                                    url: '/oz/rsvp',
                                    headers: {
                                        host: 'example.com',
                                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', otherAppTicket).field
                                    }
                                };

                                Oz.endpoints.rsvp(req, payload, options, (err, delegatedTicket) => {

                                    expect(err).to.not.exist();
                                    done();
                                });
                            });
                        });
                    });
                });
            });
        });
    });
});
