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

const lab = exports.lab = Lab.script();
const describe = lab.experiment;
const it = lab.test;
const before = lab.before;
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

    before((done) => {

        const req = {
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

        Oz.endpoints.app(req, null, options, (err, ticket) => {

            expect(err).to.not.exist();
            appTicket = ticket;
            done();
        });
    });

    describe('app()', () => {

        it('overrides defaults', (done) => {

            const req = {
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

                    callback(null, apps.social);
                },
                ticket: {
                    ttl: 10 * 60 * 1000,
                    iron: Iron.defaults
                },
                hawk: {}
            };

            Oz.endpoints.app(req, null, options, (err, ticket) => {

                expect(err).to.not.exist();
                done();
            });
        });

        it('fails on invalid app request (bad credentials)', (done) => {

            const req = {
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

                    callback(null, apps.network);
                }
            };

            Oz.endpoints.app(req, null, options, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Bad mac');
                done();
            });
        });
    });

    describe('reissue()', () => {

        it('allows null payload', (done) => {

            const req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', appTicket).field
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps.social);
                }
            };

            Oz.endpoints.reissue(req, null, options, (err, ticket) => {

                expect(err).to.not.exist();
                done();
            });
        });

        it('overrides defaults', (done) => {

            const req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', appTicket).field
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps.social);
                },
                ticket: {
                    ttl: 10 * 60 * 1000,
                    iron: Iron.defaults
                },
                hawk: {}
            };

            Oz.endpoints.reissue(req, {}, options, (err, ticket) => {

                expect(err).to.not.exist();
                done();
            });
        });

        it('reissues expired ticket', (done) => {

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
                },
                ticket: {
                    ttl: 5
                }
            };

            Oz.endpoints.app(req, null, options, (err, ticket) => {

                expect(err).to.not.exist();

                req = {
                    method: 'POST',
                    url: '/oz/reissue',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', ticket).field
                    }
                };

                setTimeout(() => {

                    Oz.endpoints.reissue(req, {}, options, (err, reissued) => {

                        expect(err).to.not.exist();
                        done();
                    });
                }, 10);
            });
        });

        it('fails on app load error', (done) => {

            const req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', appTicket).field
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(new Error('not found'));
                }
            };

            Oz.endpoints.reissue(req, {}, options, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('not found');
                done();
            });
        });

        it('fails on missing app delegation rights', (done) => {

            const req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', appTicket).field
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps.social);
                }
            };

            Oz.endpoints.reissue(req, { issueTo: apps.network.id }, options, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Application has no delegation rights');
                done();
            });
        });

        it('fails on invalid reissue (request params)', (done) => {

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            const payload = {
                issueTo: null
            };

            const req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', appTicket).field
                }
            };

            Oz.endpoints.reissue(req, payload, options, (err, delegatedTicket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('child "issueTo" fails because ["issueTo" must be a string]');
                done();
            });
        });

        it('fails on invalid reissue (fails auth)', (done) => {

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            const req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', appTicket).field
                }
            };

            options.encryptionPassword = 'a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough_x';
            Oz.endpoints.reissue(req, {}, options, (err, delegatedTicket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Bad hmac value');
                done();
            });
        });

        it('fails on invalid reissue (invalid app)', (done) => {

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            const req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', appTicket).field
                }
            };

            options.loadAppFunc = function (id, callback) {

                callback(null, null);
            };

            Oz.endpoints.reissue(req, {}, options, (err, delegatedTicket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid application');
                done();
            });
        });

        it('fails on invalid reissue (missing grant)', (done) => {

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, (err, rsvp) => {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                const payload = { rsvp: rsvp };

                const req1 = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req1, payload, options, (err, ticket) => {

                    expect(err).to.not.exist();

                    const req2 = {
                        method: 'POST',
                        url: '/oz/reissue',
                        headers: {
                            host: 'example.com',
                            authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', ticket).field
                        }
                    };

                    options.loadGrantFunc = function (id, callback) {

                        callback(null, null);
                    };

                    Oz.endpoints.reissue(req2, {}, options, (err, delegatedTicket) => {

                        expect(err).to.exist();
                        expect(err.message).to.equal('Invalid grant');
                        done();
                    });
                });
            });
        });

        it('fails on invalid reissue (grant error)', (done) => {

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, (err, rsvp) => {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                const payload = { rsvp: rsvp };

                const req1 = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req1, payload, options, (err, ticket) => {

                    expect(err).to.not.exist();

                    const req2 = {
                        method: 'POST',
                        url: '/oz/reissue',
                        headers: {
                            host: 'example.com',
                            authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', ticket).field
                        }
                    };

                    options.loadGrantFunc = function (id, callback) {

                        callback(new Error('what?'));
                    };

                    Oz.endpoints.reissue(req2, {}, options, (err, delegatedTicket) => {

                        expect(err).to.exist();
                        expect(err.message).to.equal('what?');
                        done();
                    });
                });
            });
        });

        it('fails on invalid reissue (grant user mismatch)', (done) => {

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, (err, rsvp) => {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                const payload = { rsvp: rsvp };

                const req1 = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req1, payload, options, (err, ticket) => {

                    expect(err).to.not.exist();

                    const req2 = {
                        method: 'POST',
                        url: '/oz/reissue',
                        headers: {
                            host: 'example.com',
                            authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', ticket).field
                        }
                    };

                    options.loadGrantFunc = function (id, callback) {

                        grant.user = 'steve';
                        callback(null, grant);
                    };

                    Oz.endpoints.reissue(req2, {}, options, (err, delegatedTicket) => {

                        expect(err).to.exist();
                        expect(err.message).to.equal('Invalid grant');
                        done();
                    });
                });
            });
        });

        it('fails on invalid reissue (grant missing exp)', (done) => {

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, (err, rsvp) => {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                const payload = { rsvp: rsvp };

                const req1 = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req1, payload, options, (err, ticket) => {

                    expect(err).to.not.exist();

                    const req2 = {
                        method: 'POST',
                        url: '/oz/reissue',
                        headers: {
                            host: 'example.com',
                            authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', ticket).field
                        }
                    };

                    options.loadGrantFunc = function (id, callback) {

                        delete grant.exp;
                        callback(null, grant);
                    };

                    Oz.endpoints.reissue(req2, {}, options, (err, delegatedTicket) => {

                        expect(err).to.exist();
                        expect(err.message).to.equal('Invalid grant');
                        done();
                    });
                });
            });
        });

        it('fails on invalid reissue (grant app does not match app or dlg)', (done) => {

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
                    authorization: Oz.client.header('http://example.com/oz/app', 'POST', applications.social).field
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, applications[id]);
                }
            };

            Oz.endpoints.app(req, null, options, (err, applicationTicket) => {

                expect(err).to.not.exist();

                // The user is redirected to the server, logs in, and grant app access, resulting in an rsvp

                const grant = {
                    id: 'a1b2c3d4e5f6g7h8i9j0',
                    app: applicationTicket.app,
                    user: 'john',
                    exp: Oz.hawk.utils.now() + 60000
                };

                Oz.ticket.rsvp(applications.social, grant, encryptionPassword, {}, (err, rsvp) => {

                    expect(err).to.not.exist();

                    // After granting app access, the user returns to the app with the rsvp

                    options.loadGrantFunc = function (id, callback) {

                        callback(null, grant);
                    };

                    // The app exchanges the rsvp for a ticket

                    let payload = { rsvp: rsvp };

                    req = {
                        method: 'POST',
                        url: '/oz/rsvp',
                        headers: {
                            host: 'example.com',
                            authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', applicationTicket).field
                        }
                    };

                    Oz.endpoints.rsvp(req, payload, options, (err, ticket) => {

                        expect(err).to.not.exist();

                        // The app reissues the ticket with delegation to another app

                        payload = {
                            issueTo: applications.network.id
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

                            options.loadGrantFunc = function (id, callback) {

                                grant.app = 'xyz';
                                callback(null, grant);
                            };

                            Oz.endpoints.reissue(req, {}, options, (err, reissuedDelegatedTicket) => {

                                expect(err).to.exist();
                                expect(err.message).to.equal('Invalid grant');
                                done();
                            });
                        });
                    });
                });
            });
        });
    });

    describe('rsvp()', () => {

        it('overrides defaults', (done) => {

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                },
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

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, (err, rsvp) => {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                const payload = { rsvp: rsvp };

                const req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, (err, ticket) => {

                    expect(err).to.not.exist();
                    done();
                });
            });
        });

        it('errors on invalid authentication', (done) => {

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                },
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

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, (err, rsvp) => {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                const payload = { rsvp: rsvp };

                const req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com'
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, (err, ticket) => {

                    expect(err).to.exist();
                    done();
                });
            });
        });

        it('errors on expired ticket', (done) => {

            // App ticket

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
                },
                ticket: {
                    ttl: 5
                }
            };

            Oz.endpoints.app(req, null, options, (err, applicationTicket) => {

                expect(err).to.not.exist();

                const grant = {
                    id: 'a1b2c3d4e5f6g7h8i9j0',
                    app: applicationTicket.app,
                    user: 'john',
                    exp: Oz.hawk.utils.now() + 60000
                };

                Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, (err, rsvp) => {

                    expect(err).to.not.exist();

                    options.loadGrantFunc = function (id, callback) {

                        callback(null, grant);
                    };

                    const payload = { rsvp: rsvp };

                    req = {
                        method: 'POST',
                        url: '/oz/rsvp',
                        headers: {
                            host: 'example.com',
                            authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', applicationTicket).field
                        }
                    };

                    setTimeout(() => {

                        Oz.endpoints.rsvp(req, payload, options, (err, ticket) => {

                            expect(err).to.exist();
                            done();
                        });
                    }, 10);
                });
            });
        });

        it('errors on missing payload', (done) => {

            Oz.endpoints.rsvp({}, null, {}, (err, ticket) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Missing required payload');
                done();
            });
        });

        it('fails on invalid rsvp (request params)', (done) => {

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, (err, rsvp) => {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                const payload = { rsvp: '' };

                const req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, (err, ticket) => {

                    expect(err).to.exist();
                    expect(err.message).to.equal('child "rsvp" fails because ["rsvp" is not allowed to be empty]');
                    done();
                });
            });
        });

        it('fails on invalid rsvp (invalid auth)', (done) => {

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, (err, rsvp) => {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                const payload = { rsvp: 'abc' };

                const req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, (err, ticket) => {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Incorrect number of sealed components');
                    done();
                });
            });
        });

        it('fails on invalid rsvp (user ticket)', (done) => {

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, (err, rsvp) => {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                const body = { rsvp: rsvp };

                const req1 = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req1, body, options, (err, ticket1) => {

                    expect(err).to.not.exist();

                    const req2 = {
                        method: 'POST',
                        url: '/oz/rsvp',
                        headers: {
                            host: 'example.com',
                            authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', ticket1).field
                        }
                    };

                    Oz.endpoints.rsvp(req2, body, options, (err, ticket2) => {

                        expect(err).to.exist();
                        expect(err.message).to.equal('User ticket cannot be used on an application endpoint');
                        done();
                    });
                });
            });
        });

        it('fails on invalid rsvp (mismatching apps)', (done) => {

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.network, grant, encryptionPassword, {}, (err, rsvp) => {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                const payload = { rsvp: rsvp };

                const req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, (err, ticket) => {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Mismatching ticket and rsvp apps');
                    done();
                });
            });
        });

        it('fails on invalid rsvp (expired rsvp)', (done) => {

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, { ttl: 1 }, (err, rsvp) => {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                const payload = { rsvp: rsvp };

                const req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, (err, ticket) => {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Expired rsvp');
                    done();
                });
            });
        });

        it('fails on invalid rsvp (expired grant)', (done) => {

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() - 1000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, (err, rsvp) => {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                const payload = { rsvp: rsvp };

                const req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, (err, ticket) => {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Invalid grant');
                    done();
                });
            });
        });

        it('fails on invalid rsvp (missing grant)', (done) => {

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                },
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

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, (err, rsvp) => {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, null);
                };

                const payload = { rsvp: rsvp };

                const req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, (err, ticket) => {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Invalid grant');
                    done();
                });
            });
        });

        it('fails on invalid rsvp (grant app mismatch)', (done) => {

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                },
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

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, (err, rsvp) => {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    grant.app = apps.network.id;
                    callback(null, grant);
                };

                const payload = { rsvp: rsvp };

                const req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, (err, ticket) => {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Invalid grant');
                    done();
                });
            });
        });

        it('fails on invalid rsvp (grant delegating app mismatch)', (done) => {

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                },
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

            const rsvpOptions = {
                dlg: apps.network.id
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, rsvpOptions, (err, rsvp) => {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    grant.app = 'xyz';
                    callback(null, grant);
                };

                const payload = { rsvp: rsvp };

                const req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, (err, ticket) => {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Invalid grant');
                    done();
                });
            });
        });

        it('fails on invalid rsvp (grant missing exp)', (done) => {

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                },
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

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, (err, rsvp) => {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    delete grant.exp;
                    callback(null, grant);
                };

                const payload = { rsvp: rsvp };

                const req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, (err, ticket) => {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Invalid grant');
                    done();
                });
            });
        });

        it('fails on invalid rsvp (grant error)', (done) => {

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                },
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

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, (err, rsvp) => {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(new Error('boom'));
                };

                const payload = { rsvp: rsvp };

                const req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, (err, ticket) => {

                    expect(err).to.exist();
                    expect(err.message).to.equal('boom');
                    done();
                });
            });
        });

        it('fails on invalid rsvp (app error)', (done) => {

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                },
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

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, (err, rsvp) => {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                const payload = { rsvp: rsvp };

                const req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                options.loadAppFunc = function (id, callback) {

                    return callback(new Error('nope'));
                };

                Oz.endpoints.rsvp(req, payload, options, (err, ticket) => {

                    expect(err).to.exist();
                    expect(err.message).to.equal('nope');
                    done();
                });
            });
        });

        it('fails on invalid rsvp (invalid app)', (done) => {

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            const grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, (err, rsvp) => {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                const payload = { rsvp: rsvp };

                const req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                options.loadAppFunc = function (id, callback) {

                    callback(null, null);
                };

                Oz.endpoints.rsvp(req, payload, options, (err, ticket) => {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Invalid application');
                    done();
                });
            });
        });
    });

    describe('delegate()', () => {

        const grant = {
            id: 'a1b2c3d4e5f6g7h8i9j0',
            app: apps.social.id,
            user: 'john',
            exp: Oz.hawk.utils.now() + 60000
        };

        let userTicket = null;

        before((done) => {

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, (err, rsvp) => {

                expect(err).to.not.exist();

                const options = {
                    encryptionPassword: encryptionPassword,
                    loadAppFunc: function (id, callback) {

                        callback(null, apps[id]);
                    },
                    loadGrantFunc: function (id, callback) {

                        callback(null, grant);
                    }
                };

                const payload = { rsvp: rsvp };

                const req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, (err, ticket) => {

                    expect(err).to.not.exist();
                    userTicket = ticket;
                    done();
                });
            });
        });

        it('overrides defaults', (done) => {

            const req = {
                method: 'POST',
                url: '/oz/delegate',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/delegate', 'POST', userTicket).field
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, Hoek.merge({ delegate: true }, apps[id]));
                },
                loadGrantFunc: function (id, callback) {

                    callback(null, grant);
                },
                ticket: {
                    ttl: 10 * 60 * 1000,
                    iron: Iron.defaults
                },
                hawk: {}
            };

            const payload = { delegateTo: apps.network.id };

            Oz.endpoints.delegate(req, payload, options, (err, delegate) => {

                expect(err).to.not.exist();
                done();
            });
        });

        it('fails on invalid delegate (missing payload)', (done) => {

            const req = {
                method: 'POST',
                url: '/oz/delegate',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/delegate', 'POST', userTicket).field
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, Hoek.merge({ delegate: true }, apps[id]));
                },
                loadGrantFunc: function (id, callback) {

                    callback(null, grant);
                }
            };

            const payload = null;

            Oz.endpoints.delegate(req, payload, options, (err, delegate) => {

                expect(err).to.exist();
                done();
            });
        });

        it('fails on invalid delegate (invalid request params)', (done) => {

            const req = {
                method: 'POST',
                url: '/oz/delegate',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/delegate', 'POST', userTicket).field
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, Hoek.merge({ delegate: true }, apps[id]));
                },
                loadGrantFunc: function (id, callback) {

                    callback(null, grant);
                }
            };

            const payload = { delegateTo: null };

            Oz.endpoints.delegate(req, payload, options, (err, delegate) => {

                expect(err).to.exist();
                done();
            });
        });

        it('fails on invalid authentication', (done) => {

            const req = {
                method: 'POST',
                url: '/oz/delegate',
                headers: {
                    host: 'example.com'
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, Hoek.merge({ delegate: true }, apps[id]));
                },
                loadGrantFunc: function (id, callback) {

                    callback(null, grant);
                }
            };

            const payload = { delegateTo: apps.network.id };

            Oz.endpoints.delegate(req, payload, options, (err, delegate) => {

                expect(err).to.exist();
                done();
            });
        });

        it('fails on expired ticket', (done) => {

            // User ticket

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, (err, rsvp) => {

                expect(err).to.not.exist();

                const options = {
                    encryptionPassword: encryptionPassword,
                    loadAppFunc: function (id, callback) {

                        callback(null, Hoek.merge({ delegate: true }, apps[id]));
                    },
                    loadGrantFunc: function (id, callback) {

                        callback(null, grant);
                    },
                    ticket: {
                        ttl: 5
                    }
                };

                const payload1 = { rsvp: rsvp };

                const req1 = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req1, payload1, options, (err, expiringUserTicket) => {

                    expect(err).to.not.exist();

                    const req2 = {
                        method: 'POST',
                        url: '/oz/delegate',
                        headers: {
                            host: 'example.com',
                            authorization: Oz.client.header('http://example.com/oz/delegate', 'POST', expiringUserTicket).field
                        }
                    };

                    const payload2 = { delegateTo: apps.network.id };

                    setTimeout(() => {

                        Oz.endpoints.delegate(req2, payload2, options, (err, delegate) => {

                            expect(err).to.exist();
                            done();
                        });
                    }, 10);
                });
            });
        });

        it('fails on invalid delegate (app ticket)', (done) => {

            const req = {
                method: 'POST',
                url: '/oz/delegate',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/delegate', 'POST', appTicket).field
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, Hoek.merge({ delegate: true }, apps[id]));
                },
                loadGrantFunc: function (id, callback) {

                    callback(null, grant);
                }
            };

            const payload = { delegateTo: apps.network.id };

            Oz.endpoints.delegate(req, payload, options, (err, delegate) => {

                expect(err).to.exist();
                expect(err.message).to.equal('App ticket cannot be delegated');
                done();
            });
        });

        it('fails on invalid delegate (delegated ticket)', (done) => {

            const req1 = {
                method: 'POST',
                url: '/oz/delegate',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/delegate', 'POST', userTicket).field
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, Hoek.merge({ delegate: true }, apps[id]));
                },
                loadGrantFunc: function (id, callback) {

                    callback(null, grant);
                }
            };

            const payload = { delegateTo: apps.network.id };

            Oz.endpoints.delegate(req1, payload, options, (err, delegate1) => {

                expect(err).to.not.exist();

                // App token for delegated app

                const req2 = {
                    method: 'POST',
                    url: '/oz/app',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/app', 'POST', apps.network).field
                    }
                };

                Oz.endpoints.app(req2, null, options, (err, delegatedAppTicket) => {

                    expect(err).to.not.exist();

                    // User token for delegated app

                    const req3 = {
                        method: 'POST',
                        url: '/oz/rsvp',
                        headers: {
                            host: 'example.com',
                            authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', delegatedAppTicket).field
                        }
                    };

                    Oz.endpoints.rsvp(req3, delegate1, options, (err, delegatedUserTicket) => {

                        expect(err).to.not.exist();

                        const req4 = {
                            method: 'POST',
                            url: '/oz/delegate',
                            headers: {
                                host: 'example.com',
                                authorization: Oz.client.header('http://example.com/oz/delegate', 'POST', delegatedUserTicket).field
                            }
                        };

                        payload.delegateTo = 'xyz';

                        Oz.endpoints.delegate(req4, payload, options, (err, delegate2) => {

                            expect(err).to.exist();
                            expect(err.message).to.equal('Cannot re-delegate');
                            done();
                        });
                    });
                });
            });
        });

        it('fails on invalid delegate (delegate disallowed in ticket)', (done) => {

            // User ticket with disabled delegation

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, (err, rsvp) => {

                expect(err).to.not.exist();

                const options = {
                    encryptionPassword: encryptionPassword,
                    loadAppFunc: function (id, callback) {

                        callback(null, Hoek.merge({ delegate: true }, apps[id]));
                    },
                    loadGrantFunc: function (id, callback) {

                        callback(null, grant);
                    },
                    ticket: {
                        delegate: false
                    }
                };

                const payload1 = { rsvp: rsvp };

                const req1 = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req1, payload1, options, (err, ticket) => {

                    expect(err).to.not.exist();

                    const req2 = {
                        method: 'POST',
                        url: '/oz/delegate',
                        headers: {
                            host: 'example.com',
                            authorization: Oz.client.header('http://example.com/oz/delegate', 'POST', ticket).field
                        }
                    };

                    const payload2 = { delegateTo: apps.network.id };

                    Oz.endpoints.delegate(req2, payload2, options, (err, delegate) => {

                        expect(err).to.exist();
                        expect(err.message).to.equal('Ticket does not allow delegation');
                        done();
                    });
                });
            });
        });

        it('fails on invalid delegate (invalid scope)', (done) => {

            const req = {
                method: 'POST',
                url: '/oz/delegate',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/delegate', 'POST', userTicket).field
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, Hoek.merge({ delegate: true }, apps[id]));
                },
                loadGrantFunc: function (id, callback) {

                    callback(null, grant);
                }
            };

            const payload = {
                delegateTo: apps.network.id,
                scope: ['a','a']
            };

            Oz.endpoints.delegate(req, payload, options, (err, delegate) => {

                expect(err).to.exist();
                expect(err.message).to.equal('scope includes duplicated item');
                done();
            });
        });

        it('fails on invalid delegate (missing parent scope)', (done) => {

            const req = {
                method: 'POST',
                url: '/oz/delegate',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/delegate', 'POST', userTicket).field
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, Hoek.merge({ delegate: true }, apps[id]));
                },
                loadGrantFunc: function (id, callback) {

                    callback(null, grant);
                }
            };

            const payload = {
                delegateTo: apps.network.id,
                scope: ['d']
            };

            Oz.endpoints.delegate(req, payload, options, (err, delegate) => {

                expect(err).to.exist();
                expect(err.message).to.equal('New scope is not a subset of the parent ticket scope');
                done();
            });
        });

        it('fails on invalid delegate (app load error)', (done) => {

            const req = {
                method: 'POST',
                url: '/oz/delegate',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/delegate', 'POST', userTicket).field
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    if (id === apps.social.id) {
                        callback(new Error('not found'));
                    }
                    else {
                        callback(null, Hoek.merge({ delegate: true }, apps[id]));
                    }
                },
                loadGrantFunc: function (id, callback) {

                    callback(null, grant);
                }
            };

            const payload = { delegateTo: apps.network.id };

            Oz.endpoints.delegate(req, payload, options, (err, delegate) => {

                expect(err).to.exist();
                expect(err.message).to.equal('not found');
                done();
            });
        });

        it('fails on invalid delegate (invalid app)', (done) => {

            const req = {
                method: 'POST',
                url: '/oz/delegate',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/delegate', 'POST', userTicket).field
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    if (id === apps.social.id) {
                        callback(null, null);
                    }
                    else {
                        callback(null, Hoek.merge({ delegate: true }, apps[id]));
                    }
                },
                loadGrantFunc: function (id, callback) {

                    callback(null, grant);
                }
            };

            const payload = { delegateTo: apps.network.id };

            Oz.endpoints.delegate(req, payload, options, (err, delegate) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid application');
                done();
            });
        });

        it('fails on invalid delegate (missing app delegation rights)', (done) => {

            const req = {
                method: 'POST',
                url: '/oz/delegate',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/delegate', 'POST', userTicket).field
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                },
                loadGrantFunc: function (id, callback) {

                    callback(null, grant);
                }
            };

            const payload = { delegateTo: apps.network.id };

            Oz.endpoints.delegate(req, payload, options, (err, delegate) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Application has no delegation rights');
                done();
            });
        });

        it('fails on invalid delegate (delegated app load error)', (done) => {

            const req = {
                method: 'POST',
                url: '/oz/delegate',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/delegate', 'POST', userTicket).field
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    if (id === apps.network.id) {
                        callback(new Error('not found'));
                    }
                    else {
                        callback(null, Hoek.merge({ delegate: true }, apps[id]));
                    }
                },
                loadGrantFunc: function (id, callback) {

                    callback(null, grant);
                }
            };

            const payload = { delegateTo: apps.network.id };

            Oz.endpoints.delegate(req, payload, options, (err, delegate) => {

                expect(err).to.exist();
                expect(err.message).to.equal('not found');
                done();
            });
        });

        it('fails on invalid delegate (invalid delegated app)', (done) => {

            const req = {
                method: 'POST',
                url: '/oz/delegate',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/delegate', 'POST', userTicket).field
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    if (id === apps.network.id) {
                        callback(null, null);
                    }
                    else {
                        callback(null, Hoek.merge({ delegate: true }, apps[id]));
                    }
                },
                loadGrantFunc: function (id, callback) {

                    callback(null, grant);
                }
            };

            const payload = { delegateTo: apps.network.id };

            Oz.endpoints.delegate(req, payload, options, (err, delegate) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid application');
                done();
            });
        });

        it('fails on invalid delegate (grant load error)', (done) => {

            const req = {
                method: 'POST',
                url: '/oz/delegate',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/delegate', 'POST', userTicket).field
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, Hoek.merge({ delegate: true }, apps[id]));
                },
                loadGrantFunc: function (id, callback) {

                    callback(new Error('what?'));
                }
            };

            const payload = { delegateTo: apps.network.id };

            Oz.endpoints.delegate(req, payload, options, (err, delegate) => {

                expect(err).to.exist();
                expect(err.message).to.equal('what?');
                done();
            });
        });

        it('fails on invalid delegate (invalid grant)', (done) => {

            const req = {
                method: 'POST',
                url: '/oz/delegate',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/delegate', 'POST', userTicket).field
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, Hoek.merge({ delegate: true }, apps[id]));
                },
                loadGrantFunc: function (id, callback) {

                    callback(null, null);
                }
            };

            const payload = { delegateTo: apps.network.id };

            Oz.endpoints.delegate(req, payload, options, (err, delegate) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid grant');
                done();
            });
        });

        it('fails on invalid delegate (grant app mismatch)', (done) => {

            const req = {
                method: 'POST',
                url: '/oz/delegate',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/delegate', 'POST', userTicket).field
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, Hoek.merge({ delegate: true }, apps[id]));
                },
                loadGrantFunc: function (id, callback) {

                    const grantWithDifferentApp = Hoek.shallow(grant);
                    grantWithDifferentApp.app = 'xyz';
                    callback(null, grantWithDifferentApp);
                }
            };

            const payload = { delegateTo: apps.network.id };

            Oz.endpoints.delegate(req, payload, options, (err, delegate) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid grant');
                done();
            });
        });

        it('fails on invalid delegate (grant user mismatch)', (done) => {

            const req = {
                method: 'POST',
                url: '/oz/delegate',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/delegate', 'POST', userTicket).field
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, Hoek.merge({ delegate: true }, apps[id]));
                },
                loadGrantFunc: function (id, callback) {

                    const grantWithDifferentApp = Hoek.shallow(grant);
                    grantWithDifferentApp.user = 'steve';
                    callback(null, grantWithDifferentApp);
                }
            };

            const payload = { delegateTo: apps.network.id };

            Oz.endpoints.delegate(req, payload, options, (err, delegate) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid grant');
                done();
            });
        });

        it('fails on invalid delegate (grant missing exp)', (done) => {

            const req = {
                method: 'POST',
                url: '/oz/delegate',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/delegate', 'POST', userTicket).field
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, Hoek.merge({ delegate: true }, apps[id]));
                },
                loadGrantFunc: function (id, callback) {

                    const grantWithoutExp = Hoek.shallow(grant);
                    delete grantWithoutExp.exp;
                    callback(null, grantWithoutExp);
                }
            };

            const payload = { delegateTo: apps.network.id };

            Oz.endpoints.delegate(req, payload, options, (err, delegate) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid grant');
                done();
            });
        });

        it('fails on invalid delegate (rsvp error)', (done) => {

            const req = {
                method: 'POST',
                url: '/oz/delegate',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/delegate', 'POST', userTicket).field
                }
            };

            const options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    const invalidApp = Hoek.merge({ delegate: true }, apps[id]);
                    delete invalidApp.id;
                    callback(null, invalidApp);
                },
                loadGrantFunc: function (id, callback) {

                    callback(null, grant);
                }
            };

            const payload = { delegateTo: apps.network.id };

            Oz.endpoints.delegate(req, payload, options, (err, delegate) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid application object');
                done();
            });
        });
    });
});
