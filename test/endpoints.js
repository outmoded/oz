'use strict';

// Load modules

const Code = require('code');
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
});
