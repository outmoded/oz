// Load modules

var Code = require('code');
var Iron = require('iron');
var Lab = require('lab');
var Oz = require('../lib');


// Declare internals

var internals = {};


// Test shortcuts

var lab = exports.lab = Lab.script();
var describe = lab.experiment;
var it = lab.test;
var before = lab.before;
var expect = Code.expect;


describe('Endpoints', function () {

    var encryptionPassword = 'password';

    var apps = {
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

    var appTicket = null;

    before(function (done) {

        var req = {
            method: 'POST',
            url: '/oz/app',
            headers: {
                host: 'example.com',
                authorization: Oz.client.header('http://example.com/oz/app', 'POST', apps.social).field
            }
        };

        var options = {
            encryptionPassword: encryptionPassword,
            loadAppFunc: function (id, callback) {

                callback(null, apps[id]);
            }
        };

        Oz.endpoints.app(req, null, options, function (err, ticket) {

            appTicket = ticket;
            done();
        });
    });

    describe('app()', function () {

        it('overrides defaults', function (done) {

            var req = {
                method: 'POST',
                url: '/oz/app',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/app', 'POST', apps.social).field
                }
            };

            var options = {
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

            Oz.endpoints.app(req, null, options, function (err, ticket) {

                expect(err).to.not.exist();
                done();
            });
        });

        it('fails on invalid app request (bad credentials)', function (done) {

            var req = {
                method: 'POST',
                url: '/oz/app',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/app', 'POST', apps.social).field
                }
            };

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps.network);
                }
            };

            Oz.endpoints.app(req, null, options, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Bad mac');
                done();
            });
        });
    });

    describe('reissue()', function () {

        it('allows null payload', function (done) {

            var req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', appTicket).field
                }
            };

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps.social);
                }
            };

            Oz.endpoints.reissue(req, null, options, function (err, ticket) {

                expect(err).to.not.exist();
                done();
            });
        });

        it('overrides defaults', function (done) {

            var req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', appTicket).field
                }
            };

            var options = {
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

            Oz.endpoints.reissue(req, {}, options, function (err, ticket) {

                expect(err).to.not.exist();
                done();
            });
        });

        it('reissues expired ticket', function (done) {

            var req = {
                method: 'POST',
                url: '/oz/app',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/app', 'POST', apps.social).field
                }
            };

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                },
                ticket: {
                    ttl: 5
                }
            };

            Oz.endpoints.app(req, null, options, function (err, ticket) {

                req = {
                    method: 'POST',
                    url: '/oz/reissue',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', ticket).field
                    }
                };

                setTimeout(function () {

                    Oz.endpoints.reissue(req, {}, options, function (err, reissued) {

                        expect(err).to.not.exist();
                        done();
                    });
                }, 10);
            });
        });

        it('fails on app load error', function (done) {

            var req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', appTicket).field
                }
            };

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(new Error('not found'));
                }
            };

            Oz.endpoints.reissue(req, {}, options, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('not found');
                done();
            });
        });

        it('fails on missing app delegation rights', function (done) {

            var req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', appTicket).field
                }
            };

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps.social);
                }
            };

            Oz.endpoints.reissue(req, { issueTo: apps.network.id }, options, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Application has no delegation rights');
                done();
            });
        });

        it('fails on invalid reissue (request params)', function (done) {

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            var payload = {
                issueTo: null
            };

            var req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', appTicket).field
                }
            };

            Oz.endpoints.reissue(req, payload, options, function (err, delegatedTicket) {

                expect(err).to.exist();
                expect(err.message).to.equal('child "issueTo" fails because ["issueTo" must be a string]');
                done();
            });
        });

        it('fails on invalid reissue (fails auth)', function (done) {

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            var req = {
                method: 'POST',
                url: '/oz/reissue',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', appTicket).field
                }
            };

            options.encryptionPassword = 'x';
            Oz.endpoints.reissue(req, {}, options, function (err, delegatedTicket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Bad hmac value');
                done();
            });
        });

        it('fails on invalid reissue (invalid app)', function (done) {

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            var req = {
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

            Oz.endpoints.reissue(req, {}, options, function (err, delegatedTicket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid application');
                done();
            });
        });

        it('fails on invalid reissue (missing grant)', function (done) {

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            var grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, function (err, rsvp) {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                var payload = { rsvp: rsvp };

                var req1 = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req1, payload, options, function (err, ticket) {

                    expect(err).to.not.exist();

                    var req2 = {
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

                    Oz.endpoints.reissue(req2, {}, options, function (err, delegatedTicket) {

                        expect(err).to.exist();
                        expect(err.message).to.equal('Invalid grant');
                        done();
                    });
                });
            });
        });

        it('fails on invalid reissue (grant error)', function (done) {

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            var grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, function (err, rsvp) {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                var payload = { rsvp: rsvp };

                var req1 = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req1, payload, options, function (err, ticket) {

                    expect(err).to.not.exist();

                    var req2 = {
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

                    Oz.endpoints.reissue(req2, {}, options, function (err, delegatedTicket) {

                        expect(err).to.exist();
                        expect(err.message).to.equal('what?');
                        done();
                    });
                });
            });
        });

        it('fails on invalid reissue (grant user mismatch)', function (done) {

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            var grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, function (err, rsvp) {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                var payload = { rsvp: rsvp };

                var req1 = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req1, payload, options, function (err, ticket) {

                    expect(err).to.not.exist();

                    var req2 = {
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

                    Oz.endpoints.reissue(req2, {}, options, function (err, delegatedTicket) {

                        expect(err).to.exist();
                        expect(err.message).to.equal('Invalid grant');
                        done();
                    });
                });
            });
        });

        it('fails on invalid reissue (grant missing exp)', function (done) {

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            var grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, function (err, rsvp) {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                var payload = { rsvp: rsvp };

                var req1 = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req1, payload, options, function (err, ticket) {

                    expect(err).to.not.exist();

                    var req2 = {
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

                    Oz.endpoints.reissue(req2, {}, options, function (err, delegatedTicket) {

                        expect(err).to.exist();
                        expect(err.message).to.equal('Invalid grant');
                        done();
                    });
                });
            });
        });

        it('fails on invalid reissue (grant app does not match app or dlg)', function (done) {

            var applications = {
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

            var req = {
                method: 'POST',
                url: '/oz/app',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/app', 'POST', applications.social).field
                }
            };

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, applications[id]);
                }
            };

            Oz.endpoints.app(req, null, options, function (err, applicationTicket) {

                expect(err).to.not.exist();

                // The user is redirected to the server, logs in, and grant app access, resulting in an rsvp

                var grant = {
                    id: 'a1b2c3d4e5f6g7h8i9j0',
                    app: applicationTicket.app,
                    user: 'john',
                    exp: Oz.hawk.utils.now() + 60000
                };

                Oz.ticket.rsvp(applications.social, grant, encryptionPassword, {}, function (err, rsvp) {

                    expect(err).to.not.exist();

                    // After granting app access, the user returns to the app with the rsvp

                    options.loadGrantFunc = function (id, callback) {

                        callback(null, grant);
                    };

                    // The app exchanges the rsvp for a ticket

                    var payload = { rsvp: rsvp };

                    req = {
                        method: 'POST',
                        url: '/oz/rsvp',
                        headers: {
                            host: 'example.com',
                            authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', applicationTicket).field
                        }
                    };

                    Oz.endpoints.rsvp(req, payload, options, function (err, ticket) {

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

                        Oz.endpoints.reissue(req, payload, options, function (err, delegatedTicket) {

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

                            Oz.endpoints.reissue(req, {}, options, function (err, reissuedDelegatedTicket) {

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

    describe('rsvp()', function () {

        it('overrides defaults', function (done) {

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                },
                ticket: {
                    iron: Iron.defaults
                }
            };

            var grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, function (err, rsvp) {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                var payload = { rsvp: rsvp };

                var req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, function (err, ticket) {

                    expect(err).to.not.exist();
                    done();
                });
            });
        });

        it('errors on invalid authentication', function (done) {

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                },
                ticket: {
                    iron: Iron.defaults
                }
            };

            var grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, function (err, rsvp) {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                var payload = { rsvp: rsvp };

                var req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com'
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, function (err, ticket) {

                    expect(err).to.exist();
                    done();
                });
            });
        });

        it('errors on expired ticket', function (done) {

            // App ticket

            var req = {
                method: 'POST',
                url: '/oz/app',
                headers: {
                    host: 'example.com',
                    authorization: Oz.client.header('http://example.com/oz/app', 'POST', apps.social).field
                }
            };

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                },
                ticket: {
                    ttl: 5
                }
            };

            Oz.endpoints.app(req, null, options, function (err, applicationTicket) {

                var grant = {
                    id: 'a1b2c3d4e5f6g7h8i9j0',
                    app: applicationTicket.app,
                    user: 'john',
                    exp: Oz.hawk.utils.now() + 60000
                };

                Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, function (err, rsvp) {

                    expect(err).to.not.exist();

                    options.loadGrantFunc = function (id, callback) {

                        callback(null, grant);
                    };

                    var payload = { rsvp: rsvp };

                    req = {
                        method: 'POST',
                        url: '/oz/rsvp',
                        headers: {
                            host: 'example.com',
                            authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', applicationTicket).field
                        }
                    };

                    setTimeout(function () {

                        Oz.endpoints.rsvp(req, payload, options, function (err, ticket) {

                            expect(err).to.exist();
                            done();
                        });
                    }, 10);
                });
            });
        });

        it('errors on missing payload', function (done) {

            Oz.endpoints.rsvp({}, null, {}, function (err, ticket) {

                expect(err).to.exist();
                expect(err.message).to.equal('Missing required payload');
                done();
            });
        });

        it('fails on invalid rsvp (request params)', function (done) {

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            var grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, function (err, rsvp) {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                var payload = { rsvp: '' };

                var req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, function (err, ticket) {

                    expect(err).to.exist();
                    expect(err.message).to.equal('child "rsvp" fails because ["rsvp" is not allowed to be empty]');
                    done();
                });
            });
        });

        it('fails on invalid rsvp (invalid auth)', function (done) {

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            var grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, function (err, rsvp) {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                var payload = { rsvp: 'abc' };

                var req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, function (err, ticket) {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Incorrect number of sealed components');
                    done();
                });
            });
        });

        it('fails on invalid rsvp (user ticket)', function (done) {

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            var grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, function (err, rsvp) {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                var body = { rsvp: rsvp };

                var req1 = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req1, body, options, function (err, ticket1) {

                    expect(err).to.not.exist();

                    var req2 = {
                        method: 'POST',
                        url: '/oz/rsvp',
                        headers: {
                            host: 'example.com',
                            authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', ticket1).field
                        }
                    };

                    Oz.endpoints.rsvp(req2, body, options, function (err, ticket2) {

                        expect(err).to.exist();
                        expect(err.message).to.equal('User ticket cannot be used on an application endpoint');
                        done();
                    });
                });
            });
        });

        it('fails on invalid rsvp (mismatching apps)', function (done) {

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            var grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.network, grant, encryptionPassword, {}, function (err, rsvp) {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                var payload = { rsvp: rsvp };

                var req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, function (err, ticket) {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Mismatching ticket and rsvp apps');
                    done();
                });
            });
        });

        it('fails on invalid rsvp (expired rsvp)', function (done) {

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            var grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, { ttl: 1 }, function (err, rsvp) {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                var payload = { rsvp: rsvp };

                var req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, function (err, ticket) {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Expired rsvp');
                    done();
                });
            });
        });

        it('fails on invalid rsvp (expired grant)', function (done) {

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            var grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() - 1000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, function (err, rsvp) {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                var payload = { rsvp: rsvp };

                var req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, function (err, ticket) {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Invalid grant');
                    done();
                });
            });
        });

        it('fails on invalid rsvp (missing grant)', function (done) {

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                },
                ticket: {
                    iron: Iron.defaults
                }
            };

            var grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, function (err, rsvp) {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, null);
                };

                var payload = { rsvp: rsvp };

                var req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, function (err, ticket) {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Invalid grant');
                    done();
                });
            });
        });

        it('fails on invalid rsvp (grant app mismatch)', function (done) {

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                },
                ticket: {
                    iron: Iron.defaults
                }
            };

            var grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, function (err, rsvp) {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    grant.app = apps.network.id;
                    callback(null, grant);
                };

                var payload = { rsvp: rsvp };

                var req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, function (err, ticket) {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Invalid grant');
                    done();
                });
            });
        });

        it('fails on invalid rsvp (grant missing exp)', function (done) {

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                },
                ticket: {
                    iron: Iron.defaults
                }
            };

            var grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, function (err, rsvp) {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    delete grant.exp;
                    callback(null, grant);
                };

                var payload = { rsvp: rsvp };

                var req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, function (err, ticket) {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Invalid grant');
                    done();
                });
            });
        });

        it('fails on invalid rsvp (grant error)', function (done) {

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                },
                ticket: {
                    iron: Iron.defaults
                }
            };

            var grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, function (err, rsvp) {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(new Error('boom'));
                };

                var payload = { rsvp: rsvp };

                var req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, function (err, ticket) {

                    expect(err).to.exist();
                    expect(err.message).to.equal('boom');
                    done();
                });
            });
        });

        it('fails on invalid rsvp (app error)', function (done) {

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                },
                ticket: {
                    iron: Iron.defaults
                }
            };

            var grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, function (err, rsvp) {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                var payload = { rsvp: rsvp };

                var req = {
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

                Oz.endpoints.rsvp(req, payload, options, function (err, ticket) {

                    expect(err).to.exist();
                    expect(err.message).to.equal('nope');
                    done();
                });
            });
        });

        it('fails on invalid rsvp (invalid app)', function (done) {

            var options = {
                encryptionPassword: encryptionPassword,
                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                }
            };

            var grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Oz.hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, function (err, rsvp) {

                expect(err).to.not.exist();

                options.loadGrantFunc = function (id, callback) {

                    callback(null, grant);
                };

                var payload = { rsvp: rsvp };

                var req = {
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

                Oz.endpoints.rsvp(req, payload, options, function (err, ticket) {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Invalid application');
                    done();
                });
            });
        });
    });
});
