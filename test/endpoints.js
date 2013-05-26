// Load modules

var Hawk = require('hawk');
var Lab = require('lab');
var Oz = require('../lib');


// Declare internals

var internals = {};


// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;


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
                authorization: Hawk.client.header('http://example.com/oz/app', 'POST', { credentials: apps['social'] }).field
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

    it('fails on invalid app request (bad credentials)', function (done) {

        var req = {
            method: 'POST',
            url: '/oz/app',
            headers: {
                host: 'example.com',
                authorization: Hawk.client.header('http://example.com/oz/app', 'POST', { credentials: apps['social'] }).field
            }
        };

        var options = {
            encryptionPassword: encryptionPassword,
            loadAppFunc: function (id, callback) {

                callback(null, apps.network);
            }
        };

        Oz.endpoints.app(req, null, options, function (err, appTicket) {

            expect(err).to.exist;
            expect(err.message).to.equal('Bad mac');
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

            expect(err).to.exist;
            expect(err.message).to.equal('the value of issueTo is not allowed to be null');
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

            expect(err).to.exist;
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

            expect(err).to.exist;
            expect(err.message).to.equal('Invalid application');
            done();
        });
    });

    it('fails on invalid reissue (invalid grant)', function (done) {

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
            exp: Hawk.utils.now() + 60000
        };

        Oz.ticket.rsvp(apps['social'], grant, encryptionPassword, {}, function (err, rsvp) {

            expect(err).to.not.exist;

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

                expect(err).to.not.exist;

                var req = {
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

                Oz.endpoints.reissue(req, {}, options, function (err, delegatedTicket) {

                    expect(err).to.exist;
                    expect(err.message).to.equal('Invalid grant');
                    done();
                });
            });
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
            exp: Hawk.utils.now() + 60000
        };

        Oz.ticket.rsvp(apps['social'], grant, encryptionPassword, {}, function (err, rsvp) {

            expect(err).to.not.exist;

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

                expect(err).to.exist;
                expect(err.message).to.equal('the value of rsvp is not allowed to be ');
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
            exp: Hawk.utils.now() + 60000
        };

        Oz.ticket.rsvp(apps['social'], grant, encryptionPassword, {}, function (err, rsvp) {

            expect(err).to.not.exist;

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

                expect(err).to.exist;
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
            exp: Hawk.utils.now() + 60000
        };

        Oz.ticket.rsvp(apps['social'], grant, encryptionPassword, {}, function (err, rsvp) {

            expect(err).to.not.exist;

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

                expect(err).to.not.exist;

                var payload = { rsvp: rsvp };

                var req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', ticket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, function (err, ticket) {

                    expect(err).to.exist;
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
            exp: Hawk.utils.now() + 60000
        };

        Oz.ticket.rsvp(apps['network'], grant, encryptionPassword, {}, function (err, rsvp) {

            expect(err).to.not.exist;

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

                expect(err).to.exist;
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
            exp: Hawk.utils.now() + 60000
        };

        Oz.ticket.rsvp(apps['social'], grant, encryptionPassword, { ttl: 1 }, function (err, rsvp) {

            expect(err).to.not.exist;

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

                expect(err).to.exist;
                expect(err.message).to.equal('Expired rsvp');
                done();
            });
        });
    });

    it('fails on invalid rsvp (invalid grant)', function (done) {

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
            exp: Hawk.utils.now() - 1000
        };

        Oz.ticket.rsvp(apps['social'], grant, encryptionPassword, {}, function (err, rsvp) {

            expect(err).to.not.exist;

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

                expect(err).to.exist;
                expect(err.message).to.equal('Invalid grant');
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
            exp: Hawk.utils.now() + 60000
        };

        Oz.ticket.rsvp(apps['social'], grant, encryptionPassword, {}, function (err, rsvp) {

            expect(err).to.not.exist;

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

                expect(err).to.exist;
                expect(err.message).to.equal('Invalid application');
                done();
            });
        });
    });

    it('runs a full authorization flow', function (done) {

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

        // The app requests an app ticket using Basic authentication

        var req = {
            method: 'POST',
            url: '/oz/app',
            headers: {
                host: 'example.com',
                authorization: Hawk.client.header('http://example.com/oz/app', 'POST', { credentials: apps['social'] }).field
            }
        };

        var options = {
            encryptionPassword: encryptionPassword,
            loadAppFunc: function (id, callback) {

                callback(null, apps[id]);
            }
        };

        Oz.endpoints.app(req, null, options, function (err, appTicket) {

            expect(err).to.not.exist;

            // The user is redirected to the server, logs in, and grant app access, resulting in an rsvp

            var grant = {
                id: 'a1b2c3d4e5f6g7h8i9j0',
                app: appTicket.app,
                user: 'john',
                exp: Hawk.utils.now() + 60000
            };

            Oz.ticket.rsvp(apps['social'], grant, encryptionPassword, {}, function (err, rsvp) {

                expect(err).to.not.exist;

                // After granting app access, the user returns to the app with the rsvp

                options.loadGrantFunc = function (id, callback) {

                    var ext = {
                        public: 'everybody knows',
                        private: 'the the dice are loaded'
                    };

                    callback(null, grant, ext);
                };

                // The app exchanges the rsvp for a ticket

                var payload = { rsvp: rsvp };

                req = {
                    method: 'POST',
                    url: '/oz/rsvp',
                    headers: {
                        host: 'example.com',
                        authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                    }
                };

                Oz.endpoints.rsvp(req, payload, options, function (err, ticket) {

                    expect(err).to.not.exist;

                    // The app reissues the ticket with delegation to another app

                    payload = {
                        issueTo: apps.network.id
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

                        expect(err).to.not.exist;

                        // The other app reissues their ticket

                        req = {
                            method: 'POST',
                            url: '/oz/reissue',
                            headers: {
                                host: 'example.com',
                                authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', delegatedTicket).field
                            }
                        };

                        Oz.endpoints.reissue(req, {}, options, function (err, reissuedDelegatedTicket) {

                            expect(err).to.not.exist;
                            done();
                        });
                    });
                });
            });
        });
    });
});


