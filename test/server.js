// Load modules

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


describe('Server', function () {

    describe('#authenticate', function () {

        it('returns an error on missing password', function (done) {

            Oz.server.authenticate(null, null, {}, function (err, ticket, ext) {

                expect(err).to.exist;
                expect(err.message).to.equal('Invalid encryption password');
                done();
            });
        });

        it('returns an error on an expired ticket', function (done) {

            // Note: the ticket.id already encodes all the other ticket attributes and they cannot be manually changed
            
            var encryptionPassword = 'example';

            var ticket = {
                id: '4deee737c1810925ace5aa5292c4e761f2325eb1286bc5c69cbf00b3f5de3abc:eL5Zvd2wyIiMc-6Adk2SUy7i4TjZKLnV_KTUYnTri5Q:a5f7aa17320716247dd18fd87f04e7c0495980b3417d94185f0feb6c052e123e:p1BY4SLSY-5fjKuPSz_GwQ:UDPFp5jLSyYZmGrlD111XxNrZzhvWdU32k_05EjPm4vi0pynvYpGGXYTuuxlEj7hwUR4BOmFumASxvZJVRMMERhCtOjqBwUbU9L8MzI2wYYEryFImSwDkxZAamsG37KH6K1w-rTP-UgP8mVpmboA9-vzwRrlaPzvV19VS7kLGEUeDR8DFzwQpMl2lK-dw4KQPPmsKSGFzxlUO-9hpvWdU6lyTdMYAoy8MPTNCMT4NbgRrjitYV-6YKmhJNHMErzs',
                key: '1a8da59012b3aa2100b900ccef0b6dbd574350e962dd8c176bfddb70aec75cb0',
                algorithm: 'sha256',
                app: '123'
            };

            var req = {
                method: 'GET',
                url: '/path?query',
                headers: {
                    authorization: Oz.client.header('http://example.com/path?query', 'GET', ticket, { ext: 'welcome' }).field,
                    host: 'example.com:80'
                }
            };
            
            Oz.server.authenticate(req, encryptionPassword, {}, function (err, ticket, ext) {

                expect(err).to.exist;
                expect(err.message).to.equal('');
                done();
            });
        });

        it('returns an error for an invalid authentication header', function (done) {

            // Note: the ticket.id already encodes all the other ticket attributes and they cannot be manually changed

            var encryptionPassword = 'example';

            var ticket = {
                id: '4deee737c1810925ace5aa5292c4e761f2325eb1286bc5c69cbf00b3f5de3abc:eL5Zvd2wyIiMc-6Adk2SUy7i4TjZKLnV_KTUYnTri5Q:a5f7aa17320716247dd18fd87f04e7c0495980b3417d94185f0feb6c052e123e:p1BY4SLSY-5fjKuPSz_GwQ:UDPFp5jLSyYZmGrlD111XxNrZzhvWdU32k_05EjPm4vi0pynvYpGGXYTuuxlEj7hwUR4BOmFumASxvZJVRMMERhCtOjqBwUbU9L8MzI2wYYEryFImSwDkxZAamsG37KH6K1w-rTP-UgP8mVpmboA9-vzwRrlaPzvV19VS7kLGEUeDR8DFzwQpMl2lK-dw4KQPPmsKSGFzxlUO-9hpvWdU6lyTdMYAoy8MPTNCMT4NbgRrjitYV-6YKmhJNHMErzs',
                key: 'wrong',
                algorithm: 'sha256',
                app: '123'
            };

            var request = {
                method: 'GET',
                resource: '/path?query',
                host: 'example.com',
                port: 80
            };

            var req = {
                method: request.method,
                url: request.resource,
                headers: {
                    authorization: Oz.client.header('http://example.com/path?query', 'GET', ticket).field,
                    host: request.host + ':' + request.port
                }
            };

            Oz.server.authenticate(req, encryptionPassword, {}, function (err, ticket, ext) {

                expect(err).to.exist;
                done();
            });
        });
    });
});

