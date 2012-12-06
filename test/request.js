// Load modules

var Chai = require('chai');
var Oz = process.env.TEST_COV ? require('../lib-cov') : require('../lib');


// Declare internals

var internals = {};


// Test shortcuts

var expect = Chai.expect;


describe('Request', function () {

    describe('#authenticate', function () {

        it('should return an error on an expired ticket', function (done) {

            // Note: the ticket.id already encodes all the other ticket attributes and they cannot be manually changed
            
            var encryptionPassword = 'example';

            var ticket = {
                id: '4deee737c1810925ace5aa5292c4e761f2325eb1286bc5c69cbf00b3f5de3abc:eL5Zvd2wyIiMc-6Adk2SUy7i4TjZKLnV_KTUYnTri5Q:a5f7aa17320716247dd18fd87f04e7c0495980b3417d94185f0feb6c052e123e:p1BY4SLSY-5fjKuPSz_GwQ:UDPFp5jLSyYZmGrlD111XxNrZzhvWdU32k_05EjPm4vi0pynvYpGGXYTuuxlEj7hwUR4BOmFumASxvZJVRMMERhCtOjqBwUbU9L8MzI2wYYEryFImSwDkxZAamsG37KH6K1w-rTP-UgP8mVpmboA9-vzwRrlaPzvV19VS7kLGEUeDR8DFzwQpMl2lK-dw4KQPPmsKSGFzxlUO-9hpvWdU6lyTdMYAoy8MPTNCMT4NbgRrjitYV-6YKmhJNHMErzs',
                key: '1a8da59012b3aa2100b900ccef0b6dbd574350e962dd8c176bfddb70aec75cb0',
                algorithm: 'sha256',
                app: '123'
            };
              
            var request = {
                method: 'GET',
                resource: '/path?query',
                host: 'example.com',
                port: 80
            };

            var attributes = {
                ext: '"welcome"'
            };

            var req = {
                method: request.method,
                url: request.resource,
                headers: {
                    authorization: Oz.request.generateHeader(request, ticket, attributes),
                    host: request.host + ':' + request.port
                }
            };
            
            Oz.request.authenticate(req, encryptionPassword, {}, function (err, ticket, ext) {

                expect(err).to.exist;
                done();
            });
        });

        it('should return an error for an invalid authentication header', function (done) {

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

            var attributes = {
                ext: '"welcome"'
            };

            var req = {
                method: request.method,
                url: request.resource,
                headers: {
                    authorization: Oz.request.generateHeader(request, ticket, attributes),
                    host: request.host + ':' + request.port
                }
            };

            Oz.request.authenticate(req, encryptionPassword, {}, function (err, ticket, ext) {

                expect(err).to.exist;
                done();
            });
        });
    });
});


