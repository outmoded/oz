var assert = require('assert');
var should = require('should');
var sinon = require('sinon');
var Oz = require('../lib/oz');


describe('oz', function () {

    describe('#http', function () {

        it('should construct and parse a valid authentication header', function (done) {

            var ticket = {
                id: '4deee737c1810925ace5aa5292c4e761f2325eb1286bc5c69cbf00b3f5de3abc:eL5Zvd2wyIiMc-6Adk2SUy7i4TjZKLnV_KTUYnTri5Q:a5f7aa17320716247dd18fd87f04e7c0495980b3417d94185f0feb6c052e123e:p1BY4SLSY-5fjKuPSz_GwQ:UDPFp5jLSyYZmGrlD111XxNrZzhvWdU32k_05EjPm4vi0pynvYpGGXYTuuxlEj7hwUR4BOmFumASxvZJVRMMERhCtOjqBwUbU9L8MzI2wYYEryFImSwDkxZAamsG37KH6K1w-rTP-UgP8mVpmboA9-vzwRrlaPzvV19VS7kLGEUeDR8DFzwQpMl2lK-dw4KQPPmsKSGFzxlUO-9hpvWdU6lyTdMYAoy8MPTNCMT4NbgRrjitYV-6YKmhJNHMErzs',
                key: '1a8da59012b3aa2100b900ccef0b6dbd574350e962dd8c176bfddb70aec75cb0',
                algorithm: 'sha256'
            };
              
            var request = {
                method: 'GET',
                resource: '/path?query',
                host: 'example.com',
                port: 80
            };

            var attributes = {
                ts: Date.now(),
                ext: 'welcome'
            };

            var mac = Oz.Request.mac(request, attributes, ticket);
            var header = Oz.Http.formatHeader(attributes, ticket.id, mac);

            var req = {
                method: request.method,
                url: request.resource,
                headers: {
                    authorization: header,
                    host: request.host + ':' + request.port
                }
            };
            
            Oz.Http.authenticate(req, {}, function (err, ticket, attributes) {

                should.not.exist(err);
                attributes.ext.should.equal('welcome');
                done();
            });
        });
    });
});


