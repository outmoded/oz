/* eslint hapi/hapi-capitalize-modules: "off" */

'use strict';

// Load client modules
const request = require('request');

// Load Oz
const Oz = require('oz');

// Load the client database
const { loadApp, loadGrant } = require('./client_database');

// Send unauthenticated request
request('http://0.0.0.0:8000/protected', (err, res, body) => {

    if (err) {
        throw err;
    }

    console.log(res.statusCode, JSON.parse(body));
});

// Send fully authenticated request
loadApp('8e185772-d76c-4bf9-b104-1a747b5ca1ee', (err, app) => {

    if (err) {
        throw err;
    }

    let header = Oz.client.header('http://0.0.0.0:8000/oz/app', 'POST', app);

    let options = {
        uri: 'http://0.0.0.0:8000/oz/app',
        method: 'POST',
        headers: { authorization: header.field }
    };

    request(options, (err, appRes, appBody) => {

        if (err) {
            throw err;
        }

        console.log(appRes.statusCode, JSON.parse(appBody));

        const appTicket = JSON.parse(appBody);

        loadGrant('718e2207-be0b-4a07-a222-3b3ab99eccc6', (err, grant) => {

            if (err) {
                throw err;
            }

            options = {
                uri: 'http://0.0.0.0:8000/oz/grant',
                method: 'POST',
                form: grant
            };

            request(options, (err, grantRes, grantBody) => {

                if (err) {
                    throw err;
                }

                console.log(grantRes.statusCode, JSON.parse(grantBody));

                const rsvp = JSON.parse(grantBody);

                header = Oz.client.header(
                    'http://0.0.0.0:8000/oz/rsvp',
                    'POST',
                    appTicket
                );

                options = {
                    uri: 'http://0.0.0.0:8000/oz/rsvp',
                    method: 'POST',
                    headers: { authorization: header.field },
                    form: { rsvp: rsvp }
                };

                request(options, (err, rsvpRes, rsvpBody) => {

                    if (err) {
                        throw err;
                    }

                    console.log(rsvpRes.statusCode, JSON.parse(rsvpBody));

                    const userTicket = JSON.parse(rsvpBody);

                    header = Oz.client.header(
                        'http://0.0.0.0:8000/protected',
                        'GET',
                        userTicket
                    );

                    options = {
                        uri: 'http://0.0.0.0:8000/protected',
                        method: 'GET',
                        headers: { authorization: header.field }
                    };

                    request(options, (err, protRes, protBody) => {

                        if (err) {
                            throw err;
                        }

                        console.log(protRes.statusCode, JSON.parse(protBody));

                        setTimeout(reissueWorkflow, 1000, userTicket);
                    });
                });
            });
        });
    });
});

const reissueWorkflow = (expiredUserTicket) => {

    let header = Oz.client.header(
        'http://0.0.0.0:8000/protected',
        'GET',
        expiredUserTicket
    );

    let options = {
        uri: 'http://0.0.0.0:8000/protected',
        method: 'GET',
        headers: { authorization: header.field }
    };

    request(options, (err, expRes, expBody) => {

        if (err) {
            throw err;
        }

        console.log(expRes.statusCode, JSON.parse(expBody));

        header = Oz.client.header(
            'http://0.0.0.0:8000/oz/reissue',
            'POST',
            expiredUserTicket
        );

        options = {
            uri: 'http://0.0.0.0:8000/oz/reissue',
            method: 'POST',
            headers: { authorization: header.field }
        };

        request(options, (err, reissueRes, reissueBody) => {

            if (err) {
                throw err;
            }

            console.log(reissueRes.statusCode, JSON.parse(reissueBody));

            const userTicket = JSON.parse(reissueBody);

            header = Oz.client.header(
                'http://0.0.0.0:8000/protected',
                'GET',
                userTicket
            );

            options = {
                uri: 'http://0.0.0.0:8000/protected',
                method: 'GET',
                headers: { authorization: header.field }
            };

            request(options, (err, protRes, protBody) => {

                if (err) {
                    throw err;
                }

                console.log(protRes.statusCode, JSON.parse(protBody));
            });
        });
    });
};
