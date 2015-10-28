/* eslint hapi/hapi-capitalize-modules: "off" */

'use strict';

// Load the environment variables from the .env file
require('dotenv').config();

// Load the server modules
const express = require('express');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const server = express();

// Load Oz
const Oz = require('oz');

// Load the server database
const { loadApp, loadGrant } = require('./server_database');

// Load a secret server-side encryption password
const encryptionPassword = process.env.ENCRYPTION_PASSWORD;

// Declare endpoint options
const endpointOptions = {
    encryptionPassword: encryptionPassword,
    loadAppFunc: loadApp,
    loadGrantFunc: loadGrant
};

// Allow the express server to use body parsing middleware
server.use(bodyParser.urlencoded({ extended: false }));
server.use(morgan('dev'));

// Handle app ticket requests
server.post('/oz/app', (req, res, next) => {

    Oz.endpoints.app(req, null, endpointOptions, (err, ticket) => {

        if (err) {
            return next(err);
        }

        res.json(ticket);
    });
});

// Handle rsvp requests
server.post('/oz/grant', (req, res, next) => {

    const grant = req.body;

    loadApp(grant.app, (err, app) => {

        if (err) {
            return next(err);
        }

        Oz.ticket.rsvp(app, grant, encryptionPassword, {}, (err, rsvp) => {

            if (err) {
                return next(err);
            }

            res.json(rsvp);
        });
    });
});

// Handle user ticket requests
server.post('/oz/rsvp', (req, res, next) => {

    // To demo reissuing an expired user ticket, change the duration to 1 second
    const options = Object.assign({ ticket: { ttl: 1000 } }, endpointOptions);

    Oz.endpoints.rsvp(req, req.body, options, (err, ticket) => {

        if (err) {
            return next(err);
        }

        res.json(ticket);
    });
});

// Handle user ticket reissues
server.post('/oz/reissue', (req, res, next) => {

    Oz.endpoints.reissue(req, {}, endpointOptions, (err, ticket) => {

        if (err) {
            return next(err);
        }

        res.json(ticket);
    });
});

// Handle protected resource requests
server.get('/protected', (req, res, next) => {

    Oz.server.authenticate(req, encryptionPassword, {}, (err, credentials, artifacts) => {

        if (err) {
            return next(err);
        }

        res.json({ message: `${credentials.user}, ${credentials.ext.public} ${credentials.ext.private}` });
    });
});

// Handle unknown routes
server.use((req, res) => {

    res.sendStatus(404);
});

// Handle errors
server.use((err, req, res, next) => {

    if (err.output) {
        return res
          .set(err.output.headers)
          .status(err.output.statusCode)
          .json(err.output.payload);
    }

    console.error(err.stack);
    res.sendStatus(500);
});

// Start the express server
server.listen(8000, () => {

    console.log('Listening on port 8000');
});
