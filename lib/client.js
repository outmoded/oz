'use strict';

// Load modules

const Hawk = require('hawk');
const Hoek = require('hoek');


// Declare internals

const internals = {};


// Generate header

exports.header = function (uri, method, ticket, options) {

    const settings = Hoek.shallow(options || {});
    settings.credentials = ticket;
    settings.app = ticket.app;
    settings.dlg = ticket.dlg;

    return Hawk.client.header(uri, method, settings);
};

