// Load modules

var Hawk = require('hawk');
var Hoek = require('hoek');


// Declare internals

var internals = {};


// Generate header

exports.header = function (uri, method, ticket, options) {

    var settings = Hoek.clone(options || {});
    settings.credentials = ticket;
    settings.app = ticket.app;
    settings.dlg = ticket.dlg;

    return Hawk.client.header(uri, method, settings);
};

