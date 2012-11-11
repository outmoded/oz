// Load modules

var Ticket = require('./ticket');


// Declare internals

var internals = {};


exports.Server = internals.Server = function (options) {

    return this;
};






// Reservation from authorization

// Ticket from reservation
// Ticket from username / password
// Ticket from something else

// Server configuration
// Register application






// Authenticate application
/*
Server.prototype.authApp = function (appId, appSecret, callback) {

    this.settings.methods.getApp(appId, function (err, app) {

        if (err) {

            return callback(err);
        }
        
        if (!app) {

            return callback(Err.internal('Invalid application object'));
        }

        if (app.id !== appId) {

            return callback(Err.internal('Application id does not match request'));
        }

        if (app.secret || appSecret &&
            app.secret !== appSecret) {

            return callback(Err.unauthorized('Application secret does not match'));
        }

        callback(null, app);
    });
};


*/

