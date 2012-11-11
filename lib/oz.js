// Declare internals

var internals = {
    modules: {
        crypto: require('./crypto'),
        request: require('./request'),
        ticket: require('./ticket'),
        rsvp: require('./rsvp'),
        settings: require('./settings'),
        error: require('./error'),
        utils: require('./utils')
    }
};


// Export public modules

internals.export = function () {

    for (var key in internals.modules) {
        if (internals.modules.hasOwnProperty(key)) {
            exports[key] = exports[key.charAt(0).toUpperCase() + key.slice(1)] = internals.modules[key];
        }
    }
};

internals.export();

