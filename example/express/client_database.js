'use strict';

// Declare apps with unique IDs and isomorphic, 512-bit secret keys
const apps = {
    '8e185772-d76c-4bf9-b104-1a747b5ca1ee': {
        id: '8e185772-d76c-4bf9-b104-1a747b5ca1ee',
        key: 'rSUNTr5gXhl49eR5EYNmqOjATQB7VANGza3S7DBa14bYrCKKh4DGgiyhOBMxMF74',
        algorithm: 'sha256'
    }
};

// Declare grants with unique IDs
const grants = {
    '718e2207-be0b-4a07-a222-3b3ab99eccc6': {
        id: '718e2207-be0b-4a07-a222-3b3ab99eccc6',
        app: '8e185772-d76c-4bf9-b104-1a747b5ca1ee'
    }
};

// Declare an app lookup function
const loadApp = (id, callback) => {

    return callback(null, apps[id]);
};

// Declare a grant lookup function
const loadGrant = (id, callback) => {

    callback(null, grants[id]);
};

module.exports = { loadApp, loadGrant };
