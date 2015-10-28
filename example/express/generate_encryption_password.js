/* eslint hapi/hapi-capitalize-modules: "off" */

'use strict';

const fs = require('fs');
const crypto = require('crypto');

// Generate a 256-bit encryption password
const password = crypto.randomBytes(32).toString('hex');

fs.writeFileSync('.env', `ENCRYPTION_PASSWORD=${password}\n`);
