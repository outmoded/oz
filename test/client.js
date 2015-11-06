'use strict';

// Load modules

const Code = require('code');
const Lab = require('lab');
const Oz = require('../lib');


// Declare internals

const internals = {};


// Test shortcuts

const lab = exports.lab = Lab.script();
const describe = lab.experiment;
const it = lab.test;
const expect = Code.expect;


describe('Client', () => {

    describe('header()', () => {

        it('', (done) => {

            const app = {
                id: 'social',
                scope: ['a', 'b', 'c'],
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'sha256'
            };

            const header = Oz.client.header('http://example.com/oz/app', 'POST', app, {}).field;
            expect(header).to.exist();
            done();
        });
    });
});
