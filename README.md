![oz Logo](https://raw.github.com/hueniverse/oz/master/images/oz.png)

A web authorization protocol based on industry best practices. A redo of the original ideas behind OAuth,
providing interoperability and security out-of-the-box.

[![Build Status](https://secure.travis-ci.org/hueniverse/oz.png)](http://travis-ci.org/hueniverse/oz)

# API

## `endpoints`

### `app`
Generates an application ticket.  The `Oz.endpoints.app` function has the signature `(req, payload, options, callback)`.  Here is an explanation of
each parameter:

- `req` - the node.js http server request object.  The following properties are expected to exist on `req`:
    - `method` - HTTP method used, for example: 'POST'.
    - ` url` - path to app endpoint
    - `headers` - HTTP headers with `host` and `authorization` populated.
- `payload` - The raw HTTP request payload string.  Can be null, but a parameter must be provided in this place to the function.
- `options` - the following options are available
    - `encryptionPassword` - secret string used to encrypt the password
    - `ticket` - options to pass to the `Oz.ticket.issue` function.
    - `loadAppFunc` - has the following signature `(id, callback)`.  The callback expects to be called with the following signature `(err, app)`.  The `app`
object is represented below in the [app-object-example].
    - `hawk` - object that represents options to forward to Hawk `authenticate` function.  Refer to the [Hawk](https://github.com/hapijs/hawk)
documentation for the full list of options.
- `callback` - called with the following parameters: `err` and `ticket`


### `reissue`
Reissue an existing ticket.  The `Oz.endpoints.reissue` function has the signature `(req, payload, options, callback)`.  Here is an explanation of
each parameter:

- `req` - the node.js http server request object.  The following properties are expected to exist on `req`:
    - `method` - HTTP method used, for example: 'POST'.
    - ` url` - path to app endpoint
    - `headers` - HTTP headers with `host` and `authorization` populated.
- `payload` - an object representing important payload restrictions.  The following properties are supported
    - `issueTo` - sets the ticket `issueTo` option passed to `Oz.ticket.reissue`
    - `scope` -  ticket scope, represented as an array of strings.
- `options` - the following options are available
    - `encryptionPassword` - secret string used to encrypt the password
    - `ticket` - options to pass to the `Oz.ticket.issue` function.
    - `loadAppFunc` - has the following signature `(id, callback)`.  The callback expects to be called with the following signature `(err, app)`.  The `app`
object is represented below in the [app-object-example].
    - `hawk` - object that represents options to forward to Hawk `authenticate` function.  Refer to the [Hawk](https://github.com/hapijs/hawk)
documentation for the full list of options.
- `callback` - called with the following parameters: `err` and `ticket`


## `ticket`

### `issue`
The `issue` function will create a ticket and pass it to the `callback` function.  The function signature is `(app, grant, encryptionPassword, options, callback)`.

#### `app`
An object representing the object id, scope, and secret, see [app-object-example] below.


#### `grant`
Represents the limitations of the ticket.  The user, scope, and expiration are all set.  See the [grant-object-example] below.

#### `encryptionPassword`


#### `options`
Below are the available options to provide to `options`.

- `ttl` - time to live in milliseconds, defaults to 1 hour
- `scope` -  ticket scope, represented as an array of strings
- `ext` - server extension object with the following properties
    - `tos` - version of terms of service
    - `private` -  anything inside 'private' is only included in the encrypted portion
- `iron` - object to override Iron defaults
- `keyBytes` -  ticket secret size in bytes, defaults to 32
- `hmacAlgorithm`-  Hawk algorithm to use, defaults to `'sha256'`


## `hawk`
Access to the required `hawk` module from `Oz.hawk`.

# Example Objects

## App Object Example

```js
var app = {
    id: '123',                          // Application id
    scope: ['a', 'b']                   // Grant scope
};
```

## Grant Object Example

```js
var grant = {
    id: 'd832d9283hd9823dh',            // Persistent identifier used to issue additional tickets or revoke access
    user: '456',                        // User id
    exp: 1352535473414,                 // Grant expiration
    scope: ['b']                        // Grant scope
};
```
