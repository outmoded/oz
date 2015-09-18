![oz Logo](https://raw.github.com/hueniverse/oz/master/images/oz.png)

Oz is a web authorization protocol based on industry best practices. Oz combines the
[Hawk](https://github.com/hueniverse/hawk) authentication protocol with the
[Iron](https://github.com/hueniverse/iron) encryption protocol to provide a simple to use and
secure solution for granting and authenticating third-party access to an API on behalf of a user or
an application.

Protocol version: **1.0.0**

[![Build Status](https://secure.travis-ci.org/hueniverse/oz.png)](http://travis-ci.org/hueniverse/oz)

## Protocol

Oz builds on the well-understood concepts behind the [OAuth](https://tools.ietf.org/html/rfc5849)
protocol. While the terminology has been updated to reflect the common terms used today when
building applications with third-party access, the overall architecture is the same. This document
assumes the reader is familiar with the OAuth 1.0a protocol workflow.

### Workflow

1. The [application](#application) uses its previously issued [Hawk](https://github.com/hueniverse/hawk)
  credentials to authenticate with the server and request an application [ticket](#ticket). If valid,
  the server issues an application ticket.
2. The application directs the [user](#user) to grant it authorization by providing the user with its
  application identifier. The user authenticates with the server, reviews the authorization
  [grant](#grant)and its [scope](#scope), and if approved the server returns an [rsvp](#rsvp).
3. The user returns to the application with the rsvp which the application uses to request a new
  user-specific ticket. If valid, the server returns a new ticket.
4. The application uses the user-ticket to access the user's protected resources.

### Application

Oz is an application-to-server authorization protocol. This means credentials are issued only to
applications, not to users. The method through which users authenticate is outside the scope of
this protocol.

The application represents a third-party accessing protected resource on the server. This
third-party can be another server, a native app, a single-page-app, or any other application using
web resources. The protected resources can be under the control of the application itself or under
the control of a user who grants the application access.

Each application definition includes:
- `id` - a unique application identifier.
- `scope` - the default application [scope](#scope).

Applications must be registered with the server prior to using Oz. The method through which
applications register is outside the scope of this protocol. When an application registers, it is
issued a set of [Hawk](https://github.com/hueniverse/hawk) credentials. The application uses these
credentials to obtain an Oz [ticket](#ticket).

The application Hawk credentials include:
- `id` - the unique application identifier.
- `key` - a shared secret used to authenticate.
- `algorithm` - the HMAC algorithm used to authenticate (e.g. HMAC-SHA256).

The [Hawk](https://github.com/hueniverse/hawk) protocol supports two Oz-specific header attributes
which are used for authenticating Oz applications (`app` and `dlg`).

### User

Applications act on behalf of users. Users are usually people with protected resources on the
server who would like to use the application to access those protected resources. For the purpose
of the Oz protocol, each user must have a unique identifier which is used by the protocol to record
access rights. The method through which users are registered, authenticated, and managed is beyond
the scope of this protocol.

### Ticket

An Oz ticket is a set of [Hawk](https://github.com/hueniverse/hawk) credentials used by the
application to access protected resources. Just like any other Hawk credentials, the ticket
includes:
- `id` - a unique identifier for the authorized access.
- `key` - a shared secret used to authenticate.
- `algorithm` - the HMAC algorithm used to authenticate (e.g. HMAC-SHA256).

However, unlike most Hawk credential identifiers, the Oz identifier is an encoded
[Iron](https://github.com/hueniverse/iron) string which when decoded contains:
- `exp` - ticket expiration time in milliseconds since 1/1/1970.
- `app` - the application id the ticket was issued to.
- `user` - the user id if the ticket represents access to user resources. If no user id is included,
  the ticket allows the application access to the application own resources only.
- `scope` - the ticket [scope](#scope). Defaults to `[]` if no scope is specified.
- `grant` - if `user` is set, includes the [grant](#grant) identifier referencing the authorization
  granted by the user to the application. Can be a unique identifier or string encoding the grant
  information as long as the server is able to parse the information later.
- `dlg` - if the ticket is the result of access delegation, the application id of the delegating
  application.
- `ext` - custom server data where:
    - `public` - also made available to the application when the ticket is sent back.
    - `private` - available only within the encoded ticket.

When a ticket is generated and sent to the application by the server, the response includes all of
the above properties with the exception of `ext` which is included but only with the content of
`ext.public` if present.

The ticket expiration can be shorter than the grant expiration in which case, the application can
reissue the ticket. This provides the ability to limit the time credentials are valid but allowing
grants to have longer lifetime.

When tickets are reissued, they can be constrained to less scope or duration, and can also be
issued to another application for access delegation.

#### Grant

A grant is the authorization given to an application by a user to access the user's protected
resources. Grants can be persisted in a database (usually to support revocation) or can be self
describing (using an encoded identifier). Each grant contains:
- `id` - the grant identifier, allowing the server to retrieve or recreate the grant information.
- `exp` - authorization expiration time in milliseconds since 1/1/1970.
- `user` - the user id who the user who authorized access.
- `scope` - the authorized [scope](#scope). Defaults to the application scope if no scope is
  specified.

#### Scope

Scope is an array of strings, each represents an implementation-specific permission on the server.
Each scope string adds additional permissions to the application (i.e. `['a', 'b']` grants the
application access to both the `'a'` and `'b'` rights, individually).

Each application has a default scope which is included in the tickets issued to the application
unless the grant specifies a subset of the application scope. Applications cannot be granted scopes
not present in their default set.

#### Rsvp

When the user authorizes the application access request, the server issues an rsvp which is an
encoded string containing the application identifier, the grant identifier, and an expiration.

## API

## `endpoints`

### `app(req, payload, options, callback)`

Generates an application ticket where:
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

### `reissue(req, payload, options, callback)`

Reissue an existing ticket where:
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
