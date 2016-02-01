![oz Logo](https://raw.github.com/hueniverse/oz/master/images/oz.png)

Oz is a web authorization protocol based on industry best practices. Oz combines the
[Hawk](https://github.com/hueniverse/hawk) authentication protocol with the
[Iron](https://github.com/hueniverse/iron) encryption protocol to provide a simple to use and
secure solution for granting and authenticating third-party access to an API on behalf of a user or
an application.

Protocol version: **4.0.0** (Same as v1.0.0 but moved the expired ticket indicator from a header
attribute to the error payload).

[![Build Status](https://secure.travis-ci.org/hueniverse/oz.png)](http://travis-ci.org/hueniverse/oz)

- [Protocol](#protocol)
  - [Workflow](#workflow)
  - [Application](#application)
  - [User](#user)
  - [Ticket](#ticket)
    - [Grant](#grant)
    - [Scope](#scope)
    - [Rsvp](#rsvp)
- [API](#api)
  - [Shared objects](#shared-objects)
    - [`app` object](#app-object)
    - [`grant` object](#grant-object)
    - [`ticket` response](#ticket-response)
  - [`Oz.client`](#ozclient)
    - [`Oz.client.header(uri, method, ticket, [options])`](#ozclientheaderuri-method-ticket-options)
    - [`new Oz.client.Connection(options)`](#new-ozclientconnectionoptions)
      - [`connection.request(path, ticket, options, callback)`](#connectionrequestpath-ticket-options-callback)
      - [`connection.app(path, options, callback)`](#connectionapppath-options-callback)
      - [`connection.reissue(ticket, callback)`](#connectionreissueticket-callback)
  - [`Oz.endpoints`](#ozendpoints)
    - [Endpoints options](#endpoints-options)
      - [`encryptionPassword`](#encryptionpassword)
      - [`loadAppFunc`](#loadappfunc)
      - [`loadGrantFunc`](#loadgrantfunc)
    - [`endpoints.app(req, payload, options, callback)`](#endpointsappreq-payload-options-callback)
    - [`endpoints.reissue(req, payload, options, callback)`](#endpointsreissuereq-payload-options-callback)
    - [`endpoints.rsvp(req, payload, options, callback)`](#endpointsrsvpreq-payload-options-callback)
  - [`Oz.hawk`](#ozhawk)
  - [`Oz.scope`](#ozscope)
    - [`Oz.scope.validate(scope)`](#ozscopevalidatescope)
    - [`Oz.scope.isSubset(scope, subset)`](#ozscopeissubsetscope-subset)
  - [`Oz.server`](#ozserver)
    - [`Oz.server.authenticate(req, encryptionPassword, options, callback)`](#ozserverauthenticatereq-encryptionpassword-options-callback)
  - [`Oz.ticket`](#ozticket)
    - [Ticket options](#ticket-options)
    - [`ticket.issue(app, grant, encryptionPassword, options, callback)`](#ticketissueapp-grant-encryptionpassword-options-callback)
    - [`ticket.reissue(parentTicket, grant, encryptionPassword, options, callback)`](#ticketreissueparentticket-grant-encryptionpassword-options-callback)
    - [`ticket.rsvp(app, grant, encryptionPassword, options, callback)`](#ticketrsvpapp-grant-encryptionpassword-options-callback)
    - [`ticket.generate(ticket, encryptionPassword, options, callback)`](#ticketgenerateticket-encryptionpassword-options-callback)
    - [`ticket.parse(id, encryptionPassword, options, callback)`](#ticketparseid-encryptionpassword-options-callback)

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
  [grant](#grant) and its [scope](#scope), and if approved the server returns an [rsvp](#rsvp).
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
- `delegate` - if `true`, the application is allowed to delegate a ticket to another application.
  Defaults to `false`.

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
- `delegate` - if `false`, the ticket cannot be delegated regardless of the application permissions.
  Defaults to `true` which means use the application permissions to delegate.
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

The Oz public API is offered as a full toolkit to implement the protocol as-is or to modify it to
fit custom security needs. Most implementations will only need to use the [endpoints functions](#ozendpoints)
methods and the [`ticket.rsvp()`](#ticketrsvpapp-grant-encryptionPassword-options-callback) method
directly.

### Shared objects

#### `app` object

An object describing an application where:
- `id` - the application identifier.
- `scope` - an array with the default application scope.
- `delegate` - if `true`, the application is allowed to delegate a ticket to another application.
  Defaults to `false`.
- `key` - the shared secret used to authenticate.
- `algorithm` - the HMAC algorithm used to authenticate (e.g. HMAC-SHA256).

#### `grant` object

An object describing a user grant where:
- `id` - the grant identifier.
- `app` - the application identifier.
- `user` - the user identifier.
- `exp` - grant expiration time in milliseconds since 1/1/1970.
- `scope` - an array with the scope granted by the user to the application.

#### `ticket` response

An object describing a ticket and its public properties:
- `id` - the ticket identifier used for making authenticated Hawk requests.
- `key` - a shared secret used to authenticate.
- `algorithm` - the HMAC algorithm used to authenticate (e.g. HMAC-SHA256).
- `exp` - ticket expiration time in milliseconds since 1/1/1970.
- `app` - the application id the ticket was issued to.
- `user` - the user id if the ticket represents access to user resources. If no user id is
  included, the ticket allows the application access to the application own resources only.
- `scope` - the ticket [scope](#scope). Defaults to `[]` if no scope is specified.
- `grant` - if `user` is set, includes the [grant](#grant) identifier referencing the authorization
    granted by the user to the application. Can be a unique identifier or string encoding the grant
    information as long as the server is able to parse the information later.
- `delegate` - if `false`, the ticket cannot be delegated regardless of the application permissions.
  Defaults to `true` which means use the application permissions to delegate.
- `dlg` - if the ticket is the result of access delegation, the application id of the delegating
    application.
- `ext` - custom server public data attached to the ticket.

### `Oz.client`

Utilities used for making authenticated Oz requests.

#### `Oz.client.header(uri, method, ticket, [options])`

A convenience utility to generate the application Hawk request authorization header for making
authenticated Oz requests where:
- `uri` - the request URI.
- `method` - the request HTTP method.
- `ticket` - the authorization [ticket](#ticket-response).
- `options` - additional Hawk `Hawk.client.header()` options.

#### `new Oz.client.Connection(options)`

Creates an **oz** client connection manager for easier access to protected resources. The client
manages the ticket lifecycle and will automatically refresh the ticken when expired. Accepts the
following options:
- `endpoints` - an object containing the server protocol endpoints:
    `app` - the application credentials endpoint path. Defaults to `'/oz/app'`.
    `reissue` - the ticket reissue endpoint path. Defaults to `'/oz/reissue'`.
- `uri` - required, the server full root uri without path (e.g. 'https://example.com').
- `credentials` - required, the application **hawk** credentials.

##### `connection.request(path, ticket, options, callback)`

Requests a protected resource where:
- `path` - the resource path (e.g. '/resource').
- `ticket` - the application or user ticket. If the ticket is expired, it will automatically
  attempt to refresh it.
- `options` - optional configuration object where:
    - `method` - the HTTP method (e.g. 'GET'). Defaults to `'GET'`.
    - `payload` - the request payload object or string. Defaults to no payload.
- `callback` - the callback method using the signature `function(err, result, code, ticket)` where:
    - `err` - an error condition.
    - `result` - the requested resource (parsed to object if JSON).
    - `code` - the HTTP response code.
    - `ticket` - the ticket used to make the request (may be different from the ticket provided
      when the ticket was expired and refreshed).

##### `connection.app(path, options, callback)`

Requests a protected resource using a shared application ticket where:
- `path` - the resource path (e.g. '/resource').
- `options` - optional configuration object where:
    - `method` - the HTTP method (e.g. 'GET'). Defaults to `'GET'`.
    - `payload` - the request payload object or string. Defaults to no payload.
- `callback` - the callback method using the signature `function(err, result, code, ticket)` where:
    - `err` - an error condition.
    - `result` - the requested resource (parsed to object if JSON).
    - `code` - the HTTP response code.
    - `ticket` - the ticket used to make the request (may be different from the ticket provided
      when the ticket was expired and refreshed).

Once an application ticket is obtained internally using the provided **hawk** credentials in the
constructor, it will be reused by called to `connection.app()`. If it expires, it will
automatically refresh and stored for future usage.

##### `connection.reissue(ticket, callback)`

Reissues (refresh) a ticket where:
- `ticket` - the ticket being reissued.
- `callback` - the callback method using the signature `function(err, reissued)` where:
    - `err` - an error condition.
    - `reissued` - the reissued ticket.

### `Oz.endpoints`

The endpoint methods provide a complete HTTP request handler implementation which is designed to
be plugged into an HTTP framework such as [**hapi**](http://hapijs.com). The
[**scarecrow**](https://github.com/hueniverse/scarecrow) plugin provides an example of how these
methods integrate with an existing server implementation.

#### Endpoints options

Each endpoint method accepts a set of options.

##### `encryptionPassword`

A required string used to generate the ticket encryption key. Must be kept confidential. The string
must be the same across all Oz methods and deployments in order to allow the server to parse and
generate compatible encoded strings.

The `encryptionPassword` value is passed directly to the [Iron](https://github.com/hueniverse/iron)
module which supports additional inputs for pre-generated encryption and integrity keys as well as
password rotation.

##### `loadAppFunc`

The application lookup method using the signature `function(id, next)` where:
- `id` - the application identifier being requested.
- `next` - the callback method used to return the requested application using the signature
    `function(err, app)` where:
    - `err` - an error condition.
    - `app` - an [application](#app-object) object.

##### `loadGrantFunc`

The grant lookup method using the signature `function(id, next)` where:
- `id` - the grant identifier being requested.
- `next` - the callback method used to return the requested grant using the signature
    `function(err, grant, ext)` where:
    - `err` - an error condition.
    - `grant` - a [grant](#grant-object) object.
    - `ext` - an object used to include custom server data in the ticket and response where:
        - `public` - an object which is included in the response under `ticket.ext` and in
            the encoded ticket as `ticket.ext.public`.
        - `private` - an object which is included only in the encoded ticket as
            `ticket.ext.private`.

#### `endpoints.app(req, payload, options, callback)`

Authenticates an application request and if valid, issues an application ticket where:
- `req` - the node HTTP server request object.
- `payload` - this argument is ignored and is defined only to keep the endpoint method signature
  consistent with the other endpoints.
- `options` - protocol [configuration](#endpoints-options) options where:
    - `encryptionPassword` - required.
    - `loadAppFunc` - required.
    - `ticket` - optional [ticket options](#ticket-options) used for parsing and issuance.
    - `hawk` - optional [Hawk](https://github.com/hueniverse/hawk) configuration object. Defaults to
      the Hawk defaults.
- `callback` - the method used to return the request result with signature `function(err, ticket)` where:
    - `err` - an error condition.
    - `ticket` - a [ticket response](#ticket-response) object.
        
#### `endpoints.reissue(req, payload, options, callback)`

Reissue an existing ticket (the ticket used to authenticate the request) where:
- `req` - the node HTTP server request object.
- `payload` - The HTTP request payload fully parsed into an object with the following optional keys:
    - `issueTo` - a different application identifier than the one of the current application. Used
      to delegate access between applications. Defaults to the current application.
    - `scope` - an array of scope strings which must be a subset of the ticket's granted scope.
      Defaults to the original ticket scope.
- `options` - protocol [configuration](#endpoints-options) options where:
    - `encryptionPassword` - required.
    - `loadAppFunc` - required.
    - `loadGrantFunc` - required.
    - `ticket` - optional [ticket options](#ticket-options) used for parsing and issuance.
    - `hawk` - optional [Hawk](https://github.com/hueniverse/hawk) configuration object. Defaults to
      the Hawk defaults.
- `callback` - the method used to return the request result with signature `function(err, ticket)` where:
    - `err` - an error condition.
    - `ticket` - a [ticket response](#ticket-response) object.

#### `endpoints.rsvp(req, payload, options, callback)`

Authenticates an application request and if valid, exchanges the provided rsvp with a ticket where:
- `req` - the node HTTP server request object.
- `payload` - The HTTP request payload fully parsed into an object with the following keys:
    - `rsvp` - the required rsvp string provided to the user to bring back to the application after
      granting authorization.
- `options` - protocol [configuration](#endpoints-options) options where:
    - `encryptionPassword` - required.
    - `loadAppFunc` - required.
    - `loadGrantFunc` - required.
    - `ticket` - optional [ticket options](#ticket-options) used for parsing and issuance.
    - `hawk` - optional [Hawk](https://github.com/hueniverse/hawk) configuration object. Defaults to
      the Hawk defaults.
- `callback` - the method used to return the request result with signature `function(err, ticket)` where:
    - `err` - an error condition.
    - `ticket` - a [ticket response](#ticket-response) object.

### `Oz.hawk`

Provides direct access to the underlying [Hawk](https://github.com/hueniverse/hawk) module.

### `Oz.scope`

Scope manipulation utilities.

#### `Oz.scope.validate(scope)`

Validates a scope for proper structure (an array of unique strings) where:
- `scope` - the array being validated.

Returns an `Error` is the scope failed validation, otherwise `null` for valid scope.

#### `Oz.scope.isSubset(scope, subset)`

Checks whether a scope is a subset of another where:
- `scope` - the superset.
- `subset` - the subset.

Returns `true` if the `subset` is fully contained with `scope`, otherwise `false.

### `Oz.server`

Server implementation utilities.

#### `Oz.server.authenticate(req, encryptionPassword, options, callback)`

Authenticates an incoming request using [Hawk](https://github.com/hueniverse/hawk) and performs
additional Oz-specific validations where:
Authenticates an application request and if valid, issues an application ticket where:
- `req` - the node HTTP server request object.
- `encryptionPassword` - the ticket [encryption password](#encryptionPassword).
- `options` - protocol [configuration](#endpoints-options) options where:
    - `ticket` - optional [ticket options](#ticket-options) used for parsing and issuance.
    - `hawk` - optional [Hawk](https://github.com/hueniverse/hawk) configuration object. Defaults to
      the Hawk defaults.
- `callback` - the method used to return the request result with signature
  `function(err, credentials, artifacts)` where:
    - `err` - an error condition.
    - `credentials` - the decoded [ticket response](#ticket-response) object.
    - `artifacts` - Hawk protocol artifacts.

### `Oz.ticket`

Ticket issuance, parsing, encoding, and re-issuance utilities.

#### Ticket options

The following are the supported ticket parsing and issuance options passed to the corresponding
ticket methods. Each endpoint utilizes a different subset of these options but it is safe to pass
one common object to all (it will ignore unused options):
- `ttl` - when generating a ticket, sets the ticket lifetime in milliseconds. Defaults to
    `3600000` (1 hour) for tickets and `60000` (1 minutes) for rsvps.
- `delegate` - if `false`, the ticket cannot be delegated regardless of the application permissions.
  Defaults to `true` which means use the application permissions to delegate.
- `iron` - overrides the default [Iron](https://github.com/hueniverse/iron) configuration.
- `keyBytes` - the [Hawk](https://github.com/hueniverse/hawk) key length in bytes. Defaults to
    `32`.
- `hmacAlgorithm` - the [Hawk](https://github.com/hueniverse/hawk) HMAC algorithm. Defaults to
    `sha256`.
- `ext` - an object used to provide custom server data to be included in the ticket (this option
    will be ignored when passed to an endpoint method and the `loadGrantFunc` function returns an
    `ext` value in the callback) where:
    - `public` - an object which is included in the response under `ticket.ext` and in
        the encoded ticket as `ticket.ext.public`.
    - `private` - an object which is included only in the encoded ticket as
        `ticket.ext.private`.

#### `ticket.issue(app, grant, encryptionPassword, options, callback)`

Issues a new application or user ticket where:
- `app` - the application [object](#app-object) the ticket is being issued to.
- `grant` - the grant [object](#grant-object) the ticket is being issued with if the ticket
  represents user access. `null` if the ticket is an application-only ticket.
- `encryptionPassword` - the ticket [encryption password](#encryptionPassword).
- `options` - ticket generation [options](#ticket-options).
- `callback` - the callback method using signature `function(err, ticket)` where:
    - `err` - an error condition.
    - `ticket` - a [ticket response](#ticket-response) object.

#### `ticket.reissue(parentTicket, grant, encryptionPassword, options, callback)`

Reissues a application or user ticket where:
- `parentTicket` - the [ticket](#ticket-response) object being reissued.
- `grant` - the grant [object](#grant-object) the ticket is being issued with if the ticket
  represents user access. `null` if the ticket is an application-only ticket.
- `encryptionPassword` - the ticket [encryption password](#encryptionPassword).
- `options` - ticket generation [options](#ticket-options).
- `callback` - the callback method using signature `function(err, ticket)` where:
    - `err` - an error condition.
    - `ticket` - a [ticket response](#ticket-response) object.

#### `ticket.rsvp(app, grant, encryptionPassword, options, callback)`

Generates an rsvp string representing a user grant where:
- `app` - the application [object](#app-object) the ticket is being issued to.
- `grant` - the grant [object](#grant-object) the ticket is being issued with if the ticket
  represents user access. `null` if the ticket is an application-only ticket.
- `encryptionPassword` - the ticket [encryption password](#encryptionPassword).
- `options` - ticket generation [options](#ticket-options).
- `callback` - the callback method using signature `function(err, rsvp)` where:
    - `err` - an error condition.
    - `rsvp` - the rsvp string.

#### `ticket.generate(ticket, encryptionPassword, options, callback)`

Adds the cryptographic properties to a ticket and prepares the response where:
- `ticket` - an incomplete [ticket](#ticket-response) object with the following:
    - `exp`
    - `app`
    - `user`
    - `scope`
    - `grant`
    - `dlg`
- `encryptionPassword` - the ticket [encryption password](#encryptionPassword).
- `options` - ticket generation [options](#ticket-options).
- `callback` - the callback method using signature `function(err, ticket)` where:
    - `err` - an error condition.
    - `ticket` - the completed [ticket response](#ticket-response) object.

#### `ticket.parse(id, encryptionPassword, options, callback)`

Decodes a ticket identifier into a ticket response where:
- `id` - the ticket id which contains the encoded ticket information.
- `encryptionPassword` - the ticket [encryption password](#encryptionPassword).
- `options` - ticket generation [options](#ticket-options).
- `callback` - the callback method using signature `function(err, ticket)` where:
    - `err` - an error condition.
    - `ticket` - a [ticket response](#ticket-response) object.
