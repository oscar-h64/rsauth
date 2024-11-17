# RSAuth

A minimal OAuth2 server written in Rust, with an accompanying (opinionated) library for validating tokens and enforcing
roles in Axum handlers.

CI to be written to create amd64 and arm64 Docker images.

## The important bit

1. I am not a security expert
2. I wrote this for fun, because I wanted something simpler than eg IdentityServer to use for some personal projects
   where I didn't want them public but they don't really contain anything really sensitive.
3. While as far as I know, it is secure, I haven't formally verified that, and I didn't spend that much time writing the
   code.
4. Similarly if you look at the code and think "I wouldn't have done that", you're probably right. I wanted to get on
   with writing some more interesting things.

TL;DR: I wrote this quickly, and thought I might as well leave the repo public, but I DO NOT recommend using it in
production or to protect sensitive data, and any use is entirely at your own risk.

Also - at this point I haven't done too much testing in anger yet.

## Server

### Configuration and running

There are five config keys:
- `debug` - whether to enable debug logging - option, defaults to false
- `http_port` - the port the server will listen on - option, defaults to 3001
- `postgres_connection_string` - the connection string for the postgres database - required
- `private_key_path` - the path to the ECDSA private key used to sign JWTs - required
- `public_key_path` - the path to the ECDSA public key used to verify JWTs - required

The keys are read from the following sources in priority order (highest precedence first):
- Environment variables: `RSAUTH__[key]`, eg `RSAUTH__http_port`
- `config.local.toml`: in the CWD, keys at the top level of the file
- `config.toml`: in the CWD, keys at the top level of the file

Postgres migrations are run on startup. If the database is empty then the application will seed an admin client. The ID
and secret are randomly generated GUIDs which are logged in the seeding process. Write them down.

We are using [`jsonwebtoken`](https://docs.rs/jsonwebtoken/latest/jsonwebtoken). If you need to generate a private key
you can use the following command, [as documented](https://docs.rs/jsonwebtoken/latest/jsonwebtoken/struct.EncodingKey.html#method.from_ec_pem):
```bash
openssl ecparam -genkey -noout -name prime256v1 \
    | openssl pkcs8 -topk8 -nocrypt -out keys/private.pem
```

You can create the public key with
```bash
openssl pkey -in keys/private.pem -pubout -out keys/public.pem
```

All requests to the `/management` endpoints requires a valid JWT with the `client_admin` role. The role is created by
seeding process, and given to the seed client.

### Endpoints

#### `POST /authorise`

Standard OAuth2 token endpoint. Only supports the `client_credentials` flow. Credentials can be supplied in the form
body or as basic auth.

#### `GET /management/clients`

Returns a list of all clients.

#### `POST /management/clients`

Creates a new client.

Request:
```json
{
    "clientId": "newclient",
    "clientSecret": "somethingbetterthanthis",
    "disabled": false // disabled clients cannot use /authorise
}
```

#### `GET /management/clients/:client_id`

Returns a specific client.

#### `PATCH /management/clients/:client_id`

Updates a client.

Request (all fields optional, ommission means don't change them):
```json
{
  "clientSecret": null,
  "disabled": true
}
```

#### `GET /management/roles`

Returns a list of all roles.

#### `POST /management/roles`

Creates a new role.

Request:
```json
{
    "roleId": "client_admin",
    "description": "Administrative power of clients" // optional
}
```

#### `GET /management/roles/:role_id`

Returns a specific role.

#### `PATCH /management/roles/:role_id`

Updates a role.

Request:
```json
{
    "description": "Administrative power to manage clients"
}
```

#### `GET /management/clients/:client_id/roles`

Returns a list of role relations for a specific client.

#### `GET /management/clients/:client_id/roles/:role_id`

Returns a specific role relation for a specific client.

#### `PUT /management/clients/:client_id/roles/:role_id`

Creates a role relation for a specific client (won't fail if it already exists).

#### `DELETE /management/clients/:client_id/roles/:role_id`

Deletes a role relation for a specific client.

## Library

The library provides Axum extractors to get the client ID, and to require one of a set of roles. Using either of these
extractors will force there to be a valid token.

Note the library is opinionated. The key must be an ECDSA key, such as used by the server, and issued at/not before/expires at
claims are all required, validated and forced to be "sensible" (not more than 2 hours ago/2 hours in the future). The
extractors also use [tracing](https://docs.rs/tracing/latest/tracing/) to log while extracting.

You will almost always want the `axum-extract` feature. The only time you would not enable it is if you wanted to define
all your roles in a library shared between many services, in which case that library doesn't need to pull in all the
dependencies.

### TODO

I want to add Layers to the library to allow enforcing a token, and optionally roles, at a higher level than per handler,
where it'd be too easy to miss the extractor on one handler.

### Defining roles

You should create a type for your role that implements `Role`. For example:
```rust
pub struct ClientAdminRole;

impl rsauth::Role for ClientAdminRole {
    fn role_id() -> &'static str {
        "client_admin"
    }
}
```

Note that you will of course have to create the role on the server by making a request.

### `Client` extractor

The `Client` extractor provides you the client ID from the validated JWT (or rejects if it isn't valid). If you simply
want to enforce a token without enforcing roles, you can use this extractor and discard the output.

```rust
pub async fn get_clients(
    state: State<StateRef>,
    _: extract::Client,
) -> impl IntoResponse {
    // do work
}

pub async fn get_current_client(
    state: State<StateRef>,
    Client(client_id): extract::Client,
) -> impl IntoResponse {
    // do work
}
```

`client_id` has type `ClientId` which is a newtype wrapper around `String`. You can turn it into a string with
`.to_string()`.

### `RequireRole<T>` extractor

The `RequireRole<T>` extractor is used to validate the provided token, and make sure it has _any_ of the provided roles.

```rust
pub async fn get_clients(
    state: State<StateRef>,
    _: extract::RequireRole<ClientAdminRole>, // single role
) -> impl IntoResponse {
    // do work
}

pub async fn get_clients(
    state: State<StateRef>,
    _: extract::RequireRole<Or<ClientAdminRole, ClientViewerRole>>, // two roles
) -> impl IntoResponse {
    // do work
}
```

You can pass more `Or` as the parameters to `Or` to get more roles, though for readability the library provides `Or3`
and `Or4` for three and 4 roles respectively.
