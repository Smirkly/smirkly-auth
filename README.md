# smirkly-auth

Authentication service for Smirkly built with C++20 and userver.

The service handles registration, email verification, sign-in, token refresh,
sessions, password changes, and password recovery.

## API

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/auth/v0/sign-up` | Create an account |
| `POST` | `/auth/v0/verify-email` | Verify an email address |
| `POST` | `/auth/v0/verify-email/resend` | Send a new verification code |
| `POST` | `/auth/v0/sign-in` | Sign in and create a session |
| `POST` | `/auth/v0/refresh` | Rotate the refresh token and issue a new access token |
| `POST` | `/auth/v0/logout` | Revoke the current session |
| `POST` | `/auth/v0/change-password` | Change the password and revoke existing sessions |
| `POST` | `/auth/v0/password-reset/request` | Request a password reset |
| `POST` | `/auth/v0/password-reset/confirm` | Confirm a password reset |
| `GET` | `/auth/v0/me` | Return the authenticated user |
| `GET` | `/auth/v0/sessions` | List active sessions |
| `DELETE` | `/auth/v0/sessions` | Revoke all sessions |
| `DELETE` | `/auth/v0/sessions/{session_id}` | Revoke one session |
| `GET` | `/auth/v0/.well-known/jwks.json` | Return public JWT signing keys |

## Development

Initialize the Git submodules after cloning the repository:

```bash
git submodule update --init --recursive
```

Create the local runtime config before opening the devcontainer:

```bash
cp configs/config_vars.docker.example.yaml configs/config_vars.docker.yaml
```

Generate an RSA key pair for access-token signing:

```bash
mkdir -p configs/secrets
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out configs/secrets/auth_jwt_private.pem
openssl rsa -in configs/secrets/auth_jwt_private.pem -pubout \
  -out configs/secrets/auth_jwt_public.pem
chmod 600 configs/secrets/auth_jwt_private.pem
```

Open `.devcontainer/devcontainer.json` with CLion Remote Development. The
devcontainer starts PostgreSQL and applies the migrations automatically.

Build and run the tests inside the devcontainer:

```bash
cmake --preset debug
cmake --build build-debug --parallel
ctest --test-dir build-debug --output-on-failure
```

Run the service:

```bash
./build-debug/smirkly-auth --config ./configs/static_config.yaml
```

The public API listens on port `8080`, the private monitor listener on `8081`,
and PostgreSQL on `5432`.

## Tokens and sessions

Access tokens are short-lived RS256 JWTs. Other Smirkly services verify them
with the public keys from `/auth/v0/.well-known/jwks.json`.

Refresh tokens are stored in an HttpOnly cookie and only their HMAC hashes are
persisted in PostgreSQL. Refresh rotates the token; reuse of an old token
revokes the affected session.

`AUTH_REFRESH_TOKEN_PEPPER` and the JWT private key are secrets. Do not commit
them. Changing the refresh-token pepper invalidates existing sessions.

Passwords are hashed with bcrypt. Authentication and recovery flows use shared
PostgreSQL rate limits, and password-reset requests do not reveal whether an
email address is registered.

## Email delivery

Sign-up stores the verification code and an email outbox job in the same
PostgreSQL transaction. The background worker sends queued emails through SMTP
and retries temporary failures.

Replace the `AUTH_SMTP_*` placeholders in `configs/config_vars.docker.yaml`
when testing email verification or password recovery. Do not commit SMTP
credentials.

## Production

`configs/config_vars.prod.example.yaml` documents the production runtime
configuration. Supply the real config, JWT keys, database credentials, SMTP
credentials, and refresh-token pepper through the deployment secret store.

The monitor listener and `/service/*` handlers are operational endpoints and
must not be exposed to the public internet. Runtime rate limits and outbox
policy are provided through userver dynamic config.
