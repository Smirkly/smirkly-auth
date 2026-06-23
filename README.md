# smirkly-auth

[![Status](https://img.shields.io/badge/status-active--development-orange)](#)
[![Framework](https://img.shields.io/badge/built--with-userver-blue)](https://github.com/userver-framework/userver)

Authentication microservice for the Smirkly platform, built with the [userver framework](https://github.com/userver-framework/userver).

## Scope

Implemented:
- User registration (email + password) with persistence in Postgres
- Sign-in issuing an access token and an HttpOnly refresh-token cookie
- Refresh-token storage, rotation, reuse detection, and session revocation
- Current-session logout and all-sessions revocation
- Password change with all-sessions revocation
- Email verification flow: verification code generation and enqueueing email into outbox
- Public JWKS endpoint for access-token verification

Work in progress:
- Password reset flow
- Production deployment packaging hardening
- Application-level rate limiting


> Status: active development. APIs, configuration, and internal structure may change without backward compatibility guarantees.
---

## Download and Build

### 1. Clone the repository

```bash
git clone https://github.com/Smirkly/smirkly-auth.git
cd smirkly-auth
```

If you have not cloned with --recurse-submodules, initialize submodules:

```bash
git submodule update --init
```

This will pull third-party dependencies such as userver and libbcrypt.

### 2. Create .env

Create a .env file in the project root with database settings, for example:

```dotenv
POSTGRES_DB=smirkly_auth
POSTGRES_USER=smirkly_auth
POSTGRES_PASSWORD=smirkly_auth
MIGRATE_DATABASE_URL=postgres://smirkly_auth:smirkly_auth@smirkly-postgres:5432/smirkly_auth?sslmode=disable
```

These values are used by local Postgres (e.g. via docker-compose.yml) and must match the connection settings in your
configs.

### 3. Create configs/config_vars.yaml

`configs/config_vars.yaml` is the local runtime config consumed by `static_config.yaml`. It is ignored by Git because it may contain database passwords, SMTP credentials, or environment-specific hostnames. Start from the tracked example and adjust the database host for your run mode:

```bash
cp configs/config_vars.docker.example.yaml configs/config_vars.yaml
# For a binary running on the host, use localhost instead of the Compose service name:
# postgres-dbconnection: postgresql://smirkly_auth:smirkly_auth@localhost:5432/smirkly_auth
```

`configs/config_vars.docker.yaml` is the dev Docker runtime config consumed by Compose, but it is ignored by Git. Create it from `configs/config_vars.docker.example.yaml` and put your real local SMTP values there if needed. Production should generate `config_vars.yaml` from a deployment secret source and mount it read-only.

event-threads - userver event loop threads. Treat this as startup infrastructure config and change it through deploy config plus rolling restart.

worker-threads / worker-fs-threads - userver task processors for request handling and blocking filesystem/utility work.

worker-monitor-threads - dedicated task processor for monitor/admin handlers, so diagnostics remain reachable under request load.

worker-email-outbox-threads - dedicated task processor threads for SMTP delivery. Keep SMTP work off the main request processor.

logger-level - log level (trace, debug, info, warning, error...).

server-port - HTTP port for the auth service.

monitor-server-port - private monitor listener for `/ping` and `/service/*` operational handlers. Do not expose it to the public internet.

dynamic-config-updates-enabled - `false` for local/docker development, `true` in production when a config service is available.

dynamic-config-cache-path - filesystem cache for the last successful production dynamic config snapshot. Mount it on persistent writable storage.

dynamic-config-server-url / dynamic-config-service-name - config-service endpoint and service id used by userver dynamic-config-client.

dynamic-config-update-interval / dynamic-config-full-update-interval - polling cadence for production runtime policy updates.

Runtime auth and outbox policies are modeled as typed userver dynamic configs:

- `SMIRKLY_AUTH_RUNTIME_CONFIG` controls sign-in policy, session activity write threshold, email verification code TTL, and verification rate limits.
- `SMIRKLY_EMAIL_OUTBOX_RUNTIME_CONFIG` controls outbox processing kill switch, batch size, max attempts, stuck timeout, and retry backoff.

Local and docker development use the C++ defaults from `dynamic_config::Key`. Production should fetch those keys from config-service through `dynamic-config-client-updater` and keep `dynamic-config.fs-cache-path` available for fallback on restart. Thread counts, ports, DSNs, SMTP credentials, and JWT key paths are startup/runtime variables, not dynamic config. Change them through deployment config and a rolling restart.

`AUTH_SMTP_*` controls outbound email verification delivery. `AUTH_SMTP_TLS_MODE` should match the provider port:

- `tls` with port `465` for implicit TLS, which is what Gmail commonly works with from Docker/local networks.
- `starttls` with port `587` when the provider sends a plain SMTP greeting and upgrades with STARTTLS.
- `none` only for a local fake SMTP server in isolated development.

For Gmail-based local testing, use a Google app password and placeholders like this:

```yaml
AUTH_SMTP_HOST: smtp.gmail.com
AUTH_SMTP_PORT: 465
AUTH_SMTP_TLS_MODE: tls
AUTH_SMTP_USERNAME: your-account@gmail.com
AUTH_SMTP_APP_PASSWORD: "<gmail-app-password>"
AUTH_SMTP_FROM_EMAIL: your-account@gmail.com
AUTH_SMTP_FROM_NAME: "Smirkly"
```

Do not commit real SMTP credentials. If an app password was pasted into chat, logs, screenshots, or git history, rotate it in Google Account settings and update your local secret source.

Generate a local RSA key pair for JWT signing:

```bash
mkdir -p configs/secrets
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out configs/secrets/auth_jwt_private.pem
openssl rsa -in configs/secrets/auth_jwt_private.pem -pubout -out configs/secrets/auth_jwt_public.pem
chmod 600 configs/secrets/auth_jwt_private.pem
```

The auth service signs JWTs with the private key. Other services should fetch public keys from
`/auth/v0/.well-known/jwks.json` and use them only to verify access tokens.

### Email verification and SMTP

Sign-up stores a hashed verification code and enqueues an email job in `email_outbox` in the same database transaction. The background outbox worker claims ready jobs, sends them through SMTP, retries transient failures, and eventually marks exhausted jobs as dead.

If a code expires or the email was not delivered, request a fresh code:

```bash
curl -i -X POST http://localhost:8080/auth/v0/verify-email/resend \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com"}'
```

Then verify the latest code from the email body:

```bash
curl -i -X POST http://localhost:8080/auth/v0/verify-email \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","code":"123456"}'
```

To inspect local delivery state:

```bash
docker compose exec -T smirkly-postgres \
  psql -U smirkly_auth -d smirkly_auth \
  -c "SELECT id, to_email, status, attempts, next_attempt_at, locked_until, left(coalesce(last_error, ''), 300) AS last_error, created_at, updated_at FROM email_outbox ORDER BY created_at DESC LIMIT 10;"
```

After changing `AUTH_SMTP_*` values, restart the service container or local process. A rebuild is needed only when source code changed.

### 4. Configure and build (via Makefile)

This project uses the standard userver service template Makefile.
```PRESET``` is one of:

```debug```

```release```

```debug-custom```

```release-custom``` (if you add custom presets in CMakeUserPresets.json)

Typical workflow:

```bash
# Configure CMake for debug preset
make cmake-debug

  # Build the service
make build-debug

  # Build and run all tests
make test-debug

```

Functional testsuite starts its own PostgreSQL via `initdb`; run it as a non-root user. A root dev container can build and run unit tests, but testsuite PostgreSQL startup will fail with `initdb: cannot be run as root`.


The resulting binary will be in build-debug/ (for debug preset).

## Docker

The compose file has two app profiles:

```bash
# Active development: source is mounted, build-debug is a Docker volume.
# Create the ignored dev Docker runtime config once, then start the app.
cp configs/config_vars.docker.example.yaml configs/config_vars.docker.yaml
docker compose --profile dev up --build smirkly-auth-dev

# Apply pending migrations manually, useful after adding a new migration.
docker compose --profile dev run --rm smirkly-migrate-dev

# Recompile after editing code without rebuilding the Docker image.
docker compose exec smirkly-auth-dev cmake --build build-debug --parallel --target smirkly-auth
docker compose restart smirkly-auth-dev

# Production-style run: release binary is baked into the image, no source mount.
# Runs smirkly-migrate before starting the app. The runtime config and JWT keys
# must come from outside the repository.
SMIRKLY_CONFIG_VARS_PATH=/etc/smirkly-auth/config_vars.yaml \
SMIRKLY_SECRETS_PATH=/run/secrets/smirkly-auth \
docker compose --profile prod up --build -d smirkly-auth
```

By default Compose does not force a CPU architecture; Docker uses the host's native platform. This is the right default
for production Linux hosts. If you are on Apple Silicon and the selected userver base image has no `linux/arm64` build,
force `linux/amd64` locally with the override file:

```bash
docker compose -f docker-compose.yml -f docker-compose.linux-amd64.yml --profile dev up --build smirkly-auth-dev
```

For repeated local use, put this in your untracked `.env`:

```dotenv
COMPOSE_FILE=docker-compose.yml:docker-compose.linux-amd64.yml
```

Both profiles use `smirkly-postgres` and run migrations with `golang-migrate` before the auth service starts. Dev uses
the upstream `migrate/migrate` image with `./migrations` mounted read-only. Prod builds a `smirkly-auth-migrate:prod`
image that contains the migration files, so the production runner does not need source code mounted. In real deployments,
provide `MIGRATE_DATABASE_URL` from the same secret/config source that renders `postgres-dbconnection`.

### Devcontainer

The repository also has a VS Code devcontainer for onboarding and local IDE work. It is not part of production. The
devcontainer uses the same `Dockerfile` `dev` target, starts Postgres, runs migrations, and then opens a workspace
container that stays alive for interactive commands.

Open the repository in VS Code and run `Dev Containers: Reopen in Container`. Inside the container:

```bash
cmake --build build-debug --parallel --target smirkly-auth
./build-debug/smirkly-auth --config ./configs/static_config.yaml
```

The devcontainer compose overlay defaults to `linux/amd64` because the current userver base image may not provide an
Apple Silicon build. This does not affect production compose. Override it with `SMIRKLY_DOCKER_PLATFORM` if needed.

Docker-specific runtime values live in ignored `configs/config_vars.docker.yaml`. `configs/config_vars.docker.example.yaml` is the tracked template that documents the full shape of the runtime config. For production, the Compose profile defaults to ignored local prod-style paths, but real deployments should set `SMIRKLY_CONFIG_VARS_PATH` and `SMIRKLY_SECRETS_PATH`; point them at files generated or mounted by your deployment platform, not at repository files with real secrets.

The production image starts with `configs/static_config.prod.yaml`, which intentionally does not load userver tests-control endpoints. It does include a private monitor listener with `/ping`, `/service/monitor`, `/service/log-level/{level}`, `/service/log/dynamic-debug`, `/service/inspect-requests`, `/service/dnsclient/{command}`, and `/service/on-log-rotate/`. Local development and tests still use `configs/static_config.yaml`. If you override the Postgres credentials through `.env`, keep `MIGRATE_DATABASE_URL` and the generated production `postgres-dbconnection` pointed at the same database.

If your local `pgdata` volume was created before the migration runner was added, it may already contain tables but not
the `schema_migrations` version table. For local development, recreate that database volume before the first
`smirkly-migrate-dev` run, or baseline it manually after verifying the schema.

Running the service locally

After a successful build:

Make sure Postgres is running and accessible

Either via your local installation

Or via docker-compose up if you use Docker for infra

Run the service, for example:

```bash
./build-debug/smirkly-auth \
--config ./configs/static_config.yaml
```

If your static_config.yaml is using config_vars.yaml (userver-style), ensure both files are present in configs/.

## Makefile

`PRESET` is either `debug`, `release`, or if you've added custom presets in `CMakeUserPresets.json`, it
can also be `debug-custom`, `release-custom`.

* `make cmake-PRESET` - run cmake configure, update cmake options and source file lists
* `make build-PRESET` - build the service
* `make test-PRESET` - build the service and run all tests
* `make start-PRESET` - build the service, start it in testsuite environment and leave it running
* `make install-PRESET` - build the service and install it in directory set in environment `PREFIX`
* `make` or `make all` - build and run all tests in `debug` and `release` modes
* `make format` - reformat all C++ and Python sources
* `make dist-clean` - clean build files and cmake cache
* `make docker-COMMAND` - run `make COMMAND` in docker environment
* `make docker-clean-data` - stop docker containers

## Tests

Unit tests are written in C++ using userver::utest (GoogleTest-based) and live under tests/unit/.

To run them locally:

```bash
make test-debug

```

or explicitly:

```bash
cmake -S . -B cmake-build-debug -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build cmake-build-debug -j$(nproc)
cd cmake-build-debug
ctest --output-on-failure
```

New tests should be placed under tests/unit/… and will be picked up automatically by CMake if they match the configured
glob (tests/unit/*.cpp).

## Documentation

Project documentation lives in `docs/`.

- `docs/index.html` - service overview.
- `docs/getting-started.html` - local setup and development workflow.
- `docs/api.html` - Swagger UI for `openapi/auth-v0.yaml`.
- `docs/architecture.html` - service architecture notes.
- `docs/operations.html` - deployment and operations checklist.

The `.github/workflows/pages.yml` workflow publishes the static docs site with GitHub Pages.

## License

The original template is distributed under
the [Apache-2.0 License](https://github.com/userver-framework/userver/blob/develop/LICENSE)
and [CLA](https://github.com/userver-framework/userver/blob/develop/CONTRIBUTING.md). Services based on the template may
change
the license and CLA.
