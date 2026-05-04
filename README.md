# smirkly-auth

[![Status](https://img.shields.io/badge/status-active--development-orange)](#)
[![Framework](https://img.shields.io/badge/built--with-userver-blue)](https://github.com/userver-framework/userver)

Authentication microservice for the Smirkly platform, built with the [userver framework](https://github.com/userver-framework/userver).

## Scope

Implemented:
- User registration (email + password) with persistence in Postgres
- Sign-in issuing `{access_token, refresh_token}` (JWT)
- Email verification flow: verification code generation and enqueueing email into outbox

Work in progress:
- Session/device model and refresh-token lifecycle (storage/rotation/revocation)
- Logout and token invalidation
- Password change / reset flows


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
```

These values are used by local Postgres (e.g. via docker-compose.yml) and must match the connection settings in your
configs.

### 3. Create configs/config_vars.yaml

Create configs/config_vars.yaml with basic runtime options, for example:

```yaml
worker-threads: 4
worker-fs-threads: 2
logger-level: info

is-testing: false

server-port: 8080

AUTH_JWT_AUDIENCE: smirkly-api
AUTH_JWT_KEY_ID: smirkly-auth-local-rs256
AUTH_JWT_PRIVATE_KEY_PATH: ./configs/secrets/auth_jwt_private.pem
AUTH_JWT_PUBLIC_KEY_PATH: ./configs/secrets/auth_jwt_public.pem
```

worker-threads / worker-fs-threads – userver task processors.

logger-level – log level (trace, debug, info, warning, error…).

server-port – HTTP port for the auth service.

You may extend this file as the service evolves.

Generate a local RSA key pair for JWT signing:

```bash
mkdir -p configs/secrets
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out configs/secrets/auth_jwt_private.pem
openssl rsa -in configs/secrets/auth_jwt_private.pem -pubout -out configs/secrets/auth_jwt_public.pem
chmod 600 configs/secrets/auth_jwt_private.pem
```

The auth service signs JWTs with the private key. Other services should fetch public keys from
`/auth/v0/.well-known/jwks.json` and use them only to verify access tokens.

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

The resulting binary will be in build-debug/ (for debug preset).

Running the service locally

After a successful build:

Make sure Postgres and Redis are running and accessible

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

## License

The original template is distributed under
the [Apache-2.0 License](https://github.com/userver-framework/userver/blob/develop/LICENSE)
and [CLA](https://github.com/userver-framework/userver/blob/develop/CONTRIBUTING.md). Services based on the template may
change
the license and CLA.
