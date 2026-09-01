This devcontainer is for local development only. It is not used by the production image.

It uses the self-contained `docker-compose.devcontainer.yml` to start:

- `smirkly-postgres`
- `smirkly-migrate-devcontainer`
- `smirkly-auth-workspace`

From the CLion welcome screen, select **Remote Development**, then
**Create Dev Container**, and choose `.devcontainer/devcontainer.json`.
The IDE backend, compiler, debugger, and tests run as the non-root
`developer` user inside the workspace container.

Inside the container:

```bash
cmake --preset debug
cmake --build build-debug --parallel
ctest --test-dir build-debug --output-on-failure
./build-debug/smirkly-auth --config ./configs/static_config.yaml
```

The development image follows the host architecture, so Apple Silicon uses a
native `linux/arm64` container. The first configure downloads the exact
`userver v3.0` sources into the persistent CPM cache and builds the framework;
later builds reuse the source and compiler caches.

The production Compose file is intentionally not part of the devcontainer
configuration. Its pinned userver image is `linux/amd64` only and is not needed
by CLion, which builds and runs the service directly in the workspace.

Use the `debug` CMake preset in CLion. Configure the `smirkly-auth` run target
with `--config ./configs/static_config.yaml` and `/workspace` as the working
directory. The workspace container stays alive with `sleep infinity`; run the
service from CLion so that the separate `smirkly-auth-dev` container does not
compete for port 8080.

Do not keep the same checkout open in a local CLion window and a Remote
Development window at the same time. Both IDE backends write project-local
state to `.idea/workspace.xml`, so host-only CMake paths and profiles can leak
into the Linux workspace.

If CLion creates `/workspace/cmake-build-debug`, open
**Settings | Build, Execution, Deployment | CMake**, remove the legacy `Debug`
profile, and enable the repository preset named `debug`. The expected
executable is `/workspace/build-debug/smirkly-auth`; the preset also enables
the testsuite and `tests-control` component required by
`configs/static_config.yaml`.

For the CLion Database tool, connect from the remote backend with:

- host: `smirkly-postgres`
- port: `5432`
- database, user, and local-development password: `smirkly_auth`
- introspected schema: `smirkly_auth.public`

`localhost` is incorrect inside the workspace because PostgreSQL runs in a
separate Compose service.
