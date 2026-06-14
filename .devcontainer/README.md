This devcontainer is for local development only. It is not used by the production image.

It uses `docker-compose.yml` plus `docker-compose.devcontainer.yml` to start:

- `smirkly-postgres`
- `smirkly-migrate-devcontainer`
- `smirkly-auth-workspace`

Open the repository in VS Code and run `Dev Containers: Reopen in Container`.

Inside the container:

```bash
cmake --build build-debug --parallel --target smirkly-auth
./build-debug/smirkly-auth --config ./configs/static_config.yaml
```

The workspace container stays alive with `sleep infinity`; start and stop the auth service from the terminal.

Optional Codex profile for macOS users:

- `.devcontainer/codex-macos/devcontainer.json` mounts the host `${HOME}/.codex`
  into `/root/.codex` via `docker-compose.devcontainer.codex-macos.yml` so Codex
  inside the container can reuse local auth, config, and sessions.
- The default devcontainer intentionally does not mount personal Codex state.
  Keep it that way for developers who do not use Codex and for non-macOS setups.
