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
