# Codex macOS Devcontainer

This is an optional local-development profile for macOS users who want Codex
inside the devcontainer to reuse the host Codex state.

It adds `docker-compose.devcontainer.codex-macos.yml`, which mounts the host
`${HOME}/.codex` directory into `/root/.codex` and sets `CODEX_HOME=/root/.codex`
inside the workspace container. The default `.devcontainer/devcontainer.json`
does not do this, so developers without Codex or on other setups can use the
normal devcontainer unchanged.

Use this profile only on a trusted machine. `~/.codex` may contain local auth
state such as `auth.json`; treat it as secret material.

To use it from VS Code, run `Dev Containers: Open Folder in Container...` and
select this configuration if VS Code prompts for one. If your VS Code reuses the
default profile automatically, open this folder as the devcontainer config:

```text
.devcontainer/codex-macos/devcontainer.json
```

After the container starts, verify the mounted Codex state:

```bash
echo "$CODEX_HOME"
ls -la "$CODEX_HOME"
codex resume --all
```
