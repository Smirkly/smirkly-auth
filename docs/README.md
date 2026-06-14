# Smirkly Auth Docs

This directory contains the static documentation site published by GitHub Pages.

## Structure

- `index.html` - service overview and documentation map.
- `getting-started.html` - local setup, build, test, run, and verification workflow.
- `configuration.html` - runtime variables, config files, SMTP settings, secrets, and proxy trust.
- `deployment.html` - production build, migration, rollout, and rollback guidance.
- `security.html` - production security controls and auth-specific risk boundaries.
- `runbooks.html` - operational commands for SMTP, verification, config reloads, local resets, and incidents.
- `api.html` - Swagger UI page for the OpenAPI contract.
- `architecture.html` - service architecture and data ownership notes.
- `operations.html` - deployment and operations checklist.
- `assets/site.css` - shared site styles.

## OpenAPI

The source of truth is `openapi/auth-v0.yaml` at the repository root. The Pages
workflow copies it into the published site as `openapi/auth-v0.yaml`.

## Local Preview

From the repository root:

```bash
mkdir -p /tmp/smirkly-auth-docs/openapi
cp -R docs/. /tmp/smirkly-auth-docs/
cp openapi/auth-v0.yaml /tmp/smirkly-auth-docs/openapi/auth-v0.yaml
python3 -m http.server 8088 --directory /tmp/smirkly-auth-docs
```

Open `http://localhost:8088`.

## Publishing

The `.github/workflows/pages.yml` workflow publishes the docs with GitHub Pages.
It runs on changes to `docs/`, `openapi/`, or the workflow itself after they are
pushed to `master` or `main`. It can also be started manually from the Actions
tab. Enable Pages in repository settings and select GitHub Actions as the
source. The workflow prepares the published `_site` directory, copies the
OpenAPI contract, parses every HTML page, and fails before deployment if an
internal link points to a missing file.

## Documentation Rules

- Use placeholders for credentials and private hostnames.
- Do not commit real SMTP passwords, database passwords, JWT private keys, or user tokens.
- Keep endpoint examples synchronized with `openapi/auth-v0.yaml`.
- Keep operational SQL examples synchronized with migrations and repository schema.
