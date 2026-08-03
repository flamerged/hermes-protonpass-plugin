---
name: vault-access
description: Read secrets from Proton Pass, wire existing vault items into secrets.protonpass.env, and check sync status.
version: 1.0.0
author: hermes-protonpass-plugin contributors
license: MIT
platforms: [linux, macos]
metadata:
  hermes:
    tags: [security, secrets, proton-pass, pass-cli, vault]
required_environment_variables:
  - name: PROTON_PASS_PERSONAL_ACCESS_TOKEN
    prompt: "Proton Pass service token (agent token or personal access token)"
    help: "Created with pass-cli agent create ... or from the Proton Pass account settings. See the plugin README for setup."
    required_for: "pass-cli authentication"
---

# Proton Pass Vault Access

Use this skill when the user wants to look up, reference, or troubleshoot secrets stored
in Proton Pass through this plugin.

## Requirements

- This plugin installed and enabled (`secrets.protonpass.enabled: true`)
- `PROTON_PASS_PERSONAL_ACCESS_TOKEN` configured (plugin auto-installs `pass-cli`)

## When to Use

- Finding an item's `share_id`/`item_id` to build a `pass://` ref
- Wiring a new env var to a Proton Pass item that already exists
- Checking why `hermes protonpass sync` skipped or errored on a var
- Reading a secret's value on the user's explicit request

## Common Operations

### List items in a vault

```bash
pass-cli item list "<vault-name>" --output json
```

Metadata only (title, `id`, `share_id`) — no secret values, works under a viewer-role
agent token.

### Read a field's value

```bash
pass-cli item view --field "<field>" -- "pass://<share_id>/<item_id>"
```

### Add a mapping for an item that already exists

```bash
hermes config set "secrets.protonpass.env.MY_VAR" "pass://<share_id>/<item_id>/<field>"
hermes protonpass sync
```

`sync` dry-runs the resolution — look for `would export` (or `skip (already set)` if
`override_existing` is off and the var is already present in `.env`). Restart the
gateway (or relevant process) to apply it; secrets resolve once at process startup, not
on a hot-reload.

### Check configured state

```bash
hermes protonpass status
```

Reports whether the source is enabled, how many refs are configured, and which
`pass-cli` binary it resolved to.

## Guardrails

- Read-only. Never create, update, or delete Proton Pass items through this skill — if a
  secret doesn't exist yet, tell the user to create it themselves (Proton Pass app, web
  vault, or their own `pass-cli` session), then come back to wire the reference into
  config.
- Never print a fetched secret value back to the user unless they explicitly asked for
  the value itself.
- `vault:` (bulk listing with `--show-secrets`) requires a full personal access token —
  it's rejected under a scoped viewer-role agent token. Prefer per-item `env:` refs.
