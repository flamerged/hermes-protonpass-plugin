---
name: vault-access
description: Configure references to existing Proton Pass items and diagnose secret injection with the plugin CLI.
version: 1.0.0
author: Vaibhav Seth and hermes-protonpass-plugin contributors
license: MIT
metadata:
  hermes:
    tags: [security, secrets, proton-pass, pass-cli, vault]
---

# Proton Pass Vault Access

Use this skill to map an existing vault item to an environment variable or troubleshoot
the plugin's startup secret injection. Vault access stays read-only; mapping changes
edit local Hermes configuration. Direct vault enumeration and secret display are outside
this skill's scope.

## Requirements

- This plugin installed, enabled, and configured by the user through
  `hermes protonpass setup`.
- An existing item reference supplied by the user, or already present in configuration.
  Never ask the user to paste a bootstrap token or a secret value into the conversation.

## When to Use

- Wiring a new env var to a Proton Pass item that already exists
- Checking why `hermes protonpass sync` skipped or errored on a var

## Common Operations

### Obtain a reference

A reference has exactly three non-empty components:
`pass://<share_id>/<item_id>/<field>`. The field belongs in the URI itself.
If the IDs are missing, have the user discover them in their own authenticated Proton
Pass CLI session using the [upstream reference guide](https://github.com/ProtonPass/pass-cli/blob/8e6b65368d2c5da1c81e586add07b745fb0130a2/docs/public/docs/commands/contents/secret-references.md).
Ask only for the intended reference, not an item dump. Do not run `pass-cli` through an
agent terminal or attempt to reuse the plugin's private session files.

### Add a mapping for an item that already exists

Edit the active Hermes home's `config.yaml` (normally `~/.hermes/config.yaml`). Merge
only the requested entry into the existing `secrets.protonpass.env` mapping. Preserve
all unrelated settings, mappings, comments, and the user's chosen profile. This is a
partial example, not a replacement configuration:

```yaml
secrets:
  protonpass:
    env:
      MY_API_KEY: "pass://<share_id>/<item_id>/<field>"
```

Replace the example name and reference with the user's intended mapping. Do not write
resolved values into YAML or `.env`. Do not use `hermes config set` for this edit:
Hermes 0.18.2 redirects names ending in `_API_KEY` or `_TOKEN` to `.env` instead of
updating the nested mapping.

Then validate through the plugin-owned CLI in the same Hermes home/profile:

```bash
hermes protonpass sync
```

If `sync` reports that the integration is disabled, have the user re-run
`hermes protonpass setup` in their own terminal after saving the references. Setup
enables the mapped source once refs exist; then retry `sync` in the same Hermes
home/profile.

`sync` fetches the configured references and reports a dry-run application plan without
printing values. Look for `would export`, or `skip (already set)` when
`override_existing` is off and the variable is already in the process environment.
It does not export variables into the parent shell. A new Hermes process resolves the
mapping at startup; an existing gateway or process needs a restart to pick it up.

### Check configured state

```bash
hermes protonpass status
```

Reports whether the sources are enabled, how many refs are configured, and which
verified `pass-cli` binary is available. If the mapped source is disabled, have the user
re-run `hermes protonpass setup` in their own terminal after adding the references;
setup enables the mapped source once refs exist. If authentication is missing or
expired, have the user repair it through setup in their own terminal.

## Guardrails

- Read-only vault access. Never create, update, or delete Proton Pass items. If an item
  does not exist, have the user create it themselves, then supply its reference.
- Never read, print, or forward bootstrap tokens, private session files, or secret
  values. Use plugin-owned status and sync output for diagnostics.
- Keep per-item `secrets.protonpass.env` references. Do not enable
  `secrets.protonpass_vault` bulk export or broaden token permissions to resolve a
  mapping problem. The user's scoped, read-only token should stay scoped.
