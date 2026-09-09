# Hermes Proton Pass plugin

This standalone Hermes Agent plugin resolves provider credentials from Proton
Pass through the official `pass-cli`. It implements Hermes' public
`SecretSource` contract; source ordering, conflict handling, protected
bootstrap tokens, timeouts, environment writes, and provenance remain owned by
Hermes core.

The plugin registers two sources so Hermes can preserve its mapped-over-bulk
precedence rule:

- `protonpass` — mapped `pass://SHARE/ITEM/FIELD` references, including scoped
  Proton Pass AI access tokens;
- `protonpass_vault` — optional bulk retrieval from one vault for personal
  access tokens.

`pass-cli` is verified against a pinned SHA-256 digest before use. Child
processes receive a minimal environment, secret-bearing output is never echoed,
and fetch failures never prevent Hermes from starting.

## Install from GitHub

```bash
hermes plugins install flamerged/hermes-protonpass-plugin --enable
hermes protonpass setup
```

Hermes clones the repository into `~/.hermes/plugins/`, enables the plugin, and
discovers its `protonpass` command on the next invocation. The repository can
also be installed as a Python package; it exposes the `protonpass` entry point
in the `hermes_agent.plugins` group.

## Configure

Run the plugin-owned setup command:

```bash
hermes protonpass setup
```

Or configure it manually in `~/.hermes/config.yaml`:

```yaml
plugins:
  enabled:
    - protonpass

secrets:
  sources:
    - protonpass
    - protonpass_vault
  protonpass:
    enabled: true
    service_token_env: PROTON_PASS_PERSONAL_ACCESS_TOKEN
    override_existing: true
    cache_ttl_seconds: 300
    auto_install: true
    env:
      OPENROUTER_API_KEY: pass://SHARE_ID/ITEM_ID/api_key
  protonpass_vault:
    enabled: false
    service_token_env: PROTON_PASS_PERSONAL_ACCESS_TOKEN
    vault: Personal
    override_existing: false
    cache_ttl_seconds: 300
    auto_install: true
```

Put only the bootstrap token in `~/.hermes/.env`:

```dotenv
PROTON_PASS_PERSONAL_ACCESS_TOKEN=pst_...
```

Prefer a scoped, read-only, expiring AI access token. Bulk vault mode requires
a personal access token and has broader account access. Keep
`protonpass_vault.enabled: false` unless you explicitly need whole-vault
export.

## Commands

```text
hermes protonpass setup
hermes protonpass status
hermes protonpass sync
hermes protonpass sync --apply
hermes protonpass disable
hermes protonpass install
```

## Bundled skill

The plugin bundles a `vault-access` skill (`skill_view("protonpass:vault-access")`)
for mapping existing item references in `config.yaml` and diagnosing resolution with
`hermes protonpass status` and `sync`. It works with repository and Python package
installs. Users obtain missing IDs in their own authenticated Proton Pass CLI session;
the skill does not enumerate vaults, display secrets, or request bootstrap tokens.

## Development

Run the test suite through a Hermes Agent checkout's canonical runner:

```bash
cd /path/to/hermes-agent
uv sync --python 3.11 --extra dev
uv pip install --python .venv/bin/python --no-deps \
  -e /path/to/hermes-protonpass-plugin
scripts/run_tests.sh /path/to/hermes-protonpass-plugin/tests
```

Tests are hermetic: they use temporary Hermes homes and mocked subprocess or
download boundaries. No live Proton account is required.

CI also builds the wheel and source distribution, installs each into a separate
environment with Hermes 0.18.2 and dependency resolution, and runs
`scripts/check_installed_plugin.py` from outside the checkout. This checks the real
entry point and skill loading from `site-packages`, including the bundled resource.
