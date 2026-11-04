# Contributing to SentinelAI

Thanks for helping. Bug reports, new rules (with a sample log line that triggers
them), parser fixes and documentation improvements are all welcome.

Security problems: do not open a public issue. See [SECURITY.md](SECURITY.md).

## Development setup

Requires Python 3.10+. Do not use syntax or stdlib features from 3.11 or later.

```bash
git clone https://github.com/E2xCoder/SentinelAI.git
cd SentinelAI

python -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate

pip install -e ".[ai,dev]"
```

## Commands

Run all of these before opening a pull request (CI runs the same on Python
3.10-3.13):

```bash
pytest                                              # tests
ruff check src tests                                # lint
ruff format src tests                               # format
mypy src                                            # type-check (strict)
sentinel eval --baseline benchmarks/baseline.json   # detection regression gate
```

## Project layout

| Path                       | What is there                                              |
|----------------------------|------------------------------------------------------------|
| `src/sentinelai/`          | Source. Start at `core/pipeline.py`, the composition root  |
| `src/sentinelai/parsers/`  | Parser framework (`base.py`), registry and format parsers  |
| `src/sentinelai/detection/`| Rule framework (`base.py`), engine and rules in `rules/`   |
| `src/sentinelai/cli/`      | click commands in `cli/commands/`                          |
| `tests/`                   | pytest suite                                               |
| `benchmarks/`              | Frozen detection benchmark (see below)                     |
| `examples/`                | Sample logs, the UFW adapter, an example plugin            |
| `deploy/`, `Dockerfile`    | systemd units and container image                          |
| `docs/`                    | Documentation, including `PLUGINS.md` and screenshots      |
| `scripts/`                 | Maintenance scripts (`make_screenshots.py`)                |

See the "Architecture" section of the [README](README.md) for the package
overview.

## Rules of the road

- **Core stays dependency-light.** Core dependencies are `click`, `rich`,
  `PyYAML` and `requests`. Heavy or optional libraries go behind an extra in
  `pyproject.toml`, and every new dependency needs a justification in the pull
  request.
- **Keep the layering.** Inner layers (`core`, `config`, `utils`) do not depend
  on outer ones. New external collaborators (firewalls, intel providers, LLMs,
  notifiers) go behind a small protocol.
- **Parsers never raise on bad input.** Return `None` for lines they cannot
  understand.
- **Tests are required.** Every behavior change comes with a test. Tests make no
  real network calls: mock threat-intel, LLM and webhook traffic.
- **Every rule needs an attack and a benign scenario** in
  `benchmarks/scenarios/` (see below). A rule that cannot be shown to stay quiet
  on normal activity is not ready.
- **Update the docs** (README, `config.example.yaml`, `CHANGELOG.md`) for any
  user-visible change.

## The benchmark is frozen

`benchmarks/scenarios/` is hashed in `benchmarks/MANIFEST.sha256`. Every
`sentinel eval` run verifies the manifest first and aborts if any file was
modified, added or removed. Changing the benchmark is therefore a deliberate,
reviewed step, so that a detection regression cannot be hidden by editing the
test data.

### Adding a scenario

1. Create `benchmarks/scenarios/<name>/` containing `labels.yaml` and one or
   more `*.log` files. The directory name must equal `name:` in `labels.yaml`.
   Existing scenarios use the pattern `r001_ssh_bruteforce` (attack) and
   `r001_benign_typos` (benign).
2. Write the labels. The README section "Evaluation benchmark" documents the
   format and the validation rules.
3. Run the benchmark and rewrite the manifest and the baseline:

   ```bash
   sentinel eval --update-manifest --write-baseline benchmarks/baseline.json
   ```

   `--update-manifest` validates the scenarios first. The baseline is not
   written if any scenario fails.
4. Review the diff of `MANIFEST.sha256` and `baseline.json`. Only the files you
   meant to change should differ.
5. Commit the scenario, the manifest and the baseline together, and say in the
   pull request why the benchmark changed.

Never regenerate the manifest or the baseline just to make CI pass. If a
scenario started failing, fix the code or explain in the pull request why the
scenario was wrong.

Learning or tuning code must never write into `benchmarks/`.

### Fixture conventions

- Use RFC 3339 timestamps with an explicit year and offset
  (`2026-01-07T10:15:32+00:00`). BSD-style `Jan  7 10:15:32` headers carry no
  year, so results would change over time.
- Use RFC 5737 documentation IPs (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`), and no real hostnames, users or secrets.
- Use LF line endings.

## Adding a Sigma example rule

The example pack in `examples/sigma/` and its benchmark root `benchmarks/sigma/`
are separate from the main benchmark. The README section "Sigma rule import"
describes the supported subset.

1. Write an **original** rule in `examples/sigma/`. Do not copy rules from
   SigmaHQ: they are under the Detection Rule License, the pack is MIT. Give it
   a fresh UUID `id`, an `author`, a `level` and ATT&CK `tags`.
2. Check that it imports: `sentinel rules import examples/sigma`. Your rule must
   be listed as importable, not unsupported. Note its `SIGMA-<8 hex>` id.
3. Add two scenarios under `benchmarks/sigma/scenarios/`: an **attack** that the
   rule must catch and a **benign look-alike** that stays quiet (same service
   and similar wording, harmless activity). Follow "Adding a scenario" and the
   fixture conventions above; the attack lists the `SIGMA-` id in
   `expect.rules`.
4. Regenerate the manifest and the baseline of the Sigma root (not the main
   one):

   ```bash
   sentinel eval --benchmarks benchmarks/sigma --sigma-rules examples/sigma \
     --update-manifest --write-baseline benchmarks/sigma/baseline.json
   ```

5. Review the diff, then check that both gates are still green:

   ```bash
   sentinel eval --benchmarks benchmarks/sigma --sigma-rules examples/sigma \
     --baseline benchmarks/sigma/baseline.json
   sentinel eval --baseline benchmarks/baseline.json
   ```

Commit the rule, the scenarios, the manifest and the baseline together. The same
rule as for the main benchmark applies: never regenerate them just to make CI
pass.

## Security expectations

SentinelAI parses attacker-controlled input and can change firewall state.
Contributions must keep it safe:

- **No `shell=True`**, and no building command lines from strings. Pass argument
  lists.
- **Validate input.** Treat log content, config values and model output as
  untrusted. Bound lengths, validate IPs with `ipaddress`, and keep regexes
  bounded (anchored, no nested unbounded quantifiers, applied to capped input).
- **Never log secrets.** API keys, tokens, webhook URLs and passwords must not
  appear in logs, error messages, `repr` output, reports or test snapshots.
  Secrets come from `SENTINELAI_*` environment variables.
- **Keep automated response conservative.** It stays off by default, `dry_run`
  stays the default adapter, and new code paths fail closed.
- **LLM output stays advisory.** It must never trigger or block an action.

## Screenshots

The terminal screenshots in `docs/screenshots/` are generated from the real CLI
in an isolated sandbox (temporary home, no plugins, no network). Regenerate them
when command output changes and commit the refreshed SVG files:

```bash
python scripts/make_screenshots.py
```

## Commit style

- Short imperative subject line, up to about 72 characters, for example
  `Fix R060 firing on privileged: false`.
- Explain the why in the body when it is not obvious.
- Keep commits small and logically separate; do not mix refactoring with
  behavior changes.

## Pull requests

1. Fork and create a feature branch.
2. Make the change with tests, and run the commands above.
3. Open a pull request describing the behavior change and any new config keys.
