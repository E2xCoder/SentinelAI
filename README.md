# SentinelAI

**AI-assisted security log analysis, detection and automated response for Linux.**

SentinelAI reads Linux logs (batch or in real time), parses them into structured
events, runs a rule-based detection engine and an ML anomaly detector over them,
enriches findings with threat intelligence, scores each alert with a fully
*explained* risk model, and can automatically respond by driving **your own**
firewall automation through a clean adapter boundary.

> It is designed to look and behave like a real open-source blue-team tool:
> modular, streaming, resilient to malformed input, and extensible via plugins
> without touching the core.

---

## Table of contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [CLI usage](#cli-usage)
- [Detection rules](#detection-rules)
- [Evaluation benchmark](#evaluation-benchmark)
- [Feedback and tuning](#feedback-and-tuning)
- [Threat detection example](#threat-detection-example)
- [AI explanation example](#ai-explanation-example)
- [Firewall integration](#firewall-integration)
- [Development guide](#development-guide)
- [Extending SentinelAI](#extending-sentinelai)
- [Contributing](#contributing)
- [Screenshots](#screenshots)
- [License](#license)

---

## Features

- **Streaming log ingestion** — line-by-line reading (incl. gzip), so multi-GB
  logs never load into memory.
- **8 built-in parsers** — syslog/auth, Apache access & error, Nginx access &
  error, Docker daemon, Fail2Ban, UFW. Auto-detected from content; new formats
  are a decorator away.
- **22+ detection rules** — brute force, password spraying, credential stuffing,
  root login, privilege escalation, reverse shells, suspicious cron, SSH-key
  tampering, firewall modification, container escapes, lateral movement, and
  more — each tagged with **MITRE ATT&CK** techniques.
- **Explained risk scoring** — every alert gets a 0–100 score with a per-factor
  breakdown of *why*.
- **AI engine** — Isolation Forest anomaly detection, behavior profiling,
  multi-stage attack-pattern recognition, and alert explanation via an optional
  local LLM (with a deterministic fallback).
- **Threat intelligence** — AbuseIPDB, VirusTotal and AlienVault OTX with disk
  caching, rate limiting and graceful degradation.
- **Automated response** — blocks malicious sources through *your* firewall
  project via dependency inversion; SentinelAI never implements firewall logic.
- **Live monitoring & replay** — rotation-aware tailing and historical replay.
- **Reports** — JSON, CSV and self-contained HTML.
- **Plugin system** — drop a `.py` file in the plugins directory to add parsers,
  rules, models or report formats with zero core changes.

---

## Architecture

SentinelAI follows Clean Architecture: dependencies point inward, and every
cross-boundary collaborator is a small protocol so implementations are swappable.

```
                          ┌──────────────────────────────┐
                          │            CLI (click)        │
                          │  scan · live · replay · …     │
                          └───────────────┬──────────────┘
                                          │
                          ┌───────────────▼──────────────┐
                          │      AnalysisPipeline         │
                          │  (composition root)           │
                          └──┬───┬───┬───┬───┬───┬────────┘
             ┌───────────────┘   │   │   │   │   └───────────────┐
             ▼               ▼   ▼   ▼   ▼   ▼                   ▼
      ┌────────────┐  ┌──────────┐ ┌───────┐ ┌──────────┐ ┌──────────────┐
      │  Parsers   │  │Detection │ │ Risk  │ │   AI     │ │ Threat Intel │
      │ (registry) │  │  Engine  │ │Engine │ │ Engine   │ │ (providers)  │
      └─────┬──────┘  └────┬─────┘ └───┬───┘ └────┬─────┘ └──────┬───────┘
            │              │           │          │              │
       LogEvent  ──►    Alert  ──►  RiskAssessment / AIInsight / IPReputation
                              │
                   ┌──────────┴───────────┐
                   ▼                      ▼
            ┌────────────┐        ┌───────────────────────┐
            │  Reporting │        │  Firewall boundary     │
            │ json/csv/  │        │  FirewallController    │◄── YOUR firewall
            │   html     │        │  (protocol + adapters) │    automation
            └────────────┘        └───────────────────────┘

        Core models (LogEvent, Alert, Risk…)  ·  Config  ·  Utils  ·  Store
                          (shared, dependency-free inner layer)
```

Packages (`src/sentinelai/`):

| Package      | Responsibility                                             |
|--------------|------------------------------------------------------------|
| `core`       | Domain models, pipeline, SQLite alert store, exceptions    |
| `config`     | Typed config models + YAML/env loader                      |
| `parsers`    | Parser framework, registry, 8 format parsers, classifier   |
| `detection`  | Rule framework, sliding-window state, engine, 22 rules     |
| `risk`       | Multi-factor, self-explaining risk engine                  |
| `intel`      | TI providers, TTL cache, rate limiter, aggregator          |
| `ai`         | Features, Isolation Forest, behavior, patterns, explainer  |
| `firewall`   | `FirewallController` protocol, adapters, auto-responder    |
| `monitor`    | Rotation-aware tailer, live monitor, replay                |
| `reporting`  | Report builder + JSON/CSV/HTML renderers                   |
| `evaluation` | Frozen benchmark runner, metrics, baseline comparison      |
| `tuning`     | Feedback-driven proposals, policy limits, gate, overlay    |
| `search`     | Composable event query/filter engine                       |
| `plugins`    | Directory-based plugin loader                              |
| `cli`        | click + rich command-line interface                        |
| `utils`      | Logging, time parsing, network & path helpers              |

---

## Installation

Requires **Python 3.10+**.

```bash
git clone https://github.com/E2xCoder/SentinelAI.git
cd SentinelAI

python -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate

# Core install:
pip install -e .

# With AI anomaly detection (scikit-learn):
pip install -e ".[ai]"

# For development (tests, linters, type checking):
pip install -e ".[ai,dev]"
```

This installs the `sentinel` command.

---

## Quick start

```bash
# Analyze the bundled example attack log:
sentinel scan examples/auth.log

# Write reports in every format:
sentinel scan examples/auth.log --format json --format csv --format html

# See parsed event statistics without detection:
sentinel analyze examples/auth.log

# Replay a log as if it were happening live (10x speed):
sentinel replay examples/auth.log --speed 10

# Explain a stored alert (AI-assisted if a local LLM is configured):
sentinel explain 8

# Run the detection benchmark and gate it against the committed baseline:
sentinel eval --baseline benchmarks/baseline.json
```

---

## Configuration

SentinelAI runs with defaults out of the box. To customize, copy
[`config.example.yaml`](config.example.yaml) to `config.yaml`:

```bash
cp config.example.yaml config.yaml
```

Discovery order (first match wins): `--config` → `$SENTINELAI_CONFIG` →
`./config.yaml` → `~/.sentinelai/config.yaml` → `/etc/sentinelai/config.yaml`.

**Every** key can be overridden by an environment variable, so secrets never
need to live on disk:

```bash
export SENTINELAI_INTEL_ABUSEIPDB_API_KEY="xxxxxxxx"
export SENTINELAI_INTEL_ABUSEIPDB_ENABLED=true
export SENTINELAI_RESPONSE_ENABLED=true
```

Inspect the effective configuration and component status any time:

```bash
sentinel config
```

---

## CLI usage

| Command                    | Description                                              |
|----------------------------|----------------------------------------------------------|
| `sentinel scan <log>`      | Analyze a log and report detected threats                |
| `sentinel analyze <log>`   | Parse and show event statistics (no detection)           |
| `sentinel live`            | Continuously monitor configured logs in real time        |
| `sentinel replay <log>`    | Replay a historical log through detection                |
| `sentinel search <log>`    | Search/filter events by ip/user/type/severity/date/text  |
| `sentinel explain <id>`    | Explain a stored alert (why, attack, actions, confidence)|
| `sentinel report <file>`   | Summarize a previously generated JSON report             |
| `sentinel rules`           | List all detection rules with MITRE mappings             |
| `sentinel eval`            | Run the frozen detection benchmark (precision/recall)    |
| `sentinel feedback <id>`   | Label a stored alert as true (`--tp`) or false (`--fp`) positive |
| `sentinel review`          | Interactively label recent, unlabelled alerts            |
| `sentinel tune`            | Propose, gate and (`--apply`) apply feedback-driven tuning |
| `sentinel config`          | Show effective configuration and component status        |
| `sentinel version`         | Show the version                                         |

Global options: `--config <path>`, `--debug`, `--no-plugins`, `--version`, `--help`.

**Search examples:**

```bash
sentinel search /var/log/auth.log --ip 203.0.113.5
sentinel search /var/log/auth.log --failed-logins --today
sentinel search /var/log/auth.log --user root --severity warning
sentinel search /var/log/auth.log --since 2026-01-01 --until 2026-01-07
```

---

## Detection rules

| ID   | Rule                          | Category            | MITRE               |
|------|-------------------------------|---------------------|---------------------|
| R001 | SSH Brute Force               | authentication      | T1110.001           |
| R002 | Password Spraying             | authentication      | T1110.003           |
| R003 | Credential Stuffing           | authentication      | T1110.004           |
| R004 | Repeated Auth Failures        | authentication      | T1110               |
| R005 | Root Login                    | authentication      | T1078.003           |
| R006 | Impossible Login Frequency    | authentication      | T1110               |
| R007 | Suspicious Login Hours        | authentication      | T1078               |
| R010 | Unauthorized Sudo Attempt     | privilege_escalation| T1548.003           |
| R011 | Sudo Abuse                    | privilege_escalation| T1548.003           |
| R012 | Privilege Escalation          | privilege_escalation| T1098, T1548        |
| R020 | New User Created (filtered)   | user_management     | T1136.001           |
| R021 | User Account Deleted          | user_management     | T1531               |
| R022 | Account Locked                | user_management     | T1110, T1531        |
| R030 | Port Scan                     | network             | T1046, T1595.001    |
| R031 | Reverse Shell Indicator       | network             | T1059.004, T1071    |
| R032 | Lateral Movement              | network             | T1021.004           |
| R040 | Suspicious Cron Activity      | cron                | T1053.003           |
| R041 | SSH Key Manipulation          | ssh                 | T1098.004, T1552.004|
| R042 | Persistence Indicator         | system              | T1543.002, T1546.004|
| R050 | Service Stopped Unexpectedly  | service_management  | T1489, T1562.001    |
| R051 | Firewall Modification         | firewall            | T1562.004           |
| R060 | Suspicious Docker Activity    | docker              | T1610, T1611        |

Plus `AI001` — AI Behavioral Anomaly, raised by the anomaly detector.

### R020 account classification

R020 distinguishes between account types to reduce false positives from
routine service-account creation (e.g. package installs creating `sshd`,
`www-data`, `systemd-network`):

| Account kind | How identified | Action |
|--------------|----------------|--------|
| **Privileged** | UID = 0 | Alert at CRITICAL — always |
| **System** | UID present and < `UID_MIN` | Suppress (logged internally) |
| **Service** | Username matches built-in or custom allowlist | Suppress (logged internally) |
| **Human** | Everything else (UID >= `UID_MIN`, no allowlist match) | Alert at NOTICE |

`UID_MIN` is read from `/etc/login.defs` at runtime (default 1000 when
unavailable). Override with `detection.uid_min` in config. The built-in
allowlist covers ~80 well-known service accounts with wildcard support
(`systemd-*`, `_*`). Add your own patterns via
`detection.service_account_allowlist`:

```yaml
detection:
  service_account_allowlist:
    - "myapp-*"
    - "deploy"
    - "ci-runner"
```

---

## Evaluation benchmark

`sentinel eval` measures detection quality reproducibly: it runs a fixed set of
labeled log scenarios through the detection pipeline and reports precision and
recall. In CI it acts as a regression gate against a committed baseline. The
command is offline: no plugins, no threat-intel calls, no automatic response,
and each scenario uses an isolated temporary state directory.

### Layout

```
benchmarks/
├── MANIFEST.sha256          # SHA-256 of every file under scenarios/
├── baseline.json            # committed reference report (no performance data)
└── scenarios/
    └── <name>/
        ├── labels.yaml      # what must (and must not) fire
        └── *.log            # one or more log files
```

### labels.yaml format

An attack scenario:

```yaml
name: ssh-brute-force            # must equal the directory name
kind: attack
description: Repeated SSH password failures from one source.
files:
  - auth.log
expect:
  rules: [R001]                  # all of these must fire
  min_risk_level: high           # optional; an expected alert must reach it
forbid:
  rules: [R005]                  # optional; none of these may fire
```

A benign scenario:

```yaml
name: normal-admin-session
kind: benign
description: Routine logins and a few sudo commands.
files:
  - auth.log
```

Rules, enforced when scenarios are loaded (invalid labels abort the run):

- Only the keys `name`, `kind`, `description`, `files`, `expect`, `forbid` are
  allowed at the top level; `expect` accepts `rules` and `min_risk_level`,
  `forbid` accepts `rules`. Unknown keys are rejected.
- `kind` is `attack` or `benign`. `files` must be a non-empty list.
- **Benign:** any alert at all is a false positive. It must not set
  `expect.rules` or `expect.min_risk_level`.
- **Attack:** `expect.rules` is required and non-empty. `min_risk_level`
  (`informational`, `low`, `medium`, `high`, `critical`) is satisfied when at
  least one alert from `expect.rules` reaches that level. `forbid.rules` lists
  rules that must not fire.
- Rule IDs must exist in the rule registry (or be `AI001`).
- File paths must be relative and stay inside the scenario directory; absolute
  paths, `..` and paths resolving outside the directory are rejected.

### Metrics

- Per-rule precision and recall, computed at scenario level.
- False positives per 1k benign events.
- Risk distribution of the alerts raised.
- MITRE ATT&CK coverage (techniques covered by passing expectations vs. all
  techniques mapped by registered rules) and rules not covered by any scenario.
- Throughput in events/sec (reported, never used for gating).

A scenario passes when no expected rule is missing, no forbidden rule fired
(for benign scenarios: no rule fired), and `min_risk_level` was reached.

### Running

```bash
sentinel eval                                        # run, print tables
sentinel eval --baseline benchmarks/baseline.json    # fail on regression vs baseline
sentinel eval --write-baseline benchmarks/baseline.json
sentinel eval --output eval-report.json              # full JSON report incl. performance
sentinel eval --json                                 # JSON report on stdout
```

| Option                  | Description                                                     |
|-------------------------|-----------------------------------------------------------------|
| `--benchmarks <dir>`    | Benchmark root containing `scenarios/` (default `benchmarks`)   |
| `--baseline <file>`     | Compare against this baseline and fail on regressions           |
| `--write-baseline <f>`  | Write the deterministic report (no performance data)            |
| `--output <file>`       | Write the full JSON report (with performance)                   |
| `--update-manifest`     | Rewrite `MANIFEST.sha256` instead of verifying it               |
| `--max-recall-drop <x>` | Tolerated recall drop, 0..1 (default `0.0`)                     |
| `--max-fp-increase <x>` | Tolerated rise of FP per 1k benign events (default `0.0`)       |
| `--json`                | Print the JSON report to stdout                                 |

The exit code is 1 if any scenario fails or any regression against the baseline
is found (lower overall or per-rule recall beyond the threshold, higher
false-positive rate, a previously passing scenario that now fails or is
missing, or a changed report `schema_version`).

### Frozen benchmark

Scenario files are hashed in `MANIFEST.sha256` (CRLF is normalized to LF before
hashing; symlinks are rejected). Every run first verifies the manifest and
aborts on any modified, added or removed file. Changing a scenario is therefore
a deliberate act: edit the files, run `sentinel eval --update-manifest`, then
regenerate the baseline with `--write-baseline` and commit both. Learning or
tuning code must never write into `benchmarks/`.

### Authoring scenarios

- Use RFC 3339 timestamps with an explicit year and offset
  (`2026-01-07T10:15:32+00:00`). Do not use BSD-style `Jan  7 10:15:32`
  headers: they carry no year, so the year is inferred from today's date and
  results would change over time.
- Use RFC 5737 documentation IPs (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`) and no real hostnames, users or secrets.
- Use LF line endings (the repository's `.gitattributes` is there to keep them).

### Limitations

The scenarios are synthetic and were written against the current behavior of
the rules. 100% recall and 0 false positives on this benchmark therefore means
"no regression", not real-world accuracy.

### Known detection gaps

Found while building the benchmark and still open:

- R041/R042 cannot tell a legitimate `authorized_keys` edit from an attack
  because they match on the text.
- R031 and R050 score only "medium" risk.

Fixed using the benchmark: R051 no longer flags plain `ufw allow`, R060 no
longer fires on `privileged: false`, and `pam_faillock` lines logged by sshd
are now classified as `ACCOUNT_LOCKED`.

---

## Feedback and tuning

You label alerts as true or false positives; `sentinel tune` turns those labels
into small, reviewable proposals and checks each one before anything changes.

**The promise:** the loop never changes code or model weights. It only proposes
small, bounded edits to a machine-managed overlay file, and nothing is applied
without `--apply`.

### Workflow

1. Scan as usual (`sentinel scan ...`); alerts are stored.
2. Label them: `sentinel review` (interactive: `t` true positive, `f` false
   positive with an optional note, `s` skip, `q` quit) or
   `sentinel feedback <id> --tp|--fp [--note "..."]`. Labelling an alert again
   replaces the earlier verdict.
3. `sentinel tune` lists the proposals, each marked **ACCEPT** or **REJECT**
   with a reason, and prints the accepted ones as YAML. It changes nothing.
4. `sentinel tune --apply` writes the accepted proposals to the overlay.
5. `sentinel tune --history` lists applied and rolled-back changes;
   `sentinel tune --rollback` undoes the latest apply.

| `sentinel tune` option | Description                                                    |
|------------------------|----------------------------------------------------------------|
| `--apply`              | Write the accepted proposals to the overlay                    |
| `--only <id>`          | Restrict to this proposal id (repeatable); unknown ids fail    |
| `--force`              | Relax the soft limits below (never the hard ones)              |
| `--benchmarks <dir>`   | Frozen benchmark root used by the gate (default `benchmarks`)  |
| `--yaml-out <file>`    | Also write the accepted proposals as YAML to this path         |
| `--history`            | Show applied and rolled-back changes                           |
| `--rollback`           | Undo the latest applied change and exit                        |

### What can change

| Change type        | Overlay key                  | Effect                                            |
|--------------------|------------------------------|---------------------------------------------------|
| Threshold          | `detection.<threshold>`      | Raise a count threshold of R001, R002, R003, R004, R006 or R030 |
| Suppression        | `detection.suppressions`     | Narrow, time-boxed: one rule for a user and/or a small network |
| Risk weight        | `risk.rule_weights`          | Multiply the risk score of one rule (lowered by 20% per step) |

A threshold proposal is generated when the false positives sit below the lowest
labelled true positive. A risk-weight proposal is only generated for a rule
that got neither a threshold nor a suppression proposal. The loop cannot
disable rules.

### How the gate decides

A proposal is accepted only if all three hold:

1. Frozen benchmark: attack recall must not drop and no previously passing
   scenario may fail (the benchmark is run before and after the change).
2. Analyst-labelled false positives that still alert must measurably decrease.
3. No analyst-labelled true positive may stop alerting.

Proposals are gated one by one. On `--apply`, the accepted set is gated again as
a whole, and the apply is aborted if that fails. With no labelled alerts a
proposal cannot be verified and is rejected.

### Hard limits

Enforced in code, not in configuration.

| Limit                                                        | `--force`   |
|--------------------------------------------------------------|-------------|
| Threshold stays within 0.5x-2x of its default                | Overridable |
| Suppressing a rule whose severity is critical                | Overridable |
| Suppression needs a user and/or a network no broader than /24 (IPv4) or /64 (IPv6) | No |
| Suppression expires within 90 days (default 30)              | No          |
| At most 5 active suppressions per rule                       | No          |
| Risk weight between 0.5 and 1.5                              | No          |
| Overlay may only contain thresholds, suppressions and risk weights | No    |

Alerts whose own severity is critical are **never** suppressed, whatever the
configuration says.

The proposal limits apply to what the loop generates. Suppressions you write by
hand in `config.yaml` are validated for shape (`rule`, at least one of `user` /
`ip`, `expires`, optional `note`) but not against the limits above; risk
weights are range-checked wherever they are set.

### Where things live

| What                | Location                                              |
|---------------------|-------------------------------------------------------|
| Overlay             | `<state_dir>/tuning.yaml` (`config.yaml` is never rewritten) |
| Backups             | `<state_dir>/tuning/history/NNNN-before-apply.yaml`   |
| Audit log           | `<state_dir>/tuning/audit.jsonl` (append-only)        |
| Labels, history     | `<state_dir>/alerts.db`                               |

Precedence, lowest to highest: built-in defaults, `config.yaml`, overlay,
environment variables. Overlay suppressions are added to the ones in
`config.yaml`; they never replace them.

Suppressed alerts are not dropped silently: they are counted
(`Suppressed (analyst rules): N`) and shown in reports.

`sentinel tune` needs the frozen `benchmarks/` directory (a repository checkout)
or `--benchmarks PATH`. If it cannot find `scenarios/` there it refuses to
apply.

### Example session

```
$ sentinel feedback 12 --fp --note "nightly deploy job"
Recorded alert #12 (R001) as false positive.
$ sentinel review --limit 10
...
Labelled 6 alert(s).

$ sentinel tune
                              Tuning proposals
 ID        │ Rule │ Kind        │ Change                              │ Verdict │ Reason
───────────┼──────┼─────────────┼─────────────────────────────────────┼─────────┼──────────────────────────
 P3f9a1c2e │ R001 │ threshold   │ brute_force_attempts: 5 -> 7        │ REJECT  │ benchmark regressions: scenario: r001_ssh_bruteforce
 P8b04d7a6 │ R001 │ suppression │ suppress R001 (user=deploy,         │ ACCEPT  │ benchmark attack recall unchanged at 1.0000
           │      │             │ ip=198.51.100.0/24) until 2026-12-03│         │

Accepted proposals (YAML):
# Proposed changes - nothing is applied until you run: sentinel tune --apply
- id: P8b04d7a6
  kind: suppression
  ...

Nothing was changed. Re-run with --apply to write the overlay.

$ sentinel tune --apply --only P8b04d7a6
Applied P8b04d7a6.
Overlay: /home/analyst/.sentinelai/tuning.yaml
History id: 1
Undo with: sentinel tune --rollback

$ sentinel tune --rollback
Rolled back change #1 (proposals: P8b04d7a6).
There was no overlay before that change, so it was removed.
```

### Limitations

- Proposals come from simple heuristics over labelled alerts. A rule is only
  considered with at least 3 labelled alerts, at least 3 of them false
  positives, and a false-positive share of at least 60%.
- The benchmark is synthetic, so the gate protects against regressions, not
  against every real-world miss.
- Threshold raises are often rejected, because the frozen benchmark attacks sit
  close to the default thresholds. A narrow suppression is then the usual outcome.

---

## Threat detection example

Running `sentinel scan examples/auth.log` on the bundled attack scenario:

```
┌──────────────────────────── Scan Summary ────────────────────────────┐
│ Events analyzed: 14                                                   │
│ Alerts: 9                                                             │
│ Attack patterns: 1                                                    │
│ By risk: 1 critical  3 high  5 medium                                 │
└───────────────────────────────────────────────────────────────────────┘

 # │ Risk     │ Score │ Rule │ Source IP    │ User     │ Title
───┼──────────┼───────┼──────┼──────────────┼──────────┼──────────────────────
 8 │ CRITICAL │    85 │ R031 │ -            │ root     │ Reverse shell detected
 1 │ HIGH     │    68 │ R001 │ 203.0.113.55 │ oracle   │ SSH brute force
 6 │ HIGH     │    65 │ R020 │ -            │ backdoor │ UID-0 account created
 7 │ HIGH     │    65 │ R040 │ -            │ root     │ Suspicious cron job
 …

Attack patterns detected:
  • Successful intrusion after brute force (confidence 90%):
    Source 203.0.113.55 brute-forced credentials and subsequently
    achieved a successful login — the attack likely succeeded.
```

The **attack-pattern recognizer** connected the dots: brute force → successful
login → backdoor account → reverse shell → firewall tampering, all from the same
source, and named it a multi-stage intrusion.

---

## AI explanation example

`sentinel explain 8` produces a SOC-analyst-style breakdown. With no local LLM it
uses a deterministic template; with one configured (`ai.llm.enabled: true`) it
uses the model — the output shape is identical:

```
WHY SUSPICIOUS: Content matching a reverse-shell payload was observed
(bash -i >& /dev/tcp/...). The command grants an interactive attacker
channel and targets the root account, which already triggered 3 earlier
alerts in this run.
POTENTIAL ATTACK: Consistent with MITRE ATT&CK T1059.004, T1071
(Execution, Command and Control).
RECOMMENDED ACTIONS: Treat the host as compromised: isolate it, capture
volatile state, and identify the remote endpoint of the shell.
CONFIDENCE: 85
```

To enable the local LLM, point `ai.llm.endpoint` at an Ollama-compatible server.

---

## Firewall integration

**SentinelAI contains no firewall logic.** It depends only on the
`FirewallController` protocol (`block_ip`, `unblock_ip`, `temporary_block`,
`list_blocked`, `is_blocked`) and binds it to *your* Firewall Automation project
at runtime via one of three adapters:

- **`python`** — import a controller class/factory from your project:
  ```yaml
  firewall:
    adapter: python
    module: firewall_automation.api
    attribute: FirewallManager
    init_kwargs: { profile: sentinel }
  ```
- **`command`** — call your project's CLI (args passed as a list, never a shell):
  ```yaml
  firewall:
    adapter: command
    command: firewall-automation
    block_args: ["block", "{ip}"]
    temp_block_args: ["block", "{ip}", "--duration", "{duration}"]
  ```
- **`dry_run`** — the safe default; logs intended actions without touching anything.

Automatic response (off by default) only acts above a configurable risk level,
skips allowlisted networks, enforces a per-IP cooldown and a per-run block budget.

---

## Development guide

```bash
pip install -e ".[ai,dev]"

pytest tests/ -v            # run the test suite
pytest tests/ --cov=sentinelai   # with coverage

ruff check src tests        # lint
ruff format src tests       # format
mypy src                    # type-check (strict)

sentinel eval --baseline benchmarks/baseline.json   # detection regression gate
```

CI (`.github/workflows/ci.yml`) runs ruff, mypy, pytest and `sentinel eval
--baseline benchmarks/baseline.json` on Python 3.10, 3.11, 3.12 and 3.13 for
every push to `main` and every pull request.

Layout: source in `src/sentinelai/`, tests in `tests/`, sample logs in
`examples/`. The pipeline (`core/pipeline.py`) is the composition root — start
there to understand how the pieces connect.

**Design rules of thumb**

- Keep the inner layers (`core`, `config`, `utils`) free of outward dependencies.
- Cross-boundary collaborators are protocols (`FirewallController`,
  `AnomalyModel`, `ThreatIntelProvider`, `LogParser`, `Rule`).
- Parsers must never raise on bad input — return `None`.
- Rules must be side-effect-free except through the shared sliding-window state.

---

## Extending SentinelAI

Everything pluggable uses the same pattern: implement + register. Drop a `.py`
file into `~/.sentinelai/plugins/` (or `$SENTINELAI_PLUGINS_DIR`) and it loads
automatically — no core changes.

**A custom detection rule:**

```python
from sentinelai.core.models import EventCategory, EventType, Severity
from sentinelai.detection.base import Rule, RuleContext, register_rule

@register_rule
class MyRule(Rule):
    rule_id = "X001"
    name = "My Custom Rule"
    category = EventCategory.AUTHENTICATION
    severity = Severity.WARNING
    mitre_techniques = ("T1110",)
    recommendation = "Investigate the source."

    def evaluate(self, event, ctx: RuleContext):
        if event.event_type is EventType.AUTH_FAILURE and event.user == "ceo":
            return self.make_alert(event, title="CEO account targeted",
                                   description="Failed login against the CEO account.")
        return None
```

**A custom parser:** subclass `LogParser` + `@register_parser`.
**A custom anomaly model:** implement `AnomalyModel` + `register_model(...)`.
**A custom report format:** `register_renderer("fmt", my_renderer)`.
**A custom risk factor:** implement `RiskFactorEvaluator` + `engine.add_factor(...)`.

---

## Contributing

1. Fork and create a feature branch.
2. Add or update tests for your change (the suite must stay green).
3. Run `ruff check`, `ruff format`, `mypy src`, and `pytest`.
4. Keep the architecture boundaries intact — new external collaborators go behind
   a protocol.
5. Open a pull request describing the behavior change and any new config keys.

Bug reports and rule contributions (with a sample log line that triggers them)
are especially welcome.

---

## Screenshots

_Placeholders — add terminal captures here:_

- `docs/screenshot-scan.png` — a `sentinel scan` run
- `docs/screenshot-explain.png` — a `sentinel explain` breakdown
- `docs/screenshot-report.png` — the HTML report

---

## License

MIT — see [LICENSE](LICENSE).
