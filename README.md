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
- [Structured LLM triage](#structured-llm-triage)
- [Firewall integration](#firewall-integration)
- [Safe automated response](#safe-automated-response)
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
  multi-stage attack-pattern recognition, and advisory alert triage via an
  optional local LLM (schema-validated, with a deterministic fallback).
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
| `sentinel eval --triage`   | Also measure the configured LLM's triage (advisory only) |
| `sentinel feedback <id>`   | Label a stored alert as true (`--tp`) or false (`--fp`) positive |
| `sentinel review`          | Interactively label recent, unlabelled alerts            |
| `sentinel tune`            | Propose, gate and (`--apply`) apply feedback-driven tuning |
| `sentinel respond`         | Review, approve, deny, reap and roll back firewall responses (see [Safe automated response](#safe-automated-response)) |
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
| `--triage`              | Also triage attack-scenario alerts with the configured LLM (advisory, needs `ai.llm.enabled`) |
| `--triage-limit <n>`    | Maximum number of alerts to triage (default `25`)               |
| `--triage-output <file>`| Write the triage evaluation as JSON to this path                |

The exit code is 1 if any scenario fails or any regression against the baseline
is found (lower overall or per-rule recall beyond the threshold, higher
false-positive rate, a previously passing scenario that now fails or is
missing, or a changed report `schema_version`). The `--triage` results never
affect the exit code; see [Choosing a local model](#choosing-a-local-model).

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

## Structured LLM triage

`sentinel explain <id>` explains a stored alert. With no LLM configured
(`ai.llm.enabled: false`, the default) it prints a deterministic template built
from the rule metadata, risk factors and threat intelligence:

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

With `ai.llm.enabled: true` the alert is sent to a local (or OpenAI-compatible)
model, which must answer with a structured verdict:

| Field                   | Content                                                       |
|-------------------------|---------------------------------------------------------------|
| `verdict`               | `benign`, `suspicious` or `malicious`                         |
| `confidence`            | Number from 0 to 1                                            |
| `summary`               | Short statement (max 400 characters)                          |
| `reasoning`             | Why the model decided so (max 1500 characters)                |
| `recommended_actions`   | Up to 5 actions (max 200 characters each)                     |
| `referenced_event_ids`  | Numbers (1-based, as listed in the prompt) of the events the verdict relies on |

The result is printed in the four-line format above (labels follow
`ai.llm.language`; the `POTENTIAL ATTACK` line carries the verdict), followed by a
`Triage verdict (advisory)` line with the verdict, confidence and whether it came
from the model or the template fallback. The full record, including the
referenced event numbers, the source (`llm:<model>`, `cache:<model>` or
`template`) and the reason a model answer was rejected, is stored with the alert.

**The verdict is advisory only.** It never changes the risk score, never creates
or suppresses an alert, and never triggers or blocks an automated response.
Scoring, detection and response stay rule- and policy-based.

### How model output is validated

Nothing the model returns is trusted:

- **Structured output.** The request carries the JSON schema of the answer:
  Ollama via `format` (with `/api/chat`), OpenAI-compatible servers via
  `response_format` of type `json_schema` (strict, with `/v1/chat/completions`).
  Temperature is 0.
- **Strict check on the client.** The server-side constraint is not relied upon.
  The answer must be one JSON object with exactly the six keys above; an invalid
  or non-JSON answer, duplicate keys, an unknown or missing key, a wrong type, a
  verdict outside the three values, a confidence outside 0..1, an over-long
  field, or a response above the size limit is rejected.
- **Grounding.** `referenced_event_ids` may only cite events that were in the
  prompt (E1..En, at most 5). Citing an event number that was not provided
  rejects the whole answer.
- **Retries and fallback.** Only transient failures are retried: network
  errors, timeouts, a response that is too slow, and HTTP 429 or 5xx. Retries
  are made up to `max_retries` times with exponential backoff
  (`retry_backoff_seconds * 2^attempt`) and stop once a total time budget of
  `timeout_seconds * (max_retries + 1)` is exceeded. Invalid or ungrounded
  answers, other HTTP errors and oversized responses are not retried. If no
  valid answer arrives, the deterministic template is used and the reason is
  recorded. A failure in triage never aborts `sentinel explain`.
- **Network hardening.** Redirects are not followed, a response is read for at
  most 1 MB, and the whole read must finish within `timeout_seconds`. Proxy
  settings from the environment and `~/.netrc` are ignored.
- **API key.** The key is sent only over `https://` or to a loopback address
  (`localhost`, `127.0.0.0/8`, `::1`); the configuration is rejected otherwise.
  It is excluded from `repr` output and from error messages. Set it with
  `SENTINELAI_AI_LLM_API_KEY`.
- **Cache.** Only validated answers are cached, in `<state_dir>/triage_cache.db`
  (SQLite), keyed by alert fingerprint, provider, endpoint, model, language and
  a hash of the prompt. Changing any of these therefore never serves an old
  verdict. Rows are validated again on every read and a row that fails is
  deleted; entries expire after `cache_ttl_seconds` and expired rows are purged
  when the cache is opened. `0` disables caching.

### Prompt-injection handling

Log text is written by whoever can reach the monitored host, so it is treated as
untrusted data, never as instructions.

| Risk                                          | Countermeasure                                                                 |
|-----------------------------------------------|--------------------------------------------------------------------------------|
| Hidden or terminal-control characters         | ANSI/OSC escape sequences, control characters and zero-width/invisible characters are stripped; text is Unicode-normalised (NFKC) and collapsed to one line |
| Oversized input                               | Every field is truncated (event messages to 300 characters, at most 5 events)  |
| Log text read as instructions                 | Log-derived text appears only inside one `<<<LOG_DATA ... LOG_DATA>>>` block of the **user** message, never in the system message; the system message states that the block is untrusted data |
| Forged delimiters ending the data block early | Delimiter markers are removed from the data (repeatedly, so they cannot be reassembled) |
| Invented evidence                             | Grounding check on `referenced_event_ids` (see above)                          |
| Model output used for actions                 | The verdict is advisory and cannot trigger a response                          |
| Terminal injection through explanations       | Explanation text is escaped before printing and control characters are stripped |

#### Injection corpus

`benchmarks/injection/` holds 38 attacker-controlled log strings
(`cases.yaml`) and `attack_auth.log`, an sshd brute-force log with payloads in
usernames and trailing text. It is separate from `benchmarks/scenarios/` and is
not part of `MANIFEST.sha256` or `baseline.json`. `tests/test_triage_injection.py`
runs it offline and checks that:

- attacker text appears only inside the `LOG_DATA` block of the user message;
- a simulated vulnerable model, which obeys any instruction outside that block,
  always takes the honest path;
- a compromised model whose output is ungrounded (citing events that were not
  provided) is rejected and the template is used;
- an accepted verdict leaves the risk score and the automated-response actions
  identical to a run without the LLM;
- detection results are unchanged when the payloads are stripped from the log.

### Known limitations

- These measures reduce prompt-injection risk but cannot eliminate it. A model
  can still be steered into a wrong verdict by crafted log lines, for example a
  "benign" verdict for a real attack. The delimiters are static and public, so
  lookalike characters can only be filtered heuristically and may fool the
  model. This is why the verdict is advisory and cannot trigger any response.
  Treat it as a second opinion next to the rule-based alert, not as a decision.
- `recommended_actions` is free text shown to the analyst. It is never executed.

### Configuration

All keys live under `ai.llm` (see [`config.example.yaml`](config.example.yaml)):

| Key                     | Default                  | Description                                           |
|-------------------------|--------------------------|-------------------------------------------------------|
| `enabled`               | `false`                  | Use the LLM for `sentinel explain` and `eval --triage` |
| `provider`              | `ollama`                 | `ollama` or `openai` (any OpenAI-compatible server)   |
| `endpoint`              | `http://localhost:11434` | Base URL, `http://` or `https://` (with `api_key`: `https://` or loopback only) |
| `model`                 | `llama3.1`               | Model name sent to the server                         |
| `language`              | `en`                     | Language of the answer: `en`, `tr` or `de`            |
| `timeout_seconds`       | `60.0`                   | Per-request timeout and total read deadline; finite, above 0 and at most 600 |
| `max_tokens`            | `700`                    | Maximum tokens the model may generate                 |
| `max_retries`           | `1`                      | Retries after a transient failure (0..3)              |
| `retry_backoff_seconds` | `1.0`                    | Base delay between retries, doubled each attempt; finite, 0..60 |
| `cache_ttl_seconds`     | `604800` (7 days)        | Lifetime of cached verdicts; `0` disables the cache   |
| `api_key`               | empty                    | Bearer token for `provider: openai` (not used by Ollama); never shown in `repr` |

Provide the API key through the environment, not the file. It is only sent over
`https://` or to a loopback address:

```bash
export SENTINELAI_AI_LLM_API_KEY="xxxxxxxx"
```

`language` controls the model's answer and the labels of the template fallback.
The `verdict` value itself is always one of the three English words in the stored
record.

### Choosing a local model

This project does not ship benchmark numbers for specific models. Quality,
speed and structured-output support differ per model and per machine, so measure
on your own hardware. Small instruction-tuned models that support structured
output are a reasonable starting point; on Ollama, for example, try
`llama3.1:8b`, `qwen2.5:7b` or `gemma2:9b`, and judge them with
`sentinel eval --triage`.

`sentinel eval --triage` runs the normal benchmark, then triages the alerts raised
by the attack scenarios with the configured LLM (it fails early if
`ai.llm.enabled` is false). Every one of those alerts is a true detection, so a
`benign` verdict counts as a disagreement.

```bash
sentinel eval --triage                                    # up to 25 alerts
sentinel eval --triage --triage-limit 50 --triage-output triage-report.json
```

| Metric                  | Meaning                                                          |
|-------------------------|------------------------------------------------------------------|
| Valid-answer rate       | Share of alerts where the model's answer passed validation       |
| Agreement (not benign)  | Share of verdicts that are `suspicious` or `malicious`           |
| Malicious rate          | Share of verdicts that are `malicious`                           |
| Fallbacks (template)    | Share of alerts that ended with the deterministic template       |
| Latency p50 / p95       | Median and 95th percentile time per model-answered alert         |
| Rejected: ...           | Most frequent reasons answers were rejected (top 5 in the table, top 10 in the JSON) |

`--triage-limit` caps the number of alerts (default 25); `--triage-output` writes
the metrics plus a per-alert list as JSON. The results are informational: they
do not affect the exit code or the regression gate, and the baseline is never
touched. Triage runs without the cache, so every alert is sent to the model.

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
See [Safe automated response](#safe-automated-response) for the full list of
safety rails, approval mode, the audit log and rollback.

---

## Safe automated response

Automated blocking is the part of a security tool that can do the most damage,
so it is off by default and bounded in several independent ways.

- **Off by default.** Nothing is blocked unless `response.enabled: true`.
- **`dry_run` by default.** Even when enabled, the default `firewall.adapter` is
  `dry_run`, which only logs the intended action. A real firewall is touched
  only after you configure the `python` or `command` adapter.
- **Every decision is audited**, including the reason nothing was blocked
  (except alerts below the risk threshold, and repeated identical skips are
  throttled; see [Audit log](#audit-log)).
- **Fails closed.** If SentinelAI cannot record a block, read the hourly block
  history or evaluate lockout protection, it does not block.

### Address handling

Every address is canonicalised once, before any check, and all later checks use
that form:

- IPv4-mapped IPv6 such as `::ffff:203.0.113.7` is treated as the IPv4 address
  `203.0.113.7`, so an allowlist or `admin_ranges` entry cannot be bypassed by
  writing the same host in IPv6 form.
- Input with whitespace, a zone id (`%eth0`) or a prefix (`/24`) is rejected as
  not a valid IP.
- Unspecified, loopback, multicast, link-local and reserved addresses (and
  `255.255.255.255`) are never blocked, whatever the allowlist says.

### Decision order

For each alert, `AutoResponder` checks the following in order. The first check
that fails ends the evaluation and the reason is written to the audit log
(alerts below the risk threshold are not logged, and identical skips are
throttled; see [Audit log](#audit-log)).

| # | Check | Skips when |
|---|-------|------------|
| 1 | Risk threshold | The alert's risk level is below `response.min_risk_level` |
| 2 | Valid IP | The alert has no source IP, or it is not a valid IP (see above) |
| 3 | Blockable address | The IP is unspecified, loopback, multicast, link-local or reserved |
| 4 | Allowlist | The IP is inside `response.allowlist` |
| 5 | Self-lockout protection | The IP is an admin range, the current SSH peer, the default gateway or an address of this host (see below) |
| 6 | Per-run budget | `response.max_blocks_per_run` blocks were already made in the current hourly window |
| 7 | Failure pause | Five consecutive firewall failures; automatic attempts resume in the next hourly window |
| 8 | Hourly circuit breaker | `response.max_blocks_per_hour` recorded response actions in the last hour, or the block history cannot be read (decision `circuit_breaker`; needs the alert store) |
| 9 | Cooldown | The same IP was attempted less than `response.cooldown_seconds` ago in this process (a failed attempt also starts the cooldown) |
| 10 | Already blocked | `is_blocked(ip)` reports the IP is already blocked |

The per-run budget and the failure streak reset every hour of clock time, so a
long-running `sentinel live` gets a fresh budget each hour.

If all checks pass, `response.mode` decides the outcome: `auto` blocks
immediately, `approval` queues a request for a human (below). When
`response.temporary_block` is true the block is a `temporary_block` of
`block_duration_seconds`; otherwise it is a permanent `block_ip`.

### Failure handling

- **Record first.** In `auto` mode the block is written to the alert store
  (`<state_dir>/alerts.db`) *before* the firewall is called. If it cannot be
  recorded, the block is refused and audited as `failed`, so a temporary block
  can never silently become permanent because nobody tracked its expiry. If the
  firewall then fails, the record is marked `failed`.
- **Adapter errors are failed actions.** Any exception raised by a firewall
  adapter is turned into a failed action (only the exception class name is kept
  in records). It cannot crash detection or `sentinel live`.
- **Backoff.** A failed attempt starts the per-IP cooldown. Five consecutive
  failures pause automatic attempts until the next hourly window; a successful
  block resets the streak.

### Self-lockout protection

`LockoutGuard` refuses to block an address that could cut the operator off from
the machine. It checks, in this order, and each check except `admin_ranges` can
be switched off:

| Check | Switch | Protects |
|-------|--------|----------|
| Admin ranges | `response.admin_ranges` (empty by default) | Any IP/CIDR you list, e.g. your office or VPN range |
| SSH peer | `response.protect_ssh_peer` (default `true`) | The client address of the current SSH session, read from `SSH_CONNECTION` or `SSH_CLIENT` in SentinelAI's environment |
| Default gateway | `response.protect_gateway` (default `true`) | The default IPv4 gateway(s) from `/proc/net/route` (Linux only) |
| Own addresses | `response.protect_own_addresses` (default `true`) | Loopback and the host's own addresses (hostname resolution plus the source address of the default route) |

A protected IP is skipped with the reason `self-lockout protection: ...`.
Addresses are compared in canonical form (IPv4-mapped IPv6 counts as IPv4). The
guard never raises and fails closed: if it hits an unexpected internal error
(for example the gateway lookup fails), it reports `could not evaluate lockout
protection` and the block is refused.

### Approval mode

With `response.mode: approval`, SentinelAI never blocks by itself. An alert that
passes the decision order is stored as a pending request (decision `queued`).

- At most one open request per IP; a further alert for the same IP is skipped as
  "already pending approval".
- The queue is capped at `max(100, 10 x max_blocks_per_hour)` open requests; when
  it is full, new requests are skipped as "approval queue is full".

```bash
sentinel respond --pending                      # list requests awaiting a decision
sentinel respond --approve 7 --note "confirmed" # block the IP of request #7
sentinel respond --deny 8 --note "known scanner"
```

- Approval **re-checks policy at decision time**: valid IP, blockable address,
  allowlist, self-lockout protection, hourly circuit breaker and "already
  blocked". The world may have changed since the request was queued.
  (Per-run budget, failure pause and cooldown apply to automatic blocks only.)
  The outcome depends on why a check fails:
  - **Permanent reason** (allowlisted, protected, invalid or never-blockable
    address): the request is marked denied, the reason is audited, and nothing
    is blocked.
  - **Transient reason** (hourly breaker open, IP already blocked): the request
    stays pending and the command reports "try again later".
- Approval is atomic: the request is claimed once, so two concurrent approvals
  cannot both block, and a request that was already decided cannot be approved
  again. If the block cannot be recorded or the firewall fails, the claim is
  released and the request can be retried.
- Stale requests cannot be approved. Pending requests expire after
  `response.pending_expire_seconds` (default 24 h) and are then recorded as
  `expired`. Expiry is applied whenever the queue is listed, reaped or approved.
- `--approve` and `--deny` are repeatable. Exit code is 1 if any request failed.

### Audit log

Every decision is appended to `<state_dir>/response/audit.jsonl`, one JSON
object per line. This includes decisions where nothing was blocked, so "why was
this IP not blocked?" has an answer. Two things are deliberately not logged, to
keep the file useful under a flood of alerts:

- Skips for "risk below threshold" (the alert is not a blocking candidate).
- Repeated identical skips: the same IP and reason is logged at most once per
  minute.

| Decision | Meaning |
|----------|---------|
| `blocked` | A block was applied |
| `skipped` | Policy decided not to act; `reason` says why |
| `queued` | A request is waiting for approval |
| `approved` | An operator approved a request |
| `denied` | An operator denied a request, or a re-check refused the approval for a permanent reason |
| `failed` | The firewall reported failure or raised, the block could not be recorded, or a request could not be queued |
| `reaped` | A temporary block was removed after its TTL expired |
| `rolled_back` | A block was removed by `--rollback` |
| `expired` | Pending requests timed out |
| `circuit_breaker` | The hourly cap stopped a block, or the block history could not be read |

Each record has `ts` (UTC), `event` (`response`), `decision` and, when known,
`ip`, `reason`, `alert_id`, `rule_id`, `risk_level`, `mode`, `run_id`. Strings
are stripped of control characters and capped at 500 characters, so log-derived
text cannot forge extra lines. A failed write is logged and never stops
detection.

The file rotates at 10 MB: `audit.jsonl` becomes `audit.jsonl.1`, older files
shift up, and 5 rotated files are kept (the oldest is deleted).
`sentinel respond --history` continues into the rotated files when the active
one holds fewer records than requested.

```bash
sentinel respond --history            # last 20 decisions
sentinel respond --history --limit 100
```

### TTL enforcement and reaping

Most firewall tools (UFW, for example) have no native rule expiry. SentinelAI
therefore does not rely on the firewall to remove temporary blocks: every
temporary block is recorded with an expiry time in the alert store
(`<state_dir>/alerts.db`) before the firewall is called, and SentinelAI calls
`unblock_ip` itself when the time is up. The block is then marked `reaped` and
audited.

- `sentinel respond --reap` removes all due blocks now.
- `sentinel live` reaps automatically every `response.reap_interval_seconds`
  (default 60), only when `response.enabled` is true.
- `sentinel scan` reaps at the start of the run, only when `response.enabled`
  is true.
- If `unblock_ip` fails, the block stays due and is retried on the next reap.
- Reap and rollback never remove an IP that a longer-lived block still covers.
  The row is marked `reaped` / `rolled_back` with the detail "IP stays blocked by a
  longer-lived block", and the firewall is not called.
- Permanent blocks (`response.temporary_block: false`) have no expiry and are
  removed only with `--rollback` or by your firewall tooling.

### Rollback

```bash
sentinel respond --rollback --since 2h       # blocks applied in the last 2 hours
sentinel respond --rollback --run RUN_ID     # blocks made by one run
```

`--since` accepts `30m`, `2h`, `3d` or an ISO-8601 time (no timezone means UTC).
Only blocks still in the `applied` state are unblocked; each one is audited as
`rolled_back`.

### Confirmation

`--approve`, `--deny`, `--reap` and `--rollback` ask for confirmation before they
change anything. The prompt first lists what will happen: for `--approve` and
`--deny`, one line per request as `#id ip (rule, risk)` (ids that are unknown,
already decided or expired are reported and left out); for `--reap` and
`--rollback`, the IPs that will be unblocked (first 50). `--yes` skips the
prompt and the listing. Without a terminal and without `--yes` the command
refuses and exits with code 1. `--pending` and `--history`
are read-only and never prompt.

### `sentinel respond` options

Exactly one action per call.

| Option | Description |
|--------|-------------|
| `--pending` | List responses awaiting approval |
| `--approve ID` | Approve a pending response and block its IP (repeatable) |
| `--deny ID` | Deny a pending response; nothing is blocked (repeatable) |
| `--note TEXT` | Reason stored with `--approve` / `--deny` |
| `--reap` | Unblock expired temporary blocks now |
| `--rollback` | Undo applied blocks; needs `--since` or `--run` |
| `--since TEXT` | With `--rollback`: blocks since `30m` / `2h` / `3d` ago or an ISO-8601 time |
| `--run RUN_ID` | With `--rollback`: blocks of this run id |
| `--history` | Show the response audit trail |
| `--limit N` | With `--history`: number of records (default `20`) |
| `--yes` | Skip the confirmation prompt |

### Reference adapter: UFW

[`examples/firewall_adapter_ufw.py`](examples/firewall_adapter_ufw.py) is a
ready-made `FirewallController` for UFW. It is meant to be **copied into your own
firewall project**; SentinelAI core never imports it. It runs `ufw` with list
arguments only (no shell), validates every IP with `ipaddress` first (input with
`%`, whitespace or `/` is rejected; IPv4-mapped IPv6 becomes IPv4), and refuses
private, loopback, multicast, unspecified and link-local targets. Its
`temporary_block` only installs the deny rule; expiry is done by SentinelAI's
reaper through `unblock_ip` (see above).

- Blocks use `ufw insert 1 deny from <ip>`. UFW is first match, so an appended
  rule could be shadowed by an earlier ALLOW rule.
- `sudo -n` is the default prefix, so a missing NOPASSWD rule fails immediately
  instead of waiting for a password. Allow only the needed `ufw` commands in
  sudoers.
- Every call runs with stdin closed and `LC_ALL=C LANG=C`, so output parsing does
  not depend on the locale.
- A block is refused (returns `False`, warning logged) while `ufw status`
  reports `Status: inactive`, because the rule would not be enforced.
- `ufw insert 1` fails on a completely empty rule set, so the first block on
  such a system is reported as failed.

```yaml
firewall:
  adapter: python
  module: firewall_adapter_ufw        # wherever you copied the file
  attribute: UfwFirewall
  init_kwargs:
    sudo_prefix: ["sudo", "-n"]       # default; [] when running as root
    ufw_binary: ufw
    timeout_seconds: 15
```

Your existing `firewall_manager.py` cannot be imported or driven as it is: it
runs a top-level interactive menu loop with no `if __name__ == "__main__":`
guard, so importing it starts the menu, and it has no unblock or list function,
which temporary blocks and rollback need. Either copy the UFW adapter, or
refactor that file to expose a class with the five `FirewallController` methods
and guard the menu.

### Configuration

All keys live under `response` (see [`config.example.yaml`](config.example.yaml)).
The existing keys (`enabled`, `min_risk_level`, `temporary_block`,
`block_duration_seconds`, `cooldown_seconds`, `max_blocks_per_run`, `allowlist`)
are unchanged. New keys:

| Key | Default | Description |
|-----|---------|-------------|
| `mode` | `auto` | `auto` blocks immediately; `approval` queues requests for `sentinel respond` |
| `admin_ranges` | `[]` | IPs/CIDRs that are never blocked (your admin or VPN networks) |
| `protect_ssh_peer` | `true` | Never block the client address of the current SSH session |
| `protect_gateway` | `true` | Never block the default gateway (Linux only) |
| `protect_own_addresses` | `true` | Never block the host's own addresses |
| `max_blocks_per_hour` | `30` | Hourly circuit breaker across runs; positive integer. Also sets the approval queue cap, `max(100, 10 x value)` |
| `pending_expire_seconds` | `86400` | Age after which an unapproved request expires; positive integer |
| `reap_interval_seconds` | `60` | How often `sentinel live` reaps expired blocks; positive integer |

### Limitations

- Gateway detection reads `/proc/net/route`, so it works on Linux only, and
  only finds IPv4 gateways. Elsewhere `protect_gateway` protects nothing.
- SSH-peer protection only knows the session that launched SentinelAI (from its
  environment). A SentinelAI started by systemd or cron has no such session, and
  other administrators' sessions are not known. List those networks in
  `admin_ranges`.
- The host's own addresses are a best-effort lookup (hostname resolution and the
  default-route source address), not a full interface scan.
- Run ids of operator-approved blocks are `operator`, so `--rollback --run` cannot
  tell them apart from each other. Roll them back with `--since`.
- The per-run budget, the cooldown and the failure streak are held in memory and
  reset when the process restarts; only the hourly circuit breaker is persisted.
- The audit log is append-only by convention of the code, not enforced by the
  filesystem. Rotation keeps 5 files of 10 MB, so older records are deleted.
  Protect it with file permissions or ship it elsewhere.
- With the example UFW adapter, the first block on a completely empty UFW rule
  set fails (`ufw insert 1` needs an existing rule), and no block is made while
  UFW is inactive. Both count as failed attempts toward the five-failure pause.

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
