# Security Policy

SentinelAI reads attacker-influenced data (log files) and can drive a firewall,
so security reports are taken seriously.

## Supported versions

SentinelAI is at 0.x. Only the latest release (and the current `main` branch) is
supported. Fixes are not backported to older 0.x versions.

| Version | Supported          |
|---------|--------------------|
| latest 0.x | Yes             |
| older 0.x  | No              |

## Reporting a vulnerability

Please report vulnerabilities **privately**. Do not open a public issue or pull
request for a security problem.

Use GitHub's private vulnerability reporting for this repository:

<https://github.com/E2xCoder/SentinelAI/security/advisories/new>

Only this channel is monitored for security reports.

### What to include

- The affected version or commit, and the Python version and OS.
- A description of the problem and its impact (what an attacker can do, and what
  they need to be able to do first).
- Steps to reproduce. For parser, rule or triage issues, a minimal log snippet is
  ideal. Use documentation addresses (RFC 5737) and fake credentials, never real
  hostnames, IPs, users or secrets.
- The relevant configuration (with all secrets removed).
- Any suggested fix, if you have one.

### What to expect

This is a small open-source project. Handling is best effort: reports are read
and answered as time allows, and no response or fix time is promised. If the
report is valid, a fix is prepared privately where practical, and the reporter
is credited in the release notes unless they prefer not to be.

## Scope

In scope:

- **Parsers and classifiers**: crashes, hangs, unbounded memory or CPU use
  (including regular-expression denial of service), or log content that is
  interpreted as something other than data.
- **Detection bypass or evasion**: log content that makes a built-in rule miss
  the activity it is meant to detect, or that makes a rule fire on forged input
  in a way that causes harm (for example, to get a victim address blocked).
- **Automated response safety**: any way to bypass the allowlist, lockout
  protection, approval mode, rate limits or audit log, or to block an address
  that should never be blocked.
- **LLM triage**: ways for log text to influence anything beyond the advisory
  verdict, or to escape the validation described in the README.
- **Secrets handling**: API keys, tokens, webhooks or passwords leaking into
  logs, error messages, reports, the database or terminal output.
- **Container and systemd hardening**: weaknesses in the `Dockerfile` or the
  units under `deploy/`.
- **Plugin loading**: bugs in the loader itself. Note that plugins are trusted
  code by design (see below).

Out of scope:

- Attacks that require root, or write access to SentinelAI's state, config or
  plugins directory, on the monitored host. Anyone who can do that can already
  control SentinelAI.
- Malicious code inside a plugin you chose to install. Plugins run with your
  privileges and are not sandboxed (see [docs/PLUGINS.md](docs/PLUGINS.md)).
- Findings in third-party services (AbuseIPDB, VirusTotal, OTX, Telegram, Slack,
  your SMTP server, your LLM server) or in your own firewall automation.
- Detection gaps that are already listed as known (see the README and below),
  unless you have a new evasion technique.
- Reports that need a user to run a command they were not intending to run.

## Security design principles

- **Logs are untrusted input.** Log content is attacker-controlled. It is never
  passed to a shell, used as a file path, or sent to a regular expression
  without a length bound. Terminal and notification output is stripped of
  control characters.
- **LLM output is advisory only.** A verdict never changes a risk score, creates
  or suppresses an alert, or triggers or blocks a response. Model output is
  validated strictly and must be grounded in the events that were provided.
- **Automated response is off by default and fails closed.** The default
  firewall adapter is `dry_run`. If SentinelAI cannot record a block, read the
  block history or evaluate lockout protection, it does not block. Approval mode
  lets a human decide.
- **Secrets only from the environment.** API keys, tokens, webhooks and
  passwords are meant to be supplied through `SENTINELAI_*` environment
  variables. They are excluded from `repr` output and from error messages.
- **No shell.** External commands are run with argument lists, never through a
  shell.
- **Bounded input.** Line length, decompressed size, response sizes and message
  sizes are capped (see "Hardening and limits" in the README).

## Known limitations

These are not vulnerabilities to report, but you should know them:

- Regular-expression matching in the parsers and classifiers runs on a bounded
  window of each line, not the whole line. Lines longer than the window keep
  their full text in the raw event but only the first part is matched, so
  content placed after the window is not classified.
- Access-log lines (Apache, Nginx) are matched up to 64 KiB; the other parsers
  cap regex input at 8 KiB (the syslog parser uses 8192 characters; the message
  classifier uses 4096). Reading additionally drops lines longer than
  `limits.max_line_chars` (default 65536).
- Rule regexes over command text are searched in overlapping 2 KiB windows
  (512 characters of overlap), so padding cannot hide a command. A single
  command pattern whose match is longer than 512 characters can still be cut at a
  window edge and missed.
- Gateway detection for lockout protection reads `/proc/net/route`: Linux only,
  IPv4 only.
- SSH-peer protection only knows the session that started SentinelAI. Other
  administrators must be listed in `response.admin_ranges`.
- The example UFW adapter (`examples/firewall_adapter_ufw.py`) has not been
  tested on a live UFW host.
- The systemd units under `deploy/` have not been run on a live systemd host.
  Treat them as a reviewed starting point and check them with
  `systemd-analyze verify` and `systemd-analyze security`.
- The LLM prompt-injection measures reduce risk but cannot remove it; a model can
  still be steered into a wrong verdict. That is why the verdict is advisory.
- The benchmark is synthetic. It detects regressions, not real-world misses.
- The audit log is append-only by convention of the code, not enforced by the
  filesystem.
