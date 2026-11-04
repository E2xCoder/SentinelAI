# Real-world validation

Status: **not declared stable.** The synthetic benchmark was written by us and proves little
about false alarms, so this round ran SentinelAI over two real public log sets, reviewed the
alerts by hand, fixed what was really broken, and measured speed on a 1.3M-line file.
Nothing here is tuned to make a number look good: the thresholds are unchanged.

All commands ran inside WSL2 (Ubuntu, Python 3.12, 32 cores, 15 GB RAM) on a copy of the repo
in the native ext4 home directory (not `/mnt/c`). Date of the run: 2026-11-04.

## 1. Data sources

Both files are real, public, third-party logs from the [Loghub](https://github.com/logpai/loghub)
collection (Zenodo record 8196385). They were treated as untrusted data. They live only in the
git-ignored `local-logs/` folder and are never committed.

| File | Source archive | Archive size | SHA-256 of archive | Lines | Notes |
|---|---|---|---|---|---|
| `SSH.log` | `SSH.tar.gz` | 4.6 MB | `296610a3…2a2712` | 655,147 | OpenSSH on one Linux lab server (host `LabSZ`), Dec to Jan. Attack-heavy: 1,170 source IPs, only 42 IPs ever logged in successfully (182 logins by 7+ lab users). |
| `Linux.log` | `Linux.tar.gz` | 232 KB | `7e1f820d…857820` | 25,567 | Old (2005 era) RHEL-style syslog of one host (`combo`): sshd/su via `pam_unix`, ftpd, telnetd, kernel, udev. |

Limits of these sets, stated plainly:

- `SSH.log` is almost all attack traffic. It measures **detection quality and attacker noise**
  well, but says little about false alarms on a quiet, mostly benign server (only 182 real logins).
- Neither set contains UFW, web server or Docker logs, so those parsers got no real-world check.
- Neither set has labels. "TP/FP" below is my own judgement from the raw lines.

## 2. Parser coverage

`SSH.log` (655,147 lines):

| Result | Lines | Share |
|---|---|---|
| Unparsed | 0 | 0.00% |
| `auth_failure` | 351,939 | 53.7% |
| `generic` (SSH service, no specific event type) | 150,505 | 23.0% |
| `disconnection` | 117,663 | 18.0% |
| `connection` | 18,909 | 2.9% |
| `invalid_user` | 14,577 | 2.2% |
| `port_probe` ("POSSIBLE BREAK-IN ATTEMPT") | 838 | 0.1% |
| `auth_success`, `session_opened`, `session_closed` | 182 each | <0.1% |

The 150k `generic` lines are 1,862 distinct message templates. The top ones are harmless
bookkeeping: `PAM service(sshd) ignoring max retries` (38k), `PAM N more authentication
failures` (38k), `Disconnecting: Too many authentication failures` (37k), `check pass; user
unknown` (20k). They are summaries or duplicates of events already counted elsewhere.

`Linux.log` (25,567 lines):

| | Before fixes | After fixes |
|---|---|---|
| Unparsed lines | **6,047 (23.7%)** | 67 (0.26%) |
| Remaining unparsed | | `last message repeated N times` (11), `syslogd 1.4.1: restart.` (service name contains a space) |
| Auth failures recognised | 0 from `sshd(pam_unix)` and `su(pam_unix)` | 3,431 |

Known coverage gaps (not fixed): `ftpd`, `telnetd`, `xinetd` connection lines, `Failed none for
invalid user` (432 lines, a protocol probe, not counted on purpose), `Out of Memory` kernel
lines and kernel stack traces all parse as `generic` events and raise no alerts.

**Year-less syslog timestamps.** BSD syslog has no year. The old code guessed the year per line
(this year, or last year if that would be in the future), so a log that crosses New Year, or is
older than a year, jumped around in time. `Linux.log` (Jun to Feb) was a clear case. Fixed with a
per-file `SyslogYearTracker`: the first line is anchored as before, later lines roll the year
forward when time jumps back by more than half a year. Small out-of-order jitter is tolerated.
The *absolute* year of an old log is still a guess (anchored to "not in the future"); only the
relative order is now right. Logs that have a real year (ISO/RFC 3339) are unaffected.

## 3. Alerts

Scan settings: defaults, `--no-ai`, response disabled, no network.

| | `SSH.log` | `Linux.log` |
|---|---|---|
| Events analysed | 486,435 | 25,500 |
| Alerts | 5,093 | 482 |
| Incidents | 201 | 144 |
| Critical / High / Medium / Low / Info | 180 / 4,293 / 610 / 5 / 5 | 148 / 234 / 98 / 2 / 0 |
| R001 SSH Brute Force | 2,456 | 211 |
| R002 Password Spraying | 1,572 | 0 |
| R003 Credential Stuffing | 291 | 0 |
| R004 Repeated Authentication Failures | 758 | 156 |
| R006 Impossible Login Frequency | 6 | 115 |
| R007 Suspicious Login Hours | 10 | 0 |

Top sources in `SSH.log`: `103.99.0.122` (324 alerts), `119.7.221.129` (249), `5.188.10.180`
(190). Top targeted accounts: `root` (1,153), `admin` (989), `guest` (198). (These are real
attacker addresses from a public dataset; shown here only to describe the data.)

The numbers above are **after** the fixes in section 5. Before them `SSH.log` raised 8,594
alerts and `Linux.log` raised 0 alerts from 24% unparsed lines.

### Reviewed sample (44 alerts)

Method: 7 random alerts per rule (R001, R002, R003, R004, R006) plus all 10 R007 alerts. For each I
recounted the failed logins of that source from the raw log inside the alert's own time window and
checked whether the source IP ever had a successful login.

| Rule | Sample | Verdict | Reason |
|---|---|---|---|
| R001 SSH Brute Force | 7 | 7 TP | Recount equals the alert count (5 to 61 failures in 10 to 180 s); the sources never logged in. |
| R002 Password Spraying | 7 | 7 TP | 3 to 4 distinct dictionary accounts per source in 7 to 57 s. The name is a bit off: this is one host trying many names, which is plain automated brute force. Counts are correct. |
| R003 Credential Stuffing | 7 | 7 TP, name arguable | Many failures against `root`/`admin`. Several fire from a single IP, not from many, so "stuffing" is a loose label for "heavy brute force on one account". |
| R004 Repeated Failures | 7 | 7 TP | Failures against one account; counts include several sources by design, so they are higher than a per-IP recount. |
| R006 Machine-speed attempts | 6 | 6 TP | 10 to 106 attempts in 9 to 158 s. After the double-count fix this fires only 6 times instead of 926. |
| R007 Suspicious Login Hours | 10 | **10 legit-noisy (FP)** | See table below. |

So 34 of 34 attack-rule alerts reviewed are real automated attacks, and 10 of 10 R007 alerts are
ordinary logins by known users.

### False-positive and false-negative classes

| # | Class | Kind | Cause | Action |
|---|---|---|---|---|
| 1 | **Each failed login counted 2 to 3 times** | Rule/parser logic bug | OpenSSH logs one failed password as up to three lines (`Invalid user`, `pam_unix … authentication failure`, `Failed password`). All three were counted, so every "N failures" threshold effectively fired at about 40% of its value. R006 fired 926 times; most were really 5 attempts counted as 10. | **Fixed.** The parser holds the PAM and `Invalid user` lines for up to 10 s and drops them when the matching `Failed …` line of the same sshd process arrives. Old sshd that logs only the PAM line is still counted. `SSH.log` events 655,147 to 486,435; alerts 8,594 to 5,093. |
| 2 | `sshd(pam_unix)[pid]:` not parsed | Parser bug | Header regex did not accept `service(module)`. 24% of `Linux.log` was dropped, including all `sshd` and `su` login failures. | **Fixed.** |
| 3 | `invalid user  0101` (two spaces) not classified | Parser bug | One space expected. 189 lines. | **Fixed.** |
| 4 | Year-less timestamps across New Year | Parser bug | Per-line year guess. | **Fixed** (section 2). |
| 5 | R007 "off-hours login" for known users | Legit noisy / config | The alert said "UTC", but syslog has no timezone. This server logs Shenzhen local time, so users logging in at 00:00 to 05:59 are probably evening workers, not intruders. Severity is low/informational. | Wording fixed to "log time" and explains the UTC assumption. **No threshold change.** A per-source timezone setting would be the real fix (open). |
| 6 | **Slow brute force not detected** | **False negative** | 29 of 273 sources with 10 or more failures never raised any alert (e.g. 569 failures over 12 days, 143 over 6 days). Their burst never exceeds 1 to 4 attempts per 5 minutes, below every window rule. | **Not fixed.** A long-window rule (for example failures per source per 24 h) is a new feature, so I did not add it during validation. Open issue. |
| 7 | Alert volume per attacker | Legit noisy | One persistent attacker raises up to 324 alerts, and a single attack often fires R001, R002 and R004 together. Incident correlation folds them (201 incidents for 5,093 alerts), but the raw alert list is noisy. | Not changed. |
| 8 | One login after failures | Needs a human | `curi` logged in after 4 failures within an hour from `123.255.103.142`. Looks like a typo, not a compromise, and no rule flags it. | None. |

Result of the one question that matters for a lab server: none of the 42 source IPs that ever
logged in successfully raised an R001 to R006 alert after the fixes (only the R007 "off-hours"
notes above). Before the double-count fix, one of them did: `183.62.156.108` (R003/R004 on `root`,
10 failures weeks after two other users logged in from the same, probably shared, address).

### Regression scenarios added

Both are anonymized (documentation IPs `203.0.113.x`, hostname `host1`, generic users), in
`benchmarks/scenarios/`. **The frozen manifest and baseline were deliberately updated**
(`sentinel eval --update-manifest --write-baseline benchmarks/baseline.json`): 55 to 57 scenarios.

- `rw_sshd_pam_triplet_not_double_counted` (benign): four real failures logged as Invalid user +
  PAM + Failed password. Must raise no alert.
- `rw_legacy_sshd_pam_bruteforce` (attack): six `sshd(pam_unix)` failures. Must raise R001.

Tests: `tests/test_real_world_regressions.py` (11 tests).

## 4. Performance

Test file: `SSH.log` twice, 1,310,292 lines (about 94 MB), on native WSL ext4. Python 3.12, no AI,
no network, defaults. "Events" excludes the PAM duplicates removed by the parser (972,869).

| Stage (cumulative runs) | Before | After |
|---|---|---|
| read lines | 0.3 s | 0.3 s |
| + parse | 9.3 s (105k ev/s) | 8.1 s (120k ev/s) |
| + AI observe (feature collection) | 11.6 s | 10.1 s |
| + rule engine | 41.5 s (23k ev/s) | 38.1 s (26k ev/s) |
| **full scan** (+ risk, store, correlate) | **84.3 s (11.5k ev/s)** | **47.1 s (20.6k ev/s)** |
| peak memory | 321 MB | 322 MB |

Derived stage costs after the change: read 0.3 s, parse 7.8 s, AI observe 2.0 s, rules 28.0 s,
enrichment/store/correlation about 9 s. Memory stays bounded (about 320 MB for 1.3M lines).

Profile hotspots found (cProfile, 400k lines) and what was done:

1. `sqlite3 commit` once per alert: 27% of the whole scan. **Fixed**: scans group writes with
   `AlertStore.batch()` (one commit per 200 alerts and at the end). Other store calls still
   commit immediately. Trade-off: a crash in the middle of a *scan* can lose up to 200 unsaved
   alerts; live mode is unchanged (still one commit per alert).
2. `SlidingWindowState.distinct`: copied the window and called `payload.get` twice per entry.
   **Fixed**: iterate once.
3. BSD timestamps tried the ISO parser first. **Fixed**: choose the parser by first character, and
   cheaper time parsing in the year tracker.

Not changed: regex matching (about 6% of time), the rule loop itself, AI feature collection.
`sentinel eval` results are identical (55 original scenarios compare equal to the baseline;
`tests/test_eval_incidents.py` checks this scenario by scenario).

Target set after measuring: at least 1,000 events/s without AI. Measured 20,000 events/s for the
full pipeline, so the target is met by a wide margin. The earlier "77 events/s" in `sentinel
eval` was a per-scenario setup cost on `/mnt/c`, not throughput.

Not measured: AI anomaly detection (Isolation Forest) on large inputs, intel lookups with network,
LLM triage, and live-mode latency.

## 5. Response and firewall integration

Nothing here changed a real firewall. Everything ran with `firewall.adapter: dry_run`.

**LockoutGuard** (checked with simulated environments):

| Case | Result |
|---|---|
| IP equals `SSH_CONNECTION` peer | refused: "address of the current SSH session" |
| IP equals default gateway / own address | refused |
| `SSH_CONNECTION` garbage | ignored, no crash (peer protection is then off) |
| `/proc/net/route` missing, unreadable (uid 1000, mode 000) or garbage | returns no gateways, no crash. **Gateway protection is silently OFF.** Now logs a warning ("default-gateway protection is OFF") so it is no longer silent. |
| Invalid strings (`not-an-ip`, empty, `999.1.1.1`) | guard says "not protected"; the responder skips them earlier because there is no valid source IP |
| `0.0.0.0`, `::`, `::1`, `127.0.0.1`, `fe80::1`, `169.254.x`, multicast, broadcast | never queued or blocked in either mode (non-global addresses are skipped) |

**End to end** (approval mode, dry-run adapter, 400k real lines): responses were queued as pending (per-run cap 25),
72 more were skipped with "approval queue is full" (per-run cap), 540 audit lines written. `sentinel
respond --pending` lists them; `--approve 1 --yes` approved one and the dry-run adapter recorded it
without touching any firewall. In `auto` mode with dry-run only the two global test IPs were
recorded.

**Your Firewall Automation project** (`linux-firewall-automation-main/`, inspected statically,
**never executed**): it cannot be plugged into SentinelAI as it is.

- `firewall_manager.py` is a single script whose menu loop (`while True:` with `input()`) runs at
  **module level, with no `if __name__ == "__main__"` guard**. `PythonModuleAdapter` would import
  it and hang on the menu.
- It has plain functions (`block_ip`, `allow_ip`, …) returning `None`, not a controller object.
  The adapter needs `block_ip`, `unblock_ip`, `temporary_block`, `list_blocked` (and ideally
  `is_blocked`). Unblock, temporary block and list do not exist.
- It has no command-line arguments, so `CommandAdapter` has nothing to call either.
- What it would run for a block: `sudo ufw deny from <ip>` (list arguments, no shell).
- Missing for safe use: `temporary_block` needs a way to expire a rule (`ufw delete deny from
  <ip>`), `unblock_ip` the same command, and `list_blocked`/`is_blocked` need to parse `ufw
  status`.

To integrate it, the *firewall project* needs a small importable class with those five methods and
a `__main__` guard. SentinelAI deliberately does not contain that logic. I did not modify your
project. **I have not run any command that changes firewall rules, and I will not without your
explicit permission.**

## 6. What was NOT tested

- Real UFW on a live Linux host (parser `ufw` and the UFW adapter path).
- systemd unit and Docker image on a real Linux host (the hardened unit file was never started).
- Live mode (`sentinel live`) over hours or days; the byte-offset tailer with rotation on real logs.
- Web server (Apache/Nginx), Docker and fail2ban parsers on real logs.
- A quiet, mostly benign server (the only real login data is 182 logins in an attack-heavy log).
- AI features at scale: Isolation Forest on large inputs, LLM triage, threat-intel lookups.
- The Sigma importer on real SigmaHQ packs (only our own 8 example rules were run).
- Real firewall blocking through any adapter.
- Python 3.10/3.11/3.13 behaviour locally (CI covers them; this session ran 3.12 and 3.14).

## 7. Open issues

1. **Slow brute force is not detected** (class 6): needs a long-window rule.
2. R007 has no timezone setting for logs without one.
3. `ftpd`, `telnetd`, `xinetd`, kernel OOM and `last message repeated N times` are not understood.
4. Redundant alerts: R001, R002 and R004 often fire together for one attacker; R002/R003 names do
   not match what they really detect.
5. The firewall project needs the five-method class and a `__main__` guard before it can be used.
6. `fail()` messages in the CLI (`Cannot load …`, `Not a directory`) are not sanitised.
7. Scan crash window of up to 200 unsaved alerts (batched commits).
8. Absolute year of old year-less logs is still a guess.
9. The Obsidian vault docs are stale.

## 8. How to reproduce

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[ai,dev]"
mkdir -p local-logs && cd local-logs          # git-ignored
# download SSH.tar.gz and Linux.tar.gz from https://zenodo.org/records/8196385 and extract
cd .. && sentinel scan --no-ai --format json local-logs/SSH.log
```
