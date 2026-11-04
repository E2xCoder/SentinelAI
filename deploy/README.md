# Deploying SentinelAI

Files: `sentinelai.service` (live monitor), `sentinelai-digest.service` +
`.timer` (daily digest 07:30), `sentinelai.env.example` (threat-intel keys and
generic settings, live daemon) and `sentinelai-digest.env.example` (notification
secrets, digest only).
Docker: see the comments at the top of the repo `Dockerfile`.

## Install (systemd)

```bash
# 1. Install the program system-wide (pipx notes below)
sudo python3 -m venv /opt/sentinelai
sudo /opt/sentinelai/bin/pip install '.[ai]'      # or '.' without anomaly detection
sudo ln -s /opt/sentinelai/bin/sentinel /usr/local/bin/sentinel

# 2. Dedicated unprivileged user (adm group is added by the unit for /var/log)
sudo useradd --system --home-dir /var/lib/sentinelai --shell /usr/sbin/nologin sentinelai

# 3. Config and secrets
sudo install -d -m 0755 /etc/sentinelai
sudo install -m 0644 config.example.yaml /etc/sentinelai/config.yaml
sudo install -o root -g root -m 0600 deploy/sentinelai.env.example /etc/sentinelai/sentinelai.env
sudo install -o root -g root -m 0600 deploy/sentinelai-digest.env.example /etc/sentinelai/sentinelai-digest.env
sudo editor /etc/sentinelai/sentinelai.env          # threat-intel keys only
sudo editor /etc/sentinelai/sentinelai-digest.env   # notification secrets only

# 4. Units
sudo cp deploy/sentinelai.service deploy/sentinelai-digest.service \
        deploy/sentinelai-digest.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentinelai.service sentinelai-digest.timer
```

Logs: `journalctl -u sentinelai -f`. Next digest: `systemctl list-timers sentinelai-digest`.

## Why two env files

- `sentinelai.env` is loaded by the live daemon, which parses untrusted log
  content all day. It holds only threat-intel keys (`SENTINELAI_INTEL_*`) and
  generic settings, never notification secrets.
- `sentinelai-digest.env` is loaded only by the short-lived digest oneshot and
  holds `SENTINELAI_NOTIFY_TELEGRAM_TOKEN`, `SENTINELAI_NOTIFY_SLACK_WEBHOOK`
  and `SENTINELAI_NOTIFY_EMAIL_PASSWORD`. If the daemon is ever compromised
  through a log-parsing bug, these secrets are not in its environment.
- Both files must be `root:root` with mode `0600` (`chown root:root`,
  `chmod 600`). systemd reads them as root, so the `sentinelai` user needs no
  access. Do not use 0640 or a group-readable mode.
- The digest unit needs no log access: it has no `adm` group and no
  `/var/log` mount, only its state directory.
- The firewall command adapter also runs the firewall tool with a minimal
  environment (`PATH`, `LC_ALL`, `LANG`, `HOME`), so API keys and webhooks are
  not inherited by it.

## pipx

`pipx install sentinelai` under root puts the binary in `/root/.local/bin`, which
the sandboxed `sentinelai` user cannot reach (`ProtectHome=yes`). Use
`PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin sudo -E pipx install '.[ai]'`
or the venv above, then fix `ExecStart=` in both services to match.

## Verify

```bash
systemd-analyze verify /etc/systemd/system/sentinelai*.service /etc/systemd/system/sentinelai-digest.timer
systemd-analyze security sentinelai.service     # exposure score, lower is better
```

## Honest notes

- The units have NOT been tested on a live systemd host by the author; treat
  them as a reviewed starting point and run the checks above.
- The unit cannot block IPs (no capabilities, by design). Keep
  `response.enabled: false`; the default firewall adapter is `dry_run`.
- `MemoryDenyWriteExecute=yes` may break numpy/scikit-learn on some builds; if
  so, set it to `no` for that unit only.
- `sentinel digest --send` requires the digest command and a configured notifier.
- The digest takes exact alert counts from SQL, lists the top alerts by risk
  score and ends its summary with a liveness line: the time of the last
  recorded alert, or a notice that none was ever recorded. A quiet digest
  together with an old liveness time means the live daemon may not be running.
