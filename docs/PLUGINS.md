# Writing SentinelAI plugins

Plugins add detection rules, log parsers, anomaly models and report formats
without changing SentinelAI itself. A plugin is a single Python file.

> **TRUST WARNING**
>
> A plugin is ordinary Python code imported into the SentinelAI process. It runs
> **with your privileges** and can read files, open network connections, run
> programs and change SentinelAI's own state. The loader does **not** sandbox,
> restrict or review plugins. Only install plugin code you wrote yourself or
> have read and trust, and keep the plugins directory writable only by trusted
> users: anyone who can write a `.py` file there can run code as the user that
> starts `sentinel`.
>
> The hardening in `deploy/sentinelai.service` (no capabilities, read-only
> `/var/log`, restricted file system) limits what a malicious plugin can do, but
> does not remove the risk: the unit still allows network access, so a plugin
> can still read the logs and send them elsewhere. The same applies to the
> container image.

## Where plugins live

| Location                                 | When it is used                          |
|------------------------------------------|------------------------------------------|
| `$SENTINELAI_PLUGINS_DIR`                | If the variable is set and not empty     |
| `~/.sentinelai/plugins/`                 | Otherwise                                |

```bash
mkdir -p ~/.sentinelai/plugins
cp examples/plugins/example_rule.py ~/.sentinelai/plugins/
sentinel rules          # the new rule X001 is listed
```

## How plugins are loaded

This is what `src/sentinelai/plugins/loader.py` does:

- Plugins are loaded once at startup, after the configuration is read and before
  the selected command runs. This applies to every command. Pass the global
  option `--no-plugins` to skip loading (`sentinel --no-plugins scan ...`).
- Only `*.py` files directly in the plugins directory are loaded. Sub-directories
  and packages are not. Files whose name starts with `_` are skipped. A missing
  directory is not an error.
- Files are loaded in sorted file-name order, so a numeric prefix
  (`10_rules.py`) controls the order.
- Each file is imported as the module `sentinelai_plugin_<file stem>`. It is not
  added to `sys.modules`.
- **Failure isolation.** If importing a plugin raises an `Exception`, the error
  is logged at ERROR level, the file is skipped and the remaining plugins still
  load. Successful loads are logged at INFO level.
- The isolation has limits. Anything registered before the exception stays
  registered (the registries are global). Exceptions that are not `Exception`
  subclasses (for example `SystemExit`) are not caught. There is no timeout, so
  a plugin that hangs on import hangs startup. Isolation is about robustness,
  not security.
- Registration rules: `register_rule` raises on a duplicate rule ID or a missing
  `rule_id`/`name`; `register_parser` raises on a duplicate or empty `name`;
  `register_model` raises on a duplicate name. In each case the plugin fails to
  load. `register_renderer` does **not** check: registering an existing format
  name (including `json`, `csv`, `html`) silently replaces it.

## Extension points

| You want to add      | Mechanism                                  | Usable from a plugin file via the CLI |
|----------------------|--------------------------------------------|---------------------------------------|
| A detection rule     | `Rule` subclass + `@register_rule`         | Yes                                   |
| A log parser         | `LogParser` subclass + `@register_parser`  | Yes                                   |
| An anomaly model     | `register_model(name, factory)`            | Yes (select with `ai.model`)          |
| A report format      | `register_renderer(fmt, func)`             | Not from the CLI, see below           |
| A risk factor        | `RiskEngine.add_factor(factor)`            | Not from a plugin file, see below     |

### Detection rule

[`examples/plugins/example_rule.py`](../examples/plugins/example_rule.py) is a
complete, working plugin. The core of it:

```python
from sentinelai.core.models import Alert, EventCategory, EventType, LogEvent, Severity
from sentinelai.detection.base import Rule, RuleContext, register_rule


@register_rule
class SensitiveAccountFailedLoginRule(Rule):
    rule_id = "X001"                      # unique across all rules
    name = "Example: failed login for a sensitive account"
    category = EventCategory.AUTHENTICATION
    severity = Severity.WARNING
    mitre_techniques = ("T1110",)
    recommendation = "Confirm with the account owner whether the attempt was legitimate."

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        if event.event_type is not EventType.AUTH_FAILURE:
            return None
        if (event.user or "").lower() not in {"ceo", "finance"}:
            return None
        return self.make_alert(
            event,
            title=f"Failed login for sensitive account '{event.user}'",
            description=f"A failed login for '{event.user}' was seen from {event.ip}.",
        )
```

Notes:

- `evaluate` receives one event at a time and returns an alert or `None`.
  `make_alert` fills in the rule metadata, times, IP, user and evidence.
- Pick an ID that does not clash with built-in rules (`R001`-`R060`, `AI001`).
  The example uses the `X` prefix.
- State across events (counts, windows) goes through `ctx.state`, the shared
  sliding-window store. Do not keep unbounded data of your own: log content is
  attacker-controlled.
- Rules should be side-effect free and must not raise on unexpected events.
- `detection.enabled_rules` and `detection.disabled_rules` in the configuration
  apply to plugin rules as well. If `enabled_rules` is not empty, a plugin rule
  only runs when its ID is listed there.

### Log parser

Subclass `LogParser`, give it a unique `name`, and register it. Return `None`
for lines you do not understand; never raise. Bound the input you hand to
regular expressions.

```python
import re
from datetime import datetime

from sentinelai.core.models import EventCategory, EventType, LogEvent, Severity
from sentinelai.parsers.base import LogParser, register_parser

_MAX_LINE = 8192
_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}) "
    r"LOGIN_FAIL user=(?P<user>[\w.-]{1,64}) ip=(?P<ip>[0-9A-Fa-f.:]{3,45})$"
)


@register_parser
class MyAppLoginParser(LogParser):
    name = "myapp_login"
    description = "MyApp login failures"
    filename_hints = ("myapp",)

    def match_score(self, sample_lines: list[str]) -> float:
        if not sample_lines:
            return 0.0
        hits = sum(1 for line in sample_lines if _LINE.match(line[:_MAX_LINE]))
        return hits / len(sample_lines)

    def parse_line(self, line: str) -> LogEvent | None:
        match = _LINE.match(line[:_MAX_LINE])
        if match is None:
            return None
        try:
            timestamp = datetime.fromisoformat(match["ts"])
        except ValueError:
            return None
        return LogEvent(
            timestamp=timestamp,
            message=f"login failed for {match['user']}",
            raw=line,
            service="myapp",
            event_type=EventType.AUTH_FAILURE,
            category=EventCategory.AUTHENTICATION,
            user=match["user"],
            ip=match["ip"],
            severity=Severity.WARNING,
        )
```

Use it with `sentinel scan app.log --parser myapp_login`. Without `--parser`, the
format is auto-detected: the parser with the best `match_score` (plus a small
bonus for `filename_hints`) on a sample of the file wins, and a score below 0.15
counts as "not detected". Timestamps should include a year and a UTC offset.

### Anomaly model

Implement the `AnomalyModel` protocol (a `name` and
`fit_score(matrix) -> list[float]`, one score from 0 to 1 per row, higher is more
anomalous) and register a factory that takes the configured contamination rate.

```python
from sentinelai.ai.base import register_model


class MeanDistanceModel:
    name = "mean_distance"

    def __init__(self, contamination: float) -> None:
        self._contamination = contamination

    def fit_score(self, matrix: list[list[float]]) -> list[float]:
        if not matrix:
            return []
        means = [sum(col) / len(col) for col in zip(*matrix)]
        distances = [sum(abs(v - m) for v, m in zip(row, means)) for row in matrix]
        top = max(distances) or 1.0
        return [d / top for d in distances]


register_model("mean_distance", MeanDistanceModel)
```

Select it in `config.yaml`:

```yaml
ai:
  model: "mean_distance"
```

The name `isolation_forest` is taken by the built-in model.

### Report format

```python
from sentinelai.reporting.renderers import register_renderer
from sentinelai.reporting.report import Report


def render_text(report: Report) -> str:
    return "".join(
        f"{alert.risk.level.value:<13} {alert.rule_id} {alert.title}\n"
        for alert in report.alerts
    )


register_renderer("txt", render_text)
```

A registered renderer is available to code that uses SentinelAI as a library
(`sentinelai.reporting.writer.render_report` and `write_reports`). It is **not**
reachable from the command line today: `sentinel scan --format` accepts only
`json`, `csv` and `html`, and `report.formats` in the configuration is validated
against the same three names.

### Risk factor

A risk factor is an object with `evaluate(alert, ctx) -> RiskFactor | None`
(the `RiskFactorEvaluator` protocol in `sentinelai.risk.factors`). It is added
to a `RiskEngine` instance:

```python
from sentinelai.core.models import Alert, RiskFactor
from sentinelai.risk.factors import ScoringContext


class NightTimeFactor:
    def evaluate(self, alert: Alert, ctx: ScoringContext) -> RiskFactor | None:
        if alert.last_seen.hour < 5:
            return RiskFactor("night_time", 5.0, "Activity between 00:00 and 05:00")
        return None


# Library use: build the pipeline yourself, then extend its engine.
# pipeline = AnalysisPipeline(config)
# pipeline.risk_engine.add_factor(NightTimeFactor())
```

The `RiskEngine` is created inside `AnalysisPipeline` when a command runs, which
is after plugins are loaded. A plugin file therefore has no engine to call
`add_factor` on, and the default factor list is a tuple that cannot be extended.
Today `add_factor` is for programs that embed SentinelAI. A factor that raises
is logged and skipped; it does not stop scoring.

## Testing a plugin

Test the logic directly, and test that the plugin loads. The registries are
global, so load a given plugin once per test session.

```python
import shutil
from datetime import datetime, timezone

from sentinelai.config.models import DetectionConfig
from sentinelai.core.models import EventType, LogEvent
from sentinelai.detection.base import RuleContext, available_rules
from sentinelai.plugins.loader import load_plugins


def _failed_login(user: str) -> LogEvent:
    return LogEvent(
        timestamp=datetime(2026, 1, 7, 10, 15, 32, tzinfo=timezone.utc),
        message="Failed password",
        raw="Failed password",
        event_type=EventType.AUTH_FAILURE,
        user=user,
        ip="192.0.2.10",
    )


def test_example_rule(tmp_path):
    shutil.copy("examples/plugins/example_rule.py", tmp_path)
    if "X001" not in available_rules():
        assert load_plugins(tmp_path) == ["example_rule"]
    rule = available_rules()["X001"]()
    ctx = RuleContext(DetectionConfig())
    assert rule.evaluate(_failed_login("ceo"), ctx) is not None
    assert rule.evaluate(_failed_login("alice"), ctx) is None
```

Guidelines:

- Use RFC 5737 addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
  and RFC 3339 timestamps in test data.
- Add a benign case next to every attack case.
- Make no network calls in tests.
- Check a plugin end to end with `sentinel rules` (is it registered?) and
  `sentinel scan <log>` on a sample file. Use `sentinel --no-plugins ...` to
  compare against a run without it.
- A plugin rule is not part of the frozen benchmark (`sentinel eval`); see
  [CONTRIBUTING.md](../CONTRIBUTING.md) if you want to contribute a rule to the
  project itself.

## Reminder

Plugins run with your privileges, unsandboxed. Read every plugin before you
install it, and remove ones you no longer use. See also
[SECURITY.md](../SECURITY.md).
