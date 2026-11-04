"""Plain-language alert digest for notification channels.

The digest is meant for a tired, non-expert reader. Everything derived from
logs (rule names, IPs, user names) is attacker-controlled, so it is reduced to
plain text: control characters removed, whitespace collapsed, ``<``/``>``
dropped (no mentions or markup), ``://`` defanged (no auto-links) and every
field length-capped. The output is deterministic for a fixed ``now`` and store
content.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from sentinelai.core.models import Alert
from sentinelai.core.store import AlertStore
from sentinelai.notify.base import DigestMessage, clean_text

#: Hard cap for the whole body so every channel accepts the message.
MAX_BODY_CHARS = 3500
_SCAN_LIMIT = 500
_DOT_BETWEEN_LETTERS = re.compile(r"(?<=[^\W\d_])\.(?=[^\W\d_])")
_MAX_TOP_IPS = 3
_MAX_STEPS = 3
_TITLE_CAP = 80
_IP_CAP = 45
_USER_CAP = 32
_RAW_CAP = 500
_LEVELS = ("critical", "high", "medium", "low", "informational")

_PHRASES: dict[str, dict[str, str]] = {
    "en": {
        "head_daily": "SentinelAI daily summary",
        "head_hours": "SentinelAI summary (last {hours} h)",
        "subject_quiet": "{head}: no alerts",
        "subject_calm": "{head}: {total} {alerts}, nothing urgent",
        "subject_attn": "{head}: {total} {alerts}, {attn} {needs}",
        "alert_one": "alert",
        "alert_many": "alerts",
        "needs_one": "needs attention",
        "needs_many": "need attention",
        "period": "Period: last {hours} hours, until {end} UTC (times are UTC).",
        "total": "Total alerts: {total} ({breakdown})",
        "top_alerts": "Most important alerts (showing {shown} of {total}):",
        "more": "({n} more alerts not shown)",
        "last_alert": "Last alert recorded: {when} UTC",
        "never": "No alert has ever been recorded in this state directory - "
        "check that SentinelAI is monitoring",
        "top_ips": "Most active source addresses:",
        "ip_line": "{ip}: {n} {alerts}",
        "from": "from",
        "user": "user",
        "at": "at",
        "resp_title": "Automatic response:",
        "resp_applied": "Blocks applied: {n}",
        "resp_reaped": "Blocks expired and removed: {n}",
        "resp_rolled": "Blocks rolled back: {n}",
        "resp_pending": "Requests waiting for your approval: {n} "
        "(run `sentinel respond --pending`)",
        "resp_none": "No firewall responses in this period.",
        "next_title": "What to do next:",
        "next_explain": "Look at the most serious alert: `sentinel explain {id}`",
        "next_pending": "Decide on the waiting requests: `sentinel respond --pending`",
        "next_review": "Tell SentinelAI which alerts were real or false: `sentinel review`",
        "next_none": "Nothing urgent. No action needed.",
        "quiet": "Quiet period, nothing to review.",
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "informational",
    },
    "tr": {
        "head_daily": "SentinelAI günlük özet",
        "head_hours": "SentinelAI özeti (son {hours} sa)",
        "subject_quiet": "{head}: uyarı yok",
        "subject_calm": "{head}: {total} {alerts}, acil bir şey yok",
        "subject_attn": "{head}: {total} {alerts}, {attn} tanesi {needs}",
        "alert_one": "uyarı",
        "alert_many": "uyarı",
        "needs_one": "dikkat istiyor",
        "needs_many": "dikkat istiyor",
        "period": "Dönem: son {hours} saat, {end} UTC'ye kadar (saatler UTC).",
        "total": "Toplam uyarı: {total} ({breakdown})",
        "top_alerts": "En önemli uyarılar ({total} içinden {shown} tanesi):",
        "more": "({n} uyarı daha gösterilmiyor)",
        "last_alert": "Son kaydedilen uyarı: {when} UTC",
        "never": "Bu durum dizininde şimdiye kadar hiç uyarı kaydedilmedi - "
        "SentinelAI'ın izleme yaptığını kontrol edin",
        "top_ips": "En çok görülen kaynak adresler:",
        "ip_line": "{ip}: {n} {alerts}",
        "from": "kaynak:",
        "user": "kullanıcı",
        "at": "saat",
        "resp_title": "Otomatik yanıt:",
        "resp_applied": "Uygulanan engeller: {n}",
        "resp_reaped": "Süresi dolup kaldırılan engeller: {n}",
        "resp_rolled": "Geri alınan engeller: {n}",
        "resp_pending": "Onayınızı bekleyen istekler: {n} "
        "(`sentinel respond --pending` çalıştırın)",
        "resp_none": "Bu dönemde güvenlik duvarı yanıtı yok.",
        "next_title": "Sıradaki adımlar:",
        "next_explain": "En ciddi uyarıya bakın: `sentinel explain {id}`",
        "next_pending": "Bekleyen isteklere karar verin: `sentinel respond --pending`",
        "next_review": "Hangi uyarıların gerçek ya da yanlış olduğunu bildirin: "
        "`sentinel review`",
        "next_none": "Acil bir şey yok. Yapılacak bir işlem yok.",
        "quiet": "Sakin bir dönem, incelenecek bir şey yok.",
        "critical": "kritik",
        "high": "yüksek",
        "medium": "orta",
        "low": "düşük",
        "informational": "bilgi",
    },
    "de": {
        "head_daily": "SentinelAI Tageszusammenfassung",
        "head_hours": "SentinelAI Zusammenfassung (letzte {hours} Std.)",
        "subject_quiet": "{head}: keine Alarme",
        "subject_calm": "{head}: {total} {alerts}, nichts Dringendes",
        "subject_attn": "{head}: {total} {alerts}, {attn} {needs}",
        "alert_one": "Alarm",
        "alert_many": "Alarme",
        "needs_one": "braucht Aufmerksamkeit",
        "needs_many": "brauchen Aufmerksamkeit",
        "period": "Zeitraum: letzte {hours} Stunden, bis {end} UTC (Zeiten in UTC).",
        "total": "Alarme insgesamt: {total} ({breakdown})",
        "top_alerts": "Wichtigste Alarme ({shown} von {total}):",
        "more": "({n} weitere Alarme nicht angezeigt)",
        "last_alert": "Letzter erfasster Alarm: {when} UTC",
        "never": "In diesem Zustandsverzeichnis wurde noch nie ein Alarm erfasst - "
        "prüfen Sie, ob SentinelAI überwacht",
        "top_ips": "Aktivste Quelladressen:",
        "ip_line": "{ip}: {n} {alerts}",
        "from": "von",
        "user": "Benutzer",
        "at": "um",
        "resp_title": "Automatische Reaktion:",
        "resp_applied": "Gesetzte Sperren: {n}",
        "resp_reaped": "Abgelaufene und entfernte Sperren: {n}",
        "resp_rolled": "Zurückgenommene Sperren: {n}",
        "resp_pending": "Anfragen, die auf Ihre Freigabe warten: {n} "
        "(führen Sie `sentinel respond --pending` aus)",
        "resp_none": "Keine Firewall-Reaktionen in diesem Zeitraum.",
        "next_title": "Was jetzt zu tun ist:",
        "next_explain": "Den ernstesten Alarm ansehen: `sentinel explain {id}`",
        "next_pending": "Über die wartenden Anfragen entscheiden: `sentinel respond --pending`",
        "next_review": "SentinelAI mitteilen, welche Alarme echt oder falsch waren: "
        "`sentinel review`",
        "next_none": "Nichts Dringendes. Keine Aktion nötig.",
        "quiet": "Ruhiger Zeitraum, nichts zu prüfen.",
        "critical": "kritisch",
        "high": "hoch",
        "medium": "mittel",
        "low": "niedrig",
        "informational": "informativ",
    },
}


def _plain(value: object, cap: int, defang_host: bool = False) -> str:
    """Attacker-controlled text reduced to one safe, capped plain-text line.

    With ``defang_host`` a value that looks like a hostname or URL (a dot and no
    spaces) additionally gets ``.`` between letters written as ``[.]``.
    """
    text = clean_text(value, _RAW_CAP)
    text = text.replace("<", "").replace(">", "").replace("://", "[:]//")
    text = " ".join(text.split())
    if defang_host and "." in text and " " not in text:
        text = _DOT_BETWEEN_LETTERS.sub("[.]", text)
    return clean_text(text, cap)


def _safe_ip(value: object) -> str | None:
    """Canonical IP text, or ``None`` when ``value`` is not a valid IP address."""
    if not value:
        return None
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    return str(address).split("%", 1)[0]


def _utc(moment: datetime) -> datetime:
    """Aware UTC datetime; naive values are assumed to already be UTC."""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _level(alert: Alert) -> str:
    return str(alert.risk.level.value)


def _rank_key(alert: Alert) -> tuple[float, float, int]:
    return (-float(alert.risk.score), -_utc(alert.created_at).timestamp(), -(alert.id or 0))


def _word(p: dict[str, str], key: str, n: int) -> str:
    return p[f"{key}_one"] if n == 1 else p[f"{key}_many"]


def _alert_line(alert: Alert, p: dict[str, str], with_date: bool) -> str:
    level = _level(alert).upper()
    tag = f"[{_plain(level, 16)} {float(alert.risk.score):.0f}]"
    ident = f" #{alert.id}" if alert.id is not None else ""
    title = _plain(alert.title or alert.rule_id, _TITLE_CAP, defang_host=True) or "?"
    parts = [f"{tag}{ident} {title}"]
    if alert.ip:
        parts.append(f"{p['from']} {_safe_ip(alert.ip) or '?'}")
    if alert.user:
        parts.append(f"({p['user']} {_plain(alert.user, _USER_CAP, defang_host=True)})")
    stamp = _utc(alert.created_at).strftime("%m-%d %H:%M" if with_date else "%H:%M")
    parts.append(f"{p['at']} {stamp}")
    return " ".join(parts)


def _first_with_level(ranked: list[Alert], level: str) -> Alert | None:
    for alert in ranked:
        if _level(alert) == level and alert.id is not None:
            return alert
    return None


def _next_steps(
    ranked: list[Alert], pending: int, has_feedback: bool, p: dict[str, str]
) -> list[str]:
    """Up to three concrete, deterministically chosen suggestions."""
    steps: list[str] = []
    critical = _first_with_level(ranked, "critical")
    if critical is not None:
        steps.append(p["next_explain"].format(id=critical.id))
    if pending > 0:
        steps.append(p["next_pending"])
    if critical is None:
        high = _first_with_level(ranked, "high")
        if high is not None:
            steps.append(p["next_explain"].format(id=high.id))
    if ranked and not has_feedback:
        steps.append(p["next_review"])
    return steps[:_MAX_STEPS]


def _response_lines(
    store: AlertStore, cutoff: datetime, pending: int, p: dict[str, str]
) -> list[str]:
    statuses = Counter(row.status for row in store.list_response_actions(since=cutoff))
    reaped = statuses["reaped"]
    rolled = statuses["rolled_back"]
    applied = statuses["applied"] + reaped + rolled
    lines = [p["resp_title"]]
    if applied == 0 and pending == 0:
        lines.append(p["resp_none"])
        return lines
    lines.append("  " + p["resp_applied"].format(n=applied))
    lines.append("  " + p["resp_reaped"].format(n=reaped))
    lines.append("  " + p["resp_rolled"].format(n=rolled))
    lines.append("  " + p["resp_pending"].format(n=pending))
    return lines


def _fit(body: str) -> str:
    """Drop trailing whole lines until ``body`` fits :data:`MAX_BODY_CHARS`."""
    lines = body.split("\n")
    while lines and len("\n".join(lines)) > MAX_BODY_CHARS:
        lines.pop()
    return "\n".join(lines)


def build_digest(
    store: AlertStore,
    *,
    hours: int = 24,
    language: str = "en",
    max_alerts: int = 10,
    now: datetime | None = None,
) -> DigestMessage:
    """Summarise the last ``hours`` hours of ``store`` as a plain-text digest."""
    p = _PHRASES.get(str(language).strip().lower(), _PHRASES["en"])
    hours = max(1, int(hours))
    max_alerts = max(0, int(max_alerts))
    end = _utc(now) if now is not None else datetime.now(timezone.utc)
    cutoff = end - timedelta(hours=hours)

    # Exact figures come from SQL; only the top alerts are rehydrated.
    counts = store.count_alerts_by_level_since(cutoff)
    total = store.count_alerts_since(cutoff)
    ranked = sorted(store.alerts_since(cutoff, limit=_SCAN_LIMIT), key=_rank_key)
    attention = counts.get("critical", 0) + counts.get("high", 0)
    latest = store.latest_alert_time()
    if latest is None:
        liveness = p["never"]
    else:
        liveness = p["last_alert"].format(when=f"{_utc(latest):%Y-%m-%d %H:%M}")
    pending = len(store.list_pending())

    head = p["head_daily"] if hours == 24 else p["head_hours"].format(hours=hours)
    if total == 0:
        subject = p["subject_quiet"].format(head=head)
    elif attention == 0:
        subject = p["subject_calm"].format(
            head=head, total=total, alerts=_word(p, "alert", total)
        )
    else:
        subject = p["subject_attn"].format(
            head=head,
            total=total,
            alerts=_word(p, "alert", total),
            attn=attention,
            needs=_word(p, "needs", attention),
        )

    period = p["period"].format(hours=hours, end=f"{end:%Y-%m-%d %H:%M}")
    steps = _next_steps(ranked, pending, bool(store.list_feedback()), p)
    response = _response_lines(store, cutoff, pending, p)
    next_section = [p["next_title"]] + [f"  {i}. {s}" for i, s in enumerate(steps, 1)]

    if total == 0:
        sections = [[period, p["quiet"], liveness]]
        if pending > 0:
            sections.append(response)
            sections.append(next_section)
        quiet_body = "\n\n".join("\n".join(s) for s in sections)
        return DigestMessage(subject=subject, body=_fit(quiet_body))

    breakdown = ", ".join(
        f"{counts[lvl]} {p[lvl]}" for lvl in _LEVELS if counts.get(lvl, 0) > 0
    )
    summary = [period, p["total"].format(total=total, breakdown=breakdown), liveness]
    with_date = hours > 24
    alert_lines = [f"  {_alert_line(a, p, with_date)}" for a in ranked[:max_alerts]]

    ip_counts = Counter(ip for ip in (_safe_ip(a.ip) for a in ranked) if ip is not None)
    top_ips = sorted(ip_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:_MAX_TOP_IPS]
    ip_section = [p["top_ips"]] + [
        "  " + p["ip_line"].format(ip=ip, n=n, alerts=_word(p, "alert", n))
        for ip, n in top_ips
    ]
    if not steps:
        next_section = [p["next_title"], f"  {p['next_none']}"]

    tail: list[list[str]] = [ip_section, response, next_section]
    body = ""
    for shown in range(len(alert_lines), -1, -1):
        sections = [summary]
        hidden = total - shown
        if shown > 0:
            heading = p["top_alerts"].format(shown=shown, total=total)
            block = [heading, *alert_lines[:shown]]
            if hidden > 0:
                block.append("  " + p["more"].format(n=hidden))
            sections.append(block)
        elif hidden > 0:
            sections.append([p["more"].format(n=hidden)])
        sections.extend(tail)
        body = "\n\n".join("\n".join(s) for s in sections)
        if len(body) <= MAX_BODY_CHARS:
            break
    return DigestMessage(subject=subject, body=_fit(body))
