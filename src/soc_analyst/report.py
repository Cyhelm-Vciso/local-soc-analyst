"""Markdown and JSON reports."""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone

from .detections import ATTACK, SEV_RANK, Finding

ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}


def _attack_link(t: str) -> str:
    path = t.replace(".", "/")
    return f"[{t}](https://attack.mitre.org/techniques/{path}/) {ATTACK.get(t, '')}".strip()


def _fence(text: str) -> str:
    return text.replace("```", "ˋˋˋ")


def effective_severity(f: Finding) -> str:
    t = f.triage or {}
    return t.get("severity", f.severity) if "error" not in t else f.severity


def to_markdown(findings: list[Finding], sources: list[str], n_events: int, model: str | None,
                summary: str | None = None, max_evidence: int = 8) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = Counter(effective_severity(f) for f in findings)
    out = [
        "# Security Log Triage Report",
        "",
        f"Generated {now} by local-soc-analyst · model: `{model or 'none (rules only)'}` · "
        f"{n_events} events parsed from {len(sources)} file(s)",
        "",
        "> Findings come from deterministic rules. LLM verdicts are decision support: verify before acting.",
        "",
        "## Overview",
        "",
        " · ".join(f"{ICON[s]} {s.title()}: **{counts.get(s, 0)}**" for s in ("critical", "high", "medium", "low")),
        "",
    ]
    if summary:
        out += ["### Shift summary", "", summary, ""]
    if not findings:
        out += ["No findings. That means no rule fired, not that the logs are clean.", ""]
        return "\n".join(out)

    out += ["| # | Severity | Finding | Host | ATT&CK | Verdict | First seen |", "|---|---|---|---|---|---|---|"]
    for n, f in enumerate(findings, 1):
        t = f.triage or {}
        verdict = t.get("verdict", "—").replace("_", " ") if "error" not in t else "error"
        first = f.first_seen.strftime("%Y-%m-%d %H:%M:%S") if f.first_seen else "—"
        sev = effective_severity(f)
        out.append(f"| {n} | {ICON[sev]} {sev} | {f.title.replace('|', '/')} | {f.host or '—'} | "
                   f"{', '.join(f.mitre)} | {verdict} | {first} |")
    out.append("")

    for n, f in enumerate(findings, 1):
        t = f.triage or {}
        out += [f"## {n}. {f.title}", ""]
        sev = effective_severity(f)
        line = f"**Severity:** {ICON[sev]} {sev}"
        if sev != f.severity:
            line += f" (rule: {f.severity})"
        out += [line + f" · **Rule:** `{f.rule}` · **Events:** {f.count}", ""]
        out += ["**ATT&CK:** " + " · ".join(_attack_link(m) for m in f.mitre), ""]
        if t.get("error"):
            out += [f"⚠ LLM triage failed: {t['error']}", ""]
        elif t:
            out += [f"**Verdict:** {t['verdict'].replace('_', ' ')} ({t['confidence']} confidence)", "",
                    t.get("summary", ""), ""]
            if t.get("reasoning"):
                out += [f"*Why:* {t['reasoning']}", ""]
            if t.get("next_steps"):
                out += ["**Next steps**", ""] + [f"{i}. {s}" for i, s in enumerate(t["next_steps"], 1)] + [""]
            if t.get("benign_explanations"):
                out += ["**Could be benign if**", ""] + [f"- {s}" for s in t["benign_explanations"]] + [""]
            if t.get("questions_for_owner"):
                out += ["**Ask the owner**", ""] + [f"- {s}" for s in t["questions_for_owner"]] + [""]
        else:
            out += [f.description, ""]
        for note in f.notes:
            out += [f"> {note}", ""]
        shown = f.events[:max_evidence]
        out += ["<details><summary>Evidence</summary>", "", "```text"]
        out += [_fence(e.raw[:800]) for e in shown]
        if f.count > len(shown):
            out.append(f"… {f.count - len(shown)} more")
        out += ["```", "", "</details>", ""]
    return "\n".join(out)


def to_json(findings: list[Finding], sources: list[str], n_events: int, model: str | None,
            summary: str | None = None) -> str:
    def ev(e):
        return {"ts": e.ts.isoformat() if e.ts else None, "host": e.host, "type": e.event_type, "user": e.user,
                "src_ip": e.src_ip, "process": e.process, "command_line": e.command_line, "raw": e.raw,
                "line": e.line_no}

    data = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "sources": sources,
        "events_parsed": n_events,
        "summary": summary,
        "findings": [
            {"id": f.id, "rule": f.rule, "title": f.title, "severity": effective_severity(f),
             "rule_severity": f.severity, "mitre": f.mitre, "host": f.host, "user": f.user, "src_ip": f.src_ip,
             "first_seen": f.first_seen.isoformat() if f.first_seen else None,
             "last_seen": f.last_seen.isoformat() if f.last_seen else None, "count": f.count,
             "notes": f.notes, "triage": f.triage, "events": [ev(e) for e in f.events[:50]]}
            for f in findings
        ],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


def filter_min(findings: list[Finding], minimum: str) -> list[Finding]:
    return [f for f in findings if SEV_RANK[f.severity] >= SEV_RANK[minimum]]
