"""Parse logs into a small normalised event model.

Supported inputs
  authlog   Linux auth.log / secure (classic syslog or ISO-8601 timestamps)
  windows   Windows Security/System/Sysmon events as JSON or JSONL, either flat
            (see docs/collect-windows-logs.md) or nested `evtx_dump -o jsonl` output
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Event:
    ts: datetime | None
    host: str | None
    source: str  # "authlog" | "windows"
    event_type: str
    user: str | None = None
    src_ip: str | None = None
    process: str | None = None
    command_line: str | None = None
    parent: str | None = None
    event_id: int | None = None
    target: str | None = None  # group name, service name, task name …
    detail: str | None = None  # service image path, task content …
    raw: str = ""
    line_no: int | None = None
    extra: dict = field(default_factory=dict)


# ----------------------------------------------------------------------------- time

_MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    v = str(value).strip().replace("Z", "+00:00")
    m = re.match(r"^(.*?\d{2}:\d{2}:\d{2})(\.\d+)?(.*)$", v)
    if m:  # trim fractional seconds to microseconds (Windows emits 7 digits)
        frac = (m.group(2) or "")[:7]
        v = m.group(1) + frac + m.group(3)
    v = v.replace(" ", "T", 1) if re.match(r"^\d{4}-\d{2}-\d{2} \d", v) else v
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ----------------------------------------------------------------------------- auth.log

_SYSLOG = re.compile(
    r"^(?:(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})|(?P<iso>\d{4}-\d{2}-\d{2}T\S+))"
    r"\s+(?P<host>\S+)\s+(?P<prog>[\w\-./]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
_AUTH_PATTERNS = [
    ("auth_failure", re.compile(r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")),
    ("auth_success", re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")),
    ("invalid_user", re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)")),
    ("sudo_failure", re.compile(r"pam_unix\(sudo:auth\): authentication failure;.*?\buser=(?P<user>\S+)")),
    ("sudo_denied", re.compile(r"^\s*(?P<user>\S+) : user NOT in sudoers")),
    ("sudo_command", re.compile(r"^\s*(?P<user>\S+) : .*?COMMAND=(?P<cmd>.*)$")),
    ("user_created", re.compile(r"new user: name=(?P<user>[^,\s]+)")),
    ("group_add", re.compile(r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")),
]


def parse_authlog(lines, year: int | None = None) -> list[Event]:
    year = year or datetime.now(timezone.utc).year
    events = []
    for n, line in enumerate(lines, 1):
        line = line.rstrip("\n")
        m = _SYSLOG.match(line)
        if not m:
            continue
        if m.group("iso"):
            ts = parse_iso(m.group("iso"))
        else:
            try:
                h, mi, s = map(int, m.group("time").split(":"))
                ts = datetime(year, _MONTHS[m.group("mon")], int(m.group("day")), h, mi, s, tzinfo=timezone.utc)
            except (KeyError, ValueError):
                ts = None
        msg, prog = m.group("msg"), m.group("prog")
        for etype, pat in _AUTH_PATTERNS:
            if etype.startswith("sudo") and prog != "sudo":
                continue
            pm = pat.search(msg)
            if pm:
                g = pm.groupdict()
                events.append(Event(ts, m.group("host"), "authlog", etype, user=g.get("user"), src_ip=g.get("ip"),
                                    command_line=g.get("cmd"), target=g.get("group"), process=prog,
                                    raw=line, line_no=n, extra={"method": g.get("method")}))
                break
    return events


# ----------------------------------------------------------------------------- Windows

def _scalar(v):
    if isinstance(v, dict):
        return v.get("#text", v.get("value"))
    return v


def _flatten_windows(obj: dict) -> dict:
    """Accept flat records or evtx_dump-style {"Event": {"System": …, "EventData": …}}."""
    if "Event" in obj and isinstance(obj["Event"], dict):
        ev = obj["Event"]
        system = ev.get("System", {}) or {}
        data = ev.get("EventData", {}) or {}
        if isinstance(data, dict) and "Data" in data and isinstance(data["Data"], list):
            data = {d.get("@Name") or d.get("Name"): d.get("#text") for d in data["Data"] if isinstance(d, dict)}
        tc = system.get("TimeCreated", {})
        ts = tc.get("#attributes", {}).get("SystemTime") if isinstance(tc, dict) else tc
        provider = system.get("Provider", {})
        provider = provider.get("#attributes", {}).get("Name") if isinstance(provider, dict) else provider
        flat = {"EventID": _scalar(system.get("EventID")), "TimeCreated": ts, "Computer": system.get("Computer"),
                "Channel": system.get("Channel"), "Provider": provider}
        flat.update({k: _scalar(v) for k, v in (data or {}).items() if k})
        return flat
    return obj


_PRIV_FIELDS = ("TargetUserName", "SubjectUserName", "User", "MemberName")


def windows_event(rec: dict, line_no: int | None = None) -> Event | None:
    r = _flatten_windows(rec)
    try:
        eid = int(_scalar(r.get("EventID") or r.get("Id") or r.get("event_id")))
    except (TypeError, ValueError):
        return None
    channel = str(r.get("Channel") or r.get("LogName") or "")
    host = r.get("Computer") or r.get("MachineName")
    ts = parse_iso(r.get("TimeCreated") or r.get("UtcTime") or r.get("@timestamp"))
    raw = json.dumps(rec, ensure_ascii=False, default=str)[:4000]
    is_sysmon = "sysmon" in channel.lower() or str(r.get("Provider", "")).lower().endswith("sysmon")
    ip = r.get("IpAddress") if r.get("IpAddress") not in (None, "-", "::1", "127.0.0.1") else None

    def ev(etype, **kw):
        return Event(ts, host, "windows", etype, event_id=eid, raw=raw, line_no=line_no, **kw)

    if eid == 1 and (is_sysmon or "Image" in r):
        return ev("process_create", user=r.get("User"), process=r.get("Image"), command_line=r.get("CommandLine"),
                  parent=r.get("ParentImage"), extra={"parent_command_line": r.get("ParentCommandLine")})
    if eid == 4688:
        return ev("process_create", user=r.get("SubjectUserName"), process=r.get("NewProcessName"),
                  command_line=r.get("CommandLine"), parent=r.get("ParentProcessName"))
    if eid == 4625:
        return ev("auth_failure", user=r.get("TargetUserName"), src_ip=ip,
                  extra={"logon_type": r.get("LogonType"), "status": r.get("Status") or r.get("SubStatus")})
    if eid == 4624:
        return ev("auth_success", user=r.get("TargetUserName"), src_ip=ip, extra={"logon_type": r.get("LogonType")})
    if eid == 4720:
        return ev("user_created", user=r.get("TargetUserName"), extra={"by": r.get("SubjectUserName")})
    if eid in (4728, 4732, 4756):
        member = r.get("MemberName") or r.get("MemberSid")
        if member and "CN=" in str(member):
            member = str(member).split(",")[0].replace("CN=", "")
        return ev("group_add", user=member, target=r.get("TargetUserName"), extra={"by": r.get("SubjectUserName")})
    if eid == 1102 or (eid == 104 and (not channel or channel.lower() == "system")):
        return ev("log_cleared", user=r.get("SubjectUserName") or r.get("SubjectUserName"),
                  target=channel or ("Security" if eid == 1102 else "System"))
    if eid == 7045:
        return ev("service_installed", target=r.get("ServiceName"), detail=r.get("ImagePath"),
                  user=r.get("AccountName"))
    if eid == 4698:
        return ev("task_created", target=r.get("TaskName"), detail=r.get("TaskContent"),
                  user=r.get("SubjectUserName"))
    return None


def parse_windows(text: str) -> list[Event]:
    text = text.strip()
    records: list[tuple[int | None, dict]] = []
    if text.startswith("["):
        data = json.loads(text)
        records = [(i + 1, r) for i, r in enumerate(data) if isinstance(r, dict)]
    else:
        for n, line in enumerate(text.splitlines(), 1):
            line = line.strip().lstrip("﻿")
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                records.append((n, obj))
    return [e for n, r in records if (e := windows_event(r, n))]


# ----------------------------------------------------------------------------- entry point

def detect_format(path: Path, head: str) -> str:
    stripped = head.lstrip("﻿ \n\t")
    if path.suffix.lower() in (".json", ".jsonl", ".ndjson") or stripped.startswith(("{", "[")):
        return "windows"
    return "authlog"


def load_events(path: str | Path, fmt: str = "auto", year: int | None = None) -> list[Event]:
    path = Path(path)
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    fmt = detect_format(path, text[:200]) if fmt == "auto" else fmt
    if fmt == "windows":
        return parse_windows(text)
    if fmt == "authlog":
        return parse_authlog(text.splitlines(), year)
    raise ValueError(f"Unknown format {fmt!r}")
