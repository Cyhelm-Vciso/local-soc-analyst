"""Deterministic detection rules mapped to MITRE ATT&CK.

Rules find the candidates; the LLM only explains and prioritises them. That
keeps detection reproducible and stops the model from "finding" things that
are not in the logs.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Callable

from .events import Event

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

ATTACK = {
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1027": "Obfuscated Files or Information",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1078": "Valid Accounts",
    "T1098": "Account Manipulation",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1136.001": "Create Account: Local Account",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1204.002": "User Execution: Malicious File",
    "T1218": "System Binary Proxy Execution",
    "T1490": "Inhibit System Recovery",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1548.003": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
    "T1566.001": "Phishing: Spearphishing Attachment",
}

PRIVILEGED_GROUPS = {"administrators", "domain admins", "enterprise admins", "schema admins", "account operators",
                     "backup operators", "sudo", "wheel", "admin", "root"}
OFFICE = ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "mspub.exe", "visio.exe")
SHELLS = ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
          "regsvr32.exe", "bitsadmin.exe", "certutil.exe")


@dataclass
class Finding:
    rule: str
    title: str
    severity: str
    mitre: list[str]
    description: str
    events: list[Event]
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    notes: list[str] = field(default_factory=list)
    triage: dict | None = None

    @property
    def id(self) -> str:
        key = f"{self.rule}|{self.host}|{self.user}|{self.src_ip}|{self.events[0].raw if self.events else ''}"
        return hashlib.sha1(key.encode()).hexdigest()[:10]

    @property
    def first_seen(self):
        times = [e.ts for e in self.events if e.ts]
        return min(times) if times else None

    @property
    def last_seen(self):
        times = [e.ts for e in self.events if e.ts]
        return max(times) if times else None

    @property
    def count(self) -> int:
        return len(self.events)


@dataclass
class Rule:
    id: str
    title: str
    description: str
    mitre: list[str]
    func: Callable[[list[Event], dict], list[Finding]]


RULES: dict[str, Rule] = {}

DEFAULTS = {
    "brute_force_threshold": 8,     # failures for one user from one IP
    "brute_force_window_min": 10,
    "spray_min_users": 5,           # distinct users from one IP
    "spray_window_min": 30,
    "sudo_failure_threshold": 3,
}


def rule(rule_id: str, title: str, mitre: list[str], description: str):
    def wrap(func):
        RULES[rule_id] = Rule(rule_id, title, description, mitre, func)
        return func
    return wrap


def _base(path: str | None) -> str:
    return re.split(r"[\\/]", (path or "").lower())[-1]


def _windows(events: list[Event], minutes: int):
    """Yield maximal clusters of time-sorted events where each fits in a sliding window."""
    events = sorted((e for e in events if e.ts), key=lambda e: e.ts)
    start = 0
    best: list[Event] = []
    for end in range(len(events)):
        while events[end].ts - events[start].ts > timedelta(minutes=minutes):
            start += 1
        if end - start + 1 > len(best):
            best = events[start:end + 1]
    return best


# ----------------------------------------------------------------------------- authentication

@rule("brute_force", "Password guessing against an account", ["T1110.001"],
      "Many failed logons for the same account from the same source in a short window.")
def brute_force(events, cfg):
    groups = defaultdict(list)
    for e in events:
        if e.event_type == "auth_failure" and e.src_ip and e.user:
            groups[(e.host, e.src_ip, e.user.lower())].append(e)
    out = []
    for (host, ip, user), evs in groups.items():
        burst = _windows(evs, cfg["brute_force_window_min"])
        if len(burst) >= cfg["brute_force_threshold"]:
            out.append(Finding("brute_force", f"{len(burst)} failed logons for '{evs[0].user}' from {ip}", "medium",
                               ["T1110.001"], RULES["brute_force"].description, burst, host, evs[0].user, ip))
    return out


@rule("password_spray", "Password spraying across many accounts", ["T1110.003"],
      "One source failing to log on to many different accounts, typical of password spraying.")
def password_spray(events, cfg):
    groups = defaultdict(list)
    for e in events:
        if e.event_type in ("auth_failure", "invalid_user") and e.src_ip and e.user is not None:
            groups[(e.host, e.src_ip)].append(e)
    out = []
    for (host, ip), evs in groups.items():
        burst = _windows(evs, cfg["spray_window_min"])
        users = {e.user.lower() for e in burst}
        if len(users) >= cfg["spray_min_users"]:
            f = Finding("password_spray", f"{ip} tried {len(users)} different accounts", "high", ["T1110.003"],
                        RULES["password_spray"].description, burst, host, None, ip)
            f.notes.append("Accounts targeted: " + ", ".join(sorted(users)[:20]))
            out.append(f)
    return out


@rule("success_after_failures", "Successful logon after repeated failures", ["T1110", "T1078"],
      "A source that generated failed logons later logged on successfully; the guessed password may have worked.")
def success_after_failures(events, cfg):
    failures = defaultdict(list)
    out = []
    for e in sorted((e for e in events if e.ts), key=lambda e: e.ts):
        if e.event_type in ("auth_failure", "invalid_user") and e.src_ip:
            failures[(e.host, e.src_ip)].append(e)
        elif e.event_type == "auth_success" and e.src_ip:
            prior = [f for f in failures.get((e.host, e.src_ip), []) if e.ts - f.ts <= timedelta(hours=1)]
            if len(prior) >= 5:
                f = Finding("success_after_failures",
                            f"'{e.user}' logged on from {e.src_ip} after {len(prior)} failures", "critical",
                            ["T1110", "T1078"], RULES["success_after_failures"].description,
                            prior[-10:] + [e], e.host, e.user, e.src_ip)
                out.append(f)
                failures[(e.host, e.src_ip)] = []
    return out


@rule("sudo_abuse", "Repeated sudo failures or unauthorised sudo", ["T1548.003"],
      "A user repeatedly failed sudo authentication or attempted sudo without being in sudoers.")
def sudo_abuse(events, cfg):
    groups = defaultdict(list)
    for e in events:
        if e.event_type in ("sudo_failure", "sudo_denied"):
            groups[(e.host, e.user)].append(e)
    out = []
    for (host, user), evs in groups.items():
        denied = any(e.event_type == "sudo_denied" for e in evs)
        if denied or len(evs) >= cfg["sudo_failure_threshold"]:
            out.append(Finding("sudo_abuse", f"'{user}' failed or was denied sudo {len(evs)} time(s)",
                               "medium" if denied else "low", ["T1548.003"], RULES["sudo_abuse"].description,
                               evs, host, user))
    return out


# ----------------------------------------------------------------------------- accounts

@rule("privileged_group_add", "Account added to a privileged group", ["T1098"],
      "An account was added to an administrative group (e.g. Administrators, Domain Admins, sudo, wheel).")
def privileged_group_add(events, cfg):
    created = {(e.host, (e.user or "").lower()): e for e in events if e.event_type == "user_created"}
    seen, out = set(), []
    for e in events:
        if e.event_type == "group_add" and (e.target or "").lower() in PRIVILEGED_GROUPS:
            key = (e.host, (e.user or "").lower(), e.target.lower())
            if key in seen:
                continue
            seen.add(key)
            evs = [e]
            new = created.get((e.host, (e.user or "").lower()))
            f = Finding("privileged_group_add", f"'{e.user}' added to '{e.target}'", "high", ["T1098"],
                        RULES["privileged_group_add"].description, evs, e.host, e.user)
            if new:
                f.events.insert(0, new)
                f.mitre.append("T1136.001")
                f.severity = "critical"
                f.notes.append("The account was created shortly before being made privileged: a common persistence pattern.")
            out.append(f)
    return out


@rule("account_created", "New local or domain account created", ["T1136.001"],
      "A new account was created. Expected during onboarding; suspicious outside change windows.")
def account_created(events, cfg):
    return [Finding("account_created", f"New account '{e.user}'", "low", ["T1136.001"],
                    RULES["account_created"].description, [e], e.host, e.user)
            for e in events if e.event_type == "user_created"]


# ----------------------------------------------------------------------------- defence evasion & impact

@rule("log_cleared", "Event log cleared", ["T1070.001"],
      "Security or System event log was cleared, a common anti-forensics step.")
def log_cleared(events, cfg):
    return [Finding("log_cleared", f"{e.target or 'Event'} log cleared on {e.host}", "high", ["T1070.001"],
                    RULES["log_cleared"].description, [e], e.host, e.user)
            for e in events if e.event_type == "log_cleared"]


_SHADOW = re.compile(r"vssadmin(?:\.exe)?\s+delete\s+shadows|wmic(?:\.exe)?\s+shadowcopy\s+delete|"
                     r"bcdedit(?:\.exe)?\s+/set\s+\S*\s*recoveryenabled\s+no|wbadmin(?:\.exe)?\s+delete\s+catalog|"
                     r"Get-WmiObject\s+Win32_Shadowcopy.*Delete", re.I)


@rule("inhibit_recovery", "Backups or shadow copies deleted", ["T1490"],
      "Commands that delete shadow copies or disable recovery: a strong ransomware precursor.")
def inhibit_recovery(events, cfg):
    return [Finding("inhibit_recovery", f"Recovery inhibited on {e.host}", "critical", ["T1490"],
                    RULES["inhibit_recovery"].description, [e], e.host, e.user)
            for e in events if e.event_type == "process_create" and _SHADOW.search(e.command_line or "")]


# ----------------------------------------------------------------------------- execution

_ENC = re.compile(r"\s-(?:e|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+([A-Za-z0-9+/=]{16,})", re.I)


def decode_powershell(cmd: str) -> str | None:
    m = _ENC.search(" " + (cmd or ""))
    if not m:
        return None
    blob = m.group(1)
    try:
        return base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-16-le", errors="replace")
    except (binascii.Error, ValueError):
        return None


@rule("encoded_powershell", "Encoded PowerShell command", ["T1059.001", "T1027"],
      "PowerShell launched with a Base64 -EncodedCommand, often used to hide malicious scripts.")
def encoded_powershell(events, cfg):
    out = []
    for e in events:
        if e.event_type != "process_create":
            continue
        is_ps = _base(e.process) in ("powershell.exe", "pwsh.exe") or re.search(r"powershell|pwsh", e.command_line or "", re.I)
        if is_ps and _ENC.search(" " + (e.command_line or "")):
            f = Finding("encoded_powershell", f"Encoded PowerShell on {e.host}", "high", ["T1059.001", "T1027"],
                        RULES["encoded_powershell"].description, [e], e.host, e.user)
            decoded = decode_powershell(e.command_line or "")
            if decoded:
                f.notes.append(f"Decoded command: {decoded[:600]}")
                if re.search(r"downloadstring|downloadfile|invoke-webrequest|iwr |net\.webclient|iex", decoded, re.I):
                    f.severity = "critical"
                    f.mitre.append("T1105")
            out.append(f)
    return out


@rule("office_spawns_shell", "Office application spawned a shell or script host", ["T1204.002", "T1566.001"],
      "Word/Excel/Outlook launching PowerShell, cmd or a script host is a classic malicious-document pattern.")
def office_spawns_shell(events, cfg):
    return [Finding("office_spawns_shell", f"{_base(e.parent)} → {_base(e.process)} on {e.host}", "high",
                    ["T1204.002", "T1566.001"], RULES["office_spawns_shell"].description, [e], e.host, e.user)
            for e in events
            if e.event_type == "process_create" and _base(e.parent) in OFFICE and _base(e.process) in SHELLS]


_LOLBIN = [
    (re.compile(r"certutil(?:\.exe)?.*\s[-/](?:urlcache|verifyctl)\b.*https?://", re.I), ["T1105"], "certutil download"),
    (re.compile(r"certutil(?:\.exe)?.*\s[-/]decode\b", re.I), ["T1140"], "certutil decode"),
    (re.compile(r"mshta(?:\.exe)?\s+[\"']?(?:https?://|javascript:|vbscript:)", re.I), ["T1218"], "mshta remote script"),
    (re.compile(r"regsvr32(?:\.exe)?.*\s/i:\s*https?://", re.I), ["T1218"], "regsvr32 remote scriptlet"),
    (re.compile(r"rundll32(?:\.exe)?.*javascript:", re.I), ["T1218"], "rundll32 javascript"),
    (re.compile(r"bitsadmin(?:\.exe)?.*\s/transfer\b", re.I), ["T1105"], "bitsadmin transfer"),
    (re.compile(r"(?:downloadstring|downloadfile|invoke-webrequest|\biwr\b|start-bitstransfer)\s*\(?\s*['\"]?https?://", re.I),
     ["T1105"], "PowerShell download"),
]


@rule("lolbin_abuse", "Living-off-the-land binary used to download or proxy execution", ["T1218", "T1105", "T1140"],
      "Built-in Windows tools (certutil, mshta, regsvr32, rundll32, bitsadmin) abused to fetch or run code.")
def lolbin_abuse(events, cfg):
    out = []
    for e in events:
        if e.event_type != "process_create":
            continue
        for pat, mitre, label in _LOLBIN:
            if pat.search(e.command_line or ""):
                out.append(Finding("lolbin_abuse", f"{label} on {e.host}", "high", list(mitre),
                                   RULES["lolbin_abuse"].description, [e], e.host, e.user))
                break
    return out


_LSASS = re.compile(r"comsvcs(?:\.dll)?.*minidump|procdump(?:64)?(?:\.exe)?.*lsass|sekurlsa::|lsadump::|"
                    r"\bmimikatz\b|Out-Minidump", re.I)


@rule("credential_dumping", "Possible LSASS credential dumping", ["T1003.001"],
      "Command lines associated with dumping LSASS memory to steal credentials.")
def credential_dumping(events, cfg):
    return [Finding("credential_dumping", f"Credential dumping tooling on {e.host}", "critical", ["T1003.001"],
                    RULES["credential_dumping"].description, [e], e.host, e.user)
            for e in events if e.event_type == "process_create" and _LSASS.search(e.command_line or "")]


# ----------------------------------------------------------------------------- persistence

_SUSPICIOUS_PATH = re.compile(r"powershell|pwsh|cmd(?:\.exe)?\s+/c|%comspec%|\\temp\\|\\appdata\\|\\users\\public\\|"
                              r"\\programdata\\[^\\]+\.exe|mshta|rundll32|regsvr32|https?://|-enc", re.I)


@rule("suspicious_service", "New service installed", ["T1543.003"],
      "A new Windows service was installed. High severity when it runs a shell, script or binary from a user-writable path.")
def suspicious_service(events, cfg):
    out = []
    for e in events:
        if e.event_type == "service_installed":
            bad = bool(_SUSPICIOUS_PATH.search(e.detail or ""))
            out.append(Finding("suspicious_service", f"Service '{e.target}' installed on {e.host}",
                               "high" if bad else "low", ["T1543.003"], RULES["suspicious_service"].description,
                               [e], e.host, e.user))
    return out


@rule("suspicious_task", "Scheduled task created", ["T1053.005"],
      "A scheduled task was created. High severity when it launches a shell, script or user-writable binary.")
def suspicious_task(events, cfg):
    out = []
    for e in events:
        if e.event_type == "task_created":
            bad = bool(_SUSPICIOUS_PATH.search(e.detail or ""))
            out.append(Finding("suspicious_task", f"Scheduled task '{e.target}' on {e.host}",
                               "high" if bad else "low", ["T1053.005"], RULES["suspicious_task"].description,
                               [e], e.host, e.user))
    return out


# ----------------------------------------------------------------------------- runner

def run_rules(events: list[Event], cfg: dict | None = None, only: list[str] | None = None) -> list[Finding]:
    config = {**DEFAULTS, **(cfg or {})}
    findings: list[Finding] = []
    for rid, r in RULES.items():
        if only and rid not in only:
            continue
        findings.extend(r.func(events, config))
    findings.sort(key=lambda f: (-SEV_RANK[f.severity], f.first_seen.timestamp() if f.first_seen else 0))
    return findings
