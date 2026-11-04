import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources

import pytest

from soc_analyst.cli import main
from soc_analyst.detections import decode_powershell, run_rules
from soc_analyst.events import load_events, parse_authlog, parse_iso, windows_event
from soc_analyst.llm import MockLLM
from soc_analyst.triage import Redactor, finding_prompt, parse_triage, triage_findings

SAMPLES = resources.files("soc_analyst") / "samples"

TRIAGE_JSON = {
    "verdict": "likely_malicious", "confidence": "high", "severity": "critical",
    "summary": "Attacker from 203.0.113.45 guessed root's password on web01.",
    "reasoning": "14 failures then success.", "benign_explanations": ["Admin mistyped password"],
    "next_steps": ["Disable root SSH login", "Rotate root password"], "questions_for_owner": ["Was this you?"],
}


@pytest.fixture(scope="module")
def events():
    return load_events(SAMPLES / "auth.log") + load_events(SAMPLES / "windows-security.jsonl")


@pytest.fixture(scope="module")
def findings(events):
    return run_rules(events)


def rules_fired(findings):
    return {f.rule for f in findings}


# ---------------------------------------------------------------- parsing

def test_parse_iso_handles_windows_seven_digit_fraction():
    dt = parse_iso("2026-11-03T08:59:00.1234567Z")
    assert dt and dt.microsecond == 123456 and dt.tzinfo


def test_authlog_parsing():
    evs = parse_authlog([
        "Nov  3 02:55:07 web01 sshd[1]: Failed password for invalid user admin from 203.0.113.9 port 1 ssh2",
        "2026-11-03T02:55:09.000+00:00 web01 sshd[1]: Accepted publickey for deploy from 10.0.0.5 port 2 ssh2",
        "Nov  3 02:56:00 web01 sudo[9]:   bob : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls",
        "garbage line",
    ], year=2026)
    assert [e.event_type for e in evs] == ["auth_failure", "auth_success", "sudo_command"]
    assert evs[0].user == "admin" and evs[0].src_ip == "203.0.113.9" and evs[0].ts.year == 2026
    assert evs[2].command_line == "/bin/ls"


def test_evtx_dump_nested_format():
    rec = {"Event": {"System": {"EventID": 4625, "Computer": "DC01", "Channel": "Security",
                                "TimeCreated": {"#attributes": {"SystemTime": "2026-11-03T10:00:00.000000Z"}}},
                     "EventData": {"TargetUserName": "alice", "IpAddress": "192.0.2.10", "LogonType": 3}}}
    e = windows_event(rec)
    assert e.event_type == "auth_failure" and e.user == "alice" and e.host == "DC01" and e.ts.hour == 10


def test_sample_counts(events):
    assert len(events) == 59


# ---------------------------------------------------------------- detections

def test_expected_detections_fire(findings):
    assert {"success_after_failures", "brute_force", "password_spray", "privileged_group_add", "encoded_powershell",
            "office_spawns_shell", "lolbin_abuse", "credential_dumping", "suspicious_service", "suspicious_task",
            "inhibit_recovery", "log_cleared", "sudo_abuse", "account_created"} <= rules_fired(findings)


def test_benign_activity_does_not_alert(findings):
    text = " ".join(e.raw for f in findings for e in f.events)
    assert "inventory.ps1" not in text           # admin script, no -enc
    assert "systemctl restart app" not in text   # routine sudo
    assert "Accepted publickey for deploy" not in text


def test_shadow_group_line_deduplicated(findings):
    assert len([f for f in findings if f.rule == "privileged_group_add" and f.host == "web01"]) == 1


def test_encoded_powershell_is_decoded_and_escalated(findings):
    f = next(f for f in findings if f.rule == "encoded_powershell")
    assert f.severity == "critical" and "T1105" in f.mitre
    assert any("DownloadString" in n for n in f.notes)


def test_decode_powershell_roundtrip():
    import base64
    blob = base64.b64encode("Write-Host hi".encode("utf-16-le")).decode()
    assert decode_powershell(f"powershell -NoP -EncodedCommand {blob}") == "Write-Host hi"
    assert decode_powershell("powershell -File x.ps1") is None


def test_findings_sorted_by_severity(findings):
    from soc_analyst.detections import SEV_RANK
    ranks = [SEV_RANK[f.severity] for f in findings]
    assert ranks == sorted(ranks, reverse=True)


# ---------------------------------------------------------------- triage

def test_prompt_fences_untrusted_evidence(findings):
    spray = next(f for f in findings if f.rule == "password_spray" and f.host == "DC01")
    prompt = finding_prompt(spray, Redactor(enabled=False))
    assert "<evidence>" in prompt and "ignore previous instructions" in prompt  # present but fenced
    assert prompt.index("<evidence>") < prompt.index("ignore previous instructions")
    assert prompt.count("ignore previous instructions") == prompt.split("<evidence>", 1)[1].count("ignore previous instructions")


def test_redaction_roundtrip(findings):
    f = next(f for f in findings if f.rule == "success_after_failures")
    r = Redactor()
    r.register(f)
    prompt = finding_prompt(f, r)
    assert "203.0.113.45" not in prompt and "web01" not in prompt and "IP_1" in prompt
    restored = r.revert({"summary": "Attack from IP_1 on HOST_1"})
    assert restored["summary"] == "Attack from 203.0.113.45 on web01"


def test_parse_triage_validates_fields():
    t = parse_triage('```json\n{"verdict": "pwned", "severity": "apocalyptic", "next_steps": "isolate host"}\n```', "high")
    assert t["verdict"] == "suspicious" and t["severity"] == "high" and t["next_steps"] == ["isolate host"]
    assert "error" in parse_triage("I think it's bad", "low")


def test_triage_with_mock_llm(events):
    fs = [f for f in run_rules(events) if f.rule == "success_after_failures"]
    triage_findings(fs, MockLLM(json.dumps(TRIAGE_JSON)))
    assert fs[0].triage["verdict"] == "likely_malicious" and fs[0].triage["next_steps"]


# ---------------------------------------------------------------- CLI end to end

class FakeOllama(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        is_overview = "shift handover" in payload["messages"][0]["content"]
        content = "Likely one intrusion chain starting with [1]." if is_overview else json.dumps(TRIAGE_JSON)
        body = json.dumps({"message": {"content": content}, "eval_count": 10, "eval_duration": 1e9}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def fake_ollama():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), FakeOllama)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def test_cli_demo_with_llm(tmp_path, fake_ollama):
    out, js = tmp_path / "r.md", tmp_path / "r.json"
    assert main(["demo", "--base-url", fake_ollama, "-o", str(out), "--json", str(js), "--redact"]) == 0
    md = out.read_text()
    assert "Shift summary" in md and "likely malicious" in md and "Disable root SSH login" in md
    data = json.loads(js.read_text())
    assert data["findings"][0]["triage"]["verdict"] == "likely_malicious"


def test_cli_rules_only_and_fail_on(tmp_path):
    assert main(["demo", "--no-llm", "-o", str(tmp_path / "r.md"), "--fail-on", "critical"]) == 3
    assert main(["analyze", str(SAMPLES / "auth.log"), "--no-llm", "--rule", "sudo_abuse",
                 "-o", str(tmp_path / "s.md")]) == 0
    assert "sudo" in (tmp_path / "s.md").read_text()


def test_remote_endpoint_refused(tmp_path, capsys):
    assert main(["demo", "--base-url", "https://api.example.com", "-o", str(tmp_path / "r.md")]) == 1
    assert "non-local" in capsys.readouterr().err
