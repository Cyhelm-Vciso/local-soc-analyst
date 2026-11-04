# Contributing

New detection rules, parsers and fixes are very welcome.

## Adding a rule
1. Add a function decorated with `@rule(...)` in `src/soc_analyst/detections.py`, with an accurate MITRE ATT&CK technique ID.
2. Add sample events that trigger it to `scripts/make_samples.py`, plus a benign look-alike that must **not** trigger it, then run `python scripts/make_samples.py`.
3. Add a test in `tests/test_soc.py`.

## Rules of the road
- Sample data must be synthetic. Use RFC 5737 IPs and fictional names, and never include real logs.
- Keep it dependency-free and local-first.

```bash
pip install -e ".[dev]" && pytest
```
