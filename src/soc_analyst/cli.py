"""Command line interface: `soc-analyst`."""
from __future__ import annotations

import argparse
import os
import sys
from importlib import resources
from pathlib import Path

from . import __version__
from .detections import RULES, SEVERITIES, run_rules
from .events import load_events
from .llm import PROVIDERS, LLMError, make_llm
from .report import filter_min, to_json, to_markdown
from .triage import overview, triage_findings

DEFAULT_MODEL = os.environ.get("SOC_MODEL", "llama3.1:8b")


def _analyze(paths: list[str], args) -> int:
    events, sources = [], []
    for p in paths:
        try:
            evs = load_events(p, args.format, args.year)
        except (OSError, ValueError) as e:
            print(f"error: {p}: {e}", file=sys.stderr)
            return 2
        print(f"  parsed {len(evs):>6} events from {p}", file=sys.stderr)
        events += evs
        sources.append(str(p))
    findings = filter_min(run_rules(events, only=args.rule), args.min_severity)
    print(f"  {len(findings)} finding(s) from {len(RULES) if not args.rule else len(args.rule)} rules",
          file=sys.stderr)

    model_name, summary = None, None
    if findings and not args.no_llm:
        llm = make_llm(args.provider, args.model, args.base_url, args.allow_remote)
        model_name = llm.name
        if len(findings) > args.max_triage:
            print(f"  triaging the top {args.max_triage} findings (use --max-triage to change)", file=sys.stderr)

        def progress(i, total, f):
            print(f"\r  triage {i}/{total}: {f.title[:60]:<60}", end="", file=sys.stderr, flush=True)

        try:
            triage_findings(findings[:args.max_triage], llm, redact=args.redact, progress=progress)
            print(file=sys.stderr)
            if not args.no_summary:
                summary = overview(findings[:args.max_triage], llm, redact=args.redact)
        except LLMError as e:
            print(f"\nerror: {e}\nTip: run with --no-llm for a rules-only report.", file=sys.stderr)
            return 1

    md = to_markdown(findings, sources, len(events), model_name, summary)
    if args.out:
        Path(args.out).write_text(md, encoding="utf-8")
        print(f"  report written to {args.out}", file=sys.stderr)
    else:
        print(md)
    if args.json:
        Path(args.json).write_text(to_json(findings, sources, len(events), model_name, summary), encoding="utf-8")
        print(f"  JSON written to {args.json}", file=sys.stderr)
    if args.fail_on and any(SEVERITIES.index(f.severity) >= SEVERITIES.index(args.fail_on) for f in findings):
        return 3
    return 0


def cmd_analyze(args) -> int:
    return _analyze(args.paths, args)


def cmd_demo(args) -> int:
    samples = resources.files("soc_analyst") / "samples"
    paths = [str(samples / name) for name in ("auth.log", "windows-security.jsonl")]
    print("Running on bundled synthetic sample logs (no real systems or people).", file=sys.stderr)
    return _analyze(paths, args)


def cmd_rules(args) -> int:
    for r in RULES.values():
        print(f"{r.id:<24} {', '.join(r.mitre):<26} {r.title}")
    return 0


def _analysis_opts(p):
    p.add_argument("--format", choices=["auto", "authlog", "windows"], default="auto")
    p.add_argument("--year", type=int, help="year for syslog timestamps without one (default: current)")
    p.add_argument("--provider", choices=PROVIDERS, default=os.environ.get("SOC_PROVIDER", "ollama"))
    p.add_argument("--model", default=DEFAULT_MODEL, help=f"chat model (default: {DEFAULT_MODEL})")
    p.add_argument("--base-url", default=os.environ.get("SOC_BASE_URL"))
    p.add_argument("--allow-remote", action="store_true", help="allow a non-local model server")
    p.add_argument("--no-llm", action="store_true", help="rules only, no model needed")
    p.add_argument("--no-summary", action="store_true", help="skip the shift summary")
    p.add_argument("--redact", action="store_true", help="replace users, hosts and IPs with placeholders before prompting")
    p.add_argument("--max-triage", type=int, default=25, help="max findings sent to the model (default 25)")
    p.add_argument("--min-severity", choices=SEVERITIES, default="low")
    p.add_argument("--rule", action="append", choices=sorted(RULES), help="run only this rule (repeatable)")
    p.add_argument("-o", "--out", help="write Markdown report to this file")
    p.add_argument("--json", help="also write machine-readable JSON to this file")
    p.add_argument("--fail-on", choices=SEVERITIES, help="exit code 3 if any finding is at/above this severity")


def build_parser():
    p = argparse.ArgumentParser(prog="soc-analyst", description="Triage security logs with deterministic rules + a local LLM.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("analyze", help="analyse log files")
    a.add_argument("paths", nargs="+")
    _analysis_opts(a)
    a.set_defaults(func=cmd_analyze)
    d = sub.add_parser("demo", help="run on bundled synthetic logs")
    _analysis_opts(d)
    d.set_defaults(func=cmd_demo)
    r = sub.add_parser("rules", help="list detection rules")
    r.set_defaults(func=cmd_rules)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except LLMError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
