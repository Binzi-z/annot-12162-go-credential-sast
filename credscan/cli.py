"""Command-line entry point.

Examples:
  python -m credscan scan . --sarif report.sarif
  python -m credscan scan . --incremental --base HEAD
  python -m credscan scan . --tags integration,staging --fail-on real
  python -m credscan explain report.sarif     # human-readable summary

Exit code:
  0  no blocking findings
  1  blocking findings present (CI gate)
  2  usage / IO error
"""

from __future__ import annotations

import argparse
import json
import sys

from .engine import Scanner
from .sarif import dumps as sarif_dumps


def _cmd_scan(args: argparse.Namespace) -> int:
    tags = frozenset(t.strip() for t in args.tags.split(",") if t.strip()) if args.tags \
        else frozenset({"linux", "amd64"})
    scanner = Scanner(args.repo, active_tags=tags)
    if args.incremental:
        findings = scanner.scan_incremental(base_ref=args.base)
    else:
        findings = scanner.scan()

    sarif = sarif_dumps(findings, scanner.repo_root)
    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as fh:
            fh.write(sarif)
    else:
        print(sarif)

    stats = scanner.stats
    summary = {
        "mode": "incremental" if stats.incremental else "full",
        "files_scanned": stats.files_scanned,
        "go_files": stats.go_files,
        "other_files": stats.other_files,
        "findings": stats.findings_total,
        "blocking": stats.blocking,
        "suppressed": stats.suppressed,
        "elapsed_ms": stats.elapsed_ms,
    }
    print(json.dumps(summary, indent=2), file=sys.stderr)

    blocking = [f for f in findings if f.blocking()]
    if args.fail_on == "real" and blocking:
        print(f"credscan: {len(blocking)} blocking credential finding(s)",
              file=sys.stderr)
        return 1
    return 0


def _cmd_explain(args: argparse.Namespace) -> int:
    with open(args.sarif, encoding="utf-8") as fh:
        doc = json.load(fh)
    for run in doc.get("runs", []):
        for result in run.get("results", []):
            loc = result["locations"][0]["physicalLocation"]
            props = result.get("properties", {})
            line = (
                f"{loc['artifactLocation']['uri']}:"
                f"{loc['region']['startLine']}  "
                f"{result['ruleId']}  {props.get('confidence')}  "
                f"{props.get('provider')}/{props.get('credential-kind')}  "
                f"{result['message']['text']}"
            )
            print(line)
            for reason in props.get("evidence", []):
                print(f"    - {reason}")
            for flow in result.get("codeFlows", []):
                for tf in flow["threadFlows"]:
                    for step in tf["locations"]:
                        pl = step["location"]["physicalLocation"]
                        print(f"    flow -> {pl['artifactLocation']['uri']}:"
                              f"{pl['region']['startLine']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="credscan",
                                     description="Syntax-first hardcoded credential scanner")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a repository")
    scan.add_argument("repo", help="repository root")
    scan.add_argument("--sarif", help="write SARIF to this path (default: stdout)")
    scan.add_argument("--incremental", action="store_true",
                      help="only scan files changed vs --base (git diff)")
    scan.add_argument("--base", default="HEAD", help="git base ref for incremental mode")
    scan.add_argument("--tags", help="comma-separated extra Go build tags")
    scan.add_argument("--fail-on", choices=["real", "never"], default="real")
    scan.set_defaults(func=_cmd_scan)

    explain = sub.add_parser("explain", help="print a SARIF report in human form")
    explain.add_argument("sarif")
    explain.set_defaults(func=_cmd_explain)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (OSError, KeyboardInterrupt) as exc:
        print(f"credscan: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
