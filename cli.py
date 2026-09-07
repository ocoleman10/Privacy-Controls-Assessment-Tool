"""Entrypoint: `python cli.py <target> [options]`.

Kept at the repo root rather than inside scanner/ so `python cli.py ...`
works without needing the package installed or PYTHONPATH set up — this is
meant to be runnable straight out of a freshly cloned repo.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from scanner.engine import run_scan
from scanner.report import render_json, render_markdown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pcat",
        description="Privacy and Controls Assessment Tool — scan a codebase you own for "
        "privacy/security hygiene issues, mapped to NIST CSF 2.0 / CIS Controls v8.",
    )
    parser.add_argument(
        "target",
        type=Path,
        help="Path to scan. Must be a system you own — see README's scope discipline section.",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="Write the report to this file instead of stdout.",
    )
    parser.add_argument(
        "--format",
        choices=["md", "json"],
        default="md",
        help="Report format (default: md).",
    )
    parser.add_argument(
        "--online",
        action="store_true",
        help="Query osv.dev for known-vulnerable pinned dependencies. Off by default "
        "so a plain scan never depends on network access.",
    )
    args = parser.parse_args(argv)

    target = args.target.resolve()
    if not target.exists():
        print(f"error: target path does not exist: {target}", file=sys.stderr)
        return 2

    findings = run_scan(target, online=args.online)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    if args.format == "json":
        output = render_json(findings, str(target), generated_at)
    else:
        output = render_markdown(findings, str(target), generated_at)

    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(f"Report written to {args.output} ({len(findings)} findings).")
    else:
        print(output)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
