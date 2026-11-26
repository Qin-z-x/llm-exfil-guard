"""Command line interface for exfil-guard.

Exit codes (stable, CI-gate friendly)::

    0  success (for ``scan``: no finding at/above the --fail-on threshold)
    1  ``scan --fail-on`` threshold reached
    2  usage error, unreadable input, invalid UTF-8, or invalid mode
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .core import clean, format_finding_line, scan, severity_at_least, summarize


def _read_text(path: str) -> tuple[str, str]:
    """Return (text, source-label). ``-`` means stdin."""
    if path == "-":
        data = sys.stdin.buffer.read()
        source = "<stdin>"
    else:
        try:
            data = Path(path).read_bytes()
        except OSError as exc:
            raise SystemExit("error: cannot read %s: %s" % (path, exc))
        source = path
    try:
        return data.decode("utf-8"), source
    except UnicodeDecodeError as exc:
        raise SystemExit("error: %s is not valid UTF-8: %s" % (source, exc))


def _flatten_domains(values: list[list[str]] | None) -> list[str]:
    domains: list[str] = []
    for group in values or []:
        for item in group:
            for part in item.split(","):
                part = part.strip()
                if part and part not in domains:
                    domains.append(part)
    return domains


def _print_scan(args, text: str, source: str) -> int:
    findings = scan(text, allow_domains=args.allow_domain)
    summary = summarize(findings)
    if args.json:
        payload = {
            "tool": "exfil-guard",
            "version": __version__,
            "source": source,
            "characters": len(text),
            "lines": text.count("\n") + 1,
            "allow_domains": args.allow_domain,
            "summary": summary,
            "findings": [finding.to_dict() for finding in findings],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(
            "exfil-guard %s  scan  %s  (%d chars, %d lines)"
            % (__version__, source, len(text), text.count("\n") + 1)
        )
        for finding in findings:
            print(format_finding_line(finding))
        print(
            "summary: %d finding(s): %d high, %d medium, %d low"
            % (summary["total"], summary["high"], summary["medium"], summary["low"])
        )
    if args.fail_on:
        hits = [finding for finding in findings if severity_at_least(finding.severity, args.fail_on)]
        if hits:
            if not args.json:
                print(
                    "FAIL: %d finding(s) at or above severity %r (--fail-on %s)"
                    % (len(hits), args.fail_on, args.fail_on)
                )
            return 1
        if not args.json:
            print("OK: no finding at or above severity %r" % args.fail_on)
    return 0


def _print_clean(args, text: str) -> int:
    domains = args.allow_domain
    if args.mode == "report":
        report = clean(text, "report", allow_domains=domains)
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    cleaned = clean(text, args.mode, allow_domains=domains)
    if args.json:
        report = clean(text, "report", allow_domains=domains)
        payload = {
            "tool": "exfil-guard",
            "version": __version__,
            "mode": args.mode,
            "allow_domains": domains,
            "characters": len(text),
            "cleaned_characters": len(cleaned),
            "removed": report["removed"],
            "clean_removes_remote_loads": report["summary"]["high"] > 0 and not _has_high_loads(cleaned, domains),
            "cleaned": cleaned,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    elif args.output:
        Path(args.output).write_text(cleaned, encoding="utf-8", newline="\n")
        print("wrote %s (%d chars)" % (args.output, len(cleaned)), file=sys.stderr)
    else:
        sys.stdout.write(cleaned)
        if not cleaned.endswith("\n"):
            sys.stdout.write("\n")
    return 0


def _has_high_loads(text: str, domains: list[str]) -> bool:
    high_codes = {
        "EG-EXFIL-URL",
        "EG-WEBHOOK",
        "EG-REMOTE-ASSET",
        "EG-DATA-URI",
        "EG-ACTIVE-CONTENT",
        "EG-ACTIVE-SCHEME",
        "EG-PING-ATTR",
        "EG-HIDDEN-INJECTION",
    }
    return any(finding.code in high_codes for finding in scan(text, allow_domains=domains))


def _print_demo(args) -> int:
    from .demo import DEFAULT_SINK, build_demo, build_demo_page

    sink_base = args.sink or DEFAULT_SINK
    demo = build_demo(sink_base)
    if args.html:
        page = build_demo_page(sink_base)
        Path(args.html).parent.mkdir(parents=True, exist_ok=True)
        Path(args.html).write_text(page, encoding="utf-8", newline="\n")
        print("wrote %s (%d bytes)" % (args.html, len(page.encode("utf-8"))), file=sys.stderr)
    if args.clean_html:
        page = build_demo_page(sink_base, clean_page=True)
        Path(args.clean_html).parent.mkdir(parents=True, exist_ok=True)
        Path(args.clean_html).write_text(page, encoding="utf-8", newline="\n")
        print("wrote %s (%d bytes)" % (args.clean_html, len(page.encode("utf-8"))), file=sys.stderr)
    if args.json:
        print(json.dumps(demo, indent=2, ensure_ascii=False))
        return 0
    print("exfil-guard %s  demo" % __version__)
    print("sink base: %s" % demo["sink_base"])
    print("secret marker: %s (harmless, deterministic)" % demo["secret"])
    print(
        "transcript: %d chars | findings: %d (%d high, %d medium, %d low)"
        % (
            demo["counts"]["transcript_characters"],
            demo["summary"]["total"],
            demo["summary"]["high"],
            demo["summary"]["medium"],
            demo["summary"]["low"],
        )
    )
    for finding in demo["findings"]:
        print(
            "  %s %-20s %s"
            % (finding["severity"].upper().ljust(6), finding["code"], finding["message"])
        )
    print("cleaned findings: %d high" % demo["cleaned_summary"]["high"])
    for name, value in demo["assertions"].items():
        print("  %-36s %s" % (name, "PASS" if value else "FAIL"))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="exfil-guard",
        description="Detect and defuse data-exfiltration channels in rendered LLM output.",
    )
    parser.add_argument("--version", action="version", version="exfil-guard " + __version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="scan rendered output for exfiltration channels")
    scan_parser.add_argument("path", help="file to scan, or - for stdin")
    scan_parser.add_argument("--json", action="store_true", help="machine-readable JSON output")
    scan_parser.add_argument(
        "--fail-on", choices=["low", "medium", "high"], default=None, help="exit 1 if a finding at/above this severity exists"
    )
    scan_parser.add_argument(
        "--allow-domain", action="append", nargs="+", metavar="HOST", help="trusted hostname (repeatable; subdomains included)"
    )
    scan_parser.set_defaults(func=lambda args: _print_scan(args, *_read_text(args.path)))

    clean_parser = subparsers.add_parser("clean", help="remove/neutralize remote loads in rendered output")
    clean_parser.add_argument("path", help="file to clean, or - for stdin")
    clean_parser.add_argument("--mode", choices=["strip", "allowlist", "report"], default="strip")
    clean_parser.add_argument("--json", action="store_true", help="JSON output (includes removed-count report)")
    clean_parser.add_argument("-o", "--output", help="write cleaned text to this file instead of stdout")
    clean_parser.add_argument(
        "--allow-domain", action="append", nargs="+", metavar="HOST", help="trusted hostname kept in allowlist mode"
    )
    clean_parser.set_defaults(func=lambda args: _print_clean(args, _read_text(args.path)[0]))

    demo_parser = subparsers.add_parser("demo", help="build the deterministic exfiltration demo")
    demo_parser.add_argument("--json", action="store_true", help="machine-readable JSON output")
    demo_parser.add_argument("--html", help="write the rendered demo page to this path")
    demo_parser.add_argument("--clean-html", help="write the cleaned demo page to this path")
    demo_parser.add_argument("--sink", help="override the sink base URL (default: %s)" % "https://attacker.example/collect")
    demo_parser.set_defaults(func=_print_demo)

    return parser


def _force_utf8_output() -> None:
    """Piped stdout on Windows uses the locale code page; findings contain non-ASCII."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):  # pragma: no cover - stream already closed
                pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8_output()
    parser = build_parser()
    args = parser.parse_args(argv)
    args.allow_domain = _flatten_domains(getattr(args, "allow_domain", None))
    try:
        return args.func(args)
    except SystemExit as exc:
        if isinstance(exc.code, int):
            return exc.code
        print(exc.code, file=sys.stderr)
        return 2
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
