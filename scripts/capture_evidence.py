"""Capture the real evidence used by docs/EVIDENCE.md.

Everything in this script is measured on the build machine; nothing is estimated.
It regenerates:

  * docs/demo_chat.html, docs/demo_clean.html       (deterministic demo pages)
  * evidence/demo_result.json                        (findings/cleaned/assertions)
  * evidence/raw/cli_runs.json                       (real CLI invocations)
  * evidence/terminal/*.txt                          (verbatim CLI session text)
  * evidence/browser_requests.json                   (real browser beacon requests)
  * evidence/raw/demo_page_dom.html                  (headless Edge DOM snapshot)
  * docs/screenshots/demo_chat.png, demo_clean.png   (real browser rendering)
  * docs/screenshots/terminal_*.png                  (rendered from captured text)
  * docs/EVIDENCE.md                                 (this report)

The Windows headless-browser step needs Microsoft Edge. If Edge is missing the
report records that honestly instead of inventing a result.

Usage::

    python scripts/capture_evidence.py
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import platform
import re
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from exfil_guard import __version__, clean, scan, summarize  # noqa: E402
from exfil_guard.demo import DEMO_SECRET, REF_SECRET, HIDDEN_SECRET, build_demo, build_demo_page  # noqa: E402

EDGE_CANDIDATES = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
)
GIF_1X1 = bytes.fromhex(
    "47494638396101000100800000ffffff00000021f90400000000002c00000000"
    "010001000002024401003b"
)
SINK_PATH = "/collect"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def write_json(path: Path, payload) -> None:
    write_text(path, json.dumps(payload, indent=2, ensure_ascii=True) + "\n")


def find_edge() -> str | None:
    for candidate in EDGE_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    return None


def run_python(args: list[str], cwd: Path = ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, *args], cwd=str(cwd), capture_output=True, timeout=600
    )


def run_cli(*args: str) -> dict:
    process = run_python(["-m", "exfil_guard", *args])
    stdout = process.stdout.decode("utf-8", "replace")
    stderr = process.stderr.decode("utf-8", "replace")
    return {
        "argv": ["python", "-m", "exfil_guard", *args],
        "exit_code": process.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_sha256": sha256_text(stdout),
    }


def terminal_session(runs: list[dict]) -> str:
    lines = ["Windows PowerShell - exfil-guard evidence session (real captured output)", ""]
    for run in runs:
        lines.append("$ " + " ".join(run["argv"]))
        lines.append(run["stdout"].rstrip("\n"))
        if run["stderr"].strip():
            lines.append(run["stderr"].rstrip("\n"))
        lines.append("[exit code: %d]" % run["exit_code"])
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def run_ps_render(input_file: Path, output_file: Path, title: str) -> dict:
    script = ROOT / "scripts" / "render_terminal_screenshot.ps1"
    process = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-InputFile",
            str(input_file),
            "-OutputFile",
            str(output_file),
            "-Title",
            title,
        ],
        cwd=str(ROOT),
        capture_output=True,
        timeout=180,
    )
    result = {
        "input": str(input_file.relative_to(ROOT)),
        "output": str(output_file.relative_to(ROOT)),
        "exit_code": process.returncode,
        "stdout": process.stdout.decode("utf-8", "replace").strip(),
        "stderr": process.stderr.decode("utf-8", "replace").strip()[-500:],
    }
    if output_file.is_file():
        data = output_file.read_bytes()
        result["bytes"] = len(data)
        result["sha256"] = sha256_bytes(data)
    return result


# ---------------------------------------------------------------------------
# Browser capture: serve the page locally and record the real requests
# ---------------------------------------------------------------------------


class _SinkServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _make_handler(page_bytes: bytes, clean_bytes: bytes, state: dict):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 (http.server API)
            state["requests"].append({"phase": state["phase"], "path": self.path})
            if self.path.startswith(SINK_PATH):
                body = GIF_1X1
                content_type = "image/gif"
            elif self.path.startswith("/clean"):
                body = clean_bytes
                content_type = "text/html; charset=utf-8"
            else:
                body = page_bytes
                content_type = "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # silence stderr noise
            return

    return Handler


def _run_edge(edge: str, args: list[str], profile: Path, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            edge,
            "--headless=new",
            "--disable-gpu",
            "--hide-scrollbars",
            "--no-first-run",
            "--no-default-browser-check",
            "--user-data-dir=" + str(profile),
            *args,
        ],
        capture_output=True,
        timeout=timeout,
    )


def capture_browser() -> dict:
    edge = find_edge()
    result: dict = {"edge": edge, "skipped": False}
    if not edge:
        result["skipped"] = True
        result["note"] = "Microsoft Edge not found; browser request capture skipped."
        write_json(ROOT / "evidence" / "browser_requests.json", result)
        return result

    state = {"requests": [], "phase": "poisoned"}

    # Bind the server first so the generated page can embed the real local sink URL.
    server = _SinkServer(("127.0.0.1", 0), _make_handler(b"", b"", state))
    port = server.server_address[1]
    sink_url = "http://127.0.0.1:%d%s" % (port, SINK_PATH)
    page = build_demo_page(sink_base=sink_url)
    clean_page = build_demo_page(sink_base=sink_url, clean_page=True)
    handler = _make_handler(page.encode("utf-8"), clean_page.encode("utf-8"), state)
    server.RequestHandlerClass = handler

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = "http://127.0.0.1:%d/" % port
    profile = Path(tempfile.mkdtemp(prefix="exfil-guard-edge-"))
    dom_output = ""
    try:
        # 1) Load the poisoned page: a real browser issues the beacon requests.
        state["phase"] = "poisoned"
        dump = _run_edge(
            edge,
            ["--virtual-time-budget=6000", "--dump-dom", base_url],
            profile,
        )
        dom_output = dump.stdout.decode("utf-8", "replace")
        write_text(ROOT / "evidence" / "raw" / "demo_page_dom.html", dom_output)

        shots = {}
        for name, args in (
            (
                "demo_chat.png",
                ["--virtual-time-budget=6000", "--window-size=1200,1000", "--screenshot=" + str(ROOT / "docs" / "screenshots" / "demo_chat.png"), base_url],
            ),
        ):
            state["phase"] = "poisoned"
            shot = _run_edge(edge, args, profile)
            shots[name] = {"exit_code": shot.returncode}

        # 2) Load the cleaned page: no beacon requests should be issued.
        state["phase"] = "clean"
        clean_dump = _run_edge(
            edge, ["--virtual-time-budget=6000", "--dump-dom", base_url + "clean"], profile
        )
        write_text(ROOT / "evidence" / "raw" / "demo_clean_dom.html", clean_dump.stdout.decode("utf-8", "replace"))
        clean_shot = _run_edge(
            edge,
            [
                "--virtual-time-budget=6000",
                "--window-size=1200,1000",
                "--screenshot=" + str(ROOT / "docs" / "screenshots" / "demo_clean.png"),
                base_url + "clean",
            ],
            profile,
        )
        shots["demo_clean.png"] = {"exit_code": clean_shot.returncode}
        result["screenshots"] = {}
        for name in ("demo_chat.png", "demo_clean.png"):
            path = ROOT / "docs" / "screenshots" / name
            if path.is_file():
                data = path.read_bytes()
                result["screenshots"][name] = {
                    "bytes": len(data),
                    "sha256": sha256_bytes(data),
                    "screenshot_exit_code": shots.get(name, {}).get("exit_code"),
                }
    finally:
        server.shutdown()
        server.server_close()
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", "Remove-Item -Recurse -Force -ErrorAction SilentlyContinue '%s'" % profile],
            capture_output=True,
        )

    poisoned_requests = [r for r in state["requests"] if r["phase"] == "poisoned"]
    clean_requests = [r for r in state["requests"] if r["phase"] == "clean"]
    beacon_requests = [r["path"] for r in poisoned_requests if r["path"].startswith(SINK_PATH)]
    clean_beacons = [r["path"] for r in clean_requests if r["path"].startswith(SINK_PATH)]
    decoded = []
    for path in beacon_requests:
        query = urllib.parse.urlsplit(path).query
        for key, value in urllib.parse.parse_qsl(query):
            padding = "=" * (-len(value) % 4)
            try:
                text = base64.b64decode(value + padding).decode("utf-8")
            except Exception:  # noqa: BLE001 - evidence capture must not crash on odd values
                continue
            decoded.append({"param": key, "base64": value, "decoded": text})
    matched_markers = sorted(
        marker
        for marker in (DEMO_SECRET, REF_SECRET, HIDDEN_SECRET)
        if any(marker in entry["decoded"] for entry in decoded)
    )
    dom_beacon_line = None
    match = re.search(r"beacon requests detected:\s*(\d+)", dom_output)
    if match:
        dom_beacon_line = int(match.group(1))
    result.update(
        {
            "server_url": base_url,
            "sink_url": sink_url,
            "requests_poisoned_phase": [r["path"] for r in poisoned_requests],
            "requests_clean_phase": [r["path"] for r in clean_requests],
            "beacon_requests": beacon_requests,
            "decoded_beacons": decoded,
            "matched_demo_markers": matched_markers,
            "dom_reported_beacon_count": dom_beacon_line,
            "assertions": {
                "browser_made_beacon_requests": len(beacon_requests) >= 3,
                "decoded_query_contains_demo_markers": bool(matched_markers),
                "cleaned_page_made_no_beacon_requests": len(clean_beacons) == 0,
            },
            "dom_snapshot": "evidence/raw/demo_page_dom.html",
            "clean_dom_snapshot": "evidence/raw/demo_clean_dom.html",
        }
    )
    write_json(ROOT / "evidence" / "browser_requests.json", result)
    return result


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def build_report(env: dict, demo: dict, demo_paths: dict, cli_runs: dict, browser: dict, tests: dict, shots: dict) -> str:
    summary = demo["summary"]
    cleaned_summary = demo["cleaned_summary"]
    assertion_rows = "\n".join(
        "| `%s` | **%s** |" % (name, "PASS" if value else "FAIL") for name, value in demo["assertions"].items()
    )
    finding_code_counts: dict[str, int] = {}
    finding_sev: dict[str, str] = {}
    for finding in demo["findings"]:
        finding_code_counts[finding["code"]] = finding_code_counts.get(finding["code"], 0) + 1
        finding_sev[finding["code"]] = finding["severity"]
    grouped_rows = "\n".join(
        "| `%s` | %s | %d |" % (code, finding_sev[code], count) for code, count in sorted(finding_code_counts.items())
    )

    cli_rows = "\n".join(
        "| `%s` | `%d` |" % (" ".join(run["argv"][2:]), run["exit_code"]) for run in cli_runs["runs"]
    )

    if browser.get("skipped"):
        browser_section = (
            "Headless Microsoft Edge was not available on the build machine, so the browser step was "
            "**skipped** and is not claimed. The page and the scanner output are still reproducible."
        )
        browser_assertion_rows = "| browser capture | **SKIPPED** |"
    else:
        browser_assertion_rows = "\n".join(
            "| `%s` | **%s** |" % (name, "PASS" if value else "FAIL")
            for name, value in browser.get("assertions", {}).items()
        )
        decoded_rows = "\n".join(
            "| `%s` | `%s` | %s |"
            % (entry["param"], entry["base64"][:24] + ("..." if len(entry["base64"]) > 24 else ""), "`" + entry["decoded"] + "`")
            for entry in browser.get("decoded_beacons", [])
        ) or "| _none_ | – | – |"
        browser_section = f"""A local sink server stood in for `attacker.example` and the page was loaded with headless
Microsoft Edge (`--headless=new`). The server logged the real HTTP requests the browser made.

| measurement | value |
| --- | --- |
| local page URL | `{browser.get("server_url", "")}` |
| local sink URL | `{browser.get("sink_url", "")}` |
| beacon requests observed (poisoned page) | **{len(browser.get("beacon_requests", []))}** |
| beacon requests observed (cleaned page) | **{len([p for p in browser.get("requests_clean_phase", []) if p.startswith(SINK_PATH)])}** |
| decoded demo markers recovered from query strings | {", ".join("`%s`" % marker for marker in browser.get("matched_demo_markers", [])) or "–"} |
| browser JS counter (`beacon requests detected`) | {browser.get("dom_reported_beacon_count")} |

| assertion | result |
| --- | --- |
{browser_assertion_rows}

Decoded `d=` query payloads captured by the sink server:

| query param | base64 (truncated) | decoded |
| --- | --- | --- |
{decoded_rows}

Raw requests in the poisoned phase (verbatim):

```
{chr(10).join(browser.get("requests_poisoned_phase", []))}
```

Raw requests in the cleaned phase (verbatim):

```
{chr(10).join(browser.get("requests_clean_phase", []))}
```

DOM snapshot: `evidence/raw/demo_page_dom.html`; cleaned-page DOM:
`evidence/raw/demo_clean_dom.html`.
"""

    screenshots = []
    for name in ("demo_chat.png", "demo_clean.png", "terminal_scan.png", "terminal_clean.png", "terminal_tests.png"):
        path = ROOT / "docs" / "screenshots" / name
        if path.is_file():
            data = path.read_bytes()
            screenshots.append("- `docs/screenshots/%s` (%d bytes, sha256 `%s`)" % (name, len(data), sha256_bytes(data)[:16] + "…"))
    screenshot_block = "\n".join(screenshots) if screenshots else "- _none captured_"

    terminal_render_rows = "\n".join(
        "| `%s` | %s | %s |"
        % (entry["output"], "ok" if entry.get("exit_code") == 0 else "FAILED", entry.get("sha256", "–")[:16] + "…")
        for entry in shots.values()
    )

    return f"""# Evidence log

This file is generated by `python scripts/capture_evidence.py` on the machine that built the project.
Every value below is copied from real tool output, saved JSON or an OS-level browser request log;
nothing is estimated. Re-running the script reproduces the raw files in `evidence/` (the browser
screenshots require Microsoft Edge; the CLI evidence does not).

## Scope and honesty statement

`llm-exfil-guard` is a **detection and sanitization tool plus a reproducible local demonstration**.
It does not disclose a new vulnerability, does not claim a new CVE, and makes no claim that every
chat UI renders Markdown/HTML the same way. The attack class — data exfiltration from rendered LLM
output through image beacons and hidden content — is public prior art (see
[`docs/THREAT_MODEL.md`](THREAT_MODEL.md) for citations). The demonstration uses a fixed, harmless
marker string (`{DEMO_SECRET}`) and a local sink server; no real secret or user account is involved.

## Environment

| item | value |
| --- | --- |
| operating system | {env["os"]} |
| Python | {env["python"]} |
| exfil-guard version | {__version__} |
| Microsoft Edge (headless browser) | {env["edge"] or "not found"} |
| capture time (UTC) | {env["captured_at"]} |

## 1. Deterministic demo: rendered-output exfiltration

`exfil_guard.demo` builds a synthetic chat transcript. The visible text is an ordinary code-review
reply; the exfiltration channels are a Markdown image, an HTML `<img>` with zero opacity/off-screen
positioning, a reference-style Markdown image, a `display:none` div with a hidden instruction, and an
HTML comment. Every payload URL carries a base64-encoded value in its `d=` query parameter.

| measurement | value |
| --- | --- |
| transcript length | {demo["counts"]["transcript_characters"]} characters |
| findings | {summary["total"]} ({summary["high"]} high, {summary["medium"]} medium, {summary["low"]} low) |
| encoded payloads embedded | {len(demo["payloads"])} |
| cleaned length | {demo["counts"]["cleaned_characters"]} characters |
| findings on cleaned output | {cleaned_summary["total"]} ({cleaned_summary["high"]} high) |
| `clean(strip)` removed (counts by rule) | `{json.dumps(demo["removed"], sort_keys=True)}` |
| transcript sha256 (UTF-8) | `{demo_paths["transcript_sha256"]}` |
| cleaned sha256 (UTF-8) | `{demo_paths["cleaned_sha256"]}` |
| `docs/demo_chat.html` sha256 | `{demo_paths["page_sha256"]}` |
| `docs/demo_clean.html` sha256 | `{demo_paths["clean_page_sha256"]}` |

Findings by rule code:

| rule | severity | count |
| --- | --- | --- |
{grouped_rows}

Demo assertions computed from the real objects:

| assertion | result |
| --- | --- |
{assertion_rows}

The encoded payloads are recoverable without any model or browser — the scanner decodes the
base64 value and reports it in the finding data. There is no fabricated "model obeyed" claim:
this project is about the rendered-output channel, not about model compliance.

## 2. Real browser request capture (delivery proof)

{browser_section}

## 3. CLI runs (verbatim exit codes)

The terminal sessions in `evidence/terminal/` are the verbatim stdout/stderr of the commands below.

| command (arguments after `python -m exfil_guard`) | exit code |
| --- | --- |
{cli_rows}

Machine-readable output (full JSON) for each run is in `evidence/raw/cli_runs.json`.

## 4. Test suite

```
{tests["tail"]}
```

| measurement | value |
| --- | --- |
| test runner | `python -m unittest discover -s tests -t .` |
| tests run | **{tests["count"]}** |
| result | **{tests["result"]}** |
| output file | `evidence/raw/unit_test_output.txt` |

## 5. Screenshots (real output)

Terminal screenshots are rendered from the captured session text with a monospace font — the text in
the image is the verbatim captured output, not a re-typed transcript. Demo screenshots are real
headless-Edge renderings of the generated pages.

{screenshot_block}

| terminal render | result | sha256 |
| --- | --- | --- |
{terminal_render_rows}

## 6. Reproduce

```bash
python scripts/check_core_deps.py                # stdlib-only core check
python -m unittest discover -s tests -t .         # unit tests
python scripts/gen_examples.py                    # regenerate examples/
python scripts/build_demo.py                      # regenerate docs/demo*.html
python scripts/capture_evidence.py                # regenerate this file + raw evidence
python -m exfil_guard demo --json                 # inspect the demo result directly
```

## Known limits

- Rendering is application-specific. The scanner targets the constructs that create automatic
  network requests in common Markdown/HTML renderers; a renderer with different rules may differ.
- Entropy/base64 heuristics are not proof of exfiltration. Legitimate pre-signed CDN URLs with
  long tokens can be reported (and can be allow-listed); pure checksums and UUIDs are deliberately
  not flagged.
- Hidden content can be hidden by CSS the scanner does not resolve (e.g. a class defined in an
  external stylesheet). The scanner reports inline hiding techniques and style blocks it can read.
- Browser capture uses a local HTTP sink; it proves the browser *issues* the request, not that a
  third-party server received it.
- This is defence-in-depth for a rendering pipeline. It is not a model-level guard and does not
  make untrusted output safe to feed to tool-using agents.
"""


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    captured_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    env = {
        "os": platform.platform(),
        "python": platform.python_version(),
        "edge": find_edge(),
        "captured_at": captured_at,
    }

    # 0) Regenerate the committed demo pages deterministically.
    build = run_python(["scripts/build_demo.py"])
    if build.returncode != 0:
        print(build.stderr.decode("utf-8", "replace"))
        return 1
    print(build.stdout.decode("utf-8", "replace").strip())
    demo_path = ROOT / "docs" / "demo_chat.html"
    clean_path = ROOT / "docs" / "demo_clean.html"

    # 1) Demo result + assertions.
    demo = build_demo()
    page_sha256 = sha256_bytes(demo_path.read_bytes())
    clean_page_sha256 = sha256_bytes(clean_path.read_bytes())
    demo_paths = {
        "transcript_sha256": sha256_text(demo["transcript_md"]),
        "cleaned_sha256": sha256_text(demo["cleaned_md"]),
        "page_sha256": page_sha256,
        "clean_page_sha256": clean_page_sha256,
    }
    write_json(ROOT / "evidence" / "demo_result.json", demo)
    print("demo findings:", demo["summary"], "| cleaned:", demo["cleaned_summary"])

    # 2) Real CLI runs.
    scan_session_runs = [
        run_cli("scan", "examples/poisoned_chat.md"),
        run_cli("scan", "examples/poisoned_chat.md", "--fail-on", "high"),
        run_cli("scan", "examples/clean_chat.md", "--fail-on", "low"),
        run_cli("scan", "examples/hidden_instruction.md"),
    ]
    report_run = run_cli("clean", "examples/poisoned_chat.md", "--mode", "report")
    verify_process = run_python(
        [
            "-c",
            "from exfil_guard import clean, scan\n"
            "text = open('examples/poisoned_chat.md', encoding='utf-8').read()\n"
            "report = clean(text, 'report')\n"
            "print('findings on input:', report['summary'])\n"
            "print('removed:', report['removed'])\n"
            "high_after = [f.code for f in scan(report['cleaned']) if f.severity == 'high']\n"
            "print('high findings after cleaning:', high_after)\n"
            "print('visible text preserved:', 'The retry loop change looks correct.' in report['cleaned'])\n"
            "print('demo marker absent:', 'DEMO-EXFIL-MARKER-9c4f2a7e' not in report['cleaned'])\n",
        ]
    )
    verify_run = {
        "argv": ["python", "-c", "<clean verification one-liner>"],
        "exit_code": verify_process.returncode,
        "stdout": verify_process.stdout.decode("utf-8", "replace"),
        "stderr": verify_process.stderr.decode("utf-8", "replace"),
        "stdout_sha256": sha256_text(verify_process.stdout.decode("utf-8", "replace")),
    }
    clean_session_runs = [run_cli("clean", "examples/poisoned_chat.md"), verify_run]
    all_runs = scan_session_runs + clean_session_runs + [report_run, run_cli("demo", "--json")]
    write_json(
        ROOT / "evidence" / "raw" / "cli_runs.json",
        {
            "python": sys.executable,
            "runs": all_runs,
        },
    )
    write_text(ROOT / "evidence" / "terminal" / "terminal_scan.txt", terminal_session(scan_session_runs))
    write_text(ROOT / "evidence" / "terminal" / "terminal_clean.txt", terminal_session(clean_session_runs))
    print("CLI runs captured:", [(run["exit_code"], " ".join(run["argv"][2:])) for run in scan_session_runs + clean_session_runs])

    # 3) Browser capture.
    browser = capture_browser()
    if browser.get("skipped"):
        print("browser capture skipped:", browser.get("note"))
    else:
        print("browser assertions:", browser["assertions"], "| beacons:", len(browser["beacon_requests"]))

    # 4) Tests.
    tests_proc = run_python(["-m", "unittest", "discover", "-s", "tests", "-t", "."])
    tests_text = tests_proc.stdout.decode("utf-8", "replace") + tests_proc.stderr.decode("utf-8", "replace")
    write_text(ROOT / "evidence" / "raw" / "unit_test_output.txt", tests_text)
    count_match = re.search(r"Ran (\d+) test", tests_text)
    tests = {
        "count": int(count_match.group(1)) if count_match else 0,
        "result": "OK" if tests_proc.returncode == 0 else "FAILED",
        "tail": "\n".join(tests_text.strip().splitlines()[-6:]),
        "exit_code": tests_proc.returncode,
    }
    write_text(ROOT / "evidence" / "terminal" / "terminal_tests.txt", "Windows PowerShell - unittest output\n\n" + tests_text.replace("\r\n", "\n").rstrip() + "\n")
    print("tests:", tests["count"], tests["result"])

    # 5) Render terminal screenshots from the captured text.
    shots = {
        "scan": run_ps_render(
            ROOT / "evidence" / "terminal" / "terminal_scan.txt",
            ROOT / "docs" / "screenshots" / "terminal_scan.png",
            "Windows PowerShell - exfil-guard scan (real captured output)",
        ),
        "clean": run_ps_render(
            ROOT / "evidence" / "terminal" / "terminal_clean.txt",
            ROOT / "docs" / "screenshots" / "terminal_clean.png",
            "Windows PowerShell - exfil-guard clean (real captured output)",
        ),
        "tests": run_ps_render(
            ROOT / "evidence" / "terminal" / "terminal_tests.txt",
            ROOT / "docs" / "screenshots" / "terminal_tests.png",
            "Windows PowerShell - exfil-guard unit tests (real captured output)",
        ),
    }
    for name, shot in shots.items():
        print("render %s: %s" % (name, shot.get("stdout") or shot.get("stderr")))

    # 6) Write the report.
    report = build_report(env, demo, demo_paths, {"runs": all_runs}, browser, tests, shots)
    write_text(ROOT / "docs" / "EVIDENCE.md", report)

    key_assertions = dict(demo["assertions"])
    if not browser.get("skipped"):
        key_assertions.update({"browser:" + key: value for key, value in browser.get("assertions", {}).items()})
    key_assertions["tests_pass"] = tests_proc.returncode == 0
    summary = {
        "tool": "exfil-guard",
        "version": __version__,
        "captured_at_utc": captured_at,
        "environment": env,
        "demo": {
            "summary": demo["summary"],
            "cleaned_summary": demo["cleaned_summary"],
            "assertions": demo["assertions"],
            "paths": demo_paths,
        },
        "browser": {key: value for key, value in browser.items() if key not in ("decoded_beacons",)},
        "tests": tests,
        "cli_exit_codes": [{"argv": run["argv"], "exit_code": run["exit_code"]} for run in all_runs],
        "screenshots": {
            name: {"path": shot["output"], "sha256": shot.get("sha256"), "bytes": shot.get("bytes")}
            for name, shot in shots.items()
        },
        "all_assertions": key_assertions,
        "all_assertions_pass": all(key_assertions.values()),
    }
    write_json(ROOT / "evidence" / "capture_summary.json", summary)
    print("all assertions pass:", summary["all_assertions_pass"])
    return 0 if summary["all_assertions_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
