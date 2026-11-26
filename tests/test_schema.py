"""Validate emitted JSON against the published JSON Schemas."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from tests.schema_lite import validate

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"


def load_schema(name: str) -> dict:
    return json.loads((DOCS / name).read_text(encoding="utf-8"))


class SchemaTests(unittest.TestCase):
    def test_schemas_are_valid_json(self):
        for name in ("finding.schema.json", "scan-result.schema.json", "clean-report.schema.json"):
            schema = load_schema(name)
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_scan_result_matches_schema(self):
        result = subprocess.run(
            [sys.executable, "-m", "exfil_guard", "scan", str(ROOT / "examples" / "poisoned_chat.md"), "--json"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
        )
        payload = json.loads(result.stdout)
        errors = validate(payload, load_schema("scan-result.schema.json"))
        self.assertEqual(errors, [])
        for finding in payload["findings"]:
            self.assertEqual(validate(finding, load_schema("finding.schema.json")), [])

    def test_clean_report_matches_schema(self):
        from exfil_guard import clean

        report = clean((ROOT / "examples" / "poisoned_chat.md").read_text(encoding="utf-8"), "report")
        self.assertEqual(validate(report, load_schema("clean-report.schema.json")), [])

    def test_schema_rejects_bad_finding(self):
        schema = load_schema("finding.schema.json")
        bad = {
            "code": "NOT-A-RULE",
            "kind": "exfil-url",
            "severity": "critical",
            "start": -1,
            "end": 0,
            "length": 1,
            "line": 1,
            "column": 1,
            "message": "x",
            "data": {},
        }
        self.assertNotEqual(validate(bad, schema), [])


if __name__ == "__main__":
    unittest.main()
