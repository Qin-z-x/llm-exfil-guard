## llm-exfil-guard v0.1.0

Detect and defuse data exfiltration through rendered LLM output with a
standard-library-only Python core and a reproducible local demonstration.

### What is included

- `python -m exfil_guard scan|clean|demo` with `--json`,
  `--fail-on {low,medium,high}` CI gating (exit codes 0/1/2) and repeated
  `--allow-domain` trusted hosts.
- Detection for: Markdown/HTML image beacons (including reference-style images),
  iframes/objects/embeds, CSS `url()` in styles and style attributes, link
  preload/prefetch, meta refresh, `srcset`, `ping=`, form actions, `<base>`,
  inline event handlers, `<script>`, `data:`/`javascript:` schemes; base64,
  JWT and high-entropy query/path payloads; known webhook/collaborator hosts;
  hidden content (`display:none`, opacity 0, white text, `font-size:0`,
  `aria-hidden`, HTML comments, `<template>`/`<noscript>`, off-screen styles).
- `clean` in `strip` / `allowlist` / `report` modes: removes or neutralizes
  remote loads and hidden instruction containers while preserving visible text
  and code blocks byte-for-byte.
- 135 unit tests (unittest + pytest), GitHub Actions CI on Python 3.10–3.13,
  deterministic demo pages, JSON Schemas for findings/scan results/clean reports.
- Evidence: a real headless-Microsoft-Edge browser loaded a poisoned transcript
  against a local sink server and issued **6 beacon requests** whose query strings
  decoded to all three demo markers; the cleaned page issued **0**. Raw request
  log, hashes, CLI runs and test output are in `docs/EVIDENCE.md`.

### Honest notes

- This is a detection/sanitization tool and a local demonstration. It does
  **not** disclose a new vulnerability and does **not** claim a new CVE. The
  attack class is public prior art (indirect prompt injection and Markdown-image
  exfiltration research 2023–2025, EchoLeak/CVE-2025-32711, OWASP LLM05:2025).
- Detection is heuristic. Legitimate signed CDN URLs can be reported high
  (allow-list them); custom encodings or hiding via external stylesheets can
  evade detection. See `docs/THREAT_MODEL.md`.
- The browser capture proves the browser *issues* the request. No real secret,
  user account or attacker infrastructure is involved; the demo marker is a
  fixed harmless string.
