# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-11-26

Initial release.

### Added

* `exfil_guard.scan(text)` — deterministic detection of rendered-output
  exfiltration: remote loads (Markdown/HTML images, iframes, CSS `url()`, link
  preload/prefetch, meta refresh, `srcset`, `form action`, `ping`), active content
  (`<script>`, event handlers, `<base>`, `javascript:`/`data:` schemes), encoded
  query/path payloads (base64, JWT, high-entropy), known webhook/collaborator
  hosts, and hidden content (`display:none`, opacity 0, white text, `font-size:0`,
  `aria-hidden`, HTML comments, `<template>`/`<noscript>`, off-screen styles).
* `exfil_guard.clean(text, mode)` — `strip`, `allowlist` and `report` modes.
  Remote loads and hidden instruction containers are removed/neutralized while
  visible text and code blocks are preserved.
* CLI `python -m exfil_guard scan|clean|demo` with `--json`,
  `--fail-on {low,medium,high}`, `--allow-domain`, `-o/--output`, exit codes 0/1/2.
* Deterministic demo (`exfil_guard/demo.py`, `scripts/build_demo.py`):
  `docs/demo_chat.html` and `docs/demo_clean.html`.
* Evidence capture (`scripts/capture_evidence.py`): real headless-Microsoft-Edge
  request capture against a local sink server (6 beacons from the poisoned page,
  0 from the cleaned page), raw request log, decoded payloads, CLI runs,
  deterministic hashes.
* 135 unit tests (`unittest` + `pytest`), JSON Schemas for findings / scan results /
  clean reports, GitHub Actions CI on Python 3.10–3.13.
* Documentation: `README.md` (EN + 中文简介), `docs/THREAT_MODEL.md`,
  `docs/EVIDENCE.md`, `docs/video_assets.md`, screenshots.

### Notes

* This is a defence tool and local demonstration. It does not disclose a new
  vulnerability and does not claim a new CVE; attack classes are public prior art.
* Detection is heuristic; see `docs/THREAT_MODEL.md` for limits.
