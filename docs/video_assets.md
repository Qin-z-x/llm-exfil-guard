# Video assets — llm-exfil-guard (5-minute demo)

All commands below were run on the build machine; the outputs quoted are copied
from the captured evidence. Raw material: `docs/screenshots/`, `docs/EVIDENCE.md`,
`evidence/`.

## Files ready for the edit

| asset | path | what it shows |
| --- | --- | --- |
| Demo chat screenshot | `docs/screenshots/demo_chat.png` | the rendered transcript, the beacon URLs, the decoded payloads and the network log |
| Cleaned page screenshot | `docs/screenshots/demo_clean.png` | same UI after `clean(strip)`: visible text kept, zero beacons |
| Scan terminal | `docs/screenshots/terminal_scan.png` | 10 findings (6 high) and the `--fail-on high` gate returning exit 1 |
| Clean terminal | `docs/screenshots/terminal_clean.png` | cleaned Markdown + removal counts |
| Test terminal | `docs/screenshots/terminal_tests.png` | 135 tests passing |
| Raw evidence | `docs/EVIDENCE.md` | hashes, browser request log, decoded markers |

## Suggested 5-minute structure

| time | beat | command / asset | expected output (real) |
| --- | --- | --- | --- |
| 0:00–0:25 | Hook: "the model's answer can make your browser leak data" | open `docs/screenshots/demo_chat.png`; zoom the "Network requests" panel | `beacon requests detected: 3` and `GET http://127.0.0.1:…/collect?d=…` |
| 0:25–1:05 | Threat explanation | `docs/THREAT_MODEL.md` | Markdown image beacon, hidden `display:none` instruction, reference-style image |
| 1:05–1:45 | Scan a poisoned transcript | `python -m exfil_guard scan examples/poisoned_chat.md` | `summary: 10 finding(s): 6 high, 4 medium, 0 low` |
| 1:45–2:10 | Cut off the payload | `python -m exfil_guard scan examples/poisoned_chat.md --fail-on high` | `FAIL: 6 finding(s) at or above severity 'high'`, `[exit code: 1]` |
| 2:10–2:45 | Clean while keeping the text | `python -m exfil_guard clean examples/poisoned_chat.md` | visible review text preserved; beacons/hidden instruction gone |
| 2:45–3:20 | Per-rule removal report | `python -c "from exfil_guard import clean; r=clean(open('examples/poisoned_chat.md',encoding='utf-8').read(),'report'); print(r['removed'])"` | `{'remote Markdown image': 1, 'hidden instruction container (<div>)': 1, 'remote <img> beacon': 1, 'remote reference definition': 1, 'remote reference image': 1, 'HTML comment carrying a remote URL': 1}` |
| 3:20–3:55 | Delivery proof with a real browser | `python scripts/capture_evidence.py` (browser section in `docs/EVIDENCE.md`) | **6** beacon requests for the poisoned page, **0** for the cleaned page; decoded markers `DEMO-EXFIL-MARKER-9c4f2a7e`, `DEMO-ENV-MARKER-57d10c`, `DEMO-REF-MARKER-31b8d5` |
| 3:55–4:20 | Hidden content is agent-readable | `python -m exfil_guard scan examples/hidden_instruction.md` | `EG-HIDDEN-INJECTION` high + `EG-WEBHOOK` high + `EG-HIDDEN-COMMENT` medium |
| 4:20–4:45 | Tests / trust | `python -m unittest discover -s tests -t .` | `Ran 135 tests … OK` (see `terminal_tests.png`) |
| 4:45–5:00 | Limits + call to action | `docs/THREAT_MODEL.md` §5 | heuristic, renderer-specific, allow-list for trusted CDNs; no new CVE claim |

## Exact commands for screen recording

```bash
# 1. Show the demo pages (open locally; they are self-contained)
start docs/demo_chat.html
start docs/demo_clean.html

# 2. Scan / gate / clean
python -m exfil_guard scan examples/poisoned_chat.md
python -m exfil_guard scan examples/poisoned_chat.md --fail-on high
python -m exfil_guard clean examples/poisoned_chat.md

# 3. Hidden-content example
python -m exfil_guard scan examples/hidden_instruction.md

# 4. Regenerate the evidence (needs Microsoft Edge for the browser step)
python scripts/capture_evidence.py

# 5. Tests
python -m unittest discover -s tests -t .
```

## Key on-screen numbers (copy-safe)

* 10 findings / 6 high / 4 medium on the demo transcript.
* 3 encoded payloads embedded; 3 decoded markers recovered by the browser capture.
* 6 real beacon requests from the poisoned page; **0** from the cleaned page.
* 135 tests, all passing.
* Python 3.10+, zero runtime dependencies.

## Caveats to state on camera

* The sink in the committed demo page is a documentation host (`attacker.example`);
  the live request capture uses a local `127.0.0.1` sink as a stand-in. No real
  attacker server or real secret is involved.
* Detection is heuristic: a legitimate signed CDN URL can trigger a high finding
  (allow-list it); custom encodings can evade detection.
* The tool sanitizes the *output channel*; it is not a model-level guard.
