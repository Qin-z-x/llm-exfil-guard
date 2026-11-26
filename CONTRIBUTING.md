# Contributing to llm-exfil-guard

Thanks for helping make rendered-output handling safer. This is a small,
dependency-free project; contributions are expected to stay that way.

## Ground rules

* The `exfil_guard/` package must import **only the Python standard library**
  (`python scripts/check_core_deps.py` enforces this). Test-only dependencies
  (pytest) are optional.
* All tests must pass on Python 3.10–3.13:
  `python -m unittest discover -s tests -t .` and `python -m pytest`.
* Generated artefacts are deterministic and committed:
  `python scripts/gen_examples.py`, `python scripts/build_demo.py`; CI fails if
  regeneration changes a committed file.
* Keep findings deterministic: stable codes, sorted output, JSON-serializable
  `data`. Add a test for every new rule and for every false positive you fix.
* Be honest in docs and messages. No claim of a new vulnerability/CVE; no
  fabricated results. Evidence must be reproducible via
  `python scripts/capture_evidence.py`.

## Development

```bash
git clone https://github.com/Qin-Z-x/llm-exfil-guard.git
cd llm-exfil-guard
python -m pip install -e ".[dev]"

python scripts/check_core_deps.py
python -m unittest discover -s tests -t .
python -m pytest
python -m exfil_guard demo
```

## Pull requests

1. Describe the attack primitive or false positive, with a minimal example.
2. Add tests (`tests/test_scan.py`, `tests/test_clean.py`,
   `tests/test_false_positives.py`, or `tests/test_cli.py`).
3. Update `docs/THREAT_MODEL.md` if the severity model changes.
4. Regenerate deterministic artefacts and check the diff.
5. CI must be green.

## Reporting security issues

Please use GitHub Security Advisories for this repository rather than a public
issue. This project is a defensive tool; reports about evasion of the heuristics
are welcome and will be documented as limitations.
