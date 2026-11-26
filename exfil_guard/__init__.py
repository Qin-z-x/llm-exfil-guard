"""exfil-guard: detect and defuse data-exfiltration channels in rendered LLM output.

Public API::

    from exfil_guard import scan, clean

    findings = scan(untrusted_markdown)              # list[Finding], deterministic order
    safe = clean(untrusted_markdown, "strip")         # str, remote loads removed
    report = clean(untrusted_markdown, "report")      # dict, nothing modified

The core is standard-library only (see ``scripts/check_core_deps.py``).
"""

from __future__ import annotations

from .core import (
    Finding,
    SEVERITY_ORDER,
    clean,
    format_finding_line,
    scan,
    summarize,
)

__version__ = "0.1.0"

__all__ = [
    "Finding",
    "SEVERITY_ORDER",
    "clean",
    "format_finding_line",
    "scan",
    "summarize",
    "__version__",
]
