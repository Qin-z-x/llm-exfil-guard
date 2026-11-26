"""Regenerate the committed demo pages deterministically.

CI runs this script and fails if ``git diff`` shows the pages changed, which
proves the committed demo is a deterministic function of the code.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from exfil_guard.demo import build_demo_page  # noqa: E402


def main() -> int:
    docs = ROOT / "docs"
    docs.mkdir(exist_ok=True)
    for name, clean_page in (("demo_chat.html", False), ("demo_clean.html", True)):
        page = build_demo_page(clean_page=clean_page)
        target = docs / name
        target.write_text(page, encoding="utf-8", newline="\n")
        digest = hashlib.sha256(page.encode("utf-8")).hexdigest()
        print("%s  %d bytes  sha256=%s" % (name, len(page.encode("utf-8")), digest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
