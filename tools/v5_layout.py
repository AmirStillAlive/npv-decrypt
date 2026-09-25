#!/usr/bin/env python3
"""کاوش دقیق حاشیهٔ رشتهٔ NPVS-v5/metadata و الگوهای compact envelope.

هدف: فهمیدن چیدمان بایت‌به‌بایت سرآیند v5 — magic، نسخه، metadata، sealed.
فقط می‌خواند.

    python tools/v5_layout.py path/to/libgojni.so
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2

    data = Path(sys.argv[1]).read_bytes()
    text = data.decode("ascii", errors="ignore")
    print(f"({len(data)} بایت)")

    print("\n=== حاشیهٔ NPVS-v5/metadata (±250 بایت) ===")
    for m in re.finditer(re.escape("NPVS-v5/metadata"), text):
        s = max(0, m.start() - 250)
        e = min(len(text), m.end() + 250)
        ctx = text[s:e]
        # غیرقابل‌چاپ را نقطه می‌کنیم ولی ساختار رشته‌ها را نگه می‌داریم
        printable = re.sub(r"[^ -~\n]", ".", ctx)
        print(f"--- @{m.start()} ---")
        print(f"  {printable[:600]}")

    print("\n=== همهٔ رشته‌های شامل /metadata (یکتا) ===")
    seen: set[str] = set()
    for m in re.finditer(r"[ -~]{4,110}", text):
        s = m.group(0)
        if "/metadata" in s and s not in seen:
            seen.add(s)
            print(f"  {s[:110]}")

    print("\n=== همهٔ رشته‌های شامل sealed: (یکتا، مرتب) ===")
    seen2: set[str] = set()
    items: list[str] = []
    for m in re.finditer(r"sealed: [ -~]{2,90}", text):
        s = m.group(0)
        # جدا کردن رشته از انتهای خطای Go (%w)
        core = s.split("%w")[0].strip()
        if core not in seen2:
            seen2.add(core)
            items.append(core)
    for s in sorted(items):
        print(f"  {s}")

    print("\n=== رشته‌های نسخه (unsupported version / invalid header) ===")
    seen3: set[str] = set()
    for m in re.finditer(r"[ -~]{6,120}", text):
        s = m.group(0)
        low = s.lower()
        if ("unsupported version" in low or "invalid compact envelope" in low) and s not in seen3:
            seen3.add(s)
            print(f"  {s[:120]}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
