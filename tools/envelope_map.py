#!/usr/bin/env python3
"""استخراج هدفمند نمادهای خط لولهٔ رمزگشایی NPVS از باینری Go.

هدف: بازسازی چیدمان پاکت نسخهٔ ۵، KDF نسخهٔ ۵، و رشته‌های خطای تجزیه که
ساختار را لو می‌دهند — همه فقط از روی خواندن بایت‌ها.

    python tools/envelope_map.py path/to/libgojni.so
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

GROUPS = {
    "CompactEnvelope (ساختار پاکت v5)": (r"[A-Za-z0-9_.()$-]{4,130}", ("CompactEnvelope",)),
    "توابع gen2 و appKey": (r"libnpvtunnel[./][A-Za-z0-9_*.()$-]{1,70}", ("gen2", "Gen2", "appKey", "AppKey", "Appkey")),
    "برچسب‌های نسخهٔ NPVS": (r"[ -~]{6,140}", ("NPVS-v", "NPVS", "npvs1", "NPSTNPT", "NPST")),
    "ماسک و seal": (r"libnpvtunnel[./][A-Za-z0-9_*.()$-]{1,70}", ("mask", "Mask", "seal", "Seal", "Sealed")),
    "رشته‌های خطای تجزیه": (
        r"[ -~]{8,150}",
        ("invalid", "truncated", "too short", "bad magic", "unsupported version", "parse", "length"),
    ),
    "رشته‌های chacha/password/wrap": (
        r"[ -~]{8,140}",
        ("chacha", "poly1305", "wrap", "Wrap", "kdf", "KDF", "hkdf", "pbkdf2", "salt", "nonce"),
    ),
}


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2

    text = Path(sys.argv[1]).read_bytes().decode("ascii", errors="ignore")

    for title, (pat, keys) in GROUPS.items():
        print(f"\n=== {title} ===")
        seen: set[str] = set()
        count = 0
        for m in re.finditer(pat, text):
            s = m.group(0)
            if any(k in s for k in keys) and s not in seen:
                seen.add(s)
                if count < 60:
                    print(f"  {s[:130]}")
                count += 1
        print(f"  --- یکتا: {len(seen)} ---")

    return 0


if __name__ == "__main__":
    sys.exit(main())
