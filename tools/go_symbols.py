#!/usr/bin/env python3
"""استخراج نمادهای Go از کتابخانه native اپ NPV Tunnel.

باینری‌های Go اسم توابع و مسیر فایل‌های سورس را حذف نمی‌کنند، پس فقط با
خواندن string table می‌توان کل معماری و خط لولهٔ رمز را دید.

خروجی‌ها:
  - مسیر فایل‌های .go هر پکیج
  - توابع مربوط به npvs / gen2 / KDF / seal / mask
  - رشته‌های خطای رمزنگاری (الگوی «%w»)

    python tools/go_symbols.py path/to/libgojni.so
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# الگوهای مورد علاقه برای خط لولهٔ رمز
CRYPTO_PATTERNS = (
    "npvs",
    "gen2",
    "Kdk",
    "kdk",
    "KDF",
    "seal",
    "Seal",
    "mask",
    "Mask",
    "whitebox",
    "kfold",
    "appkey",
    "appKey",
    "AppKey",
    "chacha",
    "poly1305",
    "pbkdf2",
    "passwd",
    "password",
    "Password",
    "wrap",
    "Wrap",
    "unwrap",
    "Decrypt",
    "decrypt",
    "Encrypt",
    "encrypt",
    "NpvGate",
    "openSource",
    "kdf",
)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2

    data = Path(sys.argv[1]).read_bytes()
    text = data.decode("ascii", errors="ignore")
    print(f"فایل: {Path(sys.argv[1]).name}  ({len(data)} بایت)")

    # ۱. فایل‌های سورس Go در پکیج libnpvtunnel
    print("\n=== فایل‌های .go در libnpvtunnel ===")
    files: set[str] = set()
    for m in re.finditer(r"libnpvtunnel/([A-Za-z0-9_]+\.go)", text):
        files.add(m.group(1))
    for f in sorted(files):
        print(f"  {f}")

    # ۲. توابع crypto مربوط به npvtunnel
    print("\n=== توابع libnpvtunnel مرتبط با رمز ===")
    seen: set[str] = set()
    funcs: list[str] = []
    for m in re.finditer(r"libnpvtunnel[./][A-Za-z0-9_*.()$-]{1,80}", text):
        v = m.group(0).strip(".-()")
        if len(v) < 12 or v in seen:
            continue
        seen.add(v)
        if any(p in v for p in CRYPTO_PATTERNS):
            funcs.append(v)
    for f in sorted(funcs):
        print(f"  {f}")
    if not funcs:
        print("  (یافت نشد)")

    # ۳. رشته‌های خطای رمز (الگوی chacha / %w)
    print("\n=== رشته‌های خطا و قالب (chacha، seal، open) ===")
    seen2: set[str] = set()
    for m in re.finditer(r"[ -~]{8,120}", text):
        s = m.group(0)
        low = s.lower()
        if any(
            k in low
            for k in ("chacha", "sealed:", "seal", "kdf", "hkdf", "gen2_open", "app-key", "npv")
        ):
            if s not in seen2:
                seen2.add(s)
                print(f"  {s[:120]!r}")
                if len(seen2) > 60:
                    break

    # ۴. تمام نمادهای شامل NPVS (کوتاه‌شده)
    print("\n=== همهٔ نمادهای شامل npvs/NPVS (یک مرحله‌ای) ===")
    seen3: set[str] = set()
    count = 0
    for m in re.finditer(r"[A-Za-z0-9_./$()-]{4,120}", text):
        s = m.group(0)
        if ("npvs" in s.lower() or "NPVS" in s) and s not in seen3:
            seen3.add(s)
            if count < 80:
                print(f"  {s[:110]}")
                count += 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
