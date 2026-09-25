#!/usr/bin/env python3
"""بررسی کتابخانهٔ native اپ NPV Tunnel برای پیدا کردن جدول‌های white-box.

دنبال سه نشانه می‌گردد:
  ۱) پیشوند KDF نسخهٔ ۱: "npvtunnel/appkey/v1 "
  ۲) خودِ جدول‌های نسخهٔ ۱ (آیا عینا در v5 هم هستند؟)
  ۳) بلوک‌های باینری با اندازهٔ دقیق جدول‌ها (۴۰۹۶ / ۱۶۳۸۴ / ۲۴۵۷۶)

    python tools/so_probe.py path/to/libnpvtunnel.so
"""

from __future__ import annotations

import base64
import json
import re
import sys
from pathlib import Path

KDF_PREFIX = b"npvtunnel/appkey/v1 "
TABLE_SIZES = {4096: "tboxes_last", 16384: "tyboxes/mbl", 24576: "xor"}

REPO = Path(__file__).resolve().parent.parent


def load_v1_tables() -> dict[str, bytes]:
    doc = json.loads((REPO / "npvs_tables.json").read_text(encoding="utf-8"))
    return {
        k: base64.b64decode(v["data"]) for k, v in doc["tables"].items()
    }


def findall(hay: bytes, needle: bytes) -> list[int]:
    return [m.start() for m in re.finditer(re.escape(needle), hay)]


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2

    path = Path(sys.argv[1])
    data = path.read_bytes()
    print(f"فایل: {path.name}   ({len(data)} بایت / {len(data)/1024:.1f} KB)")

    # ۱. پیشوند KDF
    print("\n--- ۱) پیشوند KDF نسخهٔ ۱ ---")
    for s in (
        b"npvtunnel/appkey/v1",
        b"npvtunnel/appkey",
        b"wbaes-ctr-sha256",
        b"pbkdf2-hmac-sha256",
        b"NPVS",
        b"NPVT1",
        b"appkey",
        b"passphrase",
        b"ChaCha20",
        b"chacha20",
        b"poly1305",
        b"PBKDF2",
    ):
        hits = findall(data, s)
        if hits:
            print(f"  [+] {s!r} در {len(hits)} مکان: {hits[:6]}")
            for h in hits[:3]:
                ctx = data[max(0, h - 40) : h + len(s) + 60]
                printable = re.sub(rb"[^\x20-\x7e]", b".", ctx)
                print(f"      …{printable.decode('ascii', 'replace')}…")

    # ۲. آیا جدول‌های نسخهٔ ۱ عینا در این فایل هستند؟
    print("\n--- ۲) تطبیق با جدول‌های نسخهٔ ۱ ---")
    tables = load_v1_tables()
    for name, blob in tables.items():
        hits = findall(data, blob)
        print(f"  {name:20s} {len(blob):6d} بایت -> {'یافت شد!' if hits else 'متفاوت'}")

    # ۳. بلوک‌هایی با اندازهٔ دقیق جدول‌ها
    print("\n--- ۳) بلوک‌هایی با اندازهٔ دقیق جدول‌ها ---")
    # این تطبیق با حالت کامل جدول‌هاست؛ چون .so فشرده نیست باید پیدا شود
    for size, label in TABLE_SIZES.items():
        # هر جایی که چند بایت متوالی یک جدول منبع را دارد بررسی می‌کنیم
        blob = tables.get("tboxes_last" if size == 4096 else "tyboxes")
        if blob is None:
            continue
        head = blob[:64]
        hits = findall(data, head)
        print(f"  {label:16s} ({size} بایت) ابتدای نسخهٔ ۱ -> {hits[:4] or 'متفاوت'}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
