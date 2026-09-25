#!/usr/bin/env python3
"""کاوش assets/rt.dat از اپ NPV Tunnel.

این فایل را libnpvtunnel.so با یک تابع zlib باز می‌کند ولی هِدِر فشرده‌سازی
معمولی ندارد. سه احتمال می‌آزماییم: raw deflate، zlib با header خاموش، یا رمز.

    python tools/rt_probe.py path/to/rt.dat
"""

from __future__ import annotations

import math
import re
import sys
import zlib
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
import base64  # noqa: E402
import json  # noqa: E402

MARKERS = [
    b"npvtunnel",
    b"kfold",
    b"mix/v1",
    b"salt/v1",
    b"NPVS",
    b"NPVT1",
    b"appkey",
    b"tybox",
    b"whitebox",
    b"AES",
    b"chacha",
    b"poly1305",
    b"pbkdf2",
    b"sha256",
]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def try_decompress(data: bytes) -> list[str]:
    out = []
    for wb in (15, -15, 31, 47, 15 + 32):
        try:
            d = zlib.decompressobj(wb)
            r = d.decompress(data)
            if len(r) > 64:
                out.append(f"windowBits={wb} -> {len(r)} بایت")
                break
        except Exception:
            pass
    # هر جایی که هِدِر zlib پیدا می‌شود
    for m in re.finditer(rb"[\x78][\x01\x5e\x9c\xda]", data[:2048]):
        try:
            r = zlib.decompress(data[m.start() :])
            out.append(f"zlib header @{m.start()} -> {len(r)} بایت")
        except Exception:
            pass
    return out


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2

    path = Path(sys.argv[1])
    data = path.read_bytes()
    print(f"فایل: {path.name}  ({len(data)} بایت / {len(data)/1024:.1f} KB)")
    print(f"ابتدای هگز: {data[:32].hex()}")
    print(f"entropy: {entropy(data):.4f} bits/byte")

    print("\n--- فشرده‌سازی ---")
    dec = try_decompress(data)
    print("  " + ("\n  ".join(dec) if dec else "هیچ روش استانداردی جواب نداد"))

    print("\n--- جست‌وجوی نشانه‌ها ---")
    for m in MARKERS:
        hits = [x.start() for x in re.finditer(re.escape(m), data, re.IGNORECASE)]
        if hits:
            print(f"  [+] {m!r} -> {hits[:8]}")

    print("\n--- رشته‌های قابل‌خواندن (≥6) ---")
    strs = [m.group() for m in re.finditer(rb"[\x20-\x7e]{6,}", data)]
    print(f"  تعداد: {len(strs)}")
    for s in strs[:40]:
        print(f"    {s[:100]!r}")

    print("\n--- تطبیق با جدول‌های نسخهٔ ۱ ---")
    doc = json.loads((REPO / "npvs_tables.json").read_text(encoding="utf-8"))
    for name, info in doc["tables"].items():
        blob = base64.b64decode(info["data"])
        idx = data.find(blob[:64])
        print(f"  {name:20s} ابتدایش -> {'یافت شد' if idx >= 0 else 'متفاوت'}")

    print("\n--- آنتروپی بلوکی (۲۵۶ بایتی) ---")
    for i in range(0, min(len(data), 4096), 256):
        print(f"  @{i:6d}  {entropy(data[i:i+256]):.3f}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
