#!/usr/bin/env python3
"""جست‌وجوی نشانه‌های رمزنگاری در یکی از بخش‌های بستهٔ .apkm.

بدون استخراج کل فایل روی دیسک، فقط همان یک ورودی را در حافظه می‌خواند.
برای libgojni.so که ۳۵ مگا است مناسب است.

    python tools/zip_scan.py <file.apkm> <member> [pattern ...]
"""

from __future__ import annotations

import re
import sys
import zipfile
from pathlib import Path

# نشانه‌هایی که رمزنگاری را لو می‌دهند
DEFAULT_PATTERNS = [
    b"npvtunnel",
    b"kfold",
    b"appkey",
    b"gen2",
    b"NpvGate",
    b"NPVS",
    b"NPVT1",
    b"passphrase",
    b"chacha",
    b"Chacha",
    b"ChaCha",
    b"poly1305",
    b"pbkdf2",
    b"sha256",
    b"AES",
    b"aes",
    b"rt.dat",
    b"whitebox",
    b"tybox",
    b"whirlpool",
]

# امضای S-box استاندارد AES
AES_SBOX_HEAD = bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5])
AES_INVSBOX_HEAD = bytes([0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38])


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2

    apkm = Path(sys.argv[1])
    member = sys.argv[2]
    patterns = [p.encode() if isinstance(p, str) else p for p in sys.argv[3:]]
    if not patterns:
        patterns = DEFAULT_PATTERNS

    if not zipfile.is_zipfile(apkm):
        print("بسته ZIP/APKM نیست")
        return 1

    with zipfile.ZipFile(apkm) as z:
        if member not in z.namelist():
            print(f"{member} در بسته نیست")
            return 1
        data = z.read(member)

    print(f"عضو: {member}   ({len(data)} بایت / {len(data)/1024/1024:.2f} MB)")

    print("\n--- نشانه‌های رمزنگاری ---")
    for p in patterns:
        hits = [m.start() for m in re.finditer(re.escape(p), data, re.IGNORECASE)]
        if hits:
            print(f"  [+] {p!r}  -> {len(hits)} مکان، نخستین: {hits[:6]}")

    print("\n--- امضای AES ---")
    print(f"  S-box     : {data.find(AES_SBOX_HEAD)}")
    print(f"  InvS-box  : {data.find(AES_INVSBOX_HEAD)}")

    print("\n--- رشته‌های قابل‌خواندن (≥8) که رمزنگاری را ممکن است لو دهد ---")
    seen = set()
    for m in re.finditer(rb"[\x20-\x7e]{8,}", data):
        s = m.group().decode("ascii")
        low = s.lower()
        if any(
            k in low
            for k in (
                "key",
                "crypt",
                "aes",
                "chacha",
                "nonce",
                "salt",
                "iv_",
                "kdf",
                "hash",
                "secure",
                "gate",
                "npv",
                "ct_",
            )
        ):
            if s not in seen:
                seen.add(s)
                print(f"  @{m.start():9d}  {s[:110]}")
    if not seen:
        print("  (هیچ)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
