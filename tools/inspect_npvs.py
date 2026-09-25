#!/usr/bin/env python3
"""بازرسی ساختار یک فایل .npvs بدون رمزگشایی محتوا.

هدر و متادیتا را نشان می‌دهد تا بفهمیم فایل با appKey ساخته شده یا با رمز.
اگر نسخه پشتیبانی‌نشده باشد، ابتدای فایل را هگز دامپ می‌کند.

    python tools/inspect_npvs.py sample.npvs
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import npvs  # noqa: E402

PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")


def hexdump(data: bytes, length: int = 256) -> None:
    """ابتدای فایل را هگز و متن قابل‌خواندن نشان می‌دهد."""
    for off in range(0, min(length, len(data)), 16):
        chunk = data[off : off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{off:08x}  {hexpart}  |{text}|")

    print("\nرشته‌های قابل‌خواندن:")
    for m in PRINTABLE.finditer(data):
        print(f"  @{m.start():6d}  {m.group()[:120]!r}")


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2

    path = Path(sys.argv[1])
    data = path.read_bytes()

    print(f"فایل: {path.name}")
    print(f"حجم: {len(data)} بایت")
    print(f"امضا: {data[:4]!r}  نسخه: {data[4]}")

    try:
        env = npvs.parse_envelope(data)
    except npvs.NpvsError as exc:
        print(f"\nساختار نسخهٔ {data[4]} هنوز پیاده نشده: {exc}")
        print("\n--- هگز دامپ ابتدای فایل ---")
        hexdump(data, 320)
        return 1

    hdr = env["header"]
    print(f"طول سرآیند: {len(env['header_raw'])} بایت")
    print(f"nonce: {env['nonce'].hex()}")
    print(f"طول بدنه: {len(env['body'])} بایت")
    print(f"امضا: {len(env['sig'])} بایت")

    print("\n--- سرآیند ---")
    print(json.dumps(hdr, indent=2, ensure_ascii=False))

    print("\n--- مسیر باز کردن ---")
    if hdr.get("appKey"):
        print("appKey -> بدون رمز باز می‌شود")
    elif hdr.get("passphrase"):
        print("passphrase -> به رمز سازنده نیاز دارد")
    elif hdr.get("recipients"):
        print("recipients -> به کلید خصوصی گیرنده نیاز دارد")
    else:
        print("نامعلوم")

    print("\n--- پیام سازنده ---")
    print(npvs._creator_message(hdr) or "(ندارد)")

    return 0


if __name__ == "__main__":
    sys.exit(main())

