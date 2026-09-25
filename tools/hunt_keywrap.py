#!/usr/bin/env python3
"""جست‌وجوی پاکت کلید appKey در فایل NPVS نسخهٔ ۵.

فرضیه: نسخهٔ ۵ شاید همان جدول‌های white-box نسخهٔ ۱ را داشته باشد و فقط چیدمان
عوض شده باشد. اگر درست باشد، جایی نزدیک ابتدای فایل یک جفت
«نمک ۱۶ بایتی + پاکت کلید ۶۰ بایتی» پیدا می‌شود که با کلید مشتق‌شده باز می‌شود.

روش: برای هر offset نمک، کلید را مشتق می‌کنیم و هر offset ممکن برای پاکت را
با ChaCha20-Poly1305 امتحان می‌کنیم. تگ درست یعنی کلید درست پیدا شده.

    python tools/hunt_keywrap.py sample.npvs [حداکثر offset]
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import npvs  # noqa: E402

SALT_LEN = npvs._SALT_SIZE
WRAP_LEN = npvs._WRAP_SIZE


def hunt(data: bytes, span: int) -> list[tuple[int, int, bytes]]:
    """جست‌وجوی (نمک، پاکت، کلید) که تگ معتبر می‌دهند."""
    found: list[tuple[int, int, bytes]] = []
    span = min(span, len(data) - WRAP_LEN)

    for so in range(0, min(span, len(data) - SALT_LEN)):
        salt = data[so : so + SALT_LEN]
        try:
            kdks = npvs.custodian_kdks(salt)
        except Exception:
            continue

        for kdk in kdks:
            for wo in range(0, span):
                wrap = data[wo : wo + WRAP_LEN]
                # AAD محتمل: خودِ نمک (مثل نسخهٔ ۱)، خالی، یا پیشوند چهار بایتی
                for aad_name, aad in (("salt", salt), ("empty", b""), ("magic", data[:4])):
                    if npvs._chacha20poly1305_open(kdk, wrap[:12], wrap[12:], aad) is not None:
                        found.append((so, wo, kdk))
                        print(
                            f"  HIT salt@{so} wrap@{wo} aad={aad_name} kdk={kdk.hex()[:16]}…",
                            flush=True,
                        )
    return found


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    data = Path(sys.argv[1]).read_bytes()
    span = int(sys.argv[2]) if len(sys.argv) > 2 else 256

    print(f"فایل: {len(data)} بایت، نسخه: {data[4]}")
    print(f"دامنهٔ جست‌وجو: {span} بایت اول")
    print("در حال امتحان…", flush=True)

    hits = hunt(data, span)

    print()
    if hits:
        print(f"{len(hits)} تطابق پیدا شد — احتمالا ساختار نسخهٔ ۵ همین است.")
    else:
        print("هیچ پاکت کلیدی با این جدول‌ها پیدا نشد.")
        print("یعنی نسخهٔ ۵ از جدول‌های white-box دیگری استفاده می‌کند")
        print("(یا ساختارش اصلا شبیه نسخهٔ ۱ نیست).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
