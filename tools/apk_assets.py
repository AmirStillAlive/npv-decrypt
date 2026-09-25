#!/usr/bin/env python3
"""فهرست محتوای یک APK، با تمرکز بر assets/ و کتابخانه‌های native.

دنبال فایل‌هایی با اندازهٔ مختص جدول‌های white-box می‌گردد
(4KB / 16KB / 24KB که نسخهٔ ۱ این چنین بود).

    python tools/apk_assets.py path/to/base.apk
"""

from __future__ import annotations

import sys
import zipfile
from collections import Counter
from pathlib import Path

# اندازه‌های محتمل جدول‌های white-box (بایت) — نسخهٔ ۱ Pantegnos
SIGNATURE_SIZES = {4096: "tboxes", 16384: "tyboxes/mbl", 24576: "xor"}


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2

    path = Path(sys.argv[1])
    if not zipfile.is_zipfile(path):
        print("این فایل APK/ZIP نیست")
        return 1

    with zipfile.ZipFile(path) as z:
        infos = [i for i in z.infolist() if not i.filename.endswith("/")]
        print(f"فایل: {path.name}   ({path.stat().st_size / 1024 / 1024:.2f} MB)")
        print(f"تعداد فایل: {len(infos)}")

        # پیشوندهای رایج
        tops = Counter(i.filename.split("/")[0] for i in infos)
        print("\n--- پیشوند مسیرها ---")
        for k, v in tops.most_common(15):
            print(f"  {k:25s} {v:5d} فایل")

        print("\n--- assets/ ---")
        assets = [i for i in infos if i.filename.startswith("assets/")]
        if not assets:
            print("  (خالی یا وجود ندارد)")
        for i in sorted(assets, key=lambda x: x.filename)[:60]:
            print(f"  {i.file_size / 1024:9.1f} KB   {i.filename}")

        print("\n--- جست‌وجوی اندازه‌های مختص جدول‌های white-box ---")
        hits = 0
        for i in infos:
            if i.file_size in SIGNATURE_SIZES:
                hits += 1
                print(f"  {i.file_size:8d} بایت  ({SIGNATURE_SIZES[i.file_size]})   {i.filename}")
        if not hits:
            print("  هیچ فایلی با اندازهٔ جدول‌های نسخهٔ ۱ پیدا نشد")

        print("\n--- کتابخانه‌های native (.so) ---")
        for i in infos:
            if i.filename.endswith(".so"):
                print(f"  {i.file_size / 1024 / 1024:8.2f} MB   {i.filename}")

        print("\n--- فایل‌های مشکوک (json/xml/txt در assets و ریشه) ---")
        for i in infos:
            if i.filename.startswith("assets/") and i.filename.endswith(
                (".json", ".txt", ".bin", ".dat", ".enc", ".cfg")
            ):
                print(f"  {i.file_size / 1024:9.1f} KB   {i.filename}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
