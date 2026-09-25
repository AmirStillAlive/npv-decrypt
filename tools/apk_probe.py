#!/usr/bin/env python3
"""بازرسی بستهٔ .apkm از APKMirror بدون هیچ نصب یا اجرایی.

APKMirror فایل‌ها را به‌صورت .apkm می‌دهد که یک ZIP حاوی چند APK جزئی است.
این اسکریپت فقط می‌خواند و فهرست می‌کند.

    python tools/apk_probe.py <file.apkm|file.apk>
"""

from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2

    path = Path(sys.argv[1])
    print(f"فایل: {path.name}")
    print(f"حجم: {path.stat().st_size / 1024 / 1024:.2f} MB")

    if not zipfile.is_zipfile(path):
        print("این فایل ZIP/APK نیست!")
        return 1

    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        print(f"تعداد فایل در بسته: {len(infos)}\n")

        print("--- فهرست ---")
        total = 0
        for i in infos:
            total += i.file_size
            if i.filename.endswith("/"):
                continue
            print(f"  {i.file_size / 1024 / 1024:8.2f} MB  {i.filename}")
        print(f"  {'-' * 10}  مجموع فشرده‌نشده: {total / 1024 / 1024:.2f} MB")

        # اطلاعات نسخه اگر هست
        for name in ("info.json", "info.json.enc", "toc.pb"):
            if name in z.namelist():
                if name.endswith(".json"):
                    print(f"\n--- {name} ---")
                    try:
                        data = json.loads(z.read(name).decode("utf-8"))
                        print(json.dumps(data, indent=2, ensure_ascii=False))
                    except Exception as exc:
                        print(f"ناتوانی در خواندن: {exc}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
