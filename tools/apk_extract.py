#!/usr/bin/env python3
"""استخراج گزینشی از یک بستهٔ .apkm یا .apk، بدون هیچ نصب یا اجرایی.

بیرون از ریپو کار می‌کند چون شامل دادهٔ ثالث می‌شود.

    python tools/apk_extract.py <file.apkm|file.apk> <پوشهٔ خروجی> [فایل‌های دلخواه]
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

# فایل‌هایی که برای آزمایش می‌خواهیم؛ اگر فهرست داده نشود همه استخراج می‌شود
WANTED = ("base.apk", "info.json", "META-INF/APKMIRRO.RSA")


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2

    src = Path(sys.argv[1])
    out = Path(sys.argv[2])
    wanted = list(sys.argv[3:]) if len(sys.argv) > 3 else list(WANTED)

    if not zipfile.is_zipfile(src):
        print("فایل ZIP نیست")
        return 1

    out.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(src) as z:
        names = z.namelist()
        total = 0
        for name in wanted:
            if name not in names:
                print(f"[skip] {name} در بسته نیست")
                continue
            target = out / Path(name).name
            target.write_bytes(z.read(name))
            total += target.stat().st_size
            print(f"[ok]   {Path(name).name}  {target.stat().st_size / 1024 / 1024:.2f} MB")

    print(f"مجموع استخراج‌شده: {total / 1024 / 1024:.2f} MB -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
