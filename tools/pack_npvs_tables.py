#!/usr/bin/env python3
"""بسته‌بندی جدول‌های white-box فرمت NPVS در یک فایل JSON.

جدول‌های خام از مخزن Pantegnos (پروانه MIT) گرفته می‌شوند:

    internal/modules/impl/assets/npvs/{tyboxes,mbl,xor,tboxes_last,tboxes_last_v2}.bin

خروجی این اسکریپت (npvs_tables.json) هم پایتون و هم وب‌اپ از آن استفاده می‌کنند.
داده‌ها به صورت base64 نگه داشته می‌شوند تا JSON خوانا و قابل diff بماند.

    python tools/pack_npvs_tables.py npvs-tmp/ npvs_tables.json
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

# نام فایل خام -> کلید در JSON
FILES = {
    "tyboxes": "tyboxes.bin",
    "mbl": "mbl.bin",
    "xor": "xor.bin",
    "tboxes_last": "tboxes_last.bin",
    "tboxes_last_v2": "tboxes_last_v2.bin",
}

# طول هر جدول بر حسب بایت؛ برای اطمینان از اینکه فایل درست دانلود شده
SIZES = {
    "tyboxes": 16384,
    "mbl": 16384,
    "xor": 24576,
    "tboxes_last": 4096,
    "tboxes_last_v2": 4096,
}

PROVENANCE = (
    "White-box tables for the NPVS appKey KDF, extracted from "
    "https://github.com/FrontierTM/Pantegnos (MIT license), "
    "internal/modules/impl/assets/npvs/."
)


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2

    src = Path(sys.argv[1])
    out = Path(sys.argv[2])

    tables: dict[str, dict[str, object]] = {}
    for key, filename in FILES.items():
        raw = (src / filename).read_bytes()
        if len(raw) != SIZES[key]:
            print(
                f"error: {filename} should be {SIZES[key]} bytes, got {len(raw)}",
                file=sys.stderr,
            )
            return 1
        tables[key] = {
            "bytes": len(raw),
            "encoding": "base64",
            "data": base64.b64encode(raw).decode("ascii"),
        }

    out.write_text(
        json.dumps(
            {"format": "npvs-whitebox-v1", "source": PROVENANCE, "tables": tables},
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {out} ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
