#!/usr/bin/env python3
"""ساخت نمونه‌های .npvs برای تست پاریتی پایتون و جاوااسکریپت.

خروجی:  web/test/fixtures/sample-appkey.npvs
         web/test/fixtures/sample-passphrase.npvs
         web/test/fixtures/manifest.json   (هش SHA-256 متن باز شده)

هر دو پیاده‌سازی باید برای هر فایل هش یکسان بدهند. رمز نمونهٔ passphrase
هم داخل manifest نوشته می‌شود تا تست جاوااسکریپت هم بتواند بازش کند.

    python tools/make_npvs_fixtures.py
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

# ماژول npvs یک پوشه بالاتر از tools/ است
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import npvs  # noqa: E402

OUT_DIR = Path(__file__).resolve().parent.parent / "web" / "test" / "fixtures"

PASSPHRASE = "sirvdaram"

APPKEY_BODY = json.dumps(
    {
        "name": "EU-Cloudflare-1",
        "v2rayProfile": {
            "server": "example.com",
            "serverPort": 443,
            "password": "11111111-2222-3333-4444-555555555555",
            "network": "ws",
            "path": "/ray",
            "security": "tls",
            "sni": "example.com",
        },
    },
    ensure_ascii=False,
    indent=2,
)

PASS_BODY = (
    "سرور آلمان\n"
    'vless://11111111-2222-3333-4444-555555555555@de.example.com:443'
    "?security=tls&type=ws&path=%2Fray#DE-1\n"
)


def b64u(raw: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def build(dek: bytes, body: str, *, app_key: bool) -> bytes:
    salt = bytes(range(16))
    wrap_nonce = bytes(range(12, 24))
    body_nonce = bytes(range(100, 112))

    if app_key:
        wrap_key = npvs.custodian_kdks(salt)[0]
        wrap_obj = {
            "kdf": npvs._KDF_APPKEY,
            "keyId": 1,
            "salt": b64u(salt),
            # wrap = nonce(۱۲) + ct(۳۲) + tag(۱۶)
            "wrap": b64u(wrap_nonce + npvs._chacha20poly1305_seal(wrap_key, wrap_nonce, dek, salt)),
        }
    else:
        iters = 2000
        wrap_key = hashlib.pbkdf2_hmac("sha256", PASSPHRASE.encode(), salt, iters, 32)
        wrap_obj = {
            "iters": iters,
            "kdf": npvs._KDF_PASS,
            "salt": b64u(salt),
            "wrap": b64u(wrap_nonce + npvs._chacha20poly1305_seal(wrap_key, wrap_nonce, dek, salt)),
        }

    header = {
        "v": 1,
        "configId": "cfg-fixture-0001",
        "issuedAt": "2026-01-01T00:00:00Z",
        "creator": {"fp": "c0ffee", "pk": "deadbeef"},
        "policy": {
            "displayMessage": "نمونهٔ آزمون",
            "configVersion": 5,
            "expiresAt": None,
        },
    }
    header["appKey" if app_key else "passphrase"] = wrap_obj

    header_raw = json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    body_part = npvs._chacha20poly1305_seal(dek, body_nonce, body.encode("utf-8"), header_raw)
    sig_part = bytes((i * 7 + 11) % 256 for i in range(64))

    return (
        b"NPVS"
        + bytes([1])
        + len(header_raw).to_bytes(4, "big")
        + header_raw
        + body_nonce
        + len(body_part).to_bytes(4, "big")
        + body_part
        + sig_part
    )


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    manifest = {"passphrase": PASSPHRASE, "files": {}}

    cases = [
        ("sample-appkey.npvs", bytes(range(32)), APPKEY_BODY, True, ""),
        ("sample-passphrase.npvs", bytes(range(32, 64)), PASS_BODY, False, PASSPHRASE),
    ]

    for name, dek, body, app_key, password in cases:
        blob = build(dek, body, app_key=app_key)
        (OUT_DIR / name).write_bytes(blob)

        # هش متن باز شده؛ هر دو پیاده‌سازی باید همین را بدهند
        res = npvs.decrypt_npvs(blob, password)
        digest = hashlib.sha256(res["plaintext"].encode("utf-8")).hexdigest()

        manifest["files"][name] = {
            "sha256": digest,
            "needsPassword": not app_key,
            "configId": res["meta"]["configId"],
        }
        print(f"{name}: {len(blob)} bytes, plaintext sha256 {digest}")

    (OUT_DIR / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"wrote {OUT_DIR / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
