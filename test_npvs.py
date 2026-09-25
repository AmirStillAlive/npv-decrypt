#!/usr/bin/env python3
"""آزمون‌های رمزگشایی NPVS.

بردارهای آزمون از خود مخزن Pantegnos گرفته شده‌اند (internal/modules/impl/npvs_test.go)
تا مطمئن شویم پورت پایتون دقیقا همان نتیجهٔ پیاده‌سازی Go را می‌دهد.

    python test_npvs.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys

import npvs

FAILED = 0


def check(name: str, got: object, want: object) -> None:
    global FAILED
    if got == want:
        print(f"  ok   {name}")
    else:
        FAILED += 1
        print(f"  FAIL {name}\n       got:  {got}\n       want: {want}")


# --- ۱. بردار KDF از آزمون Go -----------------------------------------------

GO_SALT = bytes(
    [0x84, 0x3C, 0xC2, 0xC9, 0x01, 0xCE, 0x91, 0x51,
     0x6C, 0x38, 0xCC, 0x66, 0x05, 0xB9, 0x2E, 0x47]
)
GO_KDKS = [
    "a9c9058dca50d178b64e0318ad5362be8f8d4103dc83ce2bd0ccd7e404584e3d",
    "438a04b521a5952156441a76bee5d8377a67257ff7e8291b220023614d7933d5",
]


def test_custodian_kdks() -> None:
    print("custodian KDK (بردار آزمون Go)")
    got = [k.hex() for k in npvs.custodian_kdks(GO_SALT)]
    check("دو کلید ساخته شد", len(got), 2)
    for i, want in enumerate(GO_KDKS):
        check(f"kdk[{i}]", got[i], want)


# --- ۲. ChaCha20-Poly1305 در برابر بردارهای RFC 8439 -------------------------

RFC_KEY = bytes(range(32))
RFC_NONCE = bytes.fromhex("000000000000004a00000000")
RFC_AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
RFC_PT = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you "
    b"only one tip for the future, sunscreen would be it."
)
# بردار مرجع از پیاده‌سازی مستقل Node گرفته شده است:
#   node web/test/chacha-vector.mjs
RFC_CT = bytes.fromhex(
    "6e2e359a2568f98041ba0728dd0d6981"
    "e97e7aec1d4360c20a27afccfd9fae0"
    "bf91b65c5524733ab8f593dabcd62b35"
    "71639d624e65152ab8f530c359f0861d"
    "807ca0dbf500d6a6156a38e088a22b65"
    "e52bc514d16ccf806818ce91ab779373"
    "65af90bbf74a35be6b40b8eedf2785e"
    "42874d"
)
RFC_TAG = bytes.fromhex("3179267b0ba71e40a2ad866fce5f8052")


def test_chacha_rfc8439() -> None:
    print("ChaCha20-Poly1305 (بردار مرجع از Node)")
    sealed = npvs._chacha20poly1305_seal(RFC_KEY, RFC_NONCE, RFC_PT, RFC_AAD)
    check("متن رمزشده", sealed[: len(RFC_PT)].hex(), RFC_CT.hex())
    check("تگ", sealed[len(RFC_PT) :].hex(), RFC_TAG.hex())
    check(
        "رمزگشایی برمی‌گردد",
        npvs._chacha20poly1305_open(RFC_KEY, RFC_NONCE, sealed, RFC_AAD),
        RFC_PT,
    )
    check(
        "تگ خراب رد می‌شود",
        npvs._chacha20poly1305_open(
            RFC_KEY, RFC_NONCE, sealed[:-1] + bytes([sealed[-1] ^ 1]), RFC_AAD
        ),
        None,
    )


# --- ۳. ساخت پاکت NPVS و آزمودن مسیر کامل ------------------------------------


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def build_envelope(*, dek: bytes, body: bytes, app_key: bool, password: str = "") -> bytes:
    """پاکت NPVS می‌سازد تا مسیر رمزگشایی از سر تا ته آزموده شود."""
    salt = bytes(range(16))
    wrap_nonce = bytes(range(12, 24))

    if app_key:
        # کلید پیچ‌شده باید با یکی از کلیدهای مشتق‌شده باز شود
        wrap_key = npvs.custodian_kdks(salt)[0]
        wrap_obj: dict = {
            "kdf": npvs._KDF_APPKEY,
            "keyId": 1,
            "salt": _b64u(salt),
            "wrap": _b64u(
                wrap_nonce
                + npvs._chacha20poly1305_seal(wrap_key, wrap_nonce, dek, salt)
            ),
        }
    else:
        iters = 2000
        wrap_key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters, 32)
        wrap_obj = {
            "iters": iters,
            "kdf": npvs._KDF_PASS,
            "salt": _b64u(salt),
            "wrap": _b64u(
                wrap_nonce
                + npvs._chacha20poly1305_seal(wrap_key, wrap_nonce, dek, salt)
            ),
        }

    header: dict = {
        "v": 1,
        "configId": "cfg-test-1234",
        "issuedAt": "2026-01-01T00:00:00Z",
        "creator": {"fp": "c0ffee", "pk": "deadbeef"},
        "policy": {"displayMessage": "کانفیگ تست", "configVersion": 5},
    }
    header["appKey" if app_key else "passphrase"] = wrap_obj

    header_raw = json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    body_nonce = bytes(range(100, 112))
    # body خودش شامل متن رمزشده به‌علاوهٔ تگ ۱۶ بایتی ChaCha است
    body_part = npvs._chacha20poly1305_seal(dek, body_nonce, body, header_raw)
    # sig یک امضای جداگانهٔ ۶۴ بایتی است که رمزگشایی به آن نیازی ندارد
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


def test_appkey_envelope() -> None:
    print("پاکت NPVS با appKey (بدون رمز عبور)")
    payload = json.dumps(
        {"name": "EU-1", "v2rayProfile": {"server": "example.com", "serverPort": 443}},
        ensure_ascii=False,
    ).encode("utf-8")
    env = build_envelope(dek=bytes(range(32)), body=payload, app_key=True)
    res = npvs.decrypt_npvs(env)

    check("متن درست باز شد", json.loads(res["plaintext"])["name"], "EU-1")
    check("configId", res["meta"]["configId"], "cfg-test-1234")
    check("پیام سازنده", res["meta"]["creatorMessage"], "کانفیگ تست")
    check("JSON ساختاریافته", res["json"]["v2rayProfile"]["server"], "example.com")
    check("یادداشت appKey", res["notes"][0].startswith("کلید از appKey"), True)


def test_passphrase_envelope() -> None:
    print("پاکت NPVS با رمز عبور")
    env = build_envelope(
        dek=bytes(range(32, 64)),
        body=b'{"name":"with-password"}',
        app_key=False,
        password="sirvdaram",
    )

    res = npvs.decrypt_npvs(env, "sirvdaram")
    check("متن درست باز شد", json.loads(res["plaintext"])["name"], "with-password")

    try:
        npvs.decrypt_npvs(env, "eshtebah")
        check("رمز غلط رد شد", "no error", "NpvsError")
    except npvs.NpvsError:
        check("رمز غلط رد شد", True, True)

    try:
        npvs.decrypt_npvs(env)
        check("بدون رمز راهنمایی می‌دهد", "no error", "NeedsPassphrase")
    except npvs.NeedsPassphrase as exc:
        check("بدون رمز راهنمایی می‌دهد", exc.creator_message, "کانفیگ تست")


def test_sentinels() -> None:
    print("نشانه‌های npvs1:")
    token = base64.b64encode(b"vless://uuid@host:443").decode().rstrip("=")
    check(
        "رشته مبهم باز شد",
        npvs._decode_sentinels(f"پیش npvs1:{token} پس"),
        "پیش vless://uuid@host:443 پس",
    )
    check(
        "توکن خالی دست‌نخورده ماند", npvs._decode_sentinels("npvs1:!!!"), "npvs1:!!!"
    )
    # توکنی که نه base64 استاندارد می‌شود نه utf-8 معتبر
    check(
        "توکن نامعتبر دست‌نخورده ماند", npvs._decode_sentinels("npvs1:@@@@"), "npvs1:@@@@"
    )


def test_bad_input() -> None:
    print("ورودی‌های خراب")
    for name, blob, frag in [
        ("خیلی کوتاه", b"NPVS\x01", "کوتاه"),
        ("امضای اشتباه", b"XXXX" + b"\x00" * 100, "امضای NPVS"),
    ]:
        try:
            npvs.decrypt_npvs(blob)
            check(name, "no error", "NpvsError")
        except npvs.NpvsError as exc:
            check(name, frag in str(exc), True)


def main() -> int:
    for fn in (
        test_custodian_kdks,
        test_chacha_rfc8439,
        test_appkey_envelope,
        test_passphrase_envelope,
        test_sentinels,
        test_bad_input,
    ):
        fn()
    print()
    if FAILED:
        print(f"{FAILED} آزمون شکست خورد")
        return 1
    print("همهٔ آزمون‌ها سبز است")
    return 0


if __name__ == "__main__":
    sys.exit(main())

