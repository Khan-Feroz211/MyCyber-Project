from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from urllib.parse import quote


def generate_totp_secret(length: int = 20) -> str:
    """Generate a base32-encoded secret for TOTP apps (RFC 6238)."""
    raw = os.urandom(length)
    return base64.b32encode(raw).decode("ascii").replace("=", "")


def _counter(period: int = 30, for_time: int | None = None) -> int:
    ts = int(for_time if for_time is not None else time.time())
    return ts // period


def generate_totp_code(secret: str, period: int = 30, digits: int = 6) -> str:
    """Generate a current TOTP code for a base32 secret."""
    counter = _counter(period=period)
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8), casefold=True)
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (
        ((digest[offset] & 0x7F) << 24)
        | ((digest[offset + 1] & 0xFF) << 16)
        | ((digest[offset + 2] & 0xFF) << 8)
        | (digest[offset + 3] & 0xFF)
    )
    return str(code % (10**digits)).zfill(digits)


def verify_totp_code(
    secret: str,
    code: str,
    period: int = 30,
    digits: int = 6,
    window: int = 1,
) -> bool:
    """Verify a TOTP code with ±window tolerance for clock skew."""
    if not code or not code.isdigit() or len(code) != digits:
        return False

    now = int(time.time())
    for step in range(-window, window + 1):
        candidate = generate_totp_code(
            secret,
            period=period,
            digits=digits,
        ) if step == 0 else _generate_for_counter_offset(secret, step, period, digits, now)
        if hmac.compare_digest(candidate, code):
            return True
    return False


def _generate_for_counter_offset(
    secret: str,
    offset: int,
    period: int,
    digits: int,
    now: int,
) -> str:
    target = now + (offset * period)
    counter = _counter(period=period, for_time=target)
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8), casefold=True)
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    start = digest[-1] & 0x0F
    code = (
        ((digest[start] & 0x7F) << 24)
        | ((digest[start + 1] & 0xFF) << 16)
        | ((digest[start + 2] & 0xFF) << 8)
        | (digest[start + 3] & 0xFF)
    )
    return str(code % (10**digits)).zfill(digits)


def build_otpauth_uri(secret: str, account_name: str, issuer: str = "MyCyber") -> str:
    """Create a QR-compatible otpauth URI for authenticator apps."""
    label = quote(f"{issuer}:{account_name}")
    issuer_q = quote(issuer)
    return f"otpauth://totp/{label}?secret={secret}&issuer={issuer_q}&algorithm=SHA1&digits=6&period=30"
