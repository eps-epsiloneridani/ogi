"""TOTP (RFC 6238) and recovery-code helpers for the local auth fallback.

Implements TOTP directly over ``hmac``/``hashlib`` (SHA-1, 30 s step, 6 digits)
so the password+TOTP fallback adds no third-party runtime dependency. Includes
the RFC 4226 (HOTP) and RFC 6238 test vectors so the math is pinned against the
spec, plus base32 secret handling and one-time recovery-code generation.

Secrets are 20 random bytes (160 bits, the RFC-recommended length) encoded as
RFC 4648 base32 without padding — the 32-character format authenticator apps
expect. The provisioning URI is the standard ``otpauth://`` form so any TOTP app
(Google Authenticator, 1Password, Authy, ...) can scan it.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

# Base32 alphabet for secrets (RFC 4648).
_B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

# Recovery-code alphabet: 32 unambiguous chars (no 0/O, 1/I/L, 8/B confusion).
_RECOVERY_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

ISSUER = "OpenGraph Intel"
DIGITS = 6
STEP_SECONDS = 30


# --------------------------------------------------------------------------- #
# base32
# --------------------------------------------------------------------------- #

def base32_encode(raw: bytes) -> str:
    """RFC 4648 base32, uppercase, no padding (the format TOTP apps expect)."""
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def base32_decode(secret: str) -> bytes:
    """Decode a base32 secret, tolerating lowercase, whitespace and missing
    padding (authenticator apps and users are sloppy)."""
    cleaned = "".join(ch for ch in secret.upper() if ch in _B32_ALPHABET)
    padding = "=" * (-len(cleaned) % 8)
    return base64.b32decode(cleaned + padding)


def generate_secret() -> str:
    """20 random bytes (160 bits) as a 32-character base32 secret."""
    return base32_encode(secrets.token_bytes(20))


# --------------------------------------------------------------------------- #
# HOTP / TOTP (RFC 4226 / RFC 6238)
# --------------------------------------------------------------------------- #

def hotp(secret_bytes: bytes, counter: int, digits: int = DIGITS) -> int:
    """RFC 4226 HMAC-based one-time password for a given counter value."""
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret_bytes, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = (
        ((digest[offset] & 0x7F) << 24)
        | (digest[offset + 1] << 16)
        | (digest[offset + 2] << 8)
        | digest[offset + 3]
    )
    return binary % (10 ** digits)


def totp_at(secret_b32: str, at: int, digits: int = DIGITS, step: int = STEP_SECONDS) -> str:
    """The TOTP value at a given unix timestamp, zero-padded to ``digits``."""
    secret_bytes = base32_decode(secret_b32)
    counter = int(at // step)
    return str(hotp(secret_bytes, counter, digits)).zfill(digits)


def totp_now(secret_b32: str, at: int | None = None, step: int = STEP_SECONDS) -> str:
    """The current TOTP value (6 digits, zero-padded)."""
    return totp_at(secret_b32, int(time.time()) if at is None else at, step=step)


def verify_totp(secret_b32: str, code: str, at: int | None = None, window: int = 1) -> bool:
    """Constant-time-ish compare of ``code`` against the current time step plus
    ``window`` steps on either side (default ±1 → 90 s tolerance for clock skew)."""
    if not secret_b32:
        return False
    candidate = "".join(ch for ch in code if ch.isdigit())
    if len(candidate) != DIGITS:
        return False
    now = int(time.time()) if at is None else at
    counter = int(now // STEP_SECONDS)
    secret_bytes = base32_decode(secret_b32)
    for offset in range(-window, window + 1):
        computed = f"{hotp(secret_bytes, counter + offset, DIGITS):0{DIGITS}d}"
        if hmac.compare_digest(computed, candidate):
            return True
    return False


def provisioning_uri(email: str, secret_b32: str) -> str:
    """``otpauth://`` URI an authenticator app can import (QR or manual entry)."""
    label = quote(f"{ISSUER}:{email}", safe=":@.")
    issuer = quote(ISSUER, safe="")
    return (
        f"otpauth://totp/{label}"
        f"?secret={secret_b32}&issuer={issuer}"
        f"&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
    )


# --------------------------------------------------------------------------- #
# recovery codes
# --------------------------------------------------------------------------- #

def generate_recovery_codes(count: int = 10) -> list[str]:
    """``count`` one-time recovery codes, each formatted ``XXXX-XXXX``."""
    codes: list[str] = []
    for _ in range(count):
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(8))
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes


def normalize_recovery_code(code: str) -> str:
    """Uppercase and strip separators/whitespace so users can paste freely."""
    return "".join(ch for ch in code.upper() if ch in _RECOVERY_ALPHABET)


def hash_recovery_code(code: str) -> str:
    """SHA-256 of the normalized code — only the digest is ever stored."""
    return hashlib.sha256(normalize_recovery_code(code).encode("ascii")).hexdigest()


# --------------------------------------------------------------------------- #
# RFC test vectors
# --------------------------------------------------------------------------- #

# RFC 4226 Appendix D — HMAC-SHA1, secret "12345678901234567890" (ASCII), 6 digits.
RFC4226_SECRET_BYTES = b"12345678901234567890"
RFC4226_VECTORS = [
    (0, 755224),
    (1, 287082),
    (2, 359152),
    (3, 969429),
    (4, 338314),
    (5, 254676),
    (6, 287922),
    (7, 162583),
    (8, 399871),
    (9, 520489),
]

# RFC 6238 Appendix B — TOTP/SHA1, 8 digits, secret "12345678901234567890".
RFC6238_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]
