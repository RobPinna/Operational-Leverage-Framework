import base64
import hashlib
import hmac
import os
from typing import Optional

from app.config import get_settings


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    settings = get_settings()
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        (password + settings.password_pepper).encode("utf-8"),
        salt,
        150_000,
    )
    return f"{base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_b64, digest_b64 = stored.split("$", 1)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
    except Exception:
        return False

    settings = get_settings()
    candidate = hashlib.pbkdf2_hmac(
        "sha256",
        (password + settings.password_pepper).encode("utf-8"),
        salt,
        150_000,
    )
    return hmac.compare_digest(candidate, expected)


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])


def obfuscate_secret(value: str) -> str:
    if not value:
        return ""
    settings = get_settings()
    key = hashlib.sha256(settings.api_key_pepper.encode("utf-8")).digest()
    xored = _xor_bytes(value.encode("utf-8"), key)
    return base64.urlsafe_b64encode(xored).decode("utf-8")


def deobfuscate_secret(value: str) -> Optional[str]:
    if not value:
        return None
    settings = get_settings()
    key = hashlib.sha256(settings.api_key_pepper.encode("utf-8")).digest()
    try:
        raw = base64.urlsafe_b64decode(value.encode("utf-8"))
        return _xor_bytes(raw, key).decode("utf-8")
    except Exception:
        return None
