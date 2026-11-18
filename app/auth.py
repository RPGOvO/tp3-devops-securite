"""Small authentication module used for the DevOps TP N°3."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Any

MAX_ATTEMPTS = 3
LOCKOUT_SECONDS = 300
PBKDF2_ITERATIONS = 600_000

users: dict[str, str] = {}
attempts: dict[str, int] = {}
blocked_until: dict[str, float] = {}

GENERIC_ERROR = "Identifiants incorrects"


def _valid_username(username: Any) -> bool:
    if not isinstance(username, str):
        return False
    if not (3 <= len(username) <= 32):
        return False
    return all(ch.isalnum() or ch in "._-" for ch in username)


def _valid_password(password: Any) -> bool:
    return isinstance(password, str) and 12 <= len(password) <= 128


def _hash_password(password: str) -> str:
    """Hash a password with PBKDF2-SHA256 and a random salt."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return (
        f"pbkdf2_sha256${PBKDF2_ITERATIONS}"
        f"${salt.hex()}${digest.hex()}"
    )


def _verify_password(password: str, encoded_hash: str) -> bool:
    """Verify a password against its stored PBKDF2-SHA256 hash."""
    try:
        algorithm, iterations_text, salt_hex, digest_hex = encoded_hash.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_text)
        if iterations <= 0:
            return False
        salt = bytes.fromhex(salt_hex)
        expected_digest = bytes.fromhex(digest_hex)
        actual_digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )
        return hmac.compare_digest(actual_digest, expected_digest)
    except (ValueError, TypeError, AttributeError):
        return False


def register_user(username: Any, password: Any) -> bool:
    if not _valid_username(username) or not _valid_password(password):
        return False
    if username in users:
        return False
    users[username] = _hash_password(password)
    attempts.pop(username, None)
    blocked_until.pop(username, None)
    return True


def authenticate(username: Any, password: Any) -> dict[str, Any]:
    if not _valid_username(username) or not isinstance(password, str):
        return {"success": False, "message": GENERIC_ERROR}

    now = time.time()
    lock_expiry = blocked_until.get(username)

    if lock_expiry is not None:
        if lock_expiry > now:
            return {"success": False, "message": GENERIC_ERROR}
        blocked_until.pop(username, None)
        attempts.pop(username, None)

    encoded_hash = users.get(username)

    if encoded_hash is None:
        return {"success": False, "message": GENERIC_ERROR}

    if not _verify_password(password, encoded_hash):
        _record_failure(username, now)
        return {"success": False, "message": GENERIC_ERROR}

    attempts.pop(username, None)
    blocked_until.pop(username, None)
    return {"success": True, "message": "Connexion reussie"}


def _record_failure(username: str, now: float) -> None:
    attempts[username] = attempts.get(username, 0) + 1
    if attempts[username] >= MAX_ATTEMPTS:
        blocked_until[username] = now + LOCKOUT_SECONDS


def reset_attempts() -> None:
    attempts.clear()
    blocked_until.clear()


def reset_state() -> None:
    users.clear()
    reset_attempts()
