"""Prepare GostHashedAuth verifiers on the trusted controller."""
from __future__ import annotations

import hashlib
import hmac
import secrets

GOST_AUTH_PORT = 18083
ITERATIONS = 600000


def matches(password: str, encoded: str) -> bool:
    try:
        empty, algorithm, rounds, salt, expected = encoded.split('$')
        if empty or algorithm != 'pbkdf2-sha256' or rounds != str(ITERATIONS):
            return False
        salt_bytes, expected_bytes = bytes.fromhex(salt), bytes.fromhex(expected)
        if len(salt_bytes) != 16 or len(expected_bytes) != 32:
            return False
    except (ValueError, AttributeError):
        return False
    actual = hashlib.pbkdf2_hmac('sha256', password.encode(), salt_bytes, ITERATIONS)
    return hmac.compare_digest(actual, expected_bytes)


def hash_users(passwords: dict[str, str], previous: dict[str, str]) -> dict[str, str]:
    result = {}
    for user, password in passwords.items():
        if not user or len(user.encode()) > 1024 or not 1 <= len(password.encode()) <= 4096:
            raise ValueError('GostHashedAuth credential exceeds supported length')
        encoded = previous.get(user, '')
        if not matches(password, encoded):
            salt = secrets.token_bytes(16)
            key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITERATIONS)
            encoded = f'$pbkdf2-sha256${ITERATIONS}${salt.hex()}${key.hex()}'
        result[user] = encoded
    return result
