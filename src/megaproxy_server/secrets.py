from __future__ import annotations

import secrets
import string
import subprocess
from pathlib import Path

from passlib.hash import sha512_crypt


def random_password(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits + "-_"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def password_hash(password: str) -> str:
    return sha512_crypt.using(rounds=656000).hash(password)


def generate_key(path: Path, comment: str) -> tuple[str, Path]:
    path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-a", "64", "-N", "", "-C", comment, "-f", str(path)],
        check=True,
    )
    path.chmod(0o600)
    return path.with_suffix(path.suffix + ".pub").read_text(encoding="utf-8").strip(), path


def public_key(private_key: Path) -> str:
    result = subprocess.run(
        ["ssh-keygen", "-y", "-f", str(private_key.expanduser())],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()
