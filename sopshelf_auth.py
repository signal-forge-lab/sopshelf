from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path


KDF_ITERATIONS = 600_000


def default_auth_file() -> Path:
    base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    return base / "Sopshelf" / "auth.json"


def auth_configured(path: Path | str | None = None) -> bool:
    return Path(path or default_auth_file()).is_file()


def _derive(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)


def save_password(password: str, path: Path | str | None = None) -> None:
    if len(password) < 8:
        raise ValueError("Use at least 8 characters.")
    target = Path(path or default_auth_file())
    target.parent.mkdir(parents=True, exist_ok=True)
    salt = secrets.token_bytes(16)
    digest = _derive(password, salt, KDF_ITERATIONS)
    record = {
        "version": 1,
        "kdf": "pbkdf2-hmac-sha256",
        "iterations": KDF_ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "verifier": base64.b64encode(digest).decode("ascii"),
    }
    temp = target.with_suffix(".tmp")
    temp.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    temp.replace(target)


def verify_password(password: str, path: Path | str | None = None) -> bool:
    target = Path(path or default_auth_file())
    try:
        record = json.loads(target.read_text(encoding="utf-8"))
        if record.get("version") != 1 or record.get("kdf") != "pbkdf2-hmac-sha256":
            return False
        iterations = int(record["iterations"])
        if iterations < 100_000 or iterations > 5_000_000:
            return False
        salt = base64.b64decode(record["salt"], validate=True)
        expected = base64.b64decode(record["verifier"], validate=True)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False
    actual = _derive(password, salt, iterations)
    return hmac.compare_digest(actual, expected)
