from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Callable, Mapping


APP_NAME = "Sopshelf"
VERSION = "0.1.1"
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_SECRET_ENV_RE = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|WEBHOOK|CREDENTIAL)", re.IGNORECASE)

class SopsError(RuntimeError):
    pass


def validate_secret_name(name: str) -> str:
    name = name.strip()
    if not _NAME_RE.fullmatch(name):
        raise ValueError("Use an environment-style name: letters, numbers and underscores only.")
    return name


def category_for_name(name: str) -> str:
    upper = name.upper()
    if "OPENAI" in upper or "OPENROUTER" in upper:
        return "OpenAI"
    if "GEMINI" in upper:
        return "Gemini"
    if "CONTROL_PLANE" in upper or "MCP" in upper:
        return "MCP"
    if "WEBHOOK" in upper or "DISCORD" in upper:
        return "Webhooks"
    if "ORCAROUTER" in upper or "OPENCODE" in upper or "DEEPSEEK" in upper:
        return "Models"
    return "Other"


def mask_secret(value: str) -> str:
    if not value:
        return ""
    return "•" * (len(value) if len(value) <= 4 else 12)


def known_consumers(name: str) -> tuple[str, ...]:
    return ()


def purpose_for_name(name: str) -> str:
    return {
        "OpenAI": "OpenAI-compatible provider credential",
        "Gemini": "Gemini provider credential",
        "MCP": "Local MCP / secure tunnel credential",
        "Webhooks": "Webhook delivery credential",
        "Models": "Model provider credential",
    }.get(category_for_name(name), "Encrypted local credential")


def default_secret_file() -> Path:
    configured = os.environ.get("SOPSHELF_SECRET_FILE")
    if configured:
        return Path(configured)
    return Path.home() / ".config" / "sops" / "secrets" / "global.sops.json"


def default_identity_file() -> Path:
    configured = os.environ.get("SOPS_AGE_KEY_FILE")
    if configured:
        return Path(configured)
    appdata = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    return appdata / "sops" / "age" / "keys.txt"


def default_backup_file() -> Path:
    configured = os.environ.get("SOPSHELF_BACKUP_FILE")
    if configured:
        return Path(configured)
    return Path.home() / ".config" / "sops" / "backups" / "age-keys-backup.txt.age"


def resolve_sops_exe() -> Path:
    configured = os.environ.get("SOPS_EXE")
    if configured:
        return Path(configured)
    found = shutil.which("sops")
    if found:
        return Path(found)
    local = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    return local / "Microsoft" / "WinGet" / "Packages" / "SecretsOPerationS.SOPS_Microsoft.Winget.Source_8wekyb3d8bbwe" / "sops.exe"


def sanitized_process_env(source: Mapping[str, str] | None = None) -> dict[str, str]:
    source = source or os.environ
    return {key: value for key, value in source.items() if not _SECRET_ENV_RE.search(key)}


def _hidden_startupinfo():
    if os.name != "nt":
        return None
    info = subprocess.STARTUPINFO()
    info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    info.wShowWindow = 0
    return info


class SopsStore:
    def __init__(
        self,
        secret_file: str | os.PathLike[str] | None = None,
        sops_exe: str | os.PathLike[str] | None = None,
        runner: Callable[..., object] = subprocess.run,
    ) -> None:
        self.secret_file = Path(secret_file) if secret_file else default_secret_file()
        self.sops_exe = Path(sops_exe) if sops_exe else resolve_sops_exe()
        self._runner = runner

    def _run(self, args: list[str], *, input_text: str | None = None, timeout: int = 20) -> str:
        kwargs = {
            "capture_output": True,
            "text": True,
            "timeout": timeout,
            "check": False,
        }
        if input_text is not None:
            kwargs["input"] = input_text
        startupinfo = _hidden_startupinfo()
        if startupinfo is not None:
            kwargs["startupinfo"] = startupinfo
        try:
            result = self._runner(args, **kwargs)
        except OSError as exc:
            raise SopsError("SOPS could not be started.") from exc
        returncode = int(getattr(result, "returncode", 1))
        if returncode != 0:
            raise SopsError(f"SOPS command failed (exit {returncode}).")
        return str(getattr(result, "stdout", ""))

    def _base(self) -> list[str]:
        return [str(self.sops_exe)]

    def read_all(self) -> dict[str, str]:
        raw = self._run(self._base() + ["decrypt", str(self.secret_file)])
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SopsError("SOPS output was not valid JSON.") from exc
        if not isinstance(parsed, dict):
            raise SopsError("Secret store must contain a top-level JSON object.")
        result: dict[str, str] = {}
        for key, value in parsed.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise SopsError("Sopshelf supports top-level string values only.")
            result[key] = value
        return result

    def list_names(self) -> list[str]:
        return sorted(self.read_all())

    def get_secret(self, name: str) -> str:
        name = validate_secret_name(name)
        values = self.read_all()
        if name not in values:
            raise SopsError(f"Secret is missing: {name}")
        return values[name]

    def _backup_encrypted(self) -> None:
        if not self.secret_file.is_file():
            return
        folder = self.secret_file.parent / ".sopshelf-backups"
        folder.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        shutil.copy2(self.secret_file, folder / f"global.sops.{stamp}.json")
        backups = sorted(folder.glob("global.sops.*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for old in backups[10:]:
            old.unlink(missing_ok=True)

    def set_secret(self, name: str, value: str) -> None:
        name = validate_secret_name(name)
        if not value:
            raise ValueError("Secret value cannot be empty.")
        self._backup_encrypted()
        index = json.dumps([name], separators=(",", ":"))
        self._run(
            self._base() + ["set", "--value-stdin", str(self.secret_file), index],
            input_text=json.dumps(value),
        )

    def delete_secret(self, name: str) -> None:
        name = validate_secret_name(name)
        self._backup_encrypted()
        index = json.dumps([name], separators=(",", ":"))
        self._run(self._base() + ["unset", str(self.secret_file), index])

    def modified_at(self) -> datetime | None:
        if not self.secret_file.is_file():
            return None
        return datetime.fromtimestamp(self.secret_file.stat().st_mtime)


def collect_health(
    store: SopsStore,
    *,
    identity_file: str | os.PathLike[str] | None = None,
    backup_file: str | os.PathLike[str] | None = None,
) -> dict[str, bool]:
    identity = Path(identity_file) if identity_file else default_identity_file()
    backup = Path(backup_file) if backup_file else default_backup_file()
    health = {
        "sops": store.sops_exe.is_file(),
        "secret_file": store.secret_file.is_file(),
        "age_identity": identity.is_file(),
        "backup": backup.is_file(),
        "decrypt": False,
    }
    if health["sops"] and health["secret_file"] and health["age_identity"]:
        try:
            store.read_all()
            health["decrypt"] = True
        except (SopsError, OSError):
            health["decrypt"] = False
    return health


def open_powershell_with_secret(store: SopsStore, name: str):
    name = validate_secret_name(name)
    value = store.get_secret(name)
    env = sanitized_process_env()
    env[name] = value
    command = (
        f"$Host.UI.RawUI.WindowTitle='Sopshelf - {name}'; "
        f"Write-Host 'Sopshelf: {name} is available only in this PowerShell process.'"
    )
    args = ["powershell.exe", "-NoLogo", "-NoProfile", "-NoExit", "-Command", command]
    if os.name == "nt":
        process = subprocess.Popen(args, env=env, creationflags=subprocess.CREATE_NEW_CONSOLE)
    else:
        process = subprocess.Popen(args, env=env)
    value = None
    return process
