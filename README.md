# Sopshelf

[日本語](README.ja.md)

> **Development build** — Sopshelf is under active development. Interfaces, defaults, and packaging may change. Back up your encrypted store and age identity before testing new builds.

Sopshelf is a lightweight Windows desktop GUI for an existing **SOPS + age** secret store. It does not create a second secret database: the encrypted SOPS file remains the source of truth.

## What it does

- Lists top-level string secrets from a SOPS-encrypted JSON file.
- Keeps values masked by default and automatically re-masks revealed values after 15 seconds.
- Copies secret values to the clipboard and clears them after 30 seconds when the clipboard still contains the copied value.
- Adds and updates values through `sops set --value-stdin`, keeping values out of command-line arguments.
- Deletes values through `sops unset` after confirmation.
- Keeps encrypted-only mutation backups beside the encrypted store.
- Shows health for SOPS, the encrypted store, age identity, decryptability, and an optional recovery backup.
- Opens an isolated PowerShell with only the selected secret injected into the child Process environment.
- Protects the GUI with a local app-password verifier.
- Provides a PySide6 D. Vibrant desktop UI with search, filtering, command palette, and keyboard shortcuts.

## Security boundary

Sopshelf is a GUI over SOPS; it is **not** a replacement for SOPS or age.

- Secret values are not intentionally written to logs or plaintext temporary files.
- Secret updates are sent to SOPS through stdin.
- SOPS stderr/stdout details are not echoed into user-facing failures.
- The startup password protects the **Sopshelf GUI only**. Software running as the same OS user can still invoke `sops.exe` directly or modify local files.
- The age private key remains the root credential. Protect it separately and keep a tested recovery backup.

## Requirements

- Windows 10/11
- Python 3
- PySide6
- SOPS
- age

Install the direct Python dependency:

```powershell
py -3 -m pip install PySide6
```

SOPS and age are external tools and are not bundled with Sopshelf.

## Configuration

Sopshelf supports portable configuration through environment variables.

| Variable | Purpose | Default |
|---|---|---|
| `SOPSHELF_SECRET_FILE` | Encrypted JSON store | `%USERPROFILE%\.config\sops\secrets\global.sops.json` |
| `SOPS_AGE_KEY_FILE` | age identity used by SOPS | `%APPDATA%\sops\age\keys.txt` |
| `SOPSHELF_BACKUP_FILE` | Optional recovery-backup health target | `%USERPROFILE%\.config\sops\backups\age-keys-backup.txt.age` |
| `SOPS_EXE` | Explicit `sops.exe` path | `sops` on `PATH`, then the standard WinGet package location |

The encrypted store must contain a top-level JSON object whose values are strings.

Example logical structure before encryption:

```json
{
  "SERVICE_API_KEY": "example",
  "ALERT_WEBHOOK_URL": "example"
}
```

Do not commit plaintext secret files or an age private key to this repository.

## Start

Double-click:

```text
run_sopshelf.cmd
```

or launch without a console:

```powershell
pyw -3 sopshelf.py
```

For a value-free health check:

```powershell
py -3 sopshelf.py --check
```

The health command reports status and secret count only; it does not print secret values.

## Keyboard shortcuts

- `Ctrl+K` — focus search
- `Ctrl+Shift+P` — command palette
- `F5` — refresh
- `Esc` — re-mask the currently revealed value

## Optional Modora integration

`modora.module.json` and `modora-adapter.mjs` expose open/status/signals integration for a compatible Modora host. The adapter calls the same value-free Sopshelf health check and does not read secret values directly.

## Tests

```powershell
py -3 test_sopshelf_core.py
py -3 test_sopshelf_auth.py
py -3 test_sopshelf_integration.py
$env:QT_QPA_PLATFORM = "offscreen"
py -3 test_sopshelf_ui.py
py -3 sopshelf.py --check
```

The real SOPS integration test runs against a temporary encrypted copy and skips when a local SOPS + age environment is unavailable.

## PySide6 / Qt

The GUI uses PySide6 (Qt for Python). PySide6 Community Edition is available under LGPL-3.0/GPL-3.0 terms, with commercial licensing available separately. Review the licensing requirements of the exact PySide6/Qt build you distribute.

## Project status

This repository is published as an **in-development build**. It has automated tests and local security checks, but it should not be treated as an independently audited secret-management product.
