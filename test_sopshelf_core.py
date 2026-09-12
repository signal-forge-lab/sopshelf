import contextlib
import json
import os
import shutil
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import sopshelf_core as core


@contextlib.contextmanager
def workspace_tempdir():
    """Workspace-local temp dir with default ACLs (see test_sopshelf_auth.py)."""
    root = Path(__file__).resolve().parent / "scratch-tmp" / "test-temp"
    root.mkdir(parents=True, exist_ok=True)
    td = root / f"case-{uuid.uuid4().hex[:12]}"
    td.mkdir(parents=False, exist_ok=False)
    try:
        yield str(td)
    finally:
        shutil.rmtree(td, ignore_errors=True)


class FakeCompleted:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


class CoreTests(unittest.TestCase):
    def test_validate_secret_name(self):
        self.assertEqual(core.validate_secret_name("OPENAI_ADMIN_KEY"), "OPENAI_ADMIN_KEY")
        for value in ("", "bad-name", "1BAD", "has space"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    core.validate_secret_name(value)

    def test_category_for_name(self):
        self.assertEqual(core.category_for_name("OPENAI_ADMIN_KEY"), "OpenAI")
        self.assertEqual(core.category_for_name("GEMINI_API_KEY"), "Gemini")
        self.assertEqual(core.category_for_name("CONTROL_PLANE_API_KEY"), "MCP")
        self.assertEqual(core.category_for_name("ALERT_DISCORD_WEBHOOK_URL"), "Webhooks")
        self.assertEqual(core.category_for_name("SOMETHING_ELSE"), "Other")

    def test_public_defaults_are_overridable_without_machine_specific_paths(self):
        with patch.dict(
            os.environ,
            {
                "SOPSHELF_SECRET_FILE": "C:/portable/secrets.sops.json",
                "SOPS_AGE_KEY_FILE": "C:/portable/age-keys.txt",
                "SOPSHELF_BACKUP_FILE": "D:/backup/age-keys-backup.txt.age",
            },
            clear=False,
        ):
            self.assertEqual(core.default_secret_file(), Path("C:/portable/secrets.sops.json"))
            self.assertEqual(core.default_identity_file(), Path("C:/portable/age-keys.txt"))
            self.assertEqual(core.default_backup_file(), Path("D:/backup/age-keys-backup.txt.age"))

    def test_public_build_has_no_built_in_local_consumer_registry(self):
        self.assertEqual(core.known_consumers("LOCAL_TOOL_API_KEY"), ())

    def test_mask_secret(self):
        self.assertEqual(core.mask_secret(""), "")
        self.assertEqual(core.mask_secret("abcd"), "••••")
        self.assertEqual(core.mask_secret("abcdefghijk"), "••••••••••••")

    def test_store_reads_json_without_logging_values(self):
        payload = {"OPENAI_API_KEY": "super-secret", "GEMINI_API_KEY": "another-secret"}
        runner = lambda *a, **k: FakeCompleted(json.dumps(payload))
        store = core.SopsStore(secret_file="C:/tmp/global.sops.json", sops_exe="sops.exe", runner=runner)
        self.assertEqual(store.list_names(), ["GEMINI_API_KEY", "OPENAI_API_KEY"])
        self.assertEqual(store.get_secret("OPENAI_API_KEY"), "super-secret")

    def test_set_secret_uses_stdin_not_command_line(self):
        calls = []

        def runner(args, **kwargs):
            calls.append((args, kwargs))
            return FakeCompleted("")

        store = core.SopsStore(secret_file="C:/tmp/global.sops.json", sops_exe="sops.exe", runner=runner)
        store.set_secret("OPENAI_ADMIN_KEY", "TEST_ADMIN_VALUE_NOT_ON_COMMANDLINE")
        args, kwargs = calls[0]
        self.assertNotIn("TEST_ADMIN_VALUE_NOT_ON_COMMANDLINE", " ".join(args))
        self.assertIn("--value-stdin", args)
        self.assertEqual(kwargs["input"], json.dumps("TEST_ADMIN_VALUE_NOT_ON_COMMANDLINE"))

    def test_delete_secret_uses_argv_index(self):
        calls = []

        def runner(args, **kwargs):
            calls.append(args)
            return FakeCompleted("")

        store = core.SopsStore(secret_file="C:/tmp/global.sops.json", sops_exe="sops.exe", runner=runner)
        store.delete_secret("OPENAI_ADMIN_KEY")
        self.assertEqual(calls[0][-1], '["OPENAI_ADMIN_KEY"]')

    def test_health_checks_paths_without_secret_values(self):
        with workspace_tempdir() as td:
            root = Path(td)
            secret = root / "global.sops.json"
            identity = root / "keys.txt"
            backup = root / "age-keys-backup.txt.age"
            secret.write_text("{}", encoding="utf-8")
            identity.write_text("placeholder", encoding="utf-8")
            backup.write_bytes(b"age-encryption.org/v1\n")
            store = core.SopsStore(secret_file=secret, sops_exe=Path(td) / "sops.exe", runner=lambda *a, **k: FakeCompleted("{}"))
            Path(store.sops_exe).write_text("", encoding="utf-8")
            health = core.collect_health(store, identity_file=identity, backup_file=backup)
            self.assertTrue(health["sops"])
            self.assertTrue(health["secret_file"])
            self.assertTrue(health["age_identity"])
            self.assertTrue(health["backup"])
            self.assertTrue(health["decrypt"])

    def test_process_launcher_injects_only_requested_secret(self):
        payload = {"OPENAI_ADMIN_KEY": "admin-secret", "GEMINI_API_KEY": "gemini-secret"}
        store = core.SopsStore(
            secret_file="C:/tmp/global.sops.json",
            sops_exe="sops.exe",
            runner=lambda *a, **k: FakeCompleted(json.dumps(payload)),
        )
        captured = {}

        def fake_popen(args, **kwargs):
            captured["args"] = args
            captured["env"] = kwargs["env"]
            return object()

        with patch.object(core.subprocess, "Popen", side_effect=fake_popen):
            core.open_powershell_with_secret(store, "OPENAI_ADMIN_KEY")

        self.assertEqual(captured["env"]["OPENAI_ADMIN_KEY"], "admin-secret")
        self.assertNotEqual(captured["env"].get("GEMINI_API_KEY"), "gemini-secret")
        self.assertNotIn("admin-secret", " ".join(captured["args"]))

    def test_sanitized_process_env_strips_secret_like_variables(self):
        source = {
            "PATH": "C:/tools",
            "LANG": "ja_JP",
            "SERVICE_API_KEY": "hidden",
            "SOME_TOKEN": "hidden",
            "WEBHOOK_URL": "hidden",
        }
        cleaned = core.sanitized_process_env(source)
        self.assertEqual(cleaned, {"PATH": "C:/tools", "LANG": "ja_JP"})


if __name__ == "__main__":
    unittest.main()
