import contextlib
import json
import shutil
import unittest
import uuid
from pathlib import Path

import sopshelf_auth as auth


@contextlib.contextmanager
def workspace_tempdir():
    """Workspace-local temp dir with default ACLs.

    tempfile.TemporaryDirectory() creates 0700 dirs whose restrictive DACL
    is unreadable under the DSH file sandbox on this host; a plain mkdir
    under scratch-tmp/test-temp inherits usable ACLs.
    """
    root = Path(__file__).resolve().parent / "scratch-tmp" / "test-temp"
    root.mkdir(parents=True, exist_ok=True)
    td = root / f"case-{uuid.uuid4().hex[:12]}"
    td.mkdir(parents=False, exist_ok=False)
    try:
        yield str(td)
    finally:
        shutil.rmtree(td, ignore_errors=True)


class AuthTests(unittest.TestCase):
    def test_password_is_verified_without_being_stored(self):
        with workspace_tempdir() as td:
            path = Path(td) / "auth.json"
            password = "correct horse battery staple"
            auth.save_password(password, path)
            record_text = path.read_text(encoding="utf-8")
            self.assertNotIn(password, record_text)
            self.assertTrue(auth.verify_password(password, path))
            self.assertFalse(auth.verify_password("wrong password", path))

    def test_short_password_is_rejected(self):
        with workspace_tempdir() as td:
            with self.assertRaises(ValueError):
                auth.save_password("short", Path(td) / "auth.json")

    def test_malformed_or_unreasonably_costly_record_fails_closed(self):
        with workspace_tempdir() as td:
            path = Path(td) / "auth.json"
            path.write_text("not json", encoding="utf-8")
            self.assertFalse(auth.verify_password("anything", path))
            path.write_text(json.dumps({"version": 1, "kdf": "pbkdf2-hmac-sha256", "iterations": 99_999, "salt": "AA==", "verifier": "AA=="}), encoding="utf-8")
            self.assertFalse(auth.verify_password("anything", path))


if __name__ == "__main__":
    unittest.main()
