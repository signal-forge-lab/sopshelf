import contextlib
import shutil
import unittest
import uuid
from pathlib import Path

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


class RealSopsIntegrationTests(unittest.TestCase):
    def test_set_read_delete_on_encrypted_copy(self):
        source = core.default_secret_file()
        sops = core.resolve_sops_exe()
        if not source.is_file() or not sops.is_file() or not core.default_identity_file().is_file():
            self.skipTest("Local SOPS + age environment is unavailable")

        with workspace_tempdir() as td:
            copied = Path(td) / "global.sops.json"
            shutil.copy2(source, copied)
            store = core.SopsStore(secret_file=copied, sops_exe=sops)
            test_name = "SOPSHELF_INTEGRATION_TEST"

            store.set_secret(test_name, "integration-test-value")
            self.assertEqual(store.get_secret(test_name), "integration-test-value")
            store.delete_secret(test_name)
            self.assertNotIn(test_name, store.list_names())


if __name__ == "__main__":
    unittest.main()
