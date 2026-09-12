import os
import shutil
import sys
import unittest
import uuid
from pathlib import Path

# Qt platform must be selected before a QApplication is constructed.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLabel, QLineEdit

import sopshelf
from sopshelf_core import SopsStore


class FakeStore(SopsStore):
    def __init__(self, root: Path):
        super().__init__(secret_file=root / "missing-store.json", sops_exe=root / "missing-sops.exe")

    def list_names(self):
        return ["OPENAI_API_KEY", "GEMINI_API_KEY"]

    def modified_at(self):
        return None

    def read_all(self):
        return {"OPENAI_API_KEY": "a", "GEMINI_API_KEY": "b"}


class UiSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication(sys.argv)
        cls.app.setStyleSheet(sopshelf.APP_QSS)

    def setUp(self):
        # Workspace-local temp dir (default ACLs); tempfile 0700 dirs are
        # unreadable under the DSH file sandbox on this host.
        root = Path(__file__).resolve().parent / "scratch-tmp" / "test-temp"
        root.mkdir(parents=True, exist_ok=True)
        self._tmp_path = root / f"case-{uuid.uuid4().hex[:12]}"
        self._tmp_path.mkdir(parents=False, exist_ok=False)
        self.window = sopshelf.App(FakeStore(self._tmp_path))
        self.window.show()

    def tearDown(self):
        self.window.close()
        self.window.deleteLater()
        self.app.processEvents()
        shutil.rmtree(self._tmp_path, ignore_errors=True)

    def _value_text(self, row: int) -> str:
        return self.window.table._model.item(row, 2).text()

    def test_app_builds_and_filters_without_revealing_values(self):
        self.assertTrue(sopshelf.APP_ICON_PATH.is_file())
        self.assertFalse(self.window.windowIcon().isNull())
        self.assertEqual(self.window.count_label.text(), "2")
        self.assertEqual(self.window.table._model.rowCount(), 2)
        for row in range(self.window.table._model.rowCount()):
            self.assertEqual(self._value_text(row), sopshelf.MASKED)
        self.window.set_category("Gemini")
        self.assertEqual(self.window.count_label.text(), "1")
        self.assertEqual(self.window.table._model.rowCount(), 1)
        self.assertEqual(self._value_text(0), sopshelf.MASKED)

    def test_reveal_shows_value_and_remask_hides_it(self):
        # Sorted list_names -> row 0 is GEMINI_API_KEY ("b").
        self.window.table.selectRow(0)
        self.window.reveal_button.click()
        self.assertEqual(self.window.inspector.value_label.text(), "b")
        self.assertEqual(self._value_text(0), "b")
        self.assertEqual(self.window.reveal_button.text(), "Hide")
        self.window.remask()
        self.assertEqual(self.window.inspector.value_label.text(), sopshelf.MASKED)
        self.assertEqual(self._value_text(0), sopshelf.MASKED)
        self.assertEqual(self.window.reveal_button.text(), "Reveal")

    def test_sidebar_actions_are_qt_signal_wired(self):
        sidebar = sopshelf.Sidebar()
        try:
            events = []
            sidebar.healthRequested.connect(lambda: events.append("health"))
            sidebar.settingsRequested.connect(lambda: events.append("settings"))
            sidebar._buttons["Health"].click()
            sidebar._buttons["Settings"].click()
            self.assertEqual(events, ["health", "settings"])
        finally:
            sidebar.deleteLater()
            self.app.processEvents()

    def test_reveal_and_clipboard_timers_wire_mask_and_copy_lifecycle(self):
        self.assertEqual(self.window.reveal_timer.interval(), 15000)
        self.assertEqual(self.window.clipboard_timer.interval(), 30000)
        self.window.table.selectRow(0)
        self.window.reveal_button.click()
        self.assertTrue(self.window.reveal_timer.isActive())
        self.window.reveal_timer.timeout.emit()
        self.assertFalse(self.window.reveal_timer.isActive())
        clipboard = self.app.clipboard()
        self.window.copy_button.click()
        self.assertTrue(self.window.clipboard_timer.isActive())
        # Clipboard changed by the user in between -> must NOT be cleared.
        clipboard.setText("user-typed-something")
        self.window.clipboard_timer.timeout.emit()
        self.assertEqual(clipboard.text(), "user-typed-something")
        # Still unchanged -> must be cleared.
        self.window.copy_button.click()
        self.window.clipboard_timer.timeout.emit()
        self.assertEqual(clipboard.text(), "")
        self.assertFalse(self.window.clipboard_timer.isActive())

    def test_secret_dialog_is_tall_enough_for_its_contents(self):
        dialog = sopshelf.SecretDialog(None)
        try:
            self.assertGreaterEqual(dialog.minimumHeight(), dialog.sizeHint().height())
        finally:
            dialog.deleteLater()
            self.app.processEvents()

    def test_secret_dialog_masks_value_and_locks_name_in_edit_mode(self):
        dialog = sopshelf.SecretDialog("OPENAI_API_KEY")
        try:
            self.assertFalse(dialog.name_edit.isEnabled())
            self.assertEqual(dialog.value_edit.echoMode(), QLineEdit.Password)
            self.assertEqual(dialog.save_button.objectName(), "Primary")
            self.assertIsNotNone(dialog.cancel_button)
            self.assertEqual(dialog.cancel_button.objectName(), "Ghost")
        finally:
            dialog.deleteLater()
            self.app.processEvents()

    def test_vibrant_shell_and_delete_dialog_use_custom_styles(self):
        self.assertEqual(self.window.sidebar.objectName(), "Sidebar")
        self.assertEqual(self.window.edit_button.objectName(), "Ghost")
        self.assertEqual(self.window.delete_button.objectName(), "Danger")
        self.assertIn("qlineargradient", sopshelf.APP_QSS)
        self.assertIn("QFrame#TopBar", sopshelf.APP_QSS)

        dialog = sopshelf.DeleteSecretDialog("OPENAI_API_KEY")
        try:
            self.assertEqual(dialog.delete_button.objectName(), "Danger")
            self.assertIsNotNone(dialog.cancel_button)
            self.assertEqual(dialog.cancel_button.objectName(), "Ghost")
            self.assertTrue(dialog.cancel_button.isDefault())
        finally:
            dialog.deleteLater()
            self.app.processEvents()

    def test_health_and_settings_dialogs_are_value_free(self):
        # Gap-fill smoke: Health/Settings dialogs must show status/paths only,
        # never secret values, even when the store holds distinctive dummies.
        dummies = {"OPENAI_API_KEY": "DUMMY-ALPHA-9f8e7d", "GEMINI_API_KEY": "DUMMY-BETA-1234"}

        class RichStore(FakeStore):
            def list_names(self):
                return sorted(dummies)

            def read_all(self):
                return dict(dummies)

        store = RichStore(self._tmp_path)
        health_dlg = sopshelf.HealthDialog(store)
        settings_dlg = sopshelf.SettingsDialog(store)
        try:
            health_text = "\n".join(
                label.text() for label in health_dlg.findChildren(QLabel)
            )
            settings_text = "\n".join(
                label.text() for label in settings_dlg.findChildren(QLabel)
            )
            for secret in dummies.values():
                self.assertNotIn(secret, health_text)
                self.assertNotIn(secret, settings_text)
            self.assertIn("SOPS executable", health_text)
            self.assertIn("Encrypted store", settings_text)
        finally:
            health_dlg.deleteLater()
            settings_dlg.deleteLater()
            self.app.processEvents()

    def test_name_focus_shows_copy_action_and_click_changes_to_check(self):
        self.window.table.selectRow(0)
        self.app.processEvents()
        field = self.window.inspector.name_label
        expected_name = self.window.table._model.item(0, 0).text()

        self.assertFalse(field.copy_action.isVisible())
        field.setFocus()
        self.app.processEvents()
        self.assertTrue(field.copy_action.isVisible())
        self.assertEqual(field.copy_action.text(), "Copy name")

        field.copy_action.trigger()
        self.app.processEvents()
        self.assertEqual(self.app.clipboard().text(), expected_name)
        self.assertEqual(field.copy_action.text(), "Copied")
        self.assertTrue(field.copy_action.isVisible())

        field._copy_reset_timer.timeout.emit()
        self.app.processEvents()
        self.assertEqual(field.copy_action.text(), "Copy name")


if __name__ == "__main__":
    unittest.main()
