"""Sopshelf — lightweight local SOPS + age secret manager (PySide6 + D.Vibrant QSS).

Security contract (preserved from the tkinter build):
- Encrypted store only: all reads/writes go through :class:`SopsStore`
  (``sops set --value-stdin`` for updates — values never touch argv;
  ``sops unset`` for deletes with an explicit confirm dialog).
- Masked-by-default: the Qt model and tooltips never hold real values.
  Reveal is explicit and auto re-masks after 15 s.
- Clipboard auto-clears after 30 s and only when unchanged.
- Process-only injection via ``sanitized_process_env`` + ``CREATE_NEW_CONSOLE``.
- Startup password gate reuses ``sopshelf_auth`` (PBKDF2-HMAC-SHA256 600k).
- ``--check`` is value-free.
- No secret values, age private keys, or decrypted content in logs,
  stdout, or tooltips; any explicit reveal is cleared from the UI after 15 s.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Callable

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QAction, QFont, QIcon, QKeySequence, QShortcut, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStatusBar,
    QTableView,
    QVBoxLayout,
    QWidget,
    QAbstractItemView,
)

from sopshelf_auth import auth_configured, default_auth_file, save_password, verify_password

from sopshelf_core import (
    APP_NAME,
    VERSION,
    SopsError,
    SopsStore,
    category_for_name,
    collect_health,
    default_backup_file,
    default_identity_file,
    known_consumers,
    open_powershell_with_secret,
    purpose_for_name,
    validate_secret_name,
)

MASKED = "••••••••••••"
APP_ICON_PATH = Path(__file__).resolve().parent / "assets" / "sopshelf-app-icon.png"
COPY_ICON_PATH = Path(__file__).resolve().parent / "assets" / "copy.svg"
CHECK_ICON_PATH = Path(__file__).resolve().parent / "assets" / "check.svg"

CATEGORIES = ("All", "OpenAI", "Gemini", "MCP", "Webhooks", "Models", "Other")


def app_icon() -> QIcon:
    """Return the bundled app icon, or a null icon if the asset is unavailable."""
    return QIcon(str(APP_ICON_PATH)) if APP_ICON_PATH.is_file() else QIcon()


def _set_windows_app_id() -> None:
    """Give Windows a stable identity so the Qt window icon is used on the taskbar."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "Sopshelf.SecretManager"
        )
    except Exception:
        # Cosmetic integration only; never block access to the vault.
        pass

# ---------------------------------------------------------------------------
# D.Vibrant QSS — bright background, dark text, blue/violet accents,
# high-density desktop utility styling.
# ---------------------------------------------------------------------------

APP_QSS = """
* { font-family: "Inter", "Segoe UI", sans-serif; color: #15182A; }
QMainWindow, QWidget#Shell { background: #F7F8FF; }
QWidget#Sidebar {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #F8F9FF, stop:1 #F3F5FF);
    border-right: 1px solid #E3E7F0;
}
QLabel#BrandName { color: #15182A; font-size: 16px; font-weight: 800; }
QLabel#BrandBadge {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #635BFF, stop:1 #2563EB);
    color: #FFFFFF; font-weight: 800; font-size: 13px;
    border-radius: 8px; padding: 4px 9px;
}
QLabel#SectionHead { color: #667085; font-size: 10px; font-weight: 800; letter-spacing: 1px; }
QPushButton#Nav {
    background: transparent; color: #4D5872; border: 1px solid transparent; border-radius: 8px;
    min-height: 32px; padding: 0 10px; font-size: 12px; text-align: left;
}
QPushButton#Nav:hover { background: #EEF1FF; border-color: #E2E5F3; color: #15182A; }
QPushButton#Nav[active="true"] {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #635BFF, stop:1 #2563EB);
    border-color: #635BFF; color: #FFFFFF; font-weight: 700;
}
QFrame#TopBar {
    background: rgba(255, 255, 255, 235); border: 1px solid #E3E7F0; border-radius: 14px;
}
QLabel#Eyebrow { color: #635BFF; font-size: 9px; font-weight: 800; letter-spacing: 1.5px; }
QLabel#Title { color: #15182A; font-size: 20px; font-weight: 800; }
QLabel#Count {
    background: #E9E7FF; color: #635BFF; border: 1px solid #DCD8FF;
    font-size: 10px; font-weight: 800; border-radius: 9px; padding: 2px 9px;
}
QLabel#VaultPath { color: #667085; font-family: "Cascadia Mono", Consolas, monospace; font-size: 9px; }
QLineEdit#SearchBar {
    background: #FFFFFF; color: #15182A; border: 1px solid #CDD5E6;
    border-radius: 9px; min-height: 34px; padding: 0 12px; font-size: 12px;
    selection-background-color: #635BFF;
}
QLineEdit#SearchBar:hover { border-color: #BFC8DB; }
QLineEdit#SearchBar:focus { border: 2px solid #635BFF; padding: 0 11px; }
QPushButton#Primary {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #635BFF, stop:1 #2563EB);
    color: #FFFFFF; border: 1px solid #635BFF; border-radius: 8px;
    min-height: 32px; padding: 0 15px; font-size: 12px; font-weight: 700;
}
QPushButton#Primary:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #554CF1, stop:1 #1D4ED8);
}
QPushButton#Primary:pressed { background: #4B45D8; }
QPushButton#Primary:disabled { background: #D7D9F4; border-color: #D7D9F4; color: #FFFFFF; }
QPushButton#Secondary {
    background: #EEF1F7; color: #29334A; border: 1px solid #E0E5EF; border-radius: 8px;
    min-height: 32px; padding: 0 13px; font-size: 12px; font-weight: 650;
}
QPushButton#Secondary:hover { background: #E6EAF3; border-color: #D4DAE7; }
QPushButton#Ghost {
    background: transparent; color: #635BFF; border: 1px solid transparent; border-radius: 8px;
    min-height: 32px; padding: 0 13px; font-size: 12px; font-weight: 700;
}
QPushButton#Ghost:hover { background: #F1EFFF; border-color: #E5E0FF; }
QPushButton#Danger {
    background: #DF4058; color: #FFFFFF; border: 1px solid #DF4058; border-radius: 8px;
    min-height: 32px; padding: 0 13px; font-size: 12px; font-weight: 700;
}
QPushButton#Danger:hover { background: #C9364C; border-color: #C9364C; }
QPushButton:focus { border: 2px solid #635BFF; }
QFrame#Card, QFrame#InspectorCard {
    background: #FFFFFF; border: 1px solid #E3E7F0; border-radius: 14px;
}
QFrame#InspectorCard { background: #FEFEFF; }
QFrame#ActionBar { background: #F8F9FD; border: 1px solid #ECEFF5; border-radius: 10px; }
QTableView {
    background: #FFFFFF; alternate-background-color: #FFFFFF; color: #15182A; border: none;
    gridline-color: #EDF0F5; selection-background-color: #EBEAFF;
    selection-color: #15182A; font-size: 11px; outline: none;
}
QTableView::item { padding: 5px 8px; border-bottom: 1px solid #EDF0F5; }
QTableView::item:hover { background: #F8F9FF; }
QTableView::item:selected { background: #EBEAFF; border-left: 3px solid #635BFF; }
QHeaderView::section {
    background: #F7F8FB; color: #667085; border: none; border-bottom: 1px solid #E8EBF2;
    padding: 8px 9px; font-size: 10px; font-weight: 800;
}
QLabel#DetailHead { color: #635BFF; font-size: 9px; font-weight: 800; letter-spacing: 1px; }
QLineEdit#DetailName {
    background: transparent; color: #15182A; border: 1px solid transparent;
    border-radius: 7px; min-height: 30px; padding: 0 7px;
    font-size: 14px; font-weight: 800;
    selection-background-color: #E9E7FF; selection-color: #15182A;
}
QLineEdit#DetailName:hover { background: #FAFAFF; }
QLineEdit#DetailName:focus { background: #F7F8FF; border-color: #CDD5E6; }
QLabel#ValueBox {
    background: #F7F8FC; color: #3E4860; border: 1px solid #E3E7F0;
    border-radius: 8px; padding: 9px 11px;
}
QLabel#FieldKey { color: #667085; font-size: 10px; }
QLabel#FieldVal { color: #4D5872; font-size: 11px; }
QLabel#DangerHead { color: #DF4058; font-size: 11px; font-weight: 800; }
QLabel#DangerNote { color: #667085; font-size: 10px; }
QStatusBar#Toast { background: #FFFFFF; border-top: 1px solid #E3E7F0; font-size: 11px; }
QLabel#Health { color: #4D5872; font-size: 10px; }
QLabel#StatusOk { color: #0C8052; font-size: 11px; font-weight: 800; }
QLabel#StatusWarn { color: #A96D10; font-size: 11px; font-weight: 800; }
QLabel#StatusBad { color: #C9364C; font-size: 11px; font-weight: 800; }
QLabel#StatusInfo { color: #2C5EE8; font-size: 11px; font-weight: 800; }
QDialog { background: #FFFFFF; }
QLabel#DialogEyebrow { color: #635BFF; font-size: 9px; font-weight: 800; letter-spacing: 1.4px; }
QLabel#DlgTitle { color: #15182A; font-size: 17px; font-weight: 800; }
QLabel#DlgHint { color: #667085; font-size: 10px; }
QLabel#FieldLabel { color: #4D5872; font-size: 10px; font-weight: 750; }
QLineEdit#Field {
    background: #FFFFFF; color: #15182A; border: 1px solid #CDD5E6;
    border-radius: 8px; min-height: 34px; padding: 0 11px; font-size: 12px;
    selection-background-color: #635BFF;
}
QLineEdit#Field:hover { border-color: #BFC8DB; }
QLineEdit#Field:focus { border: 2px solid #635BFF; padding: 0 10px; }
QCheckBox { color: #4D5872; font-size: 11px; spacing: 7px; }
QDialog QPushButton {
    background: #EEF1F7; color: #29334A; border: 1px solid #E0E5EF; border-radius: 8px;
    min-height: 32px; padding: 0 13px; font-size: 12px; font-weight: 650;
}
QDialog QPushButton:hover { background: #E6EAF3; border-color: #D4DAE7; }
QListWidget#Palette { border: 1px solid #E3E7F0; border-radius: 10px; font-size: 12px; color: #15182A; }
QListWidget#Palette::item { padding: 10px 12px; border-bottom: 1px solid #F0F2F6; }
QListWidget#Palette::item:selected { background: #EEECFF; color: #4138C7; }
QListWidget#Palette::item:hover { background: #F6F7FC; }
QFrame#DangerCallout { background: #FFEDF0; border: 1px solid #FFD6DC; border-radius: 10px; }
QLabel#DangerTitle { color: #C9364C; font-size: 11px; font-weight: 800; }
QLabel#DangerBody { color: #6C5660; font-size: 10px; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 3px; }
QScrollBar::handle:vertical { background: #CCD3E2; border-radius: 4px; min-height: 28px; }
QScrollBar::handle:vertical:hover { background: #B6BFCE; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
"""


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------


class Sidebar(QWidget):
    """Left navigation rail with Qt signals for category and utility actions."""

    categoryChanged = Signal(str)
    healthRequested = Signal()
    settingsRequested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self.setFixedWidth(198)
        self._buttons: dict[str, QPushButton] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 17, 12, 14)
        layout.setSpacing(4)

        brand = QHBoxLayout()
        brand.setSpacing(9)
        badge = QLabel("S", self)
        badge.setObjectName("BrandBadge")
        name = QLabel("Sopshelf", self)
        name.setObjectName("BrandName")
        brand.addWidget(badge)
        brand.addWidget(name)
        brand.addStretch(1)
        layout.addLayout(brand)
        layout.addSpacing(20)

        head = QLabel("SECRETS", self)
        head.setObjectName("SectionHead")
        layout.addWidget(head)
        layout.addSpacing(4)

        for item in CATEGORIES:
            btn = QPushButton("All Secrets" if item == "All" else item, self)
            btn.setObjectName("Nav")
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda _checked=False, value=item: self._pick(value))
            layout.addWidget(btn)
            self._buttons[item] = btn

        layout.addSpacing(14)
        divider = QFrame(self)
        divider.setFrameShape(QFrame.HLine)
        divider.setStyleSheet("color: #E3E7F2;")
        layout.addWidget(divider)
        layout.addSpacing(10)

        for item in ("Health", "Settings"):
            btn = QPushButton(item, self)
            btn.setObjectName("Nav")
            btn.setCursor(Qt.PointingHandCursor)
            if item == "Health":
                btn.clicked.connect(self.healthRequested)
            else:
                btn.clicked.connect(self.settingsRequested)
            layout.addWidget(btn)
            self._buttons[item] = btn

        layout.addStretch(1)
        ver = QLabel(f"v{VERSION}", self)
        ver.setObjectName("SectionHead")
        layout.addWidget(ver)

        self._category = "All"
        self._sync_active()

    # -- public ----------------------------------------------------------
    @property
    def category(self) -> str:
        return self._category

    def set_category(self, category: str) -> None:
        if category in CATEGORIES:
            self._category = category
            self._sync_active()

    # -- internals -------------------------------------------------------
    def _pick(self, value: str) -> None:
        self.set_category(value)
        self.categoryChanged.emit(value)

    def _sync_active(self) -> None:
        for key, btn in self._buttons.items():
            btn.setProperty("active", key == self._category)
            # Refresh QSS for the dynamic property.
            btn.style().unpolish(btn)
            btn.style().polish(btn)


# ---------------------------------------------------------------------------
# SearchBar
# ---------------------------------------------------------------------------


class SearchBar(QLineEdit):
    """Filter field. ``textChanged`` is wired straight to ``apply_filter``."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("SearchBar")
        self.setPlaceholderText("Search secrets…   Ctrl K")
        self.setClearButtonEnabled(True)
        self.setMinimumWidth(290)
        self.setMaximumWidth(430)
        self.setMinimumHeight(36)


# ---------------------------------------------------------------------------
# SecretTable — masked-by-default model. Real values are only shown after
# an explicit reveal and are never stored in UserRole / tooltips / accessible descriptions.
# ---------------------------------------------------------------------------


class SecretTable(QTableView):
    COLUMNS = ("NAME", "CATEGORY", "VALUE", "USED BY", "MODIFIED")

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._model = QStandardItemModel(0, len(self.COLUMNS), self)
        self._model.setHorizontalHeaderLabels(list(self.COLUMNS))
        self.setModel(self._model)

        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setAlternatingRowColors(False)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(42)
        self.setShowGrid(False)
        self.setSortingEnabled(False)

        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.resizeSection(2, 130)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)

    # -- rows (masked only) ----------------------------------------------
    def set_rows(self, rows: list[tuple[str, str, str, str]]) -> None:
        """Replace all rows. ``rows`` holds (name, category, used_by, modified).

        The VALUE column always shows the mask. Caller must never pass
        real values here.
        """
        self._model.removeRows(0, self._model.rowCount())
        mono = QFont("Cascadia Mono", 10)
        mono.setStyleHint(QFont.Monospace)
        for name, category, used_by, modified in rows:
            name_item = QStandardItem(name)
            name_item.setFont(mono)
            name_item.setEditable(False)
            cat_item = QStandardItem(category)
            cat_item.setEditable(False)
            value_item = QStandardItem(MASKED)
            value_item.setFont(mono)
            value_item.setEditable(False)
            used_item = QStandardItem(used_by)
            used_item.setEditable(False)
            used_item.setTextAlignment(Qt.AlignCenter)
            mod_item = QStandardItem(modified)
            mod_item.setEditable(False)
            # Deliberately: no setData(value, UserRole), no tooltips.
            self._model.appendRow([name_item, cat_item, value_item, used_item, mod_item])

    def names(self) -> list[str]:
        return [self._model.item(r, 0).text() for r in range(self._model.rowCount())]

    def reveal_row(self, name: str, value: str) -> None:
        for row in range(self._model.rowCount()):
            if self._model.item(row, 0).text() == name:
                self._model.item(row, 2).setText(value)
                return

    def remask_row(self, name: str) -> None:
        for row in range(self._model.rowCount()):
            if self._model.item(row, 0).text() == name:
                self._model.item(row, 2).setText(MASKED)
                return

    def row_for(self, name: str) -> int | None:
        for row in range(self._model.rowCount()):
            if self._model.item(row, 0).text() == name:
                return row
        return None


# ---------------------------------------------------------------------------
# Inspector drawer
# ---------------------------------------------------------------------------


class NameCopyField(QLineEdit):
    """Read-only secret-name field with a focus-only trailing copy action."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("DetailName")
        self.setReadOnly(True)
        self.setAccessibleName("Secret name")
        self.setCursorPosition(0)

        self._copy_icon = QIcon(str(COPY_ICON_PATH))
        self._check_icon = QIcon(str(CHECK_ICON_PATH))
        self.copy_action = QAction(self._copy_icon, "Copy name", self)
        self.copy_action.setToolTip("Copy name")
        self.copy_action.setVisible(False)
        self.copy_action.triggered.connect(self._copy_name)
        self.addAction(self.copy_action, QLineEdit.TrailingPosition)

        self._copyable = False
        self._copy_reset_timer = QTimer(self)
        self._copy_reset_timer.setSingleShot(True)
        self._copy_reset_timer.setInterval(1200)
        self._copy_reset_timer.timeout.connect(self._restore_copy_action)

    def set_name(self, name: str | None) -> None:
        self._copy_reset_timer.stop()
        self._restore_copy_action()
        self._copyable = bool(name)
        self.setText(name or "Select a secret")
        self.setCursorPosition(0)
        self.copy_action.setVisible(self.hasFocus() and self._copyable)

    def focusInEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().focusInEvent(event)
        self.copy_action.setVisible(self._copyable)

    def focusOutEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().focusOutEvent(event)
        self.copy_action.setVisible(False)

    def _copy_name(self) -> None:
        if not self._copyable:
            return
        QApplication.clipboard().setText(self.text())
        self.copy_action.setIcon(self._check_icon)
        self.copy_action.setText("Copied")
        self.copy_action.setToolTip("Copied")
        self.copy_action.setVisible(True)
        self._copy_reset_timer.start()

    def _restore_copy_action(self) -> None:
        self.copy_action.setIcon(self._copy_icon)
        self.copy_action.setText("Copy name")
        self.copy_action.setToolTip("Copy name")
        self.copy_action.setVisible(self.hasFocus() and self._copyable)


class Inspector(QWidget):
    """Right-hand detail panel. Value label is masked unless explicitly revealed."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        mono = QFont("Cascadia Mono", 10)
        mono.setStyleHint(QFont.Monospace)
        name_font = QFont("Cascadia Mono", 13, QFont.Bold)
        name_font.setStyleHint(QFont.Monospace)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(0)

        head = QLabel("SECRET DETAILS", self)
        head.setObjectName("DetailHead")
        layout.addWidget(head)
        layout.addSpacing(8)

        self.name_label = NameCopyField(self)
        self.name_label.setFont(name_font)
        self.name_label.set_name(None)
        layout.addWidget(self.name_label)
        layout.addSpacing(14)

        self.value_label = QLabel(MASKED, self)
        self.value_label.setObjectName("ValueBox")
        self.value_label.setFont(mono)
        self.value_label.setWordWrap(True)
        self.value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.value_label)
        layout.addSpacing(12)

        form = QFormLayout()
        form.setSpacing(9)
        self.fields: dict[str, QLabel] = {}
        for key in ("Category", "Purpose", "Used by", "Storage", "Modified"):
            k = QLabel(key, self)
            k.setObjectName("FieldKey")
            v = QLabel("—", self)
            v.setObjectName("FieldVal")
            v.setWordWrap(True)
            v.setTextInteractionFlags(Qt.TextSelectableByMouse)
            form.addRow(k, v)
            self.fields[key] = v
        layout.addLayout(form)
        layout.addSpacing(12)

        divider = QFrame(self)
        divider.setFrameShape(QFrame.HLine)
        divider.setStyleSheet("color: #E3E7F2;")
        layout.addWidget(divider)
        layout.addSpacing(10)

        danger = QLabel("Danger zone", self)
        danger.setObjectName("DangerHead")
        layout.addWidget(danger)
        note = QLabel(
            "Delete always confirms and updates only encrypted SOPS storage.", self
        )
        note.setObjectName("DangerNote")
        note.setWordWrap(True)
        layout.addWidget(note)
        layout.addStretch(1)

    def show_secret(self, name: str, storage: str, modified: str) -> None:
        self.name_label.set_name(name)
        self.fields["Category"].setText(category_for_name(name))
        self.fields["Purpose"].setText(purpose_for_name(name))
        consumers = known_consumers(name)
        self.fields["Used by"].setText("\n".join(consumers) if consumers else "No registered consumers")
        self.fields["Storage"].setText(storage)
        self.fields["Modified"].setText(modified)

    def clear(self) -> None:
        self.name_label.set_name(None)
        for label in self.fields.values():
            label.setText("—")

    def set_revealed(self, value: str) -> None:
        self.value_label.setText(value)

    def set_masked(self) -> None:
        self.value_label.setText(MASKED)


# ---------------------------------------------------------------------------
# Toast / status bar
# ---------------------------------------------------------------------------


class Toast(QStatusBar):
    """Status bar with tone-colored transient messages (5 s auto-reset)."""

    TONES = ("info", "success", "warning", "danger")

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Toast")
        self.health_label = QLabel("Checking health…", self)
        self.health_label.setObjectName("Health")
        self.addWidget(self.health_label, 1)
        self.status_label = QLabel("Ready", self)
        self.status_label.setObjectName("StatusOk")
        self.addPermanentWidget(self.status_label)

        self._reset_timer = QTimer(self)
        self._reset_timer.setSingleShot(True)
        self._reset_timer.setInterval(5000)
        self._reset_timer.timeout.connect(self._reset)

    def showMessage(self, text: str, tone: str = "info", timeout: int = 5000) -> None:  # noqa: N802 - Qt override
        # Compat: QStatusBar.showMessage(message, timeout) may arrive positionally.
        if isinstance(tone, int):
            timeout = tone
            tone = "info"
        tone = tone if tone in self.TONES else "info"
        names = {
            "info": "StatusInfo",
            "success": "StatusOk",
            "warning": "StatusWarn",
            "danger": "StatusBad",
        }
        self.status_label.setObjectName(names[tone])
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)
        self.status_label.setText(text)
        self._reset_timer.stop()
        if timeout:
            self._reset_timer.setInterval(timeout)
            self._reset_timer.start()

    def set_health(self, text: str, ok: bool) -> None:
        self.health_label.setText(text)
        self.health_label.setStyleSheet(f"color: {'#475569' if ok else '#D97706'};")

    def _reset(self) -> None:
        self.status_label.setObjectName("StatusOk")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)
        self.status_label.setText("Ready")


# ---------------------------------------------------------------------------
# Dialogs
# ---------------------------------------------------------------------------


class SecretDialog(QDialog):
    """Add / update dialog. Value uses password echo; name is locked in edit mode.

    ``on_save`` runs ``validate_secret_name`` + ``store.set_secret`` and
    returns an error string (or ``None`` on success). Failures keep the
    dialog open so typed input is not lost; the value field is wiped only
    after a successful save or an explicit cancel.
    """

    def __init__(
        self,
        existing: str | None,
        on_save: Callable[[str, str], str | None] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Update secret" if existing else "Add secret")
        self.setModal(True)
        self.setMinimumWidth(470)
        self._on_save = on_save or (lambda _name, _value: None)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(7)

        eyebrow = QLabel("ENCRYPTED SOPS STORAGE", self)
        eyebrow.setObjectName("DialogEyebrow")
        layout.addWidget(eyebrow)

        title = QLabel("Update secret" if existing else "Add new secret", self)
        title.setObjectName("DlgTitle")
        layout.addWidget(title)
        hint = QLabel("The value is passed to SOPS over stdin and never placed on the command line.", self)
        hint.setObjectName("DlgHint")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        layout.addSpacing(8)

        name_label = QLabel("Name", self)
        name_label.setObjectName("FieldLabel")
        layout.addWidget(name_label)
        self.name_edit = QLineEdit(self)
        self.name_edit.setObjectName("Field")
        self.name_edit.setAccessibleName("Secret name")
        if existing:
            self.name_edit.setText(existing)
            self.name_edit.setDisabled(True)
        layout.addWidget(self.name_edit)
        layout.addSpacing(4)

        value_label = QLabel("New value" if existing else "Value", self)
        value_label.setObjectName("FieldLabel")
        layout.addWidget(value_label)
        self.value_edit = QLineEdit(self)
        self.value_edit.setObjectName("Field")
        self.value_edit.setAccessibleName("Secret value")
        self.value_edit.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.value_edit)

        self.show_box = QCheckBox("Show value", self)
        self.show_box.setAccessibleName("Reveal secret value")
        self.show_box.toggled.connect(
            lambda on: self.value_edit.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password)
        )
        layout.addWidget(self.show_box)
        layout.addSpacing(8)

        buttons = QDialogButtonBox(QDialogButtonBox.Cancel, self)
        buttons.setObjectName("DialogActions")
        save_btn = QPushButton("Save encrypted", self)
        save_btn.setObjectName("Primary")
        save_btn.setAccessibleName("Save encrypted secret")
        save_btn.setDefault(True)
        save_btn.clicked.connect(self._try_save)
        buttons.addButton(save_btn, QDialogButtonBox.AcceptRole)
        cancel_btn = buttons.button(QDialogButtonBox.Cancel)
        if cancel_btn is not None:
            cancel_btn.setObjectName("Ghost")
            cancel_btn.setCursor(Qt.PointingHandCursor)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.save_button = save_btn
        self.cancel_button = cancel_btn
        self.setTabOrder(self.name_edit, self.value_edit)
        self.setTabOrder(self.value_edit, self.show_box)
        self.setTabOrder(self.show_box, save_btn)
        if cancel_btn is not None:
            self.setTabOrder(save_btn, cancel_btn)

        (self.value_edit if existing else self.name_edit).setFocus()

        # Match the tkinter clipping fix: never let the dialog's minimum
        # height fall below the layout's requested height.  Query after the
        # layout is complete so Qt can account for the active DPI/font metrics.
        self.ensurePolished()
        self.adjustSize()
        required = self.sizeHint()
        self.setMinimumSize(
            max(self.minimumWidth(), required.width()),
            max(360, required.height()),
        )
        self.resize(max(self.width(), self.minimumWidth()), max(self.height(), self.minimumHeight()))

    @property
    def secret_name(self) -> str:
        return self.name_edit.text()

    @property
    def secret_value(self) -> str:
        return self.value_edit.text()

    def clear_value(self) -> None:
        self.value_edit.clear()

    def _try_save(self) -> None:
        error = self._on_save(self.secret_name, self.secret_value)
        if error is not None:
            QMessageBox.critical(self, APP_NAME, error)
            return
        self.clear_value()
        self.accept()

    def reject(self) -> None:
        self.clear_value()
        super().reject()


class CommandPalette(QDialog):
    """Ctrl+Shift+P quick-action list."""

    def __init__(self, actions: list[tuple[str, Callable[[], None]]], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Command palette")
        self.setModal(True)
        self.resize(520, 330)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        title = QLabel("Command palette", self)
        title.setObjectName("DlgTitle")
        layout.addWidget(title)

        self._list = QListWidget(self)
        self._list.setObjectName("Palette")
        self._callbacks: list[Callable[[], None]] = []
        for label, callback in actions:
            QListWidgetItem(label, self._list)
            self._callbacks.append(callback)
        self._list.itemActivated.connect(lambda _item: self._run_current())
        self._list.itemClicked.connect(lambda _item: self._run_current())
        layout.addWidget(self._list)
        self._list.setFocus()

    def _run_current(self) -> None:
        row = self._list.currentRow()
        self.accept()
        if 0 <= row < len(self._callbacks):
            self._callbacks[row]()


class HealthDialog(QDialog):
    """Value-free health readout from :func:`collect_health`."""

    def __init__(self, store: SopsStore, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Sopshelf health")
        self.setModal(True)
        self.setMinimumWidth(420)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 22)
        eyebrow = QLabel("VAULT HEALTH", self)
        eyebrow.setObjectName("DialogEyebrow")
        layout.addWidget(eyebrow)
        title = QLabel("Sopshelf health", self)
        title.setObjectName("DlgTitle")
        layout.addWidget(title)
        health = collect_health(store)
        lines = (
            f"SOPS executable: {'OK' if health['sops'] else 'Missing'}",
            f"Encrypted store: {'OK' if health['secret_file'] else 'Missing'}",
            f"age identity: {'OK' if health['age_identity'] else 'Missing'}",
            f"Decrypt check: {'OK' if health['decrypt'] else 'Failed'}",
            f"Recovery backup: {'OK' if health['backup'] else 'Missing'}",
        )
        body = QLabel("\n".join(lines), self)
        body.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(body)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok, self)
        ok_btn = buttons.button(QDialogButtonBox.Ok)
        if ok_btn is not None:
            ok_btn.setObjectName("Secondary")
            ok_btn.setCursor(Qt.PointingHandCursor)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)


class SettingsDialog(QDialog):
    """Paths only — never values, keys, or decrypted content."""

    def __init__(self, store: SopsStore, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Sopshelf settings")
        self.setModal(True)
        self.setMinimumWidth(460)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 22)
        eyebrow = QLabel("LOCAL CONFIGURATION", self)
        eyebrow.setObjectName("DialogEyebrow")
        layout.addWidget(eyebrow)
        title = QLabel("Sopshelf settings", self)
        title.setObjectName("DlgTitle")
        layout.addWidget(title)
        body = QLabel(
            "Encrypted store\n"
            f"{store.secret_file}\n\n"
            "SOPS\n"
            f"{store.sops_exe}\n\n"
            "age identity\n"
            f"{default_identity_file()}\n\n"
            "Recovery backup\n"
            f"{default_backup_file()}",
            self,
        )
        body.setTextInteractionFlags(Qt.TextSelectableByMouse)
        body.setWordWrap(True)
        layout.addWidget(body)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok, self)
        ok_btn = buttons.button(QDialogButtonBox.Ok)
        if ok_btn is not None:
            ok_btn.setObjectName("Secondary")
            ok_btn.setCursor(Qt.PointingHandCursor)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)


class PasswordDialog(QDialog):
    """Compat-only gate. Reuses ``sopshelf_auth`` save/verify; no new crypto logic."""

    def __init__(self, title: str, message: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumWidth(450)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 22)
        eyebrow = QLabel("PROTECTED LOCAL VAULT", self)
        eyebrow.setObjectName("DialogEyebrow")
        layout.addWidget(eyebrow)
        head = QLabel(title, self)
        head.setObjectName("DlgTitle")
        layout.addWidget(head)
        hint = QLabel(message, self)
        hint.setObjectName("DlgHint")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        self.password_edit = QLineEdit(self)
        self.password_edit.setObjectName("Field")
        self.password_edit.setAccessibleName("Sopshelf app password")
        self.password_edit.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_edit)
        buttons = QDialogButtonBox(QDialogButtonBox.Cancel, self)
        buttons.setObjectName("DialogActions")
        ok_btn = QPushButton("Continue", self)
        ok_btn.setObjectName("Primary")
        ok_btn.setAccessibleName("Continue")
        ok_btn.setDefault(True)
        ok_btn.clicked.connect(self.accept)
        buttons.addButton(ok_btn, QDialogButtonBox.AcceptRole)
        cancel_btn = buttons.button(QDialogButtonBox.Cancel)
        if cancel_btn is not None:
            cancel_btn.setObjectName("Ghost")
            cancel_btn.setCursor(Qt.PointingHandCursor)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.setTabOrder(self.password_edit, ok_btn)
        if cancel_btn is not None:
            self.setTabOrder(ok_btn, cancel_btn)
        self.password_edit.setFocus()

        self.ensurePolished()
        self.adjustSize()
        required = self.sizeHint()
        self.setMinimumSize(
            max(self.minimumWidth(), required.width()),
            max(220, required.height()),
        )
        self.resize(max(self.width(), self.minimumWidth()), max(self.height(), self.minimumHeight()))

    def password(self) -> str | None:
        if self.result() != QDialog.Accepted:
            return None
        value = self.password_edit.text()
        self.password_edit.clear()
        return value

    def reject(self) -> None:
        self.password_edit.clear()
        super().reject()


class DeleteSecretDialog(QDialog):
    """Styled destructive confirmation matching the D. Vibrant component sheet."""

    def __init__(self, secret_name: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Delete secret")
        self.setModal(True)
        self.setMinimumWidth(470)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(8)

        eyebrow = QLabel("ENCRYPTED SOPS STORAGE", self)
        eyebrow.setObjectName("DialogEyebrow")
        layout.addWidget(eyebrow)

        title = QLabel(f"Delete {secret_name}?", self)
        title.setObjectName("DlgTitle")
        title.setWordWrap(True)
        layout.addWidget(title)

        callout = QFrame(self)
        callout.setObjectName("DangerCallout")
        callout_layout = QVBoxLayout(callout)
        callout_layout.setContentsMargins(12, 10, 12, 10)
        callout_layout.setSpacing(3)
        callout_title = QLabel("Encrypted storage will be modified", callout)
        callout_title.setObjectName("DangerTitle")
        callout_body = QLabel(
            "The secret is removed from the SOPS vault. An encrypted history copy is retained.",
            callout,
        )
        callout_body.setObjectName("DangerBody")
        callout_body.setWordWrap(True)
        callout_layout.addWidget(callout_title)
        callout_layout.addWidget(callout_body)
        layout.addWidget(callout)

        buttons = QDialogButtonBox(QDialogButtonBox.Cancel, self)
        cancel_btn = buttons.button(QDialogButtonBox.Cancel)
        if cancel_btn is not None:
            cancel_btn.setObjectName("Ghost")
            cancel_btn.setCursor(Qt.PointingHandCursor)
            cancel_btn.setDefault(True)
        delete_btn = QPushButton("Delete secret", self)
        delete_btn.setObjectName("Danger")
        delete_btn.setCursor(Qt.PointingHandCursor)
        delete_btn.setAccessibleName("Delete secret")
        delete_btn.clicked.connect(self.accept)
        buttons.addButton(delete_btn, QDialogButtonBox.DestructiveRole)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.cancel_button = cancel_btn
        self.delete_button = delete_btn
        if cancel_btn is not None:
            self.setTabOrder(cancel_btn, delete_btn)

        self.ensurePolished()
        self.adjustSize()
        required = self.sizeHint()
        self.setMinimumSize(max(470, required.width()), max(240, required.height()))


# ---------------------------------------------------------------------------
# MainWindow
# ---------------------------------------------------------------------------


class MainWindow(QMainWindow):
    def __init__(self, store: SopsStore | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.store = store or SopsStore()
        self.category = "All"
        self.all_names: list[str] = []
        self.revealed_name: str | None = None

        self.setWindowTitle(f"{APP_NAME} {VERSION}")
        icon = app_icon()
        if not icon.isNull():
            self.setWindowIcon(icon)
        self.resize(1220, 760)
        self.setMinimumSize(980, 620)

        # Timers: explicit reveal windows and transient UI state.
        self.reveal_timer = QTimer(self)
        self.reveal_timer.setSingleShot(True)
        self.reveal_timer.setInterval(15000)
        self.reveal_timer.timeout.connect(self.remask)

        self.clipboard_timer = QTimer(self)
        self.clipboard_timer.setSingleShot(True)
        self.clipboard_timer.setInterval(30000)
        self.clipboard_timer.timeout.connect(self.clear_clipboard)
        self.last_copied: str | None = None

        self._build()
        self._shortcuts()
        self.refresh()

    # -- construction ----------------------------------------------------
    def _build(self) -> None:
        shell = QWidget(self)
        shell.setObjectName("Shell")
        root = QHBoxLayout(shell)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.sidebar = Sidebar(shell)
        self.sidebar.categoryChanged.connect(self.set_category)
        self.sidebar.healthRequested.connect(self.show_health)
        self.sidebar.settingsRequested.connect(self.show_settings)
        root.addWidget(self.sidebar)

        right = QWidget(shell)
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(16, 14, 16, 0)
        right_layout.setSpacing(12)

        # Top bar: vault context + search + primary action.
        topbar = QFrame(right)
        topbar.setObjectName("TopBar")
        top = QHBoxLayout(topbar)
        top.setContentsMargins(16, 12, 14, 12)
        top.setSpacing(12)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        eyebrow = QLabel("LOCAL SECRET VAULT", topbar)
        eyebrow.setObjectName("Eyebrow")
        title_col.addWidget(eyebrow)

        title_row = QHBoxLayout()
        title_row.setSpacing(8)
        title = QLabel("Secrets", topbar)
        title.setObjectName("Title")
        self.count_label = QLabel("0", topbar)
        self.count_label.setObjectName("Count")
        title_row.addWidget(title)
        title_row.addWidget(self.count_label)
        title_row.addStretch(1)
        title_col.addLayout(title_row)

        vault_path = QLabel(str(self.store.secret_file), topbar)
        vault_path.setObjectName("VaultPath")
        vault_path.setTextInteractionFlags(Qt.TextSelectableByMouse)
        vault_path.setMaximumWidth(430)
        title_col.addWidget(vault_path)
        top.addLayout(title_col, 1)
        top.addStretch(1)
        self.search = SearchBar(topbar)
        self.search.textChanged.connect(lambda _text: self.apply_filter())
        top.addWidget(self.search)
        self.add_button = QPushButton("Add secret", topbar)
        self.add_button.setObjectName("Primary")
        self.add_button.setCursor(Qt.PointingHandCursor)
        self.add_button.clicked.connect(self.add_secret)
        top.addWidget(self.add_button)
        right_layout.addWidget(topbar)

        # Content: table card + inspector drawer.
        content = QSplitter(right)
        table_card = QFrame(content)
        table_card.setObjectName("Card")
        card_layout = QVBoxLayout(table_card)
        card_layout.setContentsMargins(10, 10, 10, 10)
        card_layout.setSpacing(8)

        table_head = QHBoxLayout()
        table_head.setContentsMargins(2, 0, 2, 0)
        table_head.setSpacing(8)
        table_label = QLabel("ENCRYPTED SECRETS", table_card)
        table_label.setObjectName("SectionHead")
        table_head.addWidget(table_label)
        table_head.addStretch(1)
        helper = QLabel("Reveal is always explicit", table_card)
        helper.setObjectName("VaultPath")
        table_head.addWidget(helper)
        card_layout.addLayout(table_head)

        self.table = SecretTable(table_card)
        self.table.selectionModel().selectionChanged.connect(lambda *_: self.on_select())
        card_layout.addWidget(self.table, 1)

        action_bar = QFrame(table_card)
        action_bar.setObjectName("ActionBar")
        actions = QHBoxLayout(action_bar)
        actions.setContentsMargins(7, 5, 7, 5)
        actions.setSpacing(7)
        self.reveal_button = QPushButton("Reveal", action_bar)
        self.reveal_button.setObjectName("Secondary")
        self.reveal_button.clicked.connect(self.toggle_reveal)
        self.copy_button = QPushButton("Copy", action_bar)
        self.copy_button.setObjectName("Secondary")
        self.copy_button.clicked.connect(self.copy_selected)
        self.run_button = QPushButton("Run with secret", action_bar)
        self.run_button.setObjectName("Secondary")
        self.run_button.clicked.connect(self.run_selected)
        self.edit_button = QPushButton("Edit", action_bar)
        self.edit_button.setObjectName("Ghost")
        self.edit_button.clicked.connect(self.edit_selected)
        self.delete_button = QPushButton("Delete", action_bar)
        self.delete_button.setObjectName("Danger")
        self.delete_button.clicked.connect(self.delete_selected)
        for btn in (self.reveal_button, self.copy_button, self.run_button):
            actions.addWidget(btn)
        actions.addStretch(1)
        actions.addWidget(self.edit_button)
        actions.addWidget(self.delete_button)
        card_layout.addWidget(action_bar)
        content.addWidget(table_card)

        inspector_card = QFrame(content)
        inspector_card.setObjectName("InspectorCard")
        inspector_layout = QVBoxLayout(inspector_card)
        inspector_layout.setContentsMargins(0, 0, 0, 0)
        self.inspector = Inspector(inspector_card)
        inspector_layout.addWidget(self.inspector)
        content.addWidget(inspector_card)
        content.setStretchFactor(0, 1)
        content.setStretchFactor(1, 0)
        content.setSizes([900, 330])
        right_layout.addWidget(content, 1)

        right_layout.addSpacing(0)
        root.addWidget(right, 1)
        self.setCentralWidget(shell)

        self.toast = Toast(self)
        self.setStatusBar(self.toast)

        # Keyboard focus order: search -> table -> actions -> add.
        self.setTabOrder(self.search, self.table)
        self.setTabOrder(self.table, self.reveal_button)
        self.setTabOrder(self.reveal_button, self.copy_button)
        self.setTabOrder(self.copy_button, self.run_button)
        self.setTabOrder(self.run_button, self.edit_button)
        self.setTabOrder(self.edit_button, self.delete_button)
        self.setTabOrder(self.delete_button, self.add_button)

    def _shortcuts(self) -> None:
        focus_search = QShortcut(QKeySequence("Ctrl+K"), self)
        focus_search.setContext(Qt.ApplicationShortcut)
        focus_search.activated.connect(self.search.setFocus)
        palette = QShortcut(QKeySequence("Ctrl+Shift+P"), self)
        palette.setContext(Qt.ApplicationShortcut)
        palette.activated.connect(self.command_palette)
        refresh = QShortcut(QKeySequence(Qt.Key_F5), self)
        refresh.setContext(Qt.ApplicationShortcut)
        refresh.activated.connect(self.refresh)
        escape = QShortcut(QKeySequence(Qt.Key_Escape), self)
        escape.setContext(Qt.ApplicationShortcut)
        escape.activated.connect(self.remask)

    # -- store <-> view ---------------------------------------------------
    def refresh(self) -> None:
        try:
            self.all_names = sorted(self.store.list_names())
        except (SopsError, OSError) as exc:
            self.all_names = []
            self.set_status(str(exc), "danger")
        self.apply_filter()
        self.refresh_health()

    def apply_filter(self) -> None:
        previous = self.selected_name()
        query = self.search.text().strip().lower()
        rows: list[tuple[str, str, str, str]] = []
        modified = self.store.modified_at()
        modified_text = modified.strftime("%Y-%m-%d %H:%M") if modified else "—"
        for name in self.all_names:
            category = category_for_name(name)
            if self.category != "All" and category != self.category:
                continue
            if query and query not in name.lower() and query not in category.lower():
                continue
            consumers = known_consumers(name)
            rows.append((name, category, str(len(consumers)) if consumers else "—", modified_text))
        self.table.set_rows(rows)
        self.count_label.setText(str(len(rows)))
        self.sidebar.set_category(self.category)
        if previous is not None:
            self.select_name(previous, silent_no_match=True)
        if self.selected_name() is None:
            self.inspector.clear()

    def refresh_health(self) -> None:
        health = collect_health(self.store)
        text = "   •   ".join(
            (
                f"SOPS {'OK' if health['sops'] else 'Missing'}",
                f"age {'OK' if health['age_identity'] else 'Missing'}",
                f"Decrypt {'OK' if health['decrypt'] else 'Failed'}",
                f"Backup {'OK' if health['backup'] else 'Missing'}",
            )
        )
        self.toast.set_health(text, all(health.values()))

    def set_category(self, category: str) -> None:
        if category in CATEGORIES:
            self.category = category
            self.apply_filter()

    # -- selection ---------------------------------------------------------
    def selected_name(self) -> str | None:
        index = self.table.currentIndex()
        if not index.isValid():
            return None
        item = self.table._model.item(index.row(), 0)
        return item.text() if item is not None else None

    def select_name(self, name: str, silent_no_match: bool = False) -> None:
        row = self.table.row_for(name)
        if row is None:
            if not silent_no_match:
                self.set_status("Select a secret first.", "warning")
            return
        index = self.table._model.index(row, 0)
        self.table.setCurrentIndex(index)
        self.table.selectRow(row)
        self.table.scrollTo(index)
        self.on_select()

    def on_select(self) -> None:
        self.remask()
        name = self.selected_name()
        if not name:
            self.inspector.clear()
            return
        modified = self.store.modified_at()
        self.inspector.show_secret(
            name,
            str(self.store.secret_file),
            modified.strftime("%Y-%m-%d %H:%M:%S") if modified else "—",
        )

    # -- reveal / clipboard --------------------------------------------------
    def toggle_reveal(self) -> None:
        name = self.selected_name()
        if not name:
            self.set_status("Select a secret first.", "warning")
            return
        if self.revealed_name == name:
            self.remask()
            return
        try:
            value = self.store.get_secret(name)
        except SopsError as exc:
            self.set_status(str(exc), "danger")
            return
        self.revealed_name = name
        self.inspector.set_revealed(value)
        self.table.reveal_row(name, value)
        self.reveal_button.setText("Hide")
        self.reveal_timer.start()
        self.set_status("Secret revealed for 15 seconds.", "info")

    def remask(self) -> None:
        self.reveal_timer.stop()
        if self.revealed_name is not None:
            self.table.remask_row(self.revealed_name)
        self.inspector.set_masked()
        self.reveal_button.setText("Reveal")
        self.revealed_name = None

    def copy_selected(self) -> None:
        name = self.selected_name()
        if not name:
            self.set_status("Select a secret first.", "warning")
            return
        try:
            value = self.store.get_secret(name)
        except SopsError as exc:
            self.set_status(str(exc), "danger")
            return
        QApplication.clipboard().setText(value)
        self.last_copied = value
        self.clipboard_timer.start()
        self.set_status("Copied — clipboard clears in 30 seconds.", "success")

    def clear_clipboard(self) -> None:
        self.clipboard_timer.stop()
        if self.last_copied is not None:
            try:
                current = QApplication.clipboard().text()
            except Exception:
                current = None
            if current == self.last_copied:
                QApplication.clipboard().clear()
        self.last_copied = None

    # -- mutations (delegated to SopsStore: stdin writes, encrypted backups) --
    def add_secret(self) -> None:
        self.secret_dialog(None)

    def edit_selected(self) -> None:
        name = self.selected_name()
        if name:
            self.secret_dialog(name)
        else:
            self.set_status("Select a secret first.", "warning")

    def secret_dialog(self, existing: str | None) -> None:
        def on_save(raw_name: str, raw_value: str) -> str | None:
            try:
                name = validate_secret_name(raw_name)
                self.store.set_secret(name, raw_value)
            except (ValueError, SopsError) as exc:
                return str(exc)
            self.refresh()
            self.select_name(name)
            self.set_status("Secret saved and encrypted.", "success")
            return None

        SecretDialog(existing, on_save, self).exec()

    def delete_selected(self) -> None:
        name = self.selected_name()
        if not name:
            self.set_status("Select a secret first.", "warning")
            return
        if DeleteSecretDialog(name, self).exec() != QDialog.Accepted:
            return
        try:
            self.store.delete_secret(name)
        except SopsError as exc:
            self.set_status(str(exc), "danger")
            return
        self.refresh()
        self.set_status("Secret deleted from encrypted storage.", "success")

    def run_selected(self) -> None:
        name = self.selected_name()
        if not name:
            self.set_status("Select a secret first.", "warning")
            return
        try:
            open_powershell_with_secret(self.store, name)
        except (SopsError, OSError) as exc:
            self.set_status(str(exc), "danger")
            return
        self.set_status(f"Opened isolated PowerShell with {name}.", "success")

    # -- palette / health / settings / status --------------------------------
    def command_palette(self) -> None:
        from PySide6.QtGui import QDesktopServices
        from PySide6.QtCore import QUrl

        actions: list[tuple[str, Callable[[], None]]] = [
            ("Copy selected value", self.copy_selected),
            ("Reveal / hide selected value", self.toggle_reveal),
            ("Open PowerShell with selected secret", self.run_selected),
            ("Refresh encrypted store", self.refresh),
            (
                "Open vault folder",
                lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.store.secret_file.parent))),
            ),
        ]
        CommandPalette(actions, self).exec()

    def show_health(self) -> None:
        HealthDialog(self.store, self).exec()

    def show_settings(self) -> None:
        SettingsDialog(self.store, self).exec()

    def set_status(self, text: str, tone: str = "info") -> None:
        self.toast.showMessage(text, tone)

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override
        self.remask()
        self.clear_clipboard()
        super().closeEvent(event)

    def close(self) -> bool:
        return super().close()


# Backwards-compatible alias (the tkinter-era entry point was ``App``).
App = MainWindow


# ---------------------------------------------------------------------------
# Value-free health check + startup gate
# ---------------------------------------------------------------------------


def run_check() -> int:
    store = SopsStore()
    health = collect_health(store)
    try:
        count = len(store.list_names()) if health["decrypt"] else 0
    except SopsError:
        count = 0
    print(
        " ".join(
            (
                f"SOPS={'OK' if health['sops'] else 'FAIL'}",
                f"STORE={'OK' if health['secret_file'] else 'FAIL'}",
                f"AGE={'OK' if health['age_identity'] else 'FAIL'}",
                f"DECRYPT={'OK' if health['decrypt'] else 'FAIL'}",
                f"BACKUP={'OK' if health['backup'] else 'FAIL'}",
                f"SECRETS={count}",
            )
        )
    )
    return 0 if all(health.values()) else 1


def _ask_app_password(title: str, message: str) -> str | None:
    dialog = PasswordDialog(title, message)
    dialog.exec()
    return dialog.password()


def authenticate() -> bool:
    auth_file = default_auth_file()
    if not auth_configured(auth_file):
        while True:
            first = _ask_app_password(
                "Set Sopshelf password",
                "Create a local app password. It must be at least 8 characters. "
                "The password itself is never stored.",
            )
            if first is None:
                return False
            if len(first) < 8:
                QMessageBox.critical(None, APP_NAME, "Use at least 8 characters.")
                continue
            second = _ask_app_password(
                "Confirm Sopshelf password", "Enter the same password again to confirm it."
            )
            if second is None:
                return False
            if first != second:
                QMessageBox.critical(None, APP_NAME, "Passwords did not match.")
                continue
            save_password(first, auth_file)
            return True

    for _attempt in range(5):
        value = _ask_app_password(
            "Unlock Sopshelf", "Enter the local Sopshelf app password to continue."
        )
        if value is None:
            return False
        if verify_password(value, auth_file):
            return True
        QMessageBox.critical(None, APP_NAME, "Incorrect password.")
    QMessageBox.critical(None, APP_NAME, "Too many incorrect attempts. Sopshelf will close.")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Lightweight local SOPS + age GUI")
    parser.add_argument("--check", action="store_true", help="Run a value-free environment health check")
    args = parser.parse_args()
    if args.check:
        return run_check()

    try:
        from PySide6.QtCore import Qt as _Qt

        if hasattr(QApplication, "setHighDpiScaleFactorRoundingPolicy"):
            QApplication.setHighDpiScaleFactorRoundingPolicy(
                _Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
            )
    except Exception:
        pass

    _set_windows_app_id()
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(VERSION)
    app.setOrganizationName(APP_NAME)
    icon = app_icon()
    if not icon.isNull():
        app.setWindowIcon(icon)
    app.setStyle("Fusion")
    app.setStyleSheet(APP_QSS)

    if not authenticate():
        return 1
    window = MainWindow()
    window.show()
    return int(app.exec())


if __name__ == "__main__":
    raise SystemExit(main())
