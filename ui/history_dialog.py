"""History of earlier checks: list on top, details below (stacks on narrow
screens), comparison with the run before it."""
from __future__ import annotations

import datetime

from PySide6.QtCore import QUrl, Qt
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (QDialog, QHBoxLayout, QListWidget,
                               QListWidgetItem, QMessageBox, QPushButton,
                               QSplitter, QTextBrowser, QVBoxLayout)

from nwsolver.engine import history
from nwsolver.engine.context import (SUITE_TITLES, changes_text,
                                     render_markdown)
from nwsolver.ui.widgets import WrapLabel

_MARK = {"ok": "✓", "warn": "!", "fail": "✗", "unknown": "–"}


class HistoryDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("History of checks")
        screen = QGuiApplication.primaryScreen()
        if screen is not None:
            a = screen.availableGeometry()
            self.resize(min(900, int(a.width() * 0.9)),
                        min(720, int(a.height() * 0.85)))
        self.items = history.load()
        self.list = QListWidget()
        self.view = QTextBrowser()
        self.view.setOpenExternalLinks(True)
        for i, h in enumerate(self.items):
            t = datetime.datetime.fromtimestamp(h.get("timestamp", 0))
            d = h["diagnosis"]
            label = (f"{_MARK.get(d['state'], '–')}  {t:%d %b %H:%M}  ·  "
                     f"{SUITE_TITLES.get(h['suite'], h['suite'])}"
                     + (f" ({h['target']})" if h.get("target") else "")
                     + f"  —  {d['headline']}")
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, i)
            self.list.addItem(item)
        self.list.currentRowChanged.connect(self._show)

        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.list)
        split.addWidget(self.view)
        split.setStretchFactor(1, 2)

        folder = QPushButton("Open folder")
        folder.clicked.connect(lambda: QDesktopServices.openUrl(
            QUrl.fromLocalFile(history.history_dir())))
        clear = QPushButton("Delete history…")
        clear.clicked.connect(self._clear)
        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        buttons = QHBoxLayout()
        buttons.addWidget(folder)
        buttons.addWidget(clear)
        buttons.addStretch(1)
        buttons.addWidget(close)

        lay = QVBoxLayout(self)
        if not self.items:
            lay.addWidget(WrapLabel("No checks have been saved yet. Every "
                                    "finished check is stored here "
                                    "automatically.", "muted"))
        lay.addWidget(split, 1)
        lay.addLayout(buttons)
        if self.items:
            self.list.setCurrentRow(0)

    def _show(self, row: int):
        if not 0 <= row < len(self.items):
            self.view.clear()
            return
        h = self.items[row]
        prev = history.previous(h, self.items)
        head = ""
        if prev is not None:
            head = "> " + changes_text(prev, h) + "\n\n"
        ctx = {"generated_at": h.get("finished_at"),
               "app": {"version": ""}, "environment": {}, "network":
               h.get("network") or {}, "runs": [h], "repeated_checks": [],
               "timeline": []}
        md = render_markdown(ctx).split("## ", 2)
        body = "## " + md[2] if len(md) > 2 else render_markdown(ctx)
        self.view.setMarkdown(head + body)

    def _clear(self):
        if QMessageBox.question(
                self, "Delete history",
                "Delete all saved checks? This cannot be undone.") != \
                QMessageBox.StandardButton.Yes:
            return
        history.clear()
        self.items = []
        self.list.clear()
        self.view.clear()
