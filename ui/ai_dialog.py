"""Result dialog for the AI assistant's reply (renders Markdown)."""
from __future__ import annotations

from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QDialog, QHBoxLayout, QLabel, QPushButton,
                               QTextBrowser, QVBoxLayout)


class AiResultDialog(QDialog):
    def __init__(self, text: str, truncated: bool = False, parent=None):
        super().__init__(parent)
        self.setWindowTitle("AI assistant")
        self.resize(800, 640)

        self.browser = QTextBrowser()
        self.browser.setMarkdown(text or "(empty reply)")
        self.browser.setOpenExternalLinks(True)

        copy_btn = QPushButton("Copy to clipboard")
        copy_btn.clicked.connect(self._copy)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(copy_btn)
        buttons.addWidget(close_btn)

        layout = QVBoxLayout(self)
        if truncated:
            banner = QLabel(
                "⚠️ The reply was truncated — the model hit the token limit "
                "(reasoning models spend a lot of tokens before answering). "
                "Increase “Max response tokens” in Tools → AI assistant settings… and ask "
                "again.")
            banner.setWordWrap(True)
            banner.setStyleSheet(
                "background: palette(base); border: 1px solid palette(mid); "
                "border-radius: 6px; padding: 6px 10px;")
            layout.addWidget(banner)
        layout.addWidget(self.browser)
        layout.addLayout(buttons)

    def _copy(self):
        QGuiApplication.clipboard().setText(self.browser.toPlainText())
