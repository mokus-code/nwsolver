"""Export dialog: AI prompt / Markdown report / JSON, with a live preview
and switches to mask identifiers before anything leaves the computer."""
from __future__ import annotations

import os
import time
from datetime import datetime

from PySide6.QtGui import QFontDatabase, QGuiApplication
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog, QFileDialog,
                               QHBoxLayout, QLabel, QMessageBox,
                               QPlainTextEdit, QPushButton, QVBoxLayout,
                               QWidget)

from nwsolver.engine import history
from nwsolver.engine.context import (MaskOptions, Masker, build_context,
                                     render_json, render_markdown, ssids_of)
from nwsolver.engine.report import build_ai_context
from nwsolver.ui.widgets import FlowLayout, WrapLabel, set_role

FORMATS = [("ai", "AI prompt (paste into ChatGPT, Claude, Gemini…)", "md"),
           ("md", "Markdown technical report", "md"),
           ("json", "JSON (structured data)", "json")]


def recent_history(hours: float = 24.0) -> list[dict]:
    cutoff = time.time() - hours * 3600
    return [h for h in history.load(100) if h.get("timestamp", 0) >= cutoff]


def render(fmt: str, env: dict, runs: dict, opts: MaskOptions,
           include_history: bool) -> str:
    hist = recent_history() if include_history else []
    context = build_context(env, runs, hist)
    masker = Masker(opts, ssids_of(context), env.get("hostname", ""),
                    env.get("user", ""))
    if fmt == "ai":
        return build_ai_context(env, runs, hist, masker=masker)
    masked = masker.data(context)
    return render_json(masked) if fmt == "json" else render_markdown(masked)


class ExportDialog(QDialog):
    def __init__(self, env: dict, runs: dict, settings, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Export diagnosis")
        self.env, self.runs, self.settings = env, runs, settings
        screen = QGuiApplication.primaryScreen()
        if screen is not None:
            a = screen.availableGeometry()
            self.resize(min(900, int(a.width() * 0.9)),
                        min(720, int(a.height() * 0.85)))

        self.fmt = QComboBox()
        for key, label, _ext in FORMATS:
            self.fmt.addItem(label, key)
        intro = WrapLabel("Everything is prepared locally. Check the preview "
                          "and choose what to hide before copying or "
                          "saving. Passwords, tokens and keys are never "
                          "included.", "muted")

        def box(text, key, default):
            cb = QCheckBox(text)
            cb.setChecked(str(self.settings.value(f"export/{key}",
                                                  default)).lower()
                          in ("true", "1"))
            cb.toggled.connect(self._refresh)
            return cb

        self.cb_public = box("Hide public IP", "public_ip", True)
        self.cb_local = box("Hide local IPs", "local_ip", False)
        self.cb_mac = box("Hide MAC / BSSID", "mac", True)
        self.cb_ssid = box("Hide Wi-Fi name", "ssid", True)
        self.cb_host = box("Hide computer & user name", "host", True)
        self.cb_hist = box("Include earlier checks (24 h)", "history", True)
        masks = QWidget()
        flow = FlowLayout(masks, spacing=12)
        for cb in (self.cb_public, self.cb_local, self.cb_mac, self.cb_ssid,
                   self.cb_host, self.cb_hist):
            flow.addWidget(cb)

        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setFont(QFontDatabase.systemFont(
            QFontDatabase.SystemFont.FixedFont))
        self.size_label = QLabel("")
        set_role(self.size_label, "muted")

        copy_btn = QPushButton("Copy")
        set_role(copy_btn, "primary")
        copy_btn.clicked.connect(self._copy)
        save_btn = QPushButton("Save…")
        save_btn.clicked.connect(self._save)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        buttons = QHBoxLayout()
        buttons.addWidget(self.size_label, 1)
        buttons.addWidget(copy_btn)
        buttons.addWidget(save_btn)
        buttons.addWidget(close_btn)

        lay = QVBoxLayout(self)
        lay.addWidget(intro)
        lay.addWidget(self.fmt)
        lay.addWidget(masks)
        lay.addWidget(self.preview, 1)
        lay.addLayout(buttons)
        self.fmt.currentIndexChanged.connect(self._refresh)
        last = str(self.settings.value("export/format", "ai"))
        idx = next((i for i, f in enumerate(FORMATS) if f[0] == last), 0)
        self.fmt.setCurrentIndex(idx)
        self._refresh()

    def _opts(self) -> MaskOptions:
        return MaskOptions(local_ip=self.cb_local.isChecked(),
                           public_ip=self.cb_public.isChecked(),
                           mac=self.cb_mac.isChecked(),
                           ssid=self.cb_ssid.isChecked(),
                           host=self.cb_host.isChecked())

    def _refresh(self, *_):
        key = self.fmt.currentData()
        text = render(key, self.env, self.runs, self._opts(),
                      self.cb_hist.isChecked())
        self.preview.setPlainText(text)
        self.size_label.setText(f"{len(text):,} characters")
        self.settings.setValue("export/format", key)
        o = self._opts()
        for name in ("public_ip", "local_ip", "mac", "ssid", "host"):
            self.settings.setValue(f"export/{name}", getattr(o, name))
        self.settings.setValue("export/history", self.cb_hist.isChecked())

    def _copy(self):
        QGuiApplication.clipboard().setText(self.preview.toPlainText())
        self.size_label.setText("Copied — paste it into the AI chat or "
                                "an email")

    def _save(self):
        ext = next(f[2] for f in FORMATS if f[0] == self.fmt.currentData())
        kind = {"ai": "ai-prompt", "md": "report", "json": "context"}[
            self.fmt.currentData()]
        default = os.path.join(
            os.path.expanduser("~"),
            f"nwsolver-{kind}-{datetime.now():%Y%m%d-%H%M%S}.{ext}")
        path, _ = QFileDialog.getSaveFileName(
            self, "Save export", default,
            "JSON (*.json)" if ext == "json" else "Markdown (*.md)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.preview.toPlainText())
        except OSError as exc:
            QMessageBox.critical(self, "Save failed", str(exc))
            return
        self.size_label.setText(f"Saved to {path}")
