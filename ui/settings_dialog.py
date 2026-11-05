"""Settings dialog: AI assistant provider, endpoint, key and model."""
from __future__ import annotations

from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import (QApplication, QComboBox, QDialog,
                               QDialogButtonBox, QFormLayout, QLabel,
                               QLineEdit, QMessageBox, QSpinBox, QVBoxLayout)

from nwsolver.ai.client import (AIConfig, AIClient, AIClientError,
                                DEFAULT_PROVIDERS)


def load_ai_config(settings: QSettings) -> AIConfig:
    """Read the persisted AI config (used by the main window)."""
    return AIConfig(
        provider=str(settings.value("ai/provider", "off")),
        base_url=str(settings.value("ai/base_url",
                                    DEFAULT_PROVIDERS["openai"]["base_url"])),
        api_key=str(settings.value("ai/api_key", "")),
        model=str(settings.value("ai/model", DEFAULT_PROVIDERS["openai"]["model"])),
        max_tokens=int(str(settings.value("ai/max_tokens", 8192))),
    )


class SettingsDialog(QDialog):
    """Modal editor for the AI assistant connection settings."""

    def __init__(self, settings: QSettings, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings — AI assistant")
        self.setMinimumWidth(420)
        self.settings = settings

        self.provider_combo = QComboBox()
        self.provider_combo.addItem("Disabled", "off")
        self.provider_combo.addItem("OpenAI-compatible", "openai")
        self.provider_combo.addItem("Ollama (local)", "ollama")

        self.base_edit = QLineEdit()
        self.base_edit.setPlaceholderText("https://api.openai.com/v1")
        self.key_edit = QLineEdit()
        self.key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.key_edit.setPlaceholderText("sk-… (only for OpenAI-compatible)")
        self.model_edit = QLineEdit()
        self.model_edit.setPlaceholderText("gpt-4o-mini")
        self.tokens_spin = QSpinBox()
        self.tokens_spin.setRange(512, 32768)
        self.tokens_spin.setSingleStep(512)
        self.tokens_spin.setValue(8192)
        self.tokens_spin.setSuffix(" tokens")
        self.tokens_spin.setToolTip(
            "Maximum response length. Reasoning models spend many tokens on "
            "thinking before answering, so raise this if answers get cut off.")

        form = QFormLayout()
        form.addRow("Provider", self.provider_combo)
        form.addRow("API base URL", self.base_edit)
        form.addRow("API key", self.key_edit)
        form.addRow("Model", self.model_edit)
        form.addRow("Max response tokens", self.tokens_spin)

        note = QLabel(
            "The scan summary (non-passing checks + suggestions, no raw dumps "
            "except for focused per-issue questions) is sent to the provider "
            "you configure. Do not enable this with sensitive production data. "
            "The API key is stored in your user config "
            "(~/.config/nwsolver/nwsolver.conf) — never share that file.\n\n"
            "OpenAI-compatible: OpenAI, OpenRouter, Groq, Mistral, local "
            "vLLM / LM Studio / llama.cpp servers, …\n"
            "Ollama: local server only (never proxied), e.g. after "
            "`ollama pull llama3.2`.")
        note.setWordWrap(True)
        note.setStyleSheet("color: palette(mid);")

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save
            | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Save).setText("Save")
        test_btn = buttons.addButton(
            "Test connection", QDialogButtonBox.ButtonRole.ActionRole)
        test_btn.clicked.connect(self._test_connection)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(note)
        layout.addWidget(buttons)

        self.provider_combo.currentIndexChanged.connect(self._on_provider_changed)
        self._load()
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)

    # -- load / save -------------------------------------------------------

    def _load(self):
        provider = str(self.settings.value("ai/provider", "off"))
        idx = self.provider_combo.findData(provider)
        self.provider_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self.base_edit.setText(str(self.settings.value("ai/base_url", "")))
        self.key_edit.setText(str(self.settings.value("ai/api_key", "")))
        self.model_edit.setText(str(self.settings.value("ai/model", "")))
        self.tokens_spin.setValue(
            int(str(self.settings.value("ai/max_tokens", 8192))))

    def _on_provider_changed(self):
        defaults = DEFAULT_PROVIDERS.get(self.provider_combo.currentData())
        if not defaults:
            return
        known_bases = {d["base_url"] for d in DEFAULT_PROVIDERS.values()}
        known_models = {d["model"] for d in DEFAULT_PROVIDERS.values()}
        if self.base_edit.text().strip() in ("", *known_bases):
            self.base_edit.setText(defaults["base_url"])
        if self.model_edit.text().strip() in ("", *known_models):
            self.model_edit.setText(defaults["model"])

    def _config(self) -> AIConfig:
        return AIConfig(
            provider=str(self.provider_combo.currentData()),
            base_url=self.base_edit.text().strip().rstrip("/")
                     or DEFAULT_PROVIDERS["openai"]["base_url"],
            api_key=self.key_edit.text().strip(),
            model=self.model_edit.text().strip()
                  or DEFAULT_PROVIDERS["openai"]["model"],
            max_tokens=self.tokens_spin.value(),
        )

    def _save(self):
        cfg = self._config()
        self.settings.setValue("ai/provider", cfg.provider)
        self.settings.setValue("ai/base_url", cfg.base_url)
        self.settings.setValue("ai/api_key", cfg.api_key)
        self.settings.setValue("ai/model", cfg.model)
        self.settings.setValue("ai/max_tokens", cfg.max_tokens)
        self.accept()

    # -- connectivity test -------------------------------------------------

    def _test_connection(self):
        cfg = self._config()
        if cfg.provider == "off":
            QMessageBox.information(self, "Test connection",
                                    "Choose a provider first.")
            return
        self.setCursor(Qt.CursorShape.WaitCursor)
        try:
            QApplication.processEvents()
            reply = AIClient(cfg).chat(
                "You are a connectivity test. Reply with exactly: OK",
                "Reply with exactly: OK", timeout=20.0)
            QMessageBox.information(
                self, "Test connection",
                f"Connection works — the model replied:\n\n{reply[:400]}")
        except AIClientError as exc:
            QMessageBox.warning(self, "Test connection", str(exc))
        finally:
            self.unsetCursor()
