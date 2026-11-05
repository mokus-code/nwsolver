"""Background worker for AI assistant requests (off the UI thread)."""
from __future__ import annotations

from PySide6.QtCore import QObject, Signal, Slot

from nwsolver.ai.client import AIClient, AIClientError


class AiWorker(QObject):
    """Moved to a QThread; emits the model's reply or a clean error."""

    finished = Signal(str, bool)  # text, truncated
    failed = Signal(str)

    def __init__(self, client: AIClient, system: str, user: str, parent=None):
        super().__init__(parent)
        self.client = client
        self.system = system
        self.user = user

    @Slot()
    def run(self):
        try:
            text = self.client.chat(self.system, self.user)
            self.finished.emit(text, self.client.last_truncated)
        except AIClientError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(f"{exc.__class__.__name__}: {exc}")
