"""Background worker: runs one diagnostic suite off the UI thread."""
from __future__ import annotations

import time

from PySide6.QtCore import QObject, Signal, Slot

from nwsolver.engine.checks import Ctx
from nwsolver.engine.collector import run_suite


class SuiteWorker(QObject):
    """Moved to a QThread. Signals are delivered to the UI thread queued."""

    started_check = Signal(int, str)     # index, title (sequential suites)
    result_ready = Signal(int, object)   # index, CheckResult
    overview_ready = Signal(object)      # dict (connection suite)
    finished = Signal(object)            # run dict (see _run_info)
    failed = Signal(str)

    def __init__(self, suite, options: dict | None = None):
        super().__init__()
        self.suite = suite
        self.options = dict(options or {})
        self._cancel = False

    def cancel(self):
        self._cancel = True

    @Slot()
    def run(self):
        try:
            start = time.monotonic()
            ctx = Ctx(**self.options)
            overview = None
            if hasattr(self.suite, "overview"):
                overview = self.suite.overview(ctx)
                self.overview_ready.emit(overview)

            def on_progress(done, total, title):
                if not getattr(self.suite, "PARALLEL", False) and done < total:
                    self.started_check.emit(done, title)

            results = run_suite(
                ctx, self.suite,
                on_progress=on_progress,
                on_result=lambda i, r: self.result_ready.emit(i, r),
                cancel_check=lambda: self._cancel)
            verdict = self.suite.analyze(results, ctx)
            self.finished.emit({
                "suite": self.suite.SUITE_ID,
                "results": results,
                "verdict": verdict,
                "overview": overview,
                "options": self.options,
                "state": ctx.state,
                "elapsed": time.monotonic() - start,
                "when": time.time(),
                "cancelled": self._cancel,
            })
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(f"{exc.__class__.__name__}: {exc}")
