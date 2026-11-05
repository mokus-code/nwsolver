"""Main window: three tabs (Connection / Speed / Website), a short toolbar,
and a status bar. Sized from the screen it opens on, and every page wraps
to the window width, so nothing runs off-screen."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

from PySide6.QtCore import QByteArray, QSettings, QThread, QTimer
from PySide6.QtGui import QAction, QFont, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (QApplication, QLabel, QMainWindow,
                               QMessageBox, QProgressBar, QTabWidget,
                               QToolBar)

from nwsolver.ai.assistant import build_prompt
from nwsolver.ai.client import AIClient
from nwsolver.engine.checks import CheckResult, Ctx
from nwsolver.engine.collector import collect_env
from nwsolver.engine import history
from nwsolver.engine.context import changes_text
from nwsolver.ui import fonts
from nwsolver.ui.ai_dialog import AiResultDialog
from nwsolver.ui.ai_worker import AiWorker
from nwsolver.ui.pages import ConnectionPage, ResourcePage, SpeedPage
from nwsolver.ui.settings_dialog import SettingsDialog, load_ai_config
from nwsolver.ui.widgets import RawOutputDialog, app_stylesheet
from nwsolver.ui.worker import SuiteWorker


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("nwsolver — Internet troubleshooter")
        self.settings = QSettings("nwsolver", "nwsolver")
        self.ctx = Ctx()
        self.env = collect_env(self.ctx)
        self._thread: QThread | None = None
        self._worker: SuiteWorker | None = None
        self._page_running = None
        self._ai_thread: QThread | None = None
        self._ai_worker: AiWorker | None = None
        self._ai_config = None

        # ---- pages -------------------------------------------------------
        self.conn_page = ConnectionPage()
        self.speed_page = SpeedPage()
        self.res_page = ResourcePage()
        self.pages = [self.conn_page, self.speed_page, self.res_page]
        for page in self.pages:
            page.run_requested.connect(self._run_suite)
            page.raw_requested.connect(self._show_raw)
            page.ai_requested.connect(self.ask_ai)
        history = self.settings.value("resource/history", []) or []
        if isinstance(history, str):
            history = [history]
        self.res_page.set_history([str(h) for h in history])
        self.res_page.history_changed.connect(
            lambda items: self.settings.setValue("resource/history", items))

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.addTab(self.conn_page, "No connection")
        self.tabs.addTab(self.speed_page, "Slow internet")
        self.tabs.addTab(self.res_page, "Site doesn't open")
        self.tabs.setTabToolTip(0, "Why is there no internet connection?")
        self.tabs.setTabToolTip(1, "Why is the internet slow?")
        self.tabs.setTabToolTip(2, "Why doesn't a website or service open?")
        self.setCentralWidget(self.tabs)

        # ---- actions -----------------------------------------------------
        self.copy_action = QAction("Copy for AI", self)
        self.copy_action.setShortcut(QKeySequence("Ctrl+Shift+C"))
        self.copy_action.setToolTip(
            "Copy a short description of the problems and the environment "
            "— paste it into ChatGPT, Claude or another AI chat to get "
            "fix recommendations")
        self.copy_action.triggered.connect(self.copy_for_ai)

        self.report_action = QAction("Export…", self)
        self.report_action.setShortcut(QKeySequence("Ctrl+E"))
        self.report_action.setToolTip(
            "Preview and export as AI prompt, Markdown report or JSON — "
            "with options to hide IP/MAC addresses and names")
        self.report_action.triggered.connect(self.export_report)

        self.history_action = QAction("History", self)
        self.history_action.setShortcut(QKeySequence("Ctrl+H"))
        self.history_action.setToolTip("Earlier checks and what changed")
        self.history_action.triggered.connect(self.show_history)

        self.ai_action = QAction("Ask AI", self)
        self.ai_action.setShortcut(QKeySequence("Ctrl+Shift+A"))
        self.ai_action.setToolTip("Ask the configured AI assistant about the "
                                  "results on the current tab")
        self.ai_action.triggered.connect(lambda: self.ask_ai(None))

        self.root_action = QAction("Run as root…", self)
        self.root_action.setToolTip(
            "Restart with administrator rights (pkexec) — a few details "
            "(kernel log, some Wi-Fi data) need it")
        self.root_action.triggered.connect(self.relaunch_as_root)
        self.root_action.setVisible(not self.ctx.is_root
                                    and shutil.which("pkexec") is not None)

        settings_action = QAction("AI assistant settings…", self)
        settings_action.setShortcut(QKeySequence("Ctrl+,"))
        settings_action.triggered.connect(self.open_settings)

        quit_action = QAction("Quit", self)
        quit_action.setShortcut(QKeySequence("Ctrl+Q"))
        quit_action.triggered.connect(self.close)

        bigger = QAction("Larger text", self)
        bigger.setShortcuts([QKeySequence("Ctrl++"), QKeySequence("Ctrl+=")])
        bigger.triggered.connect(lambda: self.apply_font_pt(fonts.font_pt() + 1))
        smaller = QAction("Smaller text", self)
        smaller.setShortcut(QKeySequence("Ctrl+-"))
        smaller.triggered.connect(lambda: self.apply_font_pt(fonts.font_pt() - 1))
        reset = QAction("Default text size", self)
        reset.setShortcut(QKeySequence("Ctrl+0"))
        reset.triggered.connect(lambda: self.apply_font_pt(self._default_pt))

        # ---- menus -------------------------------------------------------
        file_menu = self.menuBar().addMenu("&File")
        file_menu.addAction(self.copy_action)
        file_menu.addAction(self.report_action)
        file_menu.addAction(self.history_action)
        file_menu.addSeparator()
        file_menu.addAction(quit_action)
        view_menu = self.menuBar().addMenu("&View")
        view_menu.addAction(bigger)
        view_menu.addAction(smaller)
        view_menu.addAction(reset)
        tools_menu = self.menuBar().addMenu("&Tools")
        tools_menu.addAction(self.ai_action)
        tools_menu.addAction(settings_action)
        tools_menu.addSeparator()
        tools_menu.addAction(self.root_action)

        # ---- toolbar: few, short items (overflow goes into a » menu) -----
        toolbar = QToolBar("Main")
        toolbar.setMovable(False)
        toolbar.setFloatable(False)
        self.addToolBar(toolbar)
        toolbar.addAction(self.copy_action)
        toolbar.addAction(self.report_action)
        toolbar.addAction(self.history_action)
        toolbar.addAction(self.ai_action)
        toolbar.addAction(self.root_action)

        # ---- status bar --------------------------------------------------
        self.status_label = QLabel("Ready")
        self.progress = QProgressBar()
        self.progress.setMaximumWidth(180)
        self.progress.setTextVisible(False)
        self.progress.setVisible(False)
        self.statusBar().addWidget(self.status_label, 1)
        self.statusBar().addPermanentWidget(self.progress)

        # ---- size & font -------------------------------------------------
        self._default_pt = max(9, QApplication.font().pointSize() or 11)
        saved = self.settings.value("font_pt", self._default_pt)
        try:
            pt = int(str(saved))
        except ValueError:
            pt = self._default_pt
        self.apply_font_pt(pt, save=False)
        self._restore_window()
        # Save size/position shortly after the user stops moving/resizing,
        # so it survives even if the app is killed rather than closed.
        self._geo_timer = QTimer(self)
        self._geo_timer.setSingleShot(True)
        self._geo_timer.setInterval(800)
        self._geo_timer.timeout.connect(self._save_window)
        self._refresh_actions()

        self._run_suite(self.conn_page.suite, {})

    # -- geometry ------------------------------------------------------------

    def _restore_window(self):
        """Reopen with the saved size and position; fall back to a size
        derived from the screen if nothing was saved or it is off-screen."""
        screen = self.screen() or QGuiApplication.primaryScreen()
        if screen is not None:
            avail = screen.availableGeometry()
            self.setMinimumSize(min(420, avail.width()),
                                min(420, avail.height()))
        geo = self.settings.value("window/geometry")
        if isinstance(geo, QByteArray) and not geo.isEmpty() and \
                self.restoreGeometry(geo):
            frame = self.frameGeometry()
            if any(sc.availableGeometry().intersects(frame)
                   for sc in QGuiApplication.screens()):
                return
        self._fit_to_screen()

    def _save_window(self):
        self.settings.setValue("window/geometry", self.saveGeometry())
        self._sync_settings()

    def _sync_settings(self):
        self.settings.sync()
        if self.settings.status() != QSettings.Status.NoError and \
                not getattr(self, "_settings_warned", False):
            self._settings_warned = True
            path = self.settings.fileName()
            self.statusBar().showMessage(
                f"Settings can't be saved: {path} is not writable (was the "
                "app run as root?). Fix: sudo chown -R $USER "
                "~/.config/nwsolver", 15000)

    def resizeEvent(self, event):  # noqa: N802
        super().resizeEvent(event)
        if hasattr(self, "_geo_timer"):
            self._geo_timer.start()

    def moveEvent(self, event):  # noqa: N802
        super().moveEvent(event)
        if hasattr(self, "_geo_timer"):
            self._geo_timer.start()

    def _fit_to_screen(self):
        """Open at a comfortable size that always fits the current screen."""
        screen = self.screen() or QGuiApplication.primaryScreen()
        if screen is None:
            self.resize(960, 760)
            return
        avail = screen.availableGeometry()
        w = min(980, int(avail.width() * 0.9))
        h = min(820, int(avail.height() * 0.9))
        self.setMinimumSize(min(420, avail.width()), min(420, avail.height()))
        self.resize(w, h)
        self.move(avail.x() + (avail.width() - w) // 2,
                  avail.y() + (avail.height() - h) // 2)

    # -- running suites --------------------------------------------------------

    def _page_for(self, suite):
        return next(p for p in self.pages if p.suite is suite)

    def _run_suite(self, suite, options: dict):
        if self._thread is not None:
            return
        page = self._page_for(suite)
        self._page_running = page
        for p in self.pages:
            p.set_enabled_runs(False)
        page.started()
        self.tabs.setCurrentWidget(page)
        self.progress.setRange(0, 0)
        self.progress.setVisible(True)
        self.status_label.setText(f"{suite.SUITE_NAME}: running…")

        thread = QThread(self)
        worker = SuiteWorker(suite, options)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.started_check.connect(page.check_started)
        worker.started_check.connect(self._on_check_started)
        worker.result_ready.connect(page.result_ready)
        worker.overview_ready.connect(page.on_overview)
        worker.finished.connect(self._on_finished)
        worker.failed.connect(self._on_failed)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._on_thread_done)
        self._thread, self._worker = thread, worker
        thread.start()

    def _on_check_started(self, _index: int, title: str):
        page = self._page_running
        name = page.suite.SUITE_NAME if page is not None else ""
        self.status_label.setText(f"{name}: {title}…")

    def _on_finished(self, run: dict):
        page = self._page_running
        if page is not None:
            page.finished(run)
            saved = history.save(run)
            if saved is not None:
                prev = history.previous(saved)
                if prev is not None:
                    page.banner.set_changes(changes_text(prev, saved))
        v = run["verdict"]
        self.status_label.setText(f"{v.headline}  ({run['elapsed']:.0f} s)")

    def _on_failed(self, message: str):
        if self._page_running is not None:
            self._page_running.failed(message)
        self.status_label.setText("Check failed")
        QMessageBox.critical(self, "Check failed", message)

    def _on_thread_done(self):
        self._thread = None
        self._worker = None
        self._page_running = None
        self.progress.setVisible(False)
        for p in self.pages:
            p.set_enabled_runs(True)
        self._refresh_actions()

    def closeEvent(self, event):  # noqa: N802
        self._save_window()
        if self._thread is not None and self._worker is not None:
            self._worker.cancel()
            self._thread.quit()
            self._thread.wait(3000)
        super().closeEvent(event)

    # -- details / AI ----------------------------------------------------------

    def _show_raw(self, result: CheckResult):
        RawOutputDialog(result, self).exec()

    def _runs(self) -> dict:
        return {p.suite.SUITE_ID: p.last_run for p in self.pages
                if p.last_run is not None}

    @property
    def ai_config(self):
        if self._ai_config is None:
            self._ai_config = load_ai_config(self.settings)
        return self._ai_config

    def _refresh_actions(self):
        has_runs = bool(self._runs())
        self.report_action.setEnabled(has_runs)
        self.copy_action.setEnabled(has_runs)
        self.ai_action.setEnabled(has_runs and self._ai_thread is None)

    def open_settings(self):
        dialog = SettingsDialog(self.settings, self)
        if dialog.exec() == SettingsDialog.DialogCode.Accepted:
            self._ai_config = None
            self._refresh_actions()

    def ask_ai(self, focus: CheckResult | None = None):
        if self._ai_thread is not None:
            return
        cfg = self.ai_config
        if not cfg.enabled:
            QMessageBox.information(
                self, "AI assistant",
                "No AI provider is configured. Open Tools → AI assistant "
                "settings… to choose one.")
            return
        page = self.tabs.currentWidget()
        run = getattr(page, "last_run", None)
        if run is None and focus is None:
            QMessageBox.information(self, "AI assistant",
                                    "Run the check on this tab first.")
            return
        system, user = build_prompt(self.env, run, focus)
        self.status_label.setText("Asking the AI assistant…")
        self.progress.setRange(0, 0)
        self.progress.setVisible(True)
        self.ai_action.setEnabled(False)
        thread = QThread(self)
        worker = AiWorker(AIClient(cfg), system, user)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(self._on_ai_finished)
        worker.failed.connect(self._on_ai_failed)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        self._ai_thread, self._ai_worker = thread, worker
        thread.start()

    def _ai_done(self):
        self._ai_thread = None
        self._ai_worker = None
        if self._thread is None:
            self.progress.setVisible(False)
        self._refresh_actions()

    def _on_ai_finished(self, text: str, truncated: bool):
        self._ai_done()
        self.status_label.setText("AI assistant replied")
        AiResultDialog(text, truncated=truncated, parent=self).exec()

    def _on_ai_failed(self, message: str):
        self._ai_done()
        self.status_label.setText("AI assistant failed")
        QMessageBox.warning(self, "AI assistant",
                            f"Could not reach the AI assistant.\n\n{message}")

    # -- font size -------------------------------------------------------------

    def apply_font_pt(self, pt: int, save: bool = True):
        pt = max(8, min(24, int(pt)))
        fonts.set_font_pt(pt)
        app = QApplication.instance()
        if isinstance(app, QApplication):
            font = QFont(app.font())
            font.setPointSize(pt)
            app.setFont(font)
            app.setStyleSheet(app_stylesheet())
        if save:
            self.settings.setValue("font_pt", pt)
            self._sync_settings()

    # -- export & elevation ----------------------------------------------------

    def copy_for_ai(self):
        """Quick copy: AI prompt with the default privacy masks."""
        runs = self._runs()
        if not runs:
            return
        from nwsolver.engine.context import MaskOptions
        from nwsolver.ui.export_dialog import render
        QGuiApplication.clipboard().setText(
            render("ai", self.env, runs, MaskOptions(), True))
        self.statusBar().showMessage(
            "Copied (public IP, MAC and names hidden) — paste it into an AI "
            "chat with Ctrl+V. Use Export… to preview or change what is "
            "hidden.", 9000)

    def export_report(self):
        runs = self._runs()
        if not runs:
            return
        from nwsolver.ui.export_dialog import ExportDialog
        ExportDialog(self.env, runs, self.settings, self).exec()

    def show_history(self):
        from nwsolver.ui.history_dialog import HistoryDialog
        HistoryDialog(self).exec()

    def relaunch_as_root(self):
        """Restart via pkexec, passing the X display explicitly (pkexec
        clears the environment)."""
        display = os.environ.get("DISPLAY")
        if not display:
            QMessageBox.warning(
                self, "Run as root",
                "No X display found, so a graphical restart as root is not "
                "possible. In a terminal run:  sudo nwsolver")
            return
        xauth = os.environ.get("XAUTHORITY") or \
            os.path.expanduser("~/.Xauthority")
        prefix = ["env", f"DISPLAY={display}", f"XAUTHORITY={xauth}",
                  "QT_QPA_PLATFORM=xcb"]
        args = [sys.executable, os.path.abspath(sys.argv[0])]
        try:
            subprocess.Popen(["pkexec", *prefix, *args])
        except OSError as exc:
            QMessageBox.critical(self, "Run as root",
                                 f"Could not start pkexec: {exc}")
            return
        self.statusBar().showMessage(
            "Restarting with administrator rights — confirm the password "
            "prompt…", 6000)
