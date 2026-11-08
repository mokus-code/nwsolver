"""Reusable widgets. Everything wraps to the window width — no fixed-width
rows, no wide tables — so the UI fits narrow and HiDPI screens.

Styling lives in one application stylesheet (:func:`app_stylesheet`) keyed
by the dynamic ``role`` / ``state`` properties, so changing the global font
size or the theme re-styles every widget at once.
"""
from __future__ import annotations

from PySide6.QtCore import QPoint, QRect, QSize, Qt, QUrl, Signal
from PySide6.QtGui import (QColor, QDesktopServices, QGuiApplication, QIcon,
                           QPainter, QPixmap)
from PySide6.QtWidgets import (QDialog, QFrame, QHBoxLayout, QLabel, QLayout,
                               QMenu, QPlainTextEdit, QPushButton,
                               QSizePolicy, QToolButton, QVBoxLayout, QWidget)

from nwsolver.engine.checks import CheckResult, Status
from nwsolver.ui import fonts

STATUS_COLORS = {
    Status.PASS: "#1e8e3e",
    Status.WARN: "#d99a06",
    Status.FAIL: "#d93025",
    Status.SKIP: "#80868b",
    Status.ERROR: "#9334e6",
}
_GLYPHS = {Status.PASS: "✓", Status.WARN: "!", Status.FAIL: "✕",
           Status.SKIP: "–", Status.ERROR: "!"}
_STATE_FOR_STATUS = {Status.PASS: "ok", Status.WARN: "warn",
                     Status.FAIL: "fail", Status.ERROR: "fail",
                     Status.SKIP: "skip"}


def _muted_color() -> str:
    """Secondary-text colour readable on light *and* dark themes: 60 % of
    the way from the window background to the normal text colour
    (palette(mid) almost disappears on dark themes)."""
    app = QGuiApplication.instance()
    if app is None:
        return "#80868b"
    pal = app.palette()
    fg = pal.color(pal.ColorRole.WindowText)
    bg = pal.color(pal.ColorRole.Window)
    mix = [round(b + (f - b) * 0.62) for f, b in
           ((fg.red(), bg.red()), (fg.green(), bg.green()),
            (fg.blue(), bg.blue()))]
    return "#{:02x}{:02x}{:02x}".format(*mix)


def app_stylesheet() -> str:
    p = fonts.px
    muted = _muted_color()
    return f"""
QFrame[role="card"] {{
    border: 1px solid palette(mid); border-radius: 8px;
    background: palette(base);
}}
QFrame[role="banner"] {{
    border: 2px solid palette(mid); border-radius: 10px;
}}
QFrame[role="banner"][state="ok"]   {{ border-color: #1e8e3e; background: rgba(30,142,62,0.08); }}
QFrame[role="banner"][state="warn"] {{ border-color: #d99a06; background: rgba(217,154,6,0.10); }}
QFrame[role="banner"][state="fail"] {{ border-color: #d93025; background: rgba(217,48,37,0.08); }}
QFrame[role="tile"] {{
    border: 1px solid palette(mid); border-radius: 8px;
    background: palette(base);
}}
QLabel[role="state"] {{
    color: white; background: #80868b; border-radius: 6px;
    padding: 2px 8px; font-weight: 800; font-size: {p(12)}px;
}}
QLabel[role="state"][state="ok"]   {{ background: #1e8e3e; }}
QLabel[role="state"][state="warn"] {{ background: #d99a06; }}
QLabel[role="state"][state="fail"] {{ background: #d93025; }}
QLabel[role="state"][state="busy"] {{ background: #1a73e8; }}
QLabel[role="badge"] {{
    border: 1px solid palette(mid); border-radius: 6px; padding: 1px 7px;
    font-size: {p(11)}px; font-weight: 600;
}}
QLabel[role="badge"][state="confirmed"]    {{ border-color: #d93025; }}
QLabel[role="badge"][state="likely"]       {{ border-color: #d99a06; }}
QLabel[role="headline"] {{ font-size: {p(19)}px; font-weight: 700; }}
QLabel[role="section"]  {{ font-size: {p(14)}px; font-weight: 700; }}
QLabel[role="title"]    {{ font-weight: 700; }}
QLabel[role="muted"]    {{ color: {muted}; font-size: {p(11)}px; }}
QLabel[role="fix"]      {{ font-style: italic; }}
QLabel[role="tile-caption"] {{ color: {muted}; font-size: {p(11)}px; }}
QLabel[role="tile-value"]   {{ font-size: {p(18)}px; font-weight: 700; }}
QLabel[role="pill"] {{
    color: white; border-radius: 9px; padding: 2px 9px;
    font-weight: 600; font-size: {p(11)}px; background: #80868b;
}}
QLabel[role="pill"][state="ok"]      {{ background: #1e8e3e; }}
QLabel[role="pill"][state="warn"]    {{ background: #d99a06; }}
QLabel[role="pill"][state="fail"]    {{ background: #d93025; }}
QLabel[role="pill"][state="blocked"] {{ background: palette(mid); }}
QPushButton[role="primary"] {{ font-weight: 700; padding: 6px 16px; }}
"""


def set_role(widget: QWidget, role: str, state: str | None = None) -> None:
    widget.setProperty("role", role)
    if state is not None:
        set_state(widget, state)


def set_state(widget: QWidget, state: str) -> None:
    widget.setProperty("state", state)
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)


def status_icon(status: Status, size: int = 18) -> QIcon:
    return QIcon(status_pixmap(status, size))


def status_pixmap(status: Status, size: int = 18) -> QPixmap:
    ratio = 2.0
    pm = QPixmap(int(size * ratio), int(size * ratio))
    pm.setDevicePixelRatio(ratio)
    pm.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pm)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor(STATUS_COLORS[status]))
    painter.drawEllipse(1, 1, size - 2, size - 2)
    painter.setPen(QColor("white"))
    font = painter.font()
    font.setBold(True)
    font.setPixelSize(max(8, int(size * 0.6)))
    painter.setFont(font)
    painter.drawText(QRect(0, 0, size, size), Qt.AlignmentFlag.AlignCenter,
                     _GLYPHS[status])
    painter.end()
    return pm


# --------------------------------------------------------------------------
# Layout helpers
# --------------------------------------------------------------------------

class FlowLayout(QLayout):
    """Lays children out left-to-right and wraps to new lines as needed."""

    def __init__(self, parent=None, spacing: int = 6):
        super().__init__(parent)
        self._items = []
        self._spacing = spacing
        self.setContentsMargins(0, 0, 0, 0)

    def addItem(self, item):  # noqa: N802 (Qt API)
        self._items.append(item)

    def count(self):
        return len(self._items)

    def itemAt(self, index):  # noqa: N802
        return self._items[index] if 0 <= index < len(self._items) else None

    def takeAt(self, index):  # noqa: N802
        if 0 <= index < len(self._items):
            return self._items.pop(index)
        return None

    def expandingDirections(self):  # noqa: N802
        return Qt.Orientation(0)

    def hasHeightForWidth(self):  # noqa: N802
        return True

    def heightForWidth(self, width):  # noqa: N802
        return self._do_layout(QRect(0, 0, width, 0), test=True)

    def setGeometry(self, rect):  # noqa: N802
        super().setGeometry(rect)
        self._do_layout(rect, test=False)

    def sizeHint(self):  # noqa: N802
        return self.minimumSize()

    def minimumSize(self):  # noqa: N802
        size = QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        m = self.contentsMargins()
        return size + QSize(m.left() + m.right(), m.top() + m.bottom())

    def clear(self):
        while self._items:
            item = self._items.pop()
            w = item.widget()
            if w is not None:
                w.setParent(None)
                w.deleteLater()

    def _do_layout(self, rect: QRect, test: bool) -> int:
        m = self.contentsMargins()
        eff = rect.adjusted(m.left(), m.top(), -m.right(), -m.bottom())
        x, y, line_h = eff.x(), eff.y(), 0
        for item in self._items:
            w = item.widget()
            if w is not None and w.isHidden():
                continue
            hint = item.sizeHint()
            width = min(hint.width(), eff.width())
            nx = x + width + self._spacing
            if nx - self._spacing > eff.right() + 1 and line_h > 0:
                x = eff.x()
                y += line_h + self._spacing
                nx = x + width + self._spacing
                line_h = 0
            h = hint.height()
            if item.hasHeightForWidth():
                h = item.heightForWidth(width)
            if not test:
                item.setGeometry(QRect(QPoint(x, y), QSize(width, h)))
            x = nx
            line_h = max(line_h, h)
        return y + line_h - rect.y() + m.bottom()


class WrapLabel(QLabel):
    """Word-wrapping, selectable label that never forces the window wider.

    Long unbreakable words (URLs, paths) are clipped instead of widening the
    whole layout.
    """

    def __init__(self, text: str = "", role: str | None = None, parent=None):
        super().__init__(text, parent)
        self.setTextFormat(Qt.TextFormat.PlainText)
        self.setWordWrap(True)
        self.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        self.setSizePolicy(QSizePolicy.Policy.Ignored,
                           QSizePolicy.Policy.Preferred)
        if role:
            set_role(self, role)

    def minimumSizeHint(self):  # noqa: N802
        hint = super().minimumSizeHint()
        return QSize(min(hint.width(), 60), hint.height())

    def sizeHint(self):  # noqa: N802
        hint = super().sizeHint()
        return QSize(min(hint.width(), 600), hint.height())


# --------------------------------------------------------------------------
# Verdict banner
# --------------------------------------------------------------------------

class VerdictBanner(QFrame):
    """Big plain-language answer: state, headline, why, what to do, chain."""

    _WORDS = {"ok": "OK", "warn": "PROBLEM", "fail": "BROKEN",
              "unknown": "—", "busy": "CHECKING"}

    def __init__(self, idle_text: str, parent=None):
        super().__init__(parent)
        set_role(self, "banner", "unknown")
        self.state_label = QLabel("—")
        set_role(self.state_label, "state", "unknown")
        self.state_label.setSizePolicy(QSizePolicy.Policy.Fixed,
                                       QSizePolicy.Policy.Fixed)
        self.headline = WrapLabel(idle_text, "headline")
        self.changes = WrapLabel("", "muted")
        self.changes.hide()
        self.conf_label = QLabel("")
        set_role(self.conf_label, "badge")
        self.conf_label.hide()
        self.notes = WrapLabel("")
        self.notes.setTextFormat(Qt.TextFormat.RichText)
        self.notes.hide()
        self.detail = WrapLabel("")
        self.actions = WrapLabel("")
        self.actions.setTextFormat(Qt.TextFormat.RichText)
        self.detail.hide()
        self.actions.hide()
        self.pills_box = QWidget()
        self.pills = FlowLayout(self.pills_box, spacing=5)
        self.pills_box.hide()

        top = QHBoxLayout()
        top.setSpacing(10)
        top.addWidget(self.state_label, 0, Qt.AlignmentFlag.AlignTop)
        top.addWidget(self.headline, 1)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(8)
        lay.addLayout(top)
        lay.addWidget(self.conf_label, 0, Qt.AlignmentFlag.AlignLeft)
        lay.addWidget(self.changes)
        lay.addWidget(self.detail)
        lay.addWidget(self.actions)
        self.link_btn = QPushButton()
        set_role(self.link_btn, "primary")
        self.link_btn.clicked.connect(self._open_link)
        self.link_btn.hide()
        self._link_url = ""
        link_row = QHBoxLayout()
        link_row.addWidget(self.link_btn)
        link_row.addStretch(1)
        lay.addLayout(link_row)
        lay.addWidget(self.notes)
        lay.addWidget(self.pills_box)

    def set_busy(self, text: str):
        self._set_state("busy")
        self.headline.setText(text)
        self.detail.hide()
        self.actions.hide()
        self.link_btn.hide()
        self.conf_label.hide()
        self.notes.hide()
        self.changes.hide()

    def set_changes(self, text: str):
        self.changes.setText(text)
        self.changes.setVisible(bool(text))

    def _open_link(self):
        if self._link_url:
            QDesktopServices.openUrl(QUrl(self._link_url))

    def set_progress_steps(self, steps):
        """Show the chain pills while running (all grey)."""
        self.pills.clear()
        for label in steps:
            pill = QLabel(label)
            set_role(pill, "pill", "blocked")
            self.pills.addWidget(pill)
        self.pills_box.setVisible(bool(steps))

    def set_verdict(self, verdict):
        self._set_state(verdict.state)
        self.headline.setText(verdict.headline)
        self.detail.setText(verdict.detail)
        self.detail.setVisible(bool(verdict.detail))
        acts = [a for a in verdict.actions if a]
        if acts:
            items = "".join(f"<li>{_md_code(a)}</li>" for a in acts)
            self.actions.setText(
                f"<b>What to do:</b><ul style='margin:0 0 0 -20px'>"
                f"{items}</ul>")
        self.actions.setVisible(bool(acts))
        self.pills.clear()
        for step in verdict.steps:
            if step.blocked:
                state, glyph = "blocked", "·"
            else:
                state = _STATE_FOR_STATUS.get(step.status, "skip")
                glyph = _GLYPHS[step.status]
            pill = QLabel(f"{glyph} {step.label}")
            set_role(pill, "pill", state)
            pill.setToolTip(step.check.summary if step.check else "")
            self.pills.addWidget(pill)
        self.pills_box.setVisible(bool(verdict.steps))
        from nwsolver.diag.verdict import CONFIDENCE_LABELS
        conf = getattr(verdict, "confidence", "")
        if conf and verdict.state != "ok" or conf == "insufficient":
            self.conf_label.setText(CONFIDENCE_LABELS.get(conf, conf))
            set_state(self.conf_label, conf)
            self.conf_label.setToolTip({
                "confirmed": "The fault was measured directly.",
                "likely": "The most probable explanation of what was "
                          "measured; other causes are possible.",
                "insufficient": "Too few checks could run to be sure.",
            }.get(conf, ""))
            self.conf_label.show()
        else:
            self.conf_label.hide()
        notes = [n for n in getattr(verdict, "notes", []) if n]
        if notes:
            items = "".join(f"<li>{_md_code(n)}</li>" for n in notes)
            self.notes.setText(f"<b>Also noted:</b><ul style='margin:0 0 0 "
                               f"-20px'>{items}</ul>")
        self.notes.setVisible(bool(notes))
        link = getattr(verdict, "link", None)
        self._link_url = link[1] if link and link[1] else ""
        if self._link_url:
            self.link_btn.setText(link[0])
            self.link_btn.setToolTip(self._link_url)
        self.link_btn.setVisible(bool(self._link_url))

    def _set_state(self, state: str):
        set_state(self, state if state in ("ok", "warn", "fail") else
                  "unknown")
        self.state_label.setText(self._WORDS.get(state, "—"))
        set_state(self.state_label, state)


def _md_code(text: str) -> str:
    """Escape HTML and render `inline code` spans."""
    from html import escape
    parts = escape(text).split("`")
    out = []
    for i, part in enumerate(parts):
        out.append(f"<code>{part}</code>" if i % 2 else part)
    return "".join(out)


# --------------------------------------------------------------------------
# Result cards
# --------------------------------------------------------------------------

class ResultCard(QFrame):
    raw_requested = Signal(object)   # CheckResult
    ai_requested = Signal(object)    # CheckResult

    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        set_role(self, "card")
        self.result: CheckResult | None = None
        self.icon = QLabel()
        self.icon.setFixedSize(20, 20)
        self.title = WrapLabel(title, "title")
        self.more = QToolButton()
        self.more.setText("Details")
        self.more.setAutoRaise(True)
        self.more.clicked.connect(self._open_raw)
        self.more.hide()
        self.summary = WrapLabel("waiting…", "muted")
        self.fix = WrapLabel("", "fix")
        self.fix.setTextFormat(Qt.TextFormat.RichText)
        self.fix.hide()

        head = QHBoxLayout()
        head.setSpacing(8)
        head.addWidget(self.icon, 0, Qt.AlignmentFlag.AlignTop)
        head.addWidget(self.title, 1)
        head.addWidget(self.more, 0, Qt.AlignmentFlag.AlignTop)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 8, 12, 10)
        lay.setSpacing(4)
        lay.addLayout(head)
        lay.addWidget(self.summary)
        lay.addWidget(self.fix)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._menu)

    def set_running(self):
        self.icon.clear()
        self.icon.setText("…")
        self.summary.setText("checking…")

    def set_result(self, r: CheckResult):
        self.result = r
        self.icon.setText("")
        self.icon.setPixmap(status_pixmap(r.status, 18))
        self.icon.setToolTip(r.status.label)
        self.title.setText(r.title)
        self.summary.setText(r.summary)
        set_role(self.summary, "muted" if r.status is Status.SKIP else "")
        set_state(self.summary, "")
        show_fix = bool(r.suggestion) and r.status is not Status.PASS
        if show_fix:
            self.fix.setText("→ " + _md_code(r.suggestion))
        self.fix.setVisible(show_fix)
        self.more.setVisible(bool(r.raw))

    def _open_raw(self):
        if self.result is not None:
            self.raw_requested.emit(self.result)

    def _menu(self, pos):
        if self.result is None:
            return
        menu = QMenu(self)
        raw = menu.addAction("Show raw output…")
        raw.setEnabled(bool(self.result.raw))
        copy = menu.addAction("Copy text")
        ai = menu.addAction("Ask AI about this…")
        chosen = menu.exec(self.mapToGlobal(pos))
        if chosen == raw:
            self.raw_requested.emit(self.result)
        elif chosen == copy:
            r = self.result
            QGuiApplication.clipboard().setText(
                f"[{r.status.label}] {r.title}: {r.summary}"
                + (f"\nFix: {r.suggestion}" if r.suggestion else ""))
        elif chosen == ai:
            self.ai_requested.emit(self.result)


class ResultList(QWidget):
    """Vertical stack of result cards in check order."""

    raw_requested = Signal(object)
    ai_requested = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._lay = QVBoxLayout(self)
        self._lay.setContentsMargins(0, 0, 0, 0)
        self._lay.setSpacing(6)
        self.cards: list[ResultCard] = []

    def reset(self, titles: list[str]):
        for card in self.cards:
            card.setParent(None)
            card.deleteLater()
        self.cards = []
        for t in titles:
            card = ResultCard(t)
            card.raw_requested.connect(self.raw_requested)
            card.ai_requested.connect(self.ai_requested)
            self._lay.addWidget(card)
            self.cards.append(card)

    def set_running(self, index: int):
        if 0 <= index < len(self.cards):
            self.cards[index].set_running()

    def set_result(self, index: int, r: CheckResult):
        if 0 <= index < len(self.cards):
            self.cards[index].set_result(r)

    def finish(self):
        """Grey out checks that never ran (stopped early)."""
        for card in self.cards:
            if card.result is None:
                card.icon.setPixmap(status_pixmap(Status.SKIP, 18))
                card.summary.setText("not run")


# --------------------------------------------------------------------------
# Tiles (key facts / measurements)
# --------------------------------------------------------------------------

class Tile(QFrame):
    def __init__(self, caption: str, value: str = "—", parent=None):
        super().__init__(parent)
        set_role(self, "tile")
        self.caption = QLabel(caption)
        set_role(self.caption, "tile-caption")
        self.value = QLabel(value)
        set_role(self.value, "tile-value")
        self.value.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 6, 10, 8)
        lay.setSpacing(0)
        lay.addWidget(self.caption)
        lay.addWidget(self.value)

    def set(self, value: str, tooltip: str = ""):
        self.value.setText(value)
        self.setToolTip(tooltip)


class TileRow(QWidget):
    """A wrapping row of tiles."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.flow = FlowLayout(self, spacing=8)
        self.tiles: dict[str, Tile] = {}

    def set_tiles(self, items: list[tuple[str, str, str]]):
        """items: (key, caption, value)."""
        self.flow.clear()
        self.tiles = {}
        for key, caption, value in items:
            tile = Tile(caption, value)
            self.flow.addWidget(tile)
            self.tiles[key] = tile
        self.updateGeometry()


# --------------------------------------------------------------------------
# Raw output dialog
# --------------------------------------------------------------------------

class RawOutputDialog(QDialog):
    def __init__(self, result: CheckResult, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Details — {result.title}")
        screen = QGuiApplication.primaryScreen()
        avail = screen.availableGeometry() if screen else QRect(0, 0, 900, 700)
        self.resize(min(820, int(avail.width() * 0.9)),
                    min(560, int(avail.height() * 0.8)))
        head = WrapLabel(f"<b>{result.status.label}</b> — {result.summary}")
        head.setTextFormat(Qt.TextFormat.RichText)
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setPlainText(result.raw or "(no raw output captured)")
        copy_btn = QPushButton("Copy")
        copy_btn.clicked.connect(
            lambda: QGuiApplication.clipboard().setText(
                self.text.toPlainText()))
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(copy_btn)
        buttons.addWidget(close_btn)
        lay = QVBoxLayout(self)
        lay.addWidget(head)
        lay.addWidget(self.text, 1)
        lay.addLayout(buttons)
