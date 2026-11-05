"""The three tabs: Connection, Speed, Website. Each one answers a single
question with a verdict banner on top and step cards below. All content is
in a vertical scroll area that never scrolls sideways."""
from __future__ import annotations

import time

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (QComboBox, QFrame, QHBoxLayout, QLabel,
                               QPushButton, QScrollArea, QSizePolicy,
                               QVBoxLayout, QWidget)

from nwsolver.diag import connection, net, resource, speed
from nwsolver.engine.checks import Ctx
from nwsolver.ui.widgets import (ResultList, TileRow, VerdictBanner,
                                 WrapLabel, set_role)


class SuitePage(QWidget):
    """Banner + controls + (optional) tiles + step cards."""

    run_requested = Signal(object, dict)   # suite module, options
    raw_requested = Signal(object)
    ai_requested = Signal(object)

    suite = None
    idle_text = ""
    button_text = "Run"

    def __init__(self, parent=None):
        super().__init__(parent)
        self.last_run: dict | None = None
        self.banner = VerdictBanner(self.idle_text)

        self.run_btn = QPushButton(self.button_text)
        set_role(self.run_btn, "primary")
        self.run_btn.clicked.connect(self._on_run_clicked)
        self.note = WrapLabel("", "muted")

        self.tiles = TileRow()
        self.tiles.hide()

        self.controls = QHBoxLayout()
        self.controls.setSpacing(8)
        self.build_controls(self.controls)

        self.steps_title = QLabel("Steps")
        set_role(self.steps_title, "section")
        self.results = ResultList()
        self.results.raw_requested.connect(self.raw_requested)
        self.results.ai_requested.connect(self.ai_requested)

        content = QWidget()
        lay = QVBoxLayout(content)
        lay.setContentsMargins(14, 12, 14, 14)
        lay.setSpacing(10)
        lay.addWidget(self.banner)
        lay.addLayout(self.controls)
        lay.addWidget(self.note)
        self.build_extra(lay)
        lay.addWidget(self.tiles)
        lay.addWidget(self.steps_title)
        lay.addWidget(self.results)
        lay.addStretch(1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(content)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        self.steps_title.hide()

    # -- hooks for subclasses ---------------------------------------------

    def build_controls(self, row: QHBoxLayout):
        row.addWidget(self.run_btn)
        row.addStretch(1)

    def build_extra(self, lay: QVBoxLayout):
        pass

    def options(self) -> dict | None:
        """Options for the run, or None to refuse (e.g. empty input)."""
        return {}

    def busy_text(self) -> str:
        return "Checking…"

    def on_overview(self, overview: dict):
        pass

    def on_finished_extra(self, run: dict):
        pass

    # -- run lifecycle (driven by the main window) -------------------------

    def _on_run_clicked(self):
        opts = self.options()
        if opts is not None:
            self.run_requested.emit(self.suite, opts)

    def set_enabled_runs(self, enabled: bool):
        self.run_btn.setEnabled(enabled)

    def started(self):
        titles = [c.title for c in self.suite.make_checks(None)]
        self.results.reset(titles)
        self.steps_title.show()
        self.banner.set_busy(self.busy_text())
        chain = getattr(self.suite, "CHAIN", None)
        self.banner.set_progress_steps([lbl for _c, lbl in chain]
                                       if chain else [])
        if getattr(self.suite, "PARALLEL", False):
            for i in range(len(titles)):
                self.results.set_running(i)

    def check_started(self, index: int, _title: str):
        self.results.set_running(index)

    def result_ready(self, index: int, result):
        self.results.set_result(index, result)

    def finished(self, run: dict):
        self.last_run = run
        self.results.finish()
        self.banner.set_verdict(run["verdict"])
        self.on_finished_extra(run)

    def failed(self, message: str):
        self.results.finish()
        self.banner.headline.setText("The check could not run: " + message)


# --------------------------------------------------------------------------
# Connection
# --------------------------------------------------------------------------

class ConnectionPage(SuitePage):
    suite = connection
    idle_text = "Check why there is no internet connection."
    button_text = "Check connection"

    def build_controls(self, row):
        super().build_controls(row)
        self.note.setText(
            "Goes step by step from the network adapter to websites. The "
            "first broken step is the cause; later failures are only its "
            "consequences.")

    def busy_text(self):
        return "Checking the connection step by step…"

    def on_overview(self, ov: dict):
        def v(x):
            return x if x else "—"
        conn = v(ov.get("type"))
        if ov.get("network"):
            conn += f" · {ov['network']}"
        items = [("conn", "Connected via", conn),
                 ("iface", "Interface", v(ov.get("interface"))),
                 ("ip", "Your IP", v(ov.get("ip"))),
                 ("gw", "Router", v(ov.get("gateway"))),
                 ("dns", "DNS", v(ov.get("dns")))]
        if ov.get("vpn"):
            items.append(("vpn", "VPN", ov["vpn"]))
        if ov.get("proxy"):
            items.append(("proxy", "Proxy", ov["proxy"]))
        self.tiles.set_tiles(items)
        self.tiles.show()

    def on_finished_extra(self, run):
        for r in run["results"]:
            ip = r.metrics.get("public_ip")
            if ip and "pub" not in self.tiles.tiles:
                loc = r.metrics.get("location")
                items = [(k, t.caption.text(), t.value.text())
                         for k, t in self.tiles.tiles.items()]
                items.append(("pub", "Public IP",
                              ip + (f" ({loc})" if loc else "")))
                self.tiles.set_tiles(items)


# --------------------------------------------------------------------------
# Speed
# --------------------------------------------------------------------------

class SpeedPage(SuitePage):
    suite = speed
    idle_text = "Find out what slows the internet down."
    button_text = "Start speed test"

    _TILES = [("down", "Download"), ("up", "Upload"),
              ("ping", "Latency (idle)"), ("loaded", "Latency under load"),
              ("lan", "To router"), ("loss", "Loss (internet)"),
              ("link", "Wi-Fi / cable")]

    def build_controls(self, row):
        super().build_controls(row)
        self.live = QLabel("")
        set_role(self.live, "muted")
        row.addWidget(self.live)
        self.note.setText(
            "Takes about 40 seconds and transfers as much data as the line "
            "allows in that time (up to ~1 GB on gigabit). Pause downloads, "
            "streaming and cloud sync for a fair result.")
        self.tiles.set_tiles([(k, c, "—") for k, c in self._TILES])
        self.tiles.show()
        self._iface = None
        self._prev = None
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._tick)
        self._timer.start()
        QTimer.singleShot(0, self._find_iface)

    def busy_text(self):
        return "Measuring — keep the network idle until the test finishes…"

    def _find_iface(self):
        ctx = Ctx()
        itf = net.physical_uplink(ctx) or net.find_iface(
            ctx, net.uplink(ctx).dev)
        self._iface = itf.name if itf else None
        self._prev = None

    def _tick(self):
        if not self._iface or not self.isVisible():
            return
        try:
            with open(f"/sys/class/net/{self._iface}/statistics/rx_bytes") \
                    as f:
                rx = int(f.read())
            with open(f"/sys/class/net/{self._iface}/statistics/tx_bytes") \
                    as f:
                tx = int(f.read())
        except (OSError, ValueError):
            self.live.setText("")
            return
        now = time.monotonic()
        if self._prev is not None:
            p_rx, p_tx, p_t = self._prev
            dt = max(0.001, now - p_t)
            self.live.setText(
                f"{self._iface} now: ↓ {net.fmt_mbps((rx - p_rx) * 8 / dt / 1e6)}"
                f"  ↑ {net.fmt_mbps((tx - p_tx) * 8 / dt / 1e6)}")
        self._prev = (rx, tx, now)

    def started(self):
        super().started()
        for k, c in self._TILES:
            self.tiles.tiles[k].set("…")

    def result_ready(self, index, result):
        super().result_ready(index, result)
        self._fill(speed.metrics([result]), partial=True)

    def on_finished_extra(self, run):
        self._fill(speed.metrics(run["results"]))
        self._find_iface()

    def _fill(self, m: dict, partial: bool = False):
        t = self.tiles.tiles

        def put(key, value):
            if value is not None:
                t[key].set(value)
            elif not partial:
                t[key].set("—")

        put("down", net.fmt_mbps(m["down_mbps"]) if m.get("down_mbps")
            is not None else None)
        put("up", net.fmt_mbps(m["up_mbps"]) if m.get("up_mbps")
            is not None else None)
        put("ping", net.fmt_ms(m.get("wan_rtt_ms") or m.get("idle_ms"))
            if (m.get("wan_rtt_ms") or m.get("idle_ms")) else None)
        put("loaded", net.fmt_ms(m["loaded_ms"]) if m.get("loaded_ms")
            else None)
        put("lan", net.fmt_ms(m["lan_rtt_ms"]) if m.get("lan_rtt_ms")
            is not None else None)
        put("loss", f"{m['wan_loss_pct']:.0f} %" if m.get("wan_loss_pct")
            is not None else None)
        link = None
        if m.get("kind") == "wifi":
            bits = []
            if m.get("signal") is not None:
                bits.append(f"{m['signal']} dBm")
            if m.get("band"):
                bits.append(m["band"])
            link = " · ".join(bits) or "Wi-Fi"
        elif m.get("link_mbps"):
            link = f"{m['link_mbps']} Mbit/s"
        put("link", link)


# --------------------------------------------------------------------------
# Website / service
# --------------------------------------------------------------------------

class ResourcePage(SuitePage):
    suite = resource
    idle_text = "Enter a website or service that does not open."
    button_text = "Check"

    history_changed = Signal(list)

    def build_controls(self, row):
        self.target = QComboBox()
        self.target.setEditable(True)
        self.target.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.target.setSizePolicy(QSizePolicy.Policy.Expanding,
                                  QSizePolicy.Policy.Fixed)
        self.target.setMinimumContentsLength(12)
        self.target.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        line = self.target.lineEdit()
        line.setPlaceholderText("example.com, https://site/page or "
                                "host:port")
        line.returnPressed.connect(self._on_run_clicked)
        row.addWidget(self.target, 1)
        row.addWidget(self.run_btn)
        self.note.setText(
            "Checks DNS (including DNS blocking), the connection to every "
            "address, encryption and the server's answer, and tells "
            "whether the problem is on your side, a block on the way, or "
            "the site itself.")

    def set_history(self, items: list[str]):
        self.target.clear()
        self.target.addItems(items)
        self.target.setCurrentText("")

    def options(self):
        text = self.target.currentText().strip()
        if not text:
            self.target.setFocus()
            self.banner.headline.setText(
                "Type a website address first, e.g. example.com")
            return None
        items = [text] + [self.target.itemText(i)
                          for i in range(self.target.count())
                          if self.target.itemText(i) != text]
        items = items[:15]
        self.target.blockSignals(True)
        self.set_history(items)
        self.target.setCurrentText(text)
        self.target.blockSignals(False)
        self.history_changed.emit(items)
        return {"target": text}

    def busy_text(self):
        return f"Checking {self.target.currentText().strip()}…"

    def started(self):
        super().started()
        self.banner.set_progress_steps([lbl for _c, lbl in
                                        resource._CHAIN])
