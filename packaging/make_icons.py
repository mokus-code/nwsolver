#!/usr/bin/env python3
"""Install the nwsolver app icon into a hicolor icon tree.

Source: ui/icon.svg (the same file the running app uses as window icon).
Writes <dest>/scalable/apps/nwsolver.svg and PNGs at the standard sizes,
rendered with rsvg-convert when available (full fidelity), otherwise with
Qt's SVG renderer (offscreen, no display needed).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

SIZES = (16, 22, 24, 32, 48, 64, 128, 256, 512)
SVG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ui",
                   "icon.svg")


def _render_qt(sizes, dest) -> bool:
    try:
        from PySide6.QtCore import Qt
        from PySide6.QtGui import QGuiApplication, QImage, QPainter
        from PySide6.QtSvg import QSvgRenderer
    except ImportError:
        return False
    app = QGuiApplication.instance() or QGuiApplication(sys.argv)  # noqa: F841
    renderer = QSvgRenderer(SVG)
    if not renderer.isValid():
        raise RuntimeError(f"invalid SVG: {SVG}")
    for size in sizes:
        img = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
        img.fill(Qt.GlobalColor.transparent)
        painter = QPainter(img)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        renderer.render(painter)
        painter.end()
        path = os.path.join(dest, f"{size}x{size}", "apps", "nwsolver.png")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not img.save(path):
            raise RuntimeError(f"could not write {path}")
        print(f"wrote {path}")
    return True


def _render_rsvg(sizes, dest) -> bool:
    tool = shutil.which("rsvg-convert")
    if tool is None:
        return False
    for size in sizes:
        path = os.path.join(dest, f"{size}x{size}", "apps", "nwsolver.png")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        subprocess.run([tool, "-w", str(size), "-h", str(size), SVG, "-o",
                        path], check=True)
        print(f"wrote {path}")
    return True


def main() -> int:
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <dest-dir>", file=sys.stderr)
        return 2
    dest = sys.argv[1]
    scalable = os.path.join(dest, "scalable", "apps")
    os.makedirs(scalable, exist_ok=True)
    shutil.copyfile(SVG, os.path.join(scalable, "nwsolver.svg"))
    print(f"wrote {scalable}/nwsolver.svg")
    # librsvg renders the glow/shadow filters; Qt's renderer skips them.
    if not (_render_rsvg(SIZES, dest) or _render_qt(SIZES, dest)):
        print("warning: neither QtSvg nor rsvg-convert available — only the "
              "scalable SVG icon was installed", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
