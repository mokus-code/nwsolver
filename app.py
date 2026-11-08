"""GUI bootstrap: QApplication + main window."""
from __future__ import annotations

import os
import subprocess
import sys


def _xcb_cursor_missing() -> bool:
    """Qt >= 6.5 fails to load the xcb platform plugin without libxcb-cursor0.

    Only relevant when the X11 (xcb) plugin is actually going to be used:
    Wayland sessions and explicit platform overrides are skipped.
    """
    platform = os.environ.get("QT_QPA_PLATFORM", "").lower()
    if platform and platform != "xcb":
        return False
    if (os.environ.get("WAYLAND_DISPLAY")
            or os.environ.get("XDG_SESSION_TYPE", "").lower() == "wayland"):
        return False  # Wayland plugin will be used; xcb may never load.
    try:
        proc = subprocess.run(["ldconfig", "-p"], capture_output=True,
                              text=True, timeout=5.0)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return "libxcb-cursor.so" not in proc.stdout


def _sanitize_root_environment() -> None:
    """Root processes cannot reach the user's session bus (DBus).

    Qt's GNOME/GTK theme plugin and GTK's dconf layer then emit a stream of
    harmless but alarming errors ("Session DBus not running", "Error
    creating proxy", dconf warnings). Fall back to the generic Qt theme and
    an in-memory settings backend: no functional impact, much quieter logs.
    """
    if os.geteuid() == 0:
        os.environ.setdefault("QT_QPA_PLATFORMTHEME", "generic")
        os.environ.setdefault("GSETTINGS_BACKEND", "memory")


def main() -> int:
    # Imported lazily so --selftest works without PySide6 installed.
    from PySide6.QtWidgets import QApplication

    _sanitize_root_environment()

    if _xcb_cursor_missing():
        print(
            "\nQt's X11 (xcb) platform plugin needs the system package "
            "'libxcb-cursor0', which is not installed on this machine.\n"
            "Install it with:\n\n"
            "    sudo apt install libxcb-cursor0\n\n"
            "Then start the app again.\n",
            file=sys.stderr,
        )

    # Fail with a readable message instead of Qt's SIGABRT when there is no
    # display at all (e.g. pkexec stripped DISPLAY/WAYLAND_DISPLAY).
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
            or os.environ.get("QT_QPA_PLATFORM")):
        print(
            "\nnwsolver: no graphical display available (DISPLAY and "
            "WAYLAND_DISPLAY are both unset).\n"
            "If you are trying to run with root privileges, use\n\n"
            "    sudo nwsolver\n\n"
            "from a terminal, or the 'Relaunch as root' button inside the "
            "app.\n",
            file=sys.stderr,
        )
        return 1

    from nwsolver.ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("nwsolver")
    app.setApplicationDisplayName("nwsolver")
    app.setOrganizationName("nwsolver")
    app.setDesktopFileName("nwsolver")  # match the .desktop entry (Wayland)
    from PySide6.QtGui import QIcon
    bundled = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "ui", "icon.svg")
    app.setWindowIcon(QIcon.fromTheme("nwsolver", QIcon(bundled)))

    window = MainWindow()
    window.show()
    return app.exec()
