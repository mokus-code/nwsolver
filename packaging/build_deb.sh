#!/usr/bin/env sh
# Build a Debian package (.deb) for nwsolver.
#
# PySide6 is NOT packaged by Ubuntu (only Debian 13+), so this script
# bundles it into the package via pip (PySide6-Essentials + shiboken6, the
# QtCore/QtGui/QtWidgets modules the app needs). The result is a
# self-contained .deb that works on any modern Debian-based system
# (Ubuntu 22.04+ / Debian 12+; PySide6 wheels need glibc >= 2.34).
#
# Build machine needs network access to PyPI.
# Usage:  ./packaging/build_deb.sh   ->  dist/nwsolver_<version>_<arch>.deb
set -e

PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$PROJECT_DIR"

command -v dpkg-deb >/dev/null 2>&1 || { echo "error: dpkg-deb not found" >&2; exit 1; }

VERSION="$(PYTHONPATH="$(dirname "$PROJECT_DIR")" python3 -c \
    'from nwsolver import __version__; print(__version__)')"
# Native wheels are bundled, so the package is architecture-specific.
# Override with ARCH=arm64 etc. when building on that platform.
ARCH="${ARCH:-amd64}"
PKG="nwsolver"
DIST_DIR="$PROJECT_DIR/dist"
STAGE="$DIST_DIR/stage"
DEB="$DIST_DIR/${PKG}_${VERSION}_${ARCH}.deb"

rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" \
         "$STAGE/usr/bin" \
         "$STAGE/usr/lib/nwsolver" \
         "$STAGE/usr/share/applications" \
         "$STAGE/usr/share/doc/nwsolver"

# ---- 1. bundled PySide6 (pip --target, no build-time compile) ------------
echo ">> fetching PySide6-Essentials from PyPI (network required)…"
"$PROJECT_DIR/.venv/bin/python" -m pip install --quiet \
    --target "$STAGE/usr/lib/nwsolver/pyside" \
    --only-binary :all: --no-cache-dir \
    "PySide6-Essentials>=6.6"
find "$STAGE/usr/lib/nwsolver/pyside" -name '__pycache__' -type d -prune \
     -exec rm -rf {} +
find "$STAGE/usr/lib/nwsolver/pyside" -name '*.pyc' -delete

# ---- 2. app payload ------------------------------------------------------
mkdir -p "$STAGE/usr/lib/nwsolver/nwsolver"
# Copy the nwsolver package dir, skipping dev-only artefacts.
tar --exclude='./.venv' --exclude='./.git' --exclude='./__pycache__' \
    --exclude='./*.pyc' --exclude='./dist' --exclude='./layers' --exclude='./pyrightconfig.json' \
    --exclude='./requirements.txt' --exclude='./start.sh' \
    --exclude='./run.py' --exclude='./packaging' \
    -cf - . | tar -xf - -C "$STAGE/usr/lib/nwsolver/nwsolver"
cp run.py "$STAGE/usr/lib/nwsolver/run.py"
find "$STAGE/usr/lib/nwsolver/nwsolver" -name '__pycache__' -type d -prune \
     -exec rm -rf {} +

# Launcher: resolves the lib dir relative to itself, so it works from the
# staged tree during testing and from /usr/bin after installation. The
# bundled PySide6 is prepended to sys.path so it wins over any system copy.
cat > "$STAGE/usr/bin/nwsolver" <<'EOF'
#!/usr/bin/python3
"""nwsolver launcher (installed by the Debian package)."""
import os
import sys

LIB = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "..", "lib", "nwsolver")
sys.path.insert(0, os.path.join(LIB, "pyside"))  # bundled PySide6
sys.path.insert(0, LIB)

import run  # noqa: E402  (run.py: CLI parsing + GUI/selftest entry)

if __name__ == "__main__":
    sys.exit(run.main())
EOF
chmod 755 "$STAGE/usr/bin/nwsolver"

# ---- 3. icons ------------------------------------------------------------
"$PROJECT_DIR/.venv/bin/python" "$PROJECT_DIR/packaging/make_icons.py" \
    "$STAGE/usr/share/icons/hicolor"

# ---- 4. desktop entry ----------------------------------------------------
cat > "$STAGE/usr/share/applications/nwsolver.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=nwsolver
GenericName=Network diagnostics
Comment=Find out why the internet does not work, is slow, or a site does not open
Exec=nwsolver
Icon=nwsolver
Terminal=false
Categories=Network;
Keywords=internet;network;diagnostics;wifi;dns;speed;troubleshooting;
StartupWMClass=nwsolver
EOF

# ---- 5. documentation ----------------------------------------------------
cp README.md "$STAGE/usr/share/doc/nwsolver/README.md"
mkdir -p "$STAGE/usr/share/doc/nwsolver/docs"
cp docs/PLAN.md "$STAGE/usr/share/doc/nwsolver/docs/" 2>/dev/null || true
gzip -9 -n -f "$STAGE/usr/share/doc/nwsolver/README.md" \
    "$STAGE/usr/share/doc/nwsolver/docs/PLAN.md" 2>/dev/null || true

# ---- 6. DEBIAN metadata --------------------------------------------------
# PySide6/Qt are LGPL — bundled wheels keep their own licensing.
cat > "$STAGE/DEBIAN/copyright" <<'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: nwsolver

Files: *
Copyright: 2026 nwsolver developers
License: MIT

Files: usr/lib/nwsolver/pyside/*
Copyright: The Qt Company Ltd. and its contributors
License: LGPL-3.0-or-later
 PySide6 and Qt are licensed under the GNU Lesser General Public License
 version 3 or (at your option) any later version. See
 https://doc.qt.io/qtforpython/licenses.html and
 https://www.gnu.org/licenses/lgpl-3.0.html
EOF

cat > "$STAGE/DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Depends: python3 (>= 3.10), iproute2, iputils-ping, iw, libxcb-cursor0, libxcb-icccm4, libxcb-image0,
         libxcb-keysyms1, libxcb-render-util0, libxcb-shape0, libxcb-xkb1,
         libxcb-xinerama0, libxkbcommon-x11-0, libgl1, libegl1,
         libfontconfig1
Recommends: network-manager, iputils-tracepath | traceroute, pciutils
Maintainer: nwsolver developers <nwsolver@localhost>
Description: Internet connection troubleshooter
 Answers three questions in plain words: why there is no internet
 connection (walks adapter, link, IP, route, router, ISP, DNS, web and
 names the first broken step), why the internet is slow (Wi-Fi signal,
 cable speed, local and ISP loss/latency, bufferbloat, background
 traffic, measured throughput) and why a specific site does not open
 (DNS blocking, TCP, TLS, HTTP, where the route stops). Markdown report
 and optional AI assistant. Bundles PySide6 (LGPL).
 Terminal mode: nwsolver --selftest [--speed | --check URL].
EOF

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q /usr/share/icons/hicolor >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 755 "$STAGE/DEBIAN/postinst"

# Python writes __pycache__ next to the code when run as root; dpkg does not
# know these files, so remove them before upgrade/removal (otherwise dpkg
# warns "unable to delete old directory").
cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
find /usr/lib/nwsolver -name '__pycache__' -type d -prune \
     -exec rm -rf {} + 2>/dev/null || true
exit 0
EOF
chmod 755 "$STAGE/DEBIAN/prerm"

# ---- 7. normalise permissions ---------------------------------------------
# Never inherit the source tree's modes (e.g. 0600 files): everything in the
# package must be readable by all users once it is owned by root.
# Bundled PySide6 keeps its own exec bits; only make it world-readable.
find "$STAGE" -path "$STAGE/usr/lib/nwsolver/pyside" -prune -o -type d \
     -exec chmod 755 {} +
find "$STAGE" -path "$STAGE/usr/lib/nwsolver/pyside" -prune -o -type f \
     -exec chmod 644 {} +
chmod -R u+rwX,go+rX,go-w "$STAGE/usr/lib/nwsolver/pyside"
chmod 755 "$STAGE/usr/bin/nwsolver" "$STAGE/DEBIAN/postinst" \
      "$STAGE/DEBIAN/prerm"

# ---- 8. build ------------------------------------------------------------
mkdir -p "$DIST_DIR"
dpkg-deb --build --root-owner-group "$STAGE" "$DEB"
rm -rf "$STAGE"

echo "Built: $DEB"
