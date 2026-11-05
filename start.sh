#!/usr/bin/env sh
# nwsolver launcher — starts the app with the project's virtualenv Python.
#
# Usage:
#     ./start.sh                    # launch the GUI
#     ./start.sh --selftest         # headless scan (no GUI needed)
#     ./start.sh --selftest --deep  # headless scan incl. traceroute
#
# Any extra arguments are passed straight to run.py.

set -e

# Resolve the project directory (works from any CWD, and via symlinks).
SCRIPT="$0"
if command -v readlink >/dev/null 2>&1; then
    SCRIPT="$(readlink -f -- "$0" 2>/dev/null || printf '%s' "$0")"
fi
PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "$SCRIPT")" && pwd)"
VENV_PY="$PROJECT_DIR/.venv/bin/python"

if [ ! -x "$VENV_PY" ]; then
    echo "Error: virtualenv not found at $VENV_PY" >&2
    echo "Create it first:" >&2
    echo "    python3 -m venv \"$PROJECT_DIR/.venv\"" >&2
    echo "    \"$PROJECT_DIR/.venv/bin/pip\" install -r \"$PROJECT_DIR/requirements.txt\"" >&2
    exit 1
fi

if ! "$VENV_PY" -c "import PySide6" >/dev/null 2>&1; then
    echo "Error: PySide6 is not installed in the virtualenv." >&2
    echo "Install the dependencies first:" >&2
    echo "    \"$VENV_PY\" -m pip install -r \"$PROJECT_DIR/requirements.txt\"" >&2
    exit 1
fi

cd "$PROJECT_DIR"
exec "$VENV_PY" "$PROJECT_DIR/run.py" "$@"
