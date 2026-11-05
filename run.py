#!/usr/bin/env python3
"""nwsolver — internet connection troubleshooter for Ubuntu.

Usage:
    python3 run.py                          # GUI
    python3 run.py --selftest               # why is there no internet? (CLI)
    python3 run.py --selftest --speed       # why is the internet slow? (CLI)
    python3 run.py --selftest --check URL   # why doesn't URL open? (CLI)
"""
from __future__ import annotations

import argparse
import os
import sys

# The project root *is* the `nwsolver` package, so its parent directory must
# be importable for `import nwsolver` to work regardless of CWD.
_ROOT = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_ROOT)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="nwsolver",
        description="Finds why the internet doesn't work, is slow, or why a "
                    "site doesn't open.")
    parser.add_argument("--selftest", action="store_true",
                        help="run in the terminal instead of the GUI")
    parser.add_argument("--speed", action="store_true",
                        help="with --selftest: run the speed diagnosis")
    parser.add_argument("--check", metavar="URL",
                        help="with --selftest: check why URL doesn't open")
    args = parser.parse_args()

    if args.selftest:
        from nwsolver.engine.selftest import run_selftest
        if args.check:
            return run_selftest("resource", target=args.check)
        return run_selftest("speed" if args.speed else "connection")

    from nwsolver.app import main as gui_main
    return gui_main()


if __name__ == "__main__":
    sys.exit(main())
