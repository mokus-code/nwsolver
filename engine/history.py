"""Diagnosis history: every finished run is kept as one JSON file in
``$XDG_DATA_HOME/nwsolver/history`` (default ``~/.local/share``), so the
user can look back, compare with an earlier state and include past checks
in an export. Stored locally only; the newest 300 runs are kept.
"""
from __future__ import annotations

import datetime
import json
import os

from nwsolver.engine.context import run_to_dict

MAX_RUNS = 300


def history_dir() -> str:
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "nwsolver", "history")


def save(run: dict) -> dict | None:
    """Store a finished run; returns its serialised form (or None)."""
    if run.get("cancelled"):
        return None
    data = run_to_dict(run)
    d = history_dir()
    try:
        os.makedirs(d, exist_ok=True)
        ts = datetime.datetime.fromtimestamp(data["timestamp"])
        path = os.path.join(d, f"{ts:%Y%m%d-%H%M%S}-{data['suite']}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False)
        _prune(d)
    except OSError:
        return data
    return data


def _prune(d: str) -> None:
    files = sorted(f for f in os.listdir(d) if f.endswith(".json"))
    for f in files[:-MAX_RUNS]:
        try:
            os.remove(os.path.join(d, f))
        except OSError:
            pass


def load(limit: int = 200) -> list[dict]:
    """Stored runs, newest first."""
    d = history_dir()
    try:
        files = sorted((f for f in os.listdir(d) if f.endswith(".json")),
                       reverse=True)[:limit]
    except OSError:
        return []
    out = []
    for f in files:
        try:
            with open(os.path.join(d, f), encoding="utf-8") as fh:
                item = json.load(fh)
            item["_file"] = f
            out.append(item)
        except (OSError, ValueError):
            continue
    return out


def previous(data: dict, items: list[dict] | None = None) -> dict | None:
    """The run of the same tab (and target) just before ``data``."""
    items = load() if items is None else items
    return next((h for h in items
                 if h.get("suite") == data.get("suite")
                 and h.get("target") == data.get("target")
                 and h.get("timestamp", 0) < data.get("timestamp", 0)),
                None)


def clear() -> int:
    d = history_dir()
    n = 0
    try:
        for f in os.listdir(d):
            if f.endswith(".json"):
                os.remove(os.path.join(d, f))
                n += 1
    except OSError:
        pass
    return n
