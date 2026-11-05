"""One global font-size setting for the whole UI (HiDPI-friendly).

The application font point size lives here (default 12 pt). All stylesheet
font sizes are derived from it via :func:`px`, so changing the single
setting in the toolbar rescales everything — the big dashboard score,
layer headings, cards, chips and trees.

Design sizes are expressed in pixels as they looked at 12 pt on a 96 dpi
screen; :func:`px` scales them proportionally to the current point size.
"""
from __future__ import annotations

_pt = 12  # current application font size in points


def font_pt() -> int:
    """Current application font size in points."""
    return _pt


def set_font_pt(pt: int) -> None:
    global _pt
    _pt = max(6, int(pt))


def px(design_px: int) -> int:
    """Scale a font size designed for 12 pt to the current point size."""
    return max(7, round(design_px * _pt / 12))
