"""
A few helpers for making things print pretty-like.
"""

from __future__ import annotations

import os
import sys
import unicodedata

import pwndbg.color.context as ctx_color
import pwndbg.lib.config
from pwndbg import config
from pwndbg.color import strip
from pwndbg.color import theme


def _display_width(value: str) -> int:
    """Count terminal cells, keeping CJK banner titles aligned."""
    plain = strip(str(value))
    width = 0
    for char in plain:
        if unicodedata.combining(char):
            continue
        width += 2 if unicodedata.east_asian_width(char) in {"W", "F"} else 1
    return width

theme.add_param("banner-separator", "─", "repeated banner separator character")
theme.add_param("banner-title-surrounding-left", "[ ", "banner title surrounding char (left side)")
theme.add_param(
    "banner-title-surrounding-right", " ]", "banner title surrounding char (right side)"
)
title_position = theme.add_param(
    "banner-title-position",
    "center",
    "banner title position",
    param_class=pwndbg.lib.config.PARAM_ENUM,
    enum_sequence=["center", "left", "right"],
)


def banner(title, target=sys.stdout, width=None, extra=""):
    # Native context localization.  Color and separator rendering remain the
    # upstream Pwndbg implementation; only the title text is translated.
    try:
        from pwndbg.pwnbao.localization.context_zh_CN import section_title

        title = section_title(str(title))
    except ImportError:
        pass
    title = title.upper()
    if width is None:
        _height, width = get_window_size(target)
    width = max(20, int(width))
    # Configuration details are useful only when they fit.  Never let them
    # consume the cells needed by a localized section title such as
    # ``寄存器`` or ``反汇编``.
    title_width = _display_width(title) + _display_width(config.banner_title_surrounding_left) + _display_width(config.banner_title_surrounding_right)
    if extra and title_width + _display_width(extra) > width - 4:
        extra = ""
    if title:
        title = f"{config.banner_title_surrounding_left}{ctx_color.banner_title(title)}{extra}{config.banner_title_surrounding_right}"
    title_cells = _display_width(title)
    separator = str(config.banner_separator)
    if title_cells >= width:
        # Keep the full localized title and trim only decorative separators.
        return ctx_color.banner(title)
    spare = max(0, width - title_cells)
    if title_position == "left":
        left_cells, right_cells = 0, spare
    elif title_position == "right":
        left_cells, right_cells = spare, 0
    else:
        left_cells = spare // 2
        right_cells = spare - left_cells
    return ctx_color.banner(separator * left_cells + title + separator * right_cells)


def addrsz(address) -> str:
    return pwndbg.dbg.addrsz(address)


def get_window_size(target=sys.stdout) -> tuple[int, int]:
    fallback = (int(os.environ.get("LINES", 24)), int(os.environ.get("COLUMNS", 80)))
    if not target.isatty():
        return fallback
    if os.environ.get("PWNDBG_IN_TEST") is not None:
        return fallback

    if target in (sys.stdout, sys.stdin):
        # We can ask the debugger for the window size
        rows, cols = get_cmd_window_size()
        if rows is not None and cols is not None:
            return rows, cols

    try:
        term = os.get_terminal_size(target.fileno())
        return term.lines or fallback[0], term.columns or fallback[1]
    except Exception:
        pass

    return fallback


def get_cmd_window_size():
    return pwndbg.dbg.get_cmd_window_size()
