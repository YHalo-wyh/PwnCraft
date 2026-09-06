from __future__ import annotations

from dataclasses import dataclass
import codecs
import re


try:  # Locked in requirements; fallback keeps the terminal usable if omitted.
    import pyte
except ImportError:  # pragma: no cover - exercised by dependency-light builds.
    pyte = None


_ANSI_FALLBACK_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


@dataclass(frozen=True)
class AnsiCell:
    char: str = " "
    fg: str = "default"
    bg: str = "default"
    bold: bool = False
    dim: bool = False
    reverse: bool = False


class _FallbackScreen:
    def __init__(self, cols: int, rows: int, history: int):
        self.columns = cols
        self.lines = rows
        self.history_limit = history
        self._lines = [""]
        self.cursor_x = 0
        self.cursor_y = 0
        self.history_offset = 0

    def feed(self, text: str) -> None:
        # New terminal output follows the live prompt, matching a normal PTY.
        self.history_offset = 0
        text = _ANSI_FALLBACK_RE.sub("", text)
        for char in text:
            if char == "\r":
                self.cursor_x = 0
            elif char == "\n":
                self.cursor_y += 1
                self.cursor_x = 0
                while len(self._lines) <= self.cursor_y:
                    self._lines.append("")
            elif char == "\b":
                self.cursor_x = max(0, self.cursor_x - 1)
            elif char >= " ":
                line = self._lines[self.cursor_y]
                if len(line) < self.cursor_x:
                    line += " " * (self.cursor_x - len(line))
                if self.cursor_x < len(line):
                    line = line[:self.cursor_x] + char + line[self.cursor_x + 1:]
                else:
                    line += char
                self._lines[self.cursor_y] = line
                self.cursor_x += 1
        if len(self._lines) > self.history_limit:
            remove = len(self._lines) - self.history_limit
            del self._lines[:remove]
            self.cursor_y = max(0, self.cursor_y - remove)

    def resize(self, rows: int, cols: int) -> None:
        self.lines = rows
        self.columns = cols

    def display(self) -> list[str]:
        bottom = max(0, len(self._lines) - self.history_offset)
        top = max(0, bottom - self.lines)
        visible = self._lines[top:bottom]
        visible = ([""] * max(0, self.lines - len(visible))) + visible
        return [line[:self.columns].ljust(self.columns) for line in visible]

    def scroll_history(self, lines: int) -> None:
        maximum = max(0, len(self._lines) - self.lines)
        self.history_offset = max(0, min(maximum, self.history_offset + int(lines)))

    def history_viewport(self) -> tuple[int, int]:
        maximum = max(0, len(self._lines) - self.lines)
        return maximum - self.history_offset, maximum

    def cells(self, row: int) -> list[AnsiCell]:
        lines = self.display()
        text = lines[row] if 0 <= row < len(lines) else " " * self.columns
        return [AnsiCell(char) for char in text]


class AnsiTerminalScreen:
    """Version-locked pyte screen with a small dependency-free fallback."""

    def __init__(self, cols: int = 120, rows: int = 36, history: int = 10_000):
        self.cols = max(10, int(cols))
        self.rows = max(2, int(rows))
        self.history_limit = max(self.rows, int(history))
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")
        if pyte is None:
            self._fallback = _FallbackScreen(self.cols, self.rows, self.history_limit)
            self._screen = None
            self._stream = None
        else:
            self._fallback = None
            self._screen = pyte.screens.HistoryScreen(
                self.cols,
                self.rows,
                history=self.history_limit,
                ratio=0.5,
            )
            self._stream = pyte.Stream(self._screen)

    @property
    def using_fallback(self) -> bool:
        return self._fallback is not None

    @property
    def cursor(self) -> tuple[int, int]:
        if self._fallback is not None:
            return self._fallback.cursor_x, min(self.rows - 1, self._fallback.cursor_y)
        return int(self._screen.cursor.x), int(self._screen.cursor.y)

    def feed(self, data: bytes) -> None:
        text = self._decoder.decode(data)
        if not text:
            return
        if self._fallback is not None:
            self._fallback.feed(text)
        else:
            self._stream.feed(text)

    def resize(self, rows: int, cols: int) -> None:
        self.rows = max(2, int(rows))
        self.cols = max(10, int(cols))
        if self._fallback is not None:
            self._fallback.resize(self.rows, self.cols)
        else:
            self._screen.resize(self.rows, self.cols)

    def display(self) -> tuple[str, ...]:
        if self._fallback is not None:
            return tuple(self._fallback.display())
        return tuple(self._screen.display)

    def cells(self, row: int) -> tuple[AnsiCell, ...]:
        if self._fallback is not None:
            return tuple(self._fallback.cells(row))
        result: list[AnsiCell] = []
        line = self._screen.buffer[row]
        for column in range(self.cols):
            char = line[column]
            result.append(
                AnsiCell(
                    char.data,
                    str(char.fg or "default"),
                    str(char.bg or "default"),
                    bool(char.bold),
                    bool(char.italics or char.underscore),
                    bool(char.reverse),
                )
            )
        return tuple(result)

    def consume_dirty_rows(self) -> tuple[int, ...]:
        """Return rows changed by the last feed and clear pyte's dirty set."""
        if self._screen is None:
            return tuple(range(self.rows))
        dirty = tuple(sorted(int(row) for row in self._screen.dirty if 0 <= int(row) < self.rows))
        self._screen.dirty.clear()
        return dirty

    def scroll_history(self, pages: int) -> None:
        """Scroll by terminal *lines*, not half-screen pages.

        One mouse-wheel notch should move a few readable lines.  Pyte exposes
        page operations only, so temporarily select a one-line page ratio and
        repeat it.  The history buffer itself remains pyte-owned.
        """
        if pages == 0:
            return
        if self._fallback is not None:
            self._fallback.scroll_history(pages)
            return
        history = self._screen.history
        self._screen.history = history._replace(ratio=1.0 / max(1, self.rows))
        try:
            callback = self._screen.prev_page if pages > 0 else self._screen.next_page
            for _ in range(abs(int(pages))):
                callback()
        finally:
            self._screen.history = self._screen.history._replace(ratio=history.ratio)

    def history_viewport(self) -> tuple[int, int]:
        """Return ``(visible_top, maximum_top)`` for an external scrollbar."""
        if self._fallback is not None:
            return self._fallback.history_viewport()
        top_count = len(self._screen.history.top)
        return top_count, top_count + len(self._screen.history.bottom)
