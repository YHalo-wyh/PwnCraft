from __future__ import annotations

import base64
import codecs
import fcntl
import json
import os
from pathlib import Path
import select
import signal
import struct
import sys
import termios
import tty

ROOT = Path(__file__).resolve().parent
_OSC_PREFIX = b"\x1b]PWNDBG_SLASH;1;"
_OSC_END = b"\x07"


def _partial_prefix_length(buffer: bytearray, prefix: bytes) -> int:
    """Length of the tail that can still become ``prefix`` on next read.

    Keeping a fixed ``len(prefix)-1`` tail stalls the visible GDB prompt when
    the child goes idle: the final bytes of ``pwndbg> `` never reach the real
    terminal.  Only an actual partial OSC prefix may be retained.
    """
    maximum = min(len(buffer), len(prefix) - 1)
    for length in range(maximum, 0, -1):
        if buffer[-length:] == prefix[:length]:
            return length
    return 0


class SlashInput:
    """Native PTY-side slash chooser, independent from the Qt GUI.

    The chooser owns a fixed group of terminal rows below the readline
    prompt.  Redraws rewrite those rows in place instead of printing another
    command list.  This is the same interaction model used by modern coding
    assistants: type to filter, Up/Down to change the preselected live
    command, PageUp/PageDown to move a page, Enter to execute and Esc to
    close.
    """

    MENU_ROWS = 8
    PAGE_SIZE = MENU_ROWS - 1

    def __init__(self, child_fd: int, output_fd: int):
        self.child_fd = child_fd
        self.output_fd = output_fd
        self.catalog: list[dict] = []
        self.active = False
        self.query = ""
        self.selected = 0
        self.window_start = 0
        self.menu_reserved = False
        self.normal_line_active = False
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")

    def set_catalog(self, payload: bytes) -> None:
        try:
            self.catalog = list(json.loads(base64.b64decode(payload).decode("utf-8")))
        except Exception:
            self.catalog = []

    def matches(self) -> list[dict]:
        needle = self.query.split(" ", 1)[0].casefold()
        scored = []
        for item in self.catalog:
            haystack = " ".join(
                (
                    str(item.get("name", "")),
                    " ".join(item.get("aliases") or ()),
                    str(item.get("description", "")),
                    str(item.get("category", "")),
                    " ".join(item.get("keywords") or ()),
                )
            ).casefold()
            if needle and needle not in haystack:
                continue
            name = str(item.get("name", ""))
            score = 0 if name.casefold().startswith(needle) else 1
            scored.append((score, name, item))
        scored.sort(key=lambda value: (value[0], value[1]))
        return [value[2] for value in scored]

    def _selected_matches(self) -> tuple[list[dict], list[dict]]:
        matches = self.matches()
        if not matches:
            self.selected = 0
            self.window_start = 0
            return matches, []
        self.selected = max(0, min(self.selected, len(matches) - 1))
        if self.selected < self.window_start:
            self.window_start = self.selected
        elif self.selected >= self.window_start + self.PAGE_SIZE:
            self.window_start = self.selected - self.PAGE_SIZE + 1
        maximum_start = max(0, len(matches) - self.PAGE_SIZE)
        self.window_start = max(0, min(self.window_start, maximum_start))
        return matches, matches[self.window_start : self.window_start + self.PAGE_SIZE]

    def _reserve_menu_rows(self) -> None:
        if self.menu_reserved:
            return
        # Reserve once.  Subsequent redraws only rewrite these rows, so a
        # changing filter never leaves repeated candidate lists in scrollback.
        os.write(
            self.output_fd,
            (("\r\n" * self.MENU_ROWS) + f"\x1b[{self.MENU_ROWS}A").encode("ascii"),
        )
        self.menu_reserved = True

    def _paint_menu_rows(self, rows: list[str]) -> None:
        self._reserve_menu_rows()
        # Save the exact readline cursor (including a wide/Chinese query),
        # paint the already-reserved rows, then restore the cursor.
        output = ["\x1b[s"]
        for row in range(self.MENU_ROWS):
            output.append("\r\n\x1b[2K")
            output.append(rows[row] if row < len(rows) else "")
        output.append("\x1b[u")
        os.write(self.output_fd, "".join(output).encode("utf-8", "replace"))

    def _clear_menu(self) -> None:
        if not self.menu_reserved:
            return
        output = ["\x1b[s"]
        for _row in range(self.MENU_ROWS):
            output.append("\r\n\x1b[2K")
        output.append("\x1b[u")
        os.write(self.output_fd, "".join(output).encode("ascii"))
        self.menu_reserved = False

    def redraw(self) -> None:
        matches, visible = self._selected_matches()
        lines = []
        for index in range(self.PAGE_SIZE):
            if index < len(visible):
                item = visible[index]
                absolute_index = self.window_start + index
                selected = absolute_index == self.selected
                marker = "▸" if selected else " "
                row_style = "\x1b[48;5;236m\x1b[1m" if selected else ""
                row_reset = "\x1b[0m" if selected else ""
                lines.append(
                    f"{row_style}{marker} \x1b[96m/{item.get('name', ''):<24}\x1b[0m{row_style} "
                    f"\x1b[37m{item.get('description', '')}\x1b[0m{row_reset}"
                )
            else:
                lines.append("")
        if matches:
            lines.append(
                f"\x1b[33m  ↑↓ 选择  PgUp/PgDn 翻页  Tab 补全  Enter 执行  Esc 关闭"
                f"\x1b[90m   {self.selected + 1}/{len(matches)}\x1b[0m"
            )
        else:
            lines.append("\x1b[31m  未找到匹配命令。Esc 关闭，Backspace 修改筛选。\x1b[0m")
        self._paint_menu_rows(lines)

    def begin(self) -> None:
        self.active = True
        self.query = ""
        self.selected = 0
        self.window_start = 0
        os.write(self.output_fd, b"/")
        self.redraw()

    def cancel(self) -> None:
        self._clear_menu()
        self.active = False
        self.query = ""
        self.selected = 0
        self.window_start = 0
        os.write(self.output_fd, b"\r\x1b[2K")

    def submit(self) -> None:
        matches, _visible = self._selected_matches()
        query = self.query.strip()
        exact = next((item for item in self.catalog if str(item.get("name")) == query.split(" ", 1)[0]), None)
        if not query and matches:
            query = str(matches[self.selected].get("name", ""))
        elif exact is None and matches and " " not in query:
            # Enter on a filtered list selects the highlighted live command.
            query = str(matches[self.selected].get("name", query))
        command = "slash-native " + query
        self._clear_menu()
        self.active = False
        self.query = ""
        self.selected = 0
        self.window_start = 0
        os.write(self.output_fd, b"\r\x1b[2K")
        os.write(self.child_fd, command.encode("utf-8") + b"\r")

    def move_selection(self, delta: int) -> None:
        matches = self.matches()
        if not matches:
            return
        self.selected = max(0, min(len(matches) - 1, self.selected + int(delta)))
        self.redraw()

    def reset_filter_selection(self) -> None:
        self.selected = 0
        self.window_start = 0

    def feed(self, data: bytes) -> None:
        index = 0
        while index < len(data):
            if self.active:
                if data.startswith((b"\r", b"\n"), index):
                    self.submit()
                    index += 1
                    continue
                if data.startswith(b"\x1b[A", index):
                    self.move_selection(-1)
                    index += 3
                    continue
                if data.startswith(b"\x1b[B", index):
                    self.move_selection(1)
                    index += 3
                    continue
                if data.startswith(b"\x1b[5~", index):
                    self.move_selection(-self.PAGE_SIZE)
                    index += 4
                    continue
                if data.startswith(b"\x1b[6~", index):
                    self.move_selection(self.PAGE_SIZE)
                    index += 4
                    continue
                if data.startswith(b"\x1b", index):
                    self.cancel()
                    index += 1
                    continue
                byte = data[index : index + 1]
                if byte in {b"\x7f", b"\x08"}:
                    if self.query:
                        self.query = self.query[:-1]
                        self.reset_filter_selection()
                        os.write(self.output_fd, b"\b \b")
                        self.redraw()
                    else:
                        self.cancel()
                    index += 1
                    continue
                if byte == b"\t":
                    matches = self.matches()
                    if matches:
                        self.query = str(matches[self.selected].get("name", "")) + " "
                        self.reset_filter_selection()
                        os.write(self.output_fd, ("\r\x1b[2Kpwndbg> /" + self.query).encode("utf-8"))
                        self.redraw()
                    index += 1
                    continue
                # Decode one complete UTF-8 scalar without ever changing
                # terminal cell geometry in the GUI.
                text = self.decoder.decode(byte)
                if text:
                    self.query += text
                    self.reset_filter_selection()
                    os.write(self.output_fd, text.encode("utf-8"))
                    self.redraw()
                index += 1
                continue

            byte = data[index : index + 1]
            if byte == b"/" and not self.normal_line_active and self.catalog:
                self.begin()
                index += 1
                continue
            os.write(self.child_fd, byte)
            if byte in {b"\r", b"\n", b"\x03", b"\x15"}:
                self.normal_line_active = False
            elif byte not in {b"\x1b", b"[", b"A", b"B", b"C", b"D"}:
                self.normal_line_active = True
            index += 1


def _copy_winsize(source: int, target: int) -> None:
    try:
        size = fcntl.ioctl(source, termios.TIOCGWINSZ, b"\0" * 8)
        fcntl.ioctl(target, termios.TIOCSWINSZ, size)
    except OSError:
        pass


def main() -> int:
    import pty

    ld = os.environ["PWNDBG_PWNBAO_LD"]
    python = os.environ["PWNDBG_PWNBAO_PYTHON"]
    if not os.isatty(sys.stdin.fileno()):
        # Batch/CI mode needs no interactive slash interception.
        os.execv(ld, [ld, python, str(ROOT / "launcher.py"), *sys.argv[1:]])
    pid, child_fd = pty.fork()
    if pid == 0:
        os.environ["PWNBAO_SLASH_PROXY"] = "1"
        os.execv(ld, [ld, python, str(ROOT / "launcher.py"), *sys.argv[1:]])

    stdin_fd = sys.stdin.fileno()
    stdout_fd = sys.stdout.fileno()
    _copy_winsize(stdin_fd, child_fd)
    previous = termios.tcgetattr(stdin_fd) if os.isatty(stdin_fd) else None
    if previous is not None:
        tty.setraw(stdin_fd)
    state = SlashInput(child_fd, stdout_fd)
    output_buffer = bytearray()

    def resize(_signal, _frame):
        _copy_winsize(stdin_fd, child_fd)
        os.kill(pid, signal.SIGWINCH)

    signal.signal(signal.SIGWINCH, resize)
    try:
        while True:
            readable, _, _ = select.select([stdin_fd, child_fd], [], [])
            if child_fd in readable:
                try:
                    chunk = os.read(child_fd, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                output_buffer.extend(chunk)
                while True:
                    start = output_buffer.find(_OSC_PREFIX)
                    if start < 0:
                        # Preserve a possible split OSC prefix at the tail.
                        keep = _partial_prefix_length(output_buffer, _OSC_PREFIX)
                        emit = bytes(output_buffer[:-keep] if keep else output_buffer)
                        if emit:
                            os.write(stdout_fd, emit)
                            del output_buffer[: len(emit)]
                        break
                    if start:
                        os.write(stdout_fd, bytes(output_buffer[:start]))
                        del output_buffer[:start]
                    end = output_buffer.find(_OSC_END, len(_OSC_PREFIX))
                    if end < 0:
                        break
                    state.set_catalog(bytes(output_buffer[len(_OSC_PREFIX) : end]))
                    del output_buffer[: end + 1]
            if stdin_fd in readable:
                data = os.read(stdin_fd, 4096)
                if not data:
                    break
                state.feed(data)
    finally:
        if previous is not None:
            termios.tcsetattr(stdin_fd, termios.TCSADRAIN, previous)
        try:
            os.close(child_fd)
        except OSError:
            pass
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)


if __name__ == "__main__":
    raise SystemExit(main())
