#!/usr/bin/env python3
"""Small WSL-side PTY relay used by the Qt host.

The child receives a controlling Linux terminal; host stdin/stdout remain plain
pipes so this helper also works under QProcess/ConPTY-less Windows sessions.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import json
import os
import pty
import select
import signal
import struct
import sys
import termios


CONTROL_MAGIC = b"\x00PWNBAO-PTY\x00"


def set_size(fd: int, rows: int, cols: int) -> None:
    winsize = struct.pack("HHHH", max(2, rows), max(10, cols), 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)


def consume_input(buffer: bytearray, master: int, child_pid: int) -> bool:
    """Forward user bytes and consume complete host control packets."""
    while buffer:
        start = buffer.find(CONTROL_MAGIC)
        if start < 0:
            keep = 0
            for size in range(min(len(buffer), len(CONTROL_MAGIC) - 1), 0, -1):
                if bytes(buffer[-size:]) == CONTROL_MAGIC[:size]:
                    keep = size
                    break
            split = len(buffer) - keep
            if split:
                os.write(master, bytes(buffer[:split]))
                del buffer[:split]
            return True
        if start:
            os.write(master, bytes(buffer[:start]))
            del buffer[:start]
        header = len(CONTROL_MAGIC) + 4
        if len(buffer) < header:
            return True
        length = struct.unpack("!I", buffer[len(CONTROL_MAGIC):header])[0]
        if length > 65536:
            os.write(master, bytes(buffer[:1]))
            del buffer[:1]
            continue
        if len(buffer) < header + length:
            return True
        raw = bytes(buffer[header:header + length])
        del buffer[:header + length]
        try:
            message = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        kind = message.get("type")
        if kind == "resize":
            set_size(master, int(message.get("rows", 24)), int(message.get("cols", 80)))
            try:
                os.killpg(child_pid, signal.SIGWINCH)
            except OSError:
                pass
        elif kind == "close":
            try:
                os.killpg(child_pid, signal.SIGHUP)
            except OSError:
                pass
            return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=24)
    parser.add_argument("--cols", type=int, default=80)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        parser.error("missing command after --")

    child_pid, master = pty.fork()
    if child_pid == 0:
        # The host side is a QProcess pipe, but the debugger itself runs on a
        # real slave PTY.  Explicit terminal capabilities are required here:
        # WSL launched from a GUI process may otherwise inherit TERM=dumb or
        # no COLORTERM, causing Pwndbg/Rich to intentionally emit plain white
        # text even though our renderer supports 256/truecolor ANSI.
        env = os.environ.copy()
        if not env.get("TERM") or env.get("TERM", "").lower() == "dumb":
            env["TERM"] = "xterm-256color"
        else:
            env["TERM"] = "xterm-256color"
        env["COLORTERM"] = "truecolor"
        env["FORCE_COLOR"] = "1"
        env["PY_COLORS"] = "1"
        env.pop("NO_COLOR", None)
        os.execvpe(command[0], command, env)
        raise SystemExit(127)

    set_size(master, args.rows, args.cols)
    input_buffer = bytearray()
    stdin_fd = sys.stdin.buffer.fileno()
    stdout_fd = sys.stdout.buffer.fileno()
    running = True
    stdin_open = True
    while running:
        try:
            inputs = [master]
            if stdin_open:
                inputs.append(stdin_fd)
            readable, _, _ = select.select(inputs, [], [], 0.25)
        except InterruptedError:
            continue
        if stdin_fd in readable:
            data = os.read(stdin_fd, 65536)
            if not data:
                stdin_open = False
                if input_buffer:
                    os.write(master, bytes(input_buffer))
                    input_buffer.clear()
            else:
                input_buffer.extend(data)
                running = consume_input(input_buffer, master, child_pid)
        if master in readable:
            try:
                data = os.read(master, 65536)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not data:
                break
            os.write(stdout_fd, data)
        exited, status = os.waitpid(child_pid, os.WNOHANG)
        if exited:
            return os.waitstatus_to_exitcode(status)
    try:
        os.killpg(child_pid, signal.SIGHUP)
    except OSError:
        pass
    _, status = os.waitpid(child_pid, 0)
    return os.waitstatus_to_exitcode(status)


if __name__ == "__main__":
    raise SystemExit(main())
