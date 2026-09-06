from __future__ import annotations

import hashlib
import os
import re
from typing import Any

from pwndbg.pwncraft.bridge.protocol import emit

_runtime = None


def _alive() -> bool:
    import gdb

    try:
        return bool(gdb.selected_inferior().pid)
    except Exception:
        return False


def _parse_explicit_chunks(raw: str) -> dict[str, Any]:
    chunks = []
    seen = set()
    pending: int | None = None
    for line in raw.splitlines():
        size_match = re.search(r"\bsize\s*[=:]\s*(0x[0-9a-fA-F]+|\d+)", line, re.I)
        address_match = re.search(r"\b(?:addr|address)\s*[=:]\s*(0x[0-9a-fA-F]+)", line, re.I)
        addresses = re.findall(r"0x[0-9a-fA-F]+", line)
        if address_match:
            pending = int(address_match.group(1), 16)
        if size_match is None:
            continue
        address = pending if pending is not None else (int(addresses[0], 16) if addresses else None)
        pending = None
        if address is None or address in seen:
            continue
        seen.add(address)
        chunks.append(
            {
                "address": address,
                "size": int(size_match.group(1), 0),
                "source_line": line.strip(),
                "provenance": "PWNDBG_OUTPUT_EXPLICIT",
            }
        )
    return {"chunks": chunks, "raw_fallback": raw, "provenance": "PWNDBG_RUNTIME"}


class RuntimeBridge:
    """Thin runtime-truth bridge; no localization, help, Tutor or color work."""

    _HEAP_CALLS = (
        "malloc",
        "free",
        "calloc",
        "realloc",
        "memalign",
        "aligned_alloc",
        "read",
        "recv",
        "memcpy",
        "memmove",
    )

    def __init__(self) -> None:
        self._pending_allocator = False
        self._memory_dirty = False
        self._last_digest = ""
        self._snapshot_running = False

    def install(self) -> None:
        import gdb

        bridge = self

        class SnapshotCommand(gdb.Command):
            def __init__(self):
                super().__init__("pwncraft-snapshot", gdb.COMMAND_USER)

            def invoke(self, argument: str, _from_tty: bool) -> None:
                self.dont_repeat()
                bridge.snapshot(compact=argument.strip().casefold() == "compact")

        SnapshotCommand()
        gdb.events.cont.connect(self._on_continue)
        gdb.events.stop.connect(self._on_stop)
        gdb.events.exited.connect(self._on_exited)
        memory_changed = getattr(gdb.events, "memory_changed", None)
        if memory_changed is not None:
            memory_changed.connect(self._on_memory_changed)
        before_prompt = getattr(gdb.events, "before_prompt", None)
        if before_prompt is not None:
            before_prompt.connect(self._on_before_prompt)
        # Send the live command registry to embedded clients.  It is derived
        # after all upstream commands have loaded, so aliases and localized
        # descriptions stay in sync with the actual Pwndbg parser.
        try:
            from pwndbg.pwncraft.slash.registry import commands, option_hints
            command_catalog = [
                {
                    "name": item.name,
                    "aliases": list(item.aliases),
                    "category": item.category,
                    "description": " ".join((item.description_zh or item.description).split())[:120],
                    "description_zh": " ".join((item.description_zh or item.description).split())[:120],
                    "description_en": " ".join(item.description.split())[:120],
                    "options": list(option_hints(item)),
                }
                for item in commands()
            ]
        except Exception:
            command_catalog = []
        emit(
            "extension_hello",
            {
                "extension": "pwndbg-mogai-bridge",
                "extension_version": "0.13.0",
                "pwndbg_actual": "2026.07.29-pwndbg-mogai.16",
                "compatible": True,
                "bridge_scope": ["heap", "file", "dirty", "selection"],
                "command_catalog": command_catalog,
            },
        )
        emit("session_state", {"state": "READY", "reason": "fork_loaded"})

    def _instruction_is_heap_call(self) -> bool:
        import gdb

        try:
            instruction = gdb.execute("x/i $pc", to_string=True).casefold()
        except Exception:
            return False
        return "call" in instruction and any(name in instruction for name in self._HEAP_CALLS)

    def _on_continue(self, _event) -> None:
        # Lightweight classification only.  No bins/heap traversal happens in
        # a GDB event callback.
        self._pending_allocator = self._instruction_is_heap_call()
        emit("session_state", {"state": "RUNNING_INFERIOR", "reason": "gdb_continue"})

    def _on_memory_changed(self, _event) -> None:
        self._memory_dirty = True

    def _on_stop(self, event) -> None:
        import gdb

        signal = event.stop_signal if isinstance(event, gdb.SignalEvent) else ""
        reason = ""
        if signal in {"SIGABRT", "SIGSEGV"}:
            reason = "signal:" + signal
        elif self._pending_allocator:
            reason = "allocator-call-returned"
        emit(
            "stop_state",
            {"reason": event.__class__.__name__, "signal": signal, "heap_dirty": bool(reason)},
        )
        if reason:
            emit("heap_dirty", {"reason": reason})
        self._pending_allocator = False

    def _on_before_prompt(self) -> None:
        # A prompt is the last point before bytes reach either the GUI or the
        # native PTY. Reassert the fork palette here so persisted GDB options
        # cannot silently turn the fused interface into white-on-black text.
        try:
            from pwndbg.pwncraft.theme import ensure_classic_colors
            ensure_classic_colors()
        except Exception:
            pass
        if self._memory_dirty:
            self._memory_dirty = False
            emit("heap_dirty", {"reason": "debugger-memory-write"})

    def _on_exited(self, event) -> None:
        emit("session_state", {"state": "EXITED", "exit_code": getattr(event, "exit_code", None)})

    def snapshot(self, *, compact: bool = False) -> None:
        import gdb

        if self._snapshot_running:
            return
        if not _alive():
            emit("heap_snapshot", {"available": False, "reason": "inferior_not_running"})
            return
        self._snapshot_running = True
        try:
            commands = ("tcachebins", "fastbins", "bins", "heap --count 64")
            output = []
            errors = []
            for command in commands:
                try:
                    output.append(f"$ {command}\n" + gdb.execute(command, to_string=True))
                except Exception as error:
                    errors.append({"command": command, "error": str(error)})
            raw = "\n".join(output)
            digest = hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest() if raw else ""
            if digest and digest == self._last_digest:
                emit("heap_snapshot_unchanged", {"available": True, "digest": digest})
                self.file_snapshot()
                return
            self._last_digest = digest
            payload = _parse_explicit_chunks(raw)
            payload.update({"available": bool(output), "errors": errors, "compact": compact, "digest": digest})
            emit("heap_snapshot", payload)
            self.file_snapshot()
        finally:
            self._snapshot_running = False

    def file_snapshot(self) -> None:
        import gdb

        files = []
        for label, symbol in (
            ("stdout", "_IO_2_1_stdout_"),
            ("stderr", "_IO_2_1_stderr_"),
            ("stdin", "_IO_2_1_stdin_"),
        ):
            try:
                address = int(gdb.parse_and_eval(f"&{symbol}"))
                raw = bytes(gdb.selected_inferior().read_memory(address, 0xE0))
            except Exception:
                continue
            files.append({"symbol": label, "address": address, "raw_hex": raw.hex(), "size": len(raw)})
        if files:
            emit("file_snapshot", {"available": True, "files": files, "provenance": "PWNDBG_RUNTIME"})


def install_if_enabled() -> RuntimeBridge | None:
    global _runtime
    if os.environ.get("PWNCRAFT_BRIDGE", "").casefold() not in {"1", "true", "yes"}:
        return None
    if _runtime is None:
        _runtime = RuntimeBridge()
        _runtime.install()
    return _runtime
