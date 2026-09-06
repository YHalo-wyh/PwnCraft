from __future__ import annotations

import os
import sys
import subprocess


def hidden_windows_process_kwargs() -> dict[str, object]:
    """Prevent short-lived WSL/tool subprocesses from opening consoles."""
    if os.name != "nt":
        return {}
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    return {
        "startupinfo": startup,
        "creationflags": subprocess.CREATE_NO_WINDOW,
    }


def prepare_windows_system_process() -> None:
    """Remove a frozen bundle's private DLL search path before spawning WSL.

    A frozen desktop bundle may leave ``SetDllDirectory`` pointing at its
    extraction directory.  Native Windows programs spawned later can then
    resolve one of their DLLs from the bundle and fail before ``main`` with
    0xc0000142.  Resetting the process DLL directory is the documented
    boundary before launching system executables such as ``wsl.exe``.

    This does not modify WSL, the selected distribution, ``~/.gdbinit`` or an
    existing Pwndbg installation.
    """

    if os.name != "nt" or not getattr(sys, "frozen", False):
        return
    try:
        import ctypes

        ctypes.windll.kernel32.SetDllDirectoryW(None)
    except (AttributeError, OSError):
        # The subsequent process error is surfaced through subprocess.
        # Failing open keeps source-mode and non-Windows hosts usable.
        return
