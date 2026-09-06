"""Terminal emulation and machine-protocol primitives.

The Electron app drives interactive terminals through node-pty.  The
``pty_relay.py`` helper stays because it is spawned as a WSL-side subprocess
for machine-protocol tests and fallback probes.
"""

from pwnbao.core.terminal.ansi import AnsiTerminalScreen
from pwnbao.core.terminal.protocol import MachineMessage, MachineProtocolDecoder
from pwnbao.core.terminal.session import TerminalSessionState

__all__ = [
    "AnsiTerminalScreen",
    "MachineMessage",
    "MachineProtocolDecoder",
    "TerminalSessionState",
]
