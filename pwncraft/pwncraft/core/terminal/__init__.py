"""Terminal emulation and machine-protocol primitives.

The Electron app drives interactive terminals through node-pty.  The
``pty_relay.py`` helper stays because it is spawned as a WSL-side subprocess
for machine-protocol tests and fallback probes.
"""

from pwncraft.core.terminal.ansi import AnsiTerminalScreen
from pwncraft.core.terminal.protocol import MachineMessage, MachineProtocolDecoder
from pwncraft.core.terminal.session import TerminalSessionState

__all__ = [
    "AnsiTerminalScreen",
    "MachineMessage",
    "MachineProtocolDecoder",
    "TerminalSessionState",
]
