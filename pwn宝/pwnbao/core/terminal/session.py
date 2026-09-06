from __future__ import annotations

from enum import Enum


class TerminalSessionState(str, Enum):
    IDLE = "IDLE"
    STARTING = "STARTING"
    READY = "READY"
    RUNNING_INFERIOR = "RUNNING_INFERIOR"
    STOPPED = "STOPPED"
    INTERRUPTING = "INTERRUPTING"
    EXITED = "EXITED"
    ERROR = "ERROR"


def state_from_message(message_type: str, payload: dict) -> TerminalSessionState | None:
    if message_type == "prompt_state" and payload.get("ready"):
        return TerminalSessionState.STOPPED if payload.get("inferior_alive") else TerminalSessionState.READY
    if message_type == "session_state":
        try:
            return TerminalSessionState(str(payload.get("state")))
        except ValueError:
            return None
    if message_type == "stop_state":
        return TerminalSessionState.STOPPED
    return None
