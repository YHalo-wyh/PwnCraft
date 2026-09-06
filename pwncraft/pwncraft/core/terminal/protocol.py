from __future__ import annotations

from dataclasses import dataclass
import base64
import json
import struct
from typing import Any


PROTOCOL_VERSION = 1
OSC_PREFIX = b"\x1b]PWNCRAFT;1;"
OSC_END = b"\x07"
TRANSPORT_CONTROL_MAGIC = b"\x00PWNCRAFT-PTY\x00"


@dataclass(frozen=True)
class MachineMessage:
    type: str
    session_id: str
    sequence: int
    payload: dict[str, Any]
    protocol_version: int = PROTOCOL_VERSION

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "MachineMessage":
        return cls(
            str(value.get("type") or "error"),
            str(value.get("session_id") or ""),
            int(value.get("sequence") or 0),
            dict(value.get("payload") or {}),
            int(value.get("protocol_version") or 0),
        )


def encode_machine_message(message: MachineMessage | dict[str, Any]) -> bytes:
    if isinstance(message, MachineMessage):
        value = {
            "protocol_version": message.protocol_version,
            "session_id": message.session_id,
            "sequence": message.sequence,
            "type": message.type,
            "payload": message.payload,
        }
    else:
        value = dict(message)
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return OSC_PREFIX + base64.b64encode(raw) + OSC_END


def encode_transport_control(kind: str, **payload: Any) -> bytes:
    raw = json.dumps({"type": kind, **payload}, separators=(",", ":")).encode("utf-8")
    return TRANSPORT_CONTROL_MAGIC + struct.pack("!I", len(raw)) + raw


class MachineProtocolDecoder:
    """Strip framed Tutor messages from PTY bytes without scraping terminal text."""

    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, data: bytes) -> tuple[bytes, tuple[MachineMessage, ...]]:
        self._buffer.extend(data)
        visible = bytearray()
        messages: list[MachineMessage] = []
        while self._buffer:
            start = self._buffer.find(OSC_PREFIX)
            if start < 0:
                keep = self._possible_prefix_suffix(self._buffer)
                if keep:
                    visible.extend(self._buffer[:-keep])
                    del self._buffer[:-keep]
                else:
                    visible.extend(self._buffer)
                    self._buffer.clear()
                break
            visible.extend(self._buffer[:start])
            del self._buffer[: start + len(OSC_PREFIX)]
            end = self._buffer.find(OSC_END)
            if end < 0:
                self._buffer[:0] = OSC_PREFIX
                break
            encoded = bytes(self._buffer[:end])
            del self._buffer[: end + len(OSC_END)]
            try:
                mapping = json.loads(base64.b64decode(encoded, validate=True).decode("utf-8"))
                message = MachineMessage.from_mapping(mapping)
                if message.protocol_version == PROTOCOL_VERSION:
                    messages.append(message)
            except (ValueError, TypeError, json.JSONDecodeError):
                # Malformed frames remain invisible control-plane data.
                continue
        return bytes(visible), tuple(messages)

    @staticmethod
    def _possible_prefix_suffix(data: bytearray) -> int:
        maximum = min(len(data), len(OSC_PREFIX) - 1)
        for size in range(maximum, 0, -1):
            if bytes(data[-size:]) == OSC_PREFIX[:size]:
                return size
        return 0
