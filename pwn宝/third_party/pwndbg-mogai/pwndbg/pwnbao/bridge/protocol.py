from __future__ import annotations

import base64
import json
import os
import uuid

_PREFIX = "\x1b]PWNBAO;1;"
_END = "\x07"
_session_id = uuid.uuid4().hex
_sequence = 0


def emit(message_type: str, payload: dict) -> None:
    """Write one invisible OSC frame; ordinary Pwndbg text stays untouched."""
    global _sequence
    _sequence += 1
    message = {
        "protocol_version": 1,
        "session_id": _session_id,
        "sequence": _sequence,
        "type": message_type,
        "payload": payload,
    }
    encoded = base64.b64encode(
        json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    frame = (_PREFIX + encoded + _END).encode("ascii")
    pending = memoryview(frame)
    while pending:
        written = os.write(1, pending)
        pending = pending[written:]

