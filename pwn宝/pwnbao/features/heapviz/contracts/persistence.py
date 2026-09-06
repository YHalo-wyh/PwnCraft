from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .model import HelperContract


SCHEMA_VERSION = 4


def save_contracts(path: str | Path, contracts: Iterable[HelperContract], challenge_fingerprint: str = "") -> None:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "challenge_fingerprint": challenge_fingerprint,
        "contracts": [item.to_dict() for item in contracts],
    }
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(target)


def load_contracts(path: str | Path) -> tuple[HelperContract, ...]:
    target = Path(path)
    if not target.exists():
        return ()
    payload = json.loads(target.read_text(encoding="utf-8"))
    return tuple(HelperContract.from_dict(item) for item in payload.get("contracts", []))
