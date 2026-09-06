"""Leak records and libc-base derivation (规划 §二十四/§二十五).

Leaks are explicit, editable facts.  A derived base is always stored with
its formula so the value can be audited and recomputed later.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Leak:
    symbol: str
    address: int | None = None
    raw_hex: str = ""
    source: str = ""
    formula: str = ""
    confidence: str = "confirmed"
    note: str = ""

    def __post_init__(self) -> None:
        if not str(self.symbol).strip():
            raise ValueError("Leak 必须有符号名")

    def to_dict(self) -> dict[str, object]:
        return {
            "symbol": self.symbol,
            "address": self.address,
            "raw_hex": self.raw_hex,
            "source": self.source,
            "formula": self.formula,
            "confidence": self.confidence,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "Leak":
        address = payload.get("address")
        return cls(
            symbol=str(payload.get("symbol", "")),
            address=int(address, 0) if isinstance(address, str) else (int(address) if isinstance(address, int) else None),
            raw_hex=str(payload.get("raw_hex", "")),
            source=str(payload.get("source", "")),
            formula=str(payload.get("formula", "")),
            confidence=str(payload.get("confidence", "confirmed")),
            note=str(payload.get("note", "")),
        )


def derive_base(leak_address: int, symbol_offset: int) -> tuple[int, str]:
    """Return ``(libc_base, formula_text)``; no rounding or guessing."""
    base = int(leak_address) - int(symbol_offset)
    if base < 0:
        raise ValueError("泄露地址小于符号偏移，无法得到合法基址")
    if base & 0xFFF:
        raise ValueError("推导出的基址未按页对齐（低 12 位非零），请核对符号偏移")
    formula = f"{int(leak_address):#x} - {int(symbol_offset):#x}"
    return base, formula
