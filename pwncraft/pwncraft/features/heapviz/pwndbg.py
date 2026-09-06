from __future__ import annotations

import re
from dataclasses import dataclass, field

from pwncraft.features.heapviz.expressions import parse_int_expr
from pwncraft.features.heapviz.models import HeapSnapshot


@dataclass(frozen=True)
class ObservedChunk:
    address: int
    size: int | None = None
    status: str = ""


@dataclass(frozen=True)
class ObservedHeapState:
    bins: dict[str, dict[int, tuple[int, ...]]] = field(default_factory=dict)
    chunks: tuple[ObservedChunk, ...] = ()
    raw_sections: tuple[str, ...] = ()

    @property
    def address_count(self) -> int:
        return sum(len(chain) for mapping in self.bins.values() for chain in mapping.values())


@dataclass(frozen=True)
class HeapDiff:
    matched: int
    mismatched: int
    unknown: int
    lines: tuple[str, ...]
    provenance: str = "CALIBRATED"

    @property
    def ok(self) -> bool:
        return self.mismatched == 0 and self.matched > 0

    def format(self) -> str:
        head = f"[{self.provenance}] 校准结果：matched={self.matched} / mismatch={self.mismatched} / unknown={self.unknown}"
        return "\n".join((head, *self.lines))


_SECTION_NAMES = {
    "tcachebins": "tcache",
    "fastbins": "fastbins",
    "smallbins": "smallbins",
    "largebins": "largebins",
    "unsortedbin": "unsorted",
    "unsortedbins": "unsorted",
}

_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{5,}")
_SIZE_LINE_RE = re.compile(r"^\s*(0x[0-9a-fA-F]+)\s*(?:\[[^\]]*\])?\s*:\s*(.*)$")
_ADDR_LINE_RE = re.compile(r"\bAddr:\s*(0x[0-9a-fA-F]+)", re.I)
_CHUNK_SIZE_RE = re.compile(r"\bSize:\s*(0x[0-9a-fA-F]+)", re.I)


def parse_pwndbg_snapshot(text: str) -> ObservedHeapState:
    bins: dict[str, dict[int, tuple[int, ...]]] = {
        "tcache": {},
        "fastbins": {},
        "smallbins": {},
        "largebins": {},
        "unsorted": {},
    }
    sections: list[str] = []
    current = ""
    chunks: list[ObservedChunk] = []
    pending_chunk_addr: int | None = None
    pending_status = ""

    for raw in (text or "").splitlines():
        line = _strip_ansi(raw).strip()
        if not line:
            continue
        lowered = line.lower().rstrip(":")
        if lowered in _SECTION_NAMES:
            current = _SECTION_NAMES[lowered]
            sections.append(current)
            continue
        if line.lower().startswith(("allocated chunk", "free chunk", "top chunk")):
            pending_status = line.split("|", 1)[0].strip().lower()
            continue
        addr_match = _ADDR_LINE_RE.search(line)
        if addr_match:
            pending_chunk_addr = int(addr_match.group(1), 16)
            continue
        size_match = _CHUNK_SIZE_RE.search(line)
        if size_match and pending_chunk_addr is not None:
            chunks.append(ObservedChunk(pending_chunk_addr, int(size_match.group(1), 16), pending_status))
            pending_chunk_addr = None
            pending_status = ""
            continue

        if not current:
            continue
        size_match = _SIZE_LINE_RE.match(line)
        if current == "unsorted" and line.lower().startswith("all:"):
            size = -1
            rest = line.split(":", 1)[1]
        elif size_match:
            size = int(size_match.group(1), 16)
            rest = size_match.group(2)
        else:
            continue
        addresses = []
        for token in _ADDR_RE.findall(rest):
            value = int(token, 16)
            # Filter obvious libc/main_arena links when they are annotated; we
            # still keep heap-looking addresses without assuming ASLR ranges.
            if value == 0:
                continue
            if value not in addresses:
                addresses.append(value)
        bins[current][size] = tuple(addresses)

    return ObservedHeapState(
        bins={name: mapping for name, mapping in bins.items() if mapping},
        chunks=tuple(chunks),
        raw_sections=tuple(dict.fromkeys(sections)),
    )


def diff_snapshot(snapshot: HeapSnapshot, observed: ObservedHeapState) -> HeapDiff:
    simulated_by_address: dict[int, tuple[str, str, int | None]] = {}
    for chunk in snapshot.chunks.values():
        chunk_addr = parse_int_expr(chunk.address)
        user_addr = parse_int_expr(chunk.user_address)
        size = parse_int_expr(chunk.chunk_size)
        for address in (chunk_addr, user_addr):
            if address is not None:
                simulated_by_address[address] = (chunk.chunk_id, chunk.bin_location, size)

    matched = mismatched = unknown = 0
    lines: list[str] = []
    for bin_name, mapping in observed.bins.items():
        for size, addresses in mapping.items():
            for address in addresses:
                simulated = simulated_by_address.get(address)
                if simulated is None:
                    unknown += 1
                    lines.append(f"? {bin_name}[{_size_label(size)}] @ {hex(address)}：模拟图中没有对应地址")
                    continue
                chunk_id, location, simulated_size = simulated
                location_ok = _location_matches(bin_name, location)
                size_ok = size < 0 or simulated_size is None or simulated_size == size
                if location_ok and size_ok:
                    matched += 1
                    lines.append(f"✓ {chunk_id} @ {hex(address)}：{bin_name}[{_size_label(size)}] 与 Pwndbg 一致")
                else:
                    mismatched += 1
                    lines.append(
                        f"✗ {chunk_id} @ {hex(address)}：Pwndbg={bin_name}[{_size_label(size)}]，模拟={location or 'none'}"
                    )

    for observed_chunk in observed.chunks:
        simulated = simulated_by_address.get(observed_chunk.address)
        if simulated is None:
            unknown += 1
            lines.append(f"? heap chunk @ {hex(observed_chunk.address)}：模拟图中未找到")
            continue
        chunk_id, _location, size = simulated
        if observed_chunk.size is None or size is None or observed_chunk.size == size:
            matched += 1
            lines.append(f"✓ {chunk_id} header @ {hex(observed_chunk.address)} size={_size_label(observed_chunk.size)}")
        else:
            mismatched += 1
            lines.append(f"✗ {chunk_id} size：Pwndbg={hex(observed_chunk.size)}，模拟={hex(size)}")

    if observed.address_count == 0 and not observed.chunks:
        lines.append("没有解析到可比较地址。建议一起粘贴：tcachebins、fastbins、bins、heap。")
    elif mismatched == 0:
        lines.append("当前已解析项目没有发现冲突；未出现在 Pwndbg 文本里的字段仍不能视为已验证。")
    return HeapDiff(matched, mismatched, unknown, tuple(lines))


def _location_matches(observed: str, simulated: str) -> bool:
    text = (simulated or "").lower()
    if observed == "tcache":
        return text.startswith("tcache")
    if observed == "fastbins":
        return text.startswith("fastbin")
    if observed == "smallbins":
        return "smallbin" in text
    if observed == "largebins":
        return "largebin" in text
    if observed == "unsorted":
        return text.startswith("unsorted")
    return False


def _size_label(size: int | None) -> str:
    if size is None:
        return "?"
    return "all" if size < 0 else hex(size)


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)
