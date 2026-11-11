"""Offline-first ELF artifact evidence provider.

The existing Binary Semantic Provider accepts address-anchored semantic records
from IDA/IDACLI.  This module covers the complementary evidence that comes from
an ELF artifact itself: symbols, relocations, load/RELRO ranges and bounded
instruction windows.

Nothing in this module labels a vulnerability or exploit technique.  It only
normalizes deterministic tool output and exposes exact queries for downstream
reasoning.  Collection uses local ``readelf``/``objdump`` only; no network is
required.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Iterable, Sequence

SCHEMA_VERSION = "pwncraft-elf-artifact-1.0"
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SYMBOL_LINE_RE = re.compile(
    r"^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+?)\s*$"
)
_RELOCATION_LINE_RE = re.compile(
    r"^\s*([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+(\S+)\s+([0-9a-fA-F]+)\s+(\S+)(?:\s+\+\s+(.+?))?\s*$"
)
_FUNCTION_LABEL_RE = re.compile(r"^\s*([0-9a-fA-F]+)\s+<(.+)>:\s*$")
_INSTRUCTION_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s*([A-Za-z.][A-Za-z0-9_.]*)\s*(.*?)\s*$")


def _address(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("boolean is not an address")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        result = int(value.strip(), 0)
    else:
        raise ValueError("address must be int or numeric string")
    if result < 0:
        raise ValueError("address must be non-negative")
    return result


def _base_symbol_name(name: str) -> str:
    return name.split("@", 1)[0]


def _parse_addend(value: str | None) -> int:
    if value is None:
        return 0
    text = value.strip()
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(text, 16)
        except ValueError as exc:
            raise ValueError(f"unsupported relocation addend: {value!r}") from exc


@dataclass(frozen=True)
class ElfSymbolEvidence:
    name: str
    base_name: str
    value: int
    size: int
    symbol_type: str
    binding: str
    visibility: str
    section_index: str
    provenance: str = "READELF_SYMBOL_TABLE"

    @property
    def defined(self) -> bool:
        return self.section_index != "UND"


@dataclass(frozen=True)
class ElfRelocationEvidence:
    offset: int
    relocation_type: str
    symbol_value: int
    symbol_name: str
    symbol_base_name: str
    addend: int = 0
    provenance: str = "READELF_RELOCATION_TABLE"


@dataclass(frozen=True)
class ElfMemoryRangeEvidence:
    kind: str
    start: int
    end: int
    file_offset: int
    flags: str
    provenance: str = "READELF_PROGRAM_HEADERS"

    def contains(self, address: int) -> bool:
        return self.start <= address < self.end


@dataclass(frozen=True)
class ElfInstructionEvidence:
    address: int
    mnemonic: str
    operands: str
    function_name: str | None = None
    provenance: str = "OBJDUMP_DISASSEMBLY"


@dataclass(frozen=True)
class ElfArtifactSnapshot:
    schema_version: str
    artifact_sha256: str
    artifact_name: str
    elf_class: str
    data_encoding: str
    elf_type: str
    machine: str
    entry_point: int
    provider: str
    tool_versions: dict[str, str]
    symbols: tuple[ElfSymbolEvidence, ...]
    relocations: tuple[ElfRelocationEvidence, ...]
    memory_ranges: tuple[ElfMemoryRangeEvidence, ...]
    instructions: tuple[ElfInstructionEvidence, ...] = ()
    degraded: bool = False
    degrade_notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "artifact_sha256": self.artifact_sha256,
            "artifact_name": self.artifact_name,
            "elf_class": self.elf_class,
            "data_encoding": self.data_encoding,
            "elf_type": self.elf_type,
            "machine": self.machine,
            "entry_point": self.entry_point,
            "provider": self.provider,
            "tool_versions": dict(self.tool_versions),
            "symbols": [asdict(item) for item in self.symbols],
            "relocations": [asdict(item) for item in self.relocations],
            "memory_ranges": [asdict(item) for item in self.memory_ranges],
            "instructions": [asdict(item) for item in self.instructions],
            "degraded": self.degraded,
            "degrade_notes": list(self.degrade_notes),
        }


def parse_readelf_header(text: str) -> dict[str, Any]:
    fields: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        for label, key in (
            ("Class:", "elf_class"),
            ("Data:", "data_encoding"),
            ("Type:", "elf_type"),
            ("Machine:", "machine"),
            ("Entry point address:", "entry_point"),
        ):
            if line.startswith(label):
                fields[key] = line[len(label):].strip()
                break
    required = ("elf_class", "data_encoding", "elf_type", "machine", "entry_point")
    missing = [key for key in required if not fields.get(key)]
    if missing:
        raise ValueError(f"readelf header missing fields: {', '.join(missing)}")
    # Keep only the stable type token (EXEC/DYN/REL/CORE) instead of localized prose.
    elf_type = fields["elf_type"].split(None, 1)[0]
    return {
        "elf_class": fields["elf_class"],
        "data_encoding": fields["data_encoding"],
        "elf_type": elf_type,
        "machine": fields["machine"],
        "entry_point": _address(fields["entry_point"]),
    }


def parse_readelf_symbols(text: str) -> tuple[ElfSymbolEvidence, ...]:
    symbols: list[ElfSymbolEvidence] = []
    seen: set[tuple[str, int, str, str]] = set()
    for line in text.splitlines():
        match = _SYMBOL_LINE_RE.match(line)
        if not match:
            continue
        value, size, symbol_type, binding, visibility, section_index, name = match.groups()
        name = name.strip()
        if not name:
            continue
        item = ElfSymbolEvidence(
            name=name,
            base_name=_base_symbol_name(name),
            value=int(value, 16),
            size=int(size, 10),
            symbol_type=symbol_type,
            binding=binding,
            visibility=visibility,
            section_index=section_index,
        )
        key = (item.name, item.value, item.symbol_type, item.section_index)
        if key not in seen:
            symbols.append(item)
            seen.add(key)
    return tuple(symbols)


def parse_readelf_relocations(text: str) -> tuple[ElfRelocationEvidence, ...]:
    relocations: list[ElfRelocationEvidence] = []
    for line in text.splitlines():
        match = _RELOCATION_LINE_RE.match(line)
        if not match:
            continue
        offset, relocation_type, symbol_value, symbol_name, addend = match.groups()
        # Some RELATIVE relocations have no meaningful symbol column and are not
        # useful for target-symbol binding.  Preserve only named symbol records.
        symbol_name = symbol_name.strip()
        if not symbol_name or symbol_name in {"+", "0"}:
            continue
        try:
            parsed_addend = _parse_addend(addend)
        except ValueError:
            parsed_addend = 0
        relocations.append(ElfRelocationEvidence(
            offset=int(offset, 16),
            relocation_type=relocation_type,
            symbol_value=int(symbol_value, 16),
            symbol_name=symbol_name,
            symbol_base_name=_base_symbol_name(symbol_name),
            addend=parsed_addend,
        ))
    return tuple(relocations)


def parse_readelf_program_headers(text: str) -> tuple[ElfMemoryRangeEvidence, ...]:
    ranges: list[ElfMemoryRangeEvidence] = []
    for raw_line in text.splitlines():
        parts = raw_line.split()
        if not parts or parts[0] not in {"LOAD", "GNU_RELRO"}:
            continue
        # readelf -lW columns:
        # Type Offset VirtAddr PhysAddr FileSiz MemSiz Flg Align
        if len(parts) < 8:
            continue
        try:
            file_offset = int(parts[1], 16)
            start = int(parts[2], 16)
            mem_size = int(parts[5], 16)
            flags = "".join(parts[6:-1])
        except (ValueError, IndexError):
            continue
        ranges.append(ElfMemoryRangeEvidence(
            kind=parts[0],
            start=start,
            end=start + mem_size,
            file_offset=file_offset,
            flags=flags,
        ))
    return tuple(ranges)


def parse_objdump_instructions(text: str) -> tuple[ElfInstructionEvidence, ...]:
    instructions: list[ElfInstructionEvidence] = []
    current_function: str | None = None
    for line in text.splitlines():
        label = _FUNCTION_LABEL_RE.match(line)
        if label:
            current_function = label.group(2)
            continue
        match = _INSTRUCTION_RE.match(line)
        if not match:
            continue
        address, mnemonic, operands = match.groups()
        instructions.append(ElfInstructionEvidence(
            address=int(address, 16),
            mnemonic=mnemonic,
            operands=operands.strip(),
            function_name=current_function,
        ))
    return tuple(instructions)


def snapshot_from_tool_outputs(
    *,
    artifact_sha256: str,
    artifact_name: str,
    header_text: str,
    symbols_text: str,
    relocations_text: str,
    program_headers_text: str,
    disassembly_texts: Iterable[str] = (),
    provider: str = "local-binutils",
    tool_versions: dict[str, str] | None = None,
    degraded: bool = False,
    degrade_notes: Sequence[str] = (),
) -> ElfArtifactSnapshot:
    if not _SHA256_RE.fullmatch(artifact_sha256):
        raise ValueError("artifact_sha256 must be an exact 64-hex digest")
    artifact_name = str(artifact_name).strip()
    if not artifact_name:
        raise ValueError("artifact_name is required")
    provider = str(provider).strip()
    if not provider:
        raise ValueError("provider identity is required")
    header = parse_readelf_header(header_text)
    instructions: list[ElfInstructionEvidence] = []
    seen_instruction_addresses: set[int] = set()
    for text in disassembly_texts:
        for item in parse_objdump_instructions(text):
            if item.address not in seen_instruction_addresses:
                instructions.append(item)
                seen_instruction_addresses.add(item.address)
    return ElfArtifactSnapshot(
        schema_version=SCHEMA_VERSION,
        artifact_sha256=artifact_sha256.lower(),
        artifact_name=artifact_name,
        provider=provider,
        tool_versions=dict(tool_versions or {}),
        symbols=parse_readelf_symbols(symbols_text),
        relocations=parse_readelf_relocations(relocations_text),
        memory_ranges=parse_readelf_program_headers(program_headers_text),
        instructions=tuple(instructions),
        degraded=bool(degraded),
        degrade_notes=tuple(str(note) for note in degrade_notes),
        **header,
    )


def load_elf_artifact_snapshot(payload: dict[str, Any]) -> ElfArtifactSnapshot:
    """Validate a persisted artifact snapshot without trusting loose dictionaries."""
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported ELF artifact snapshot schema")
    digest = str(payload.get("artifact_sha256") or "").strip()
    if not _SHA256_RE.fullmatch(digest):
        raise ValueError("artifact_sha256 must be an exact 64-hex digest")
    artifact_name = str(payload.get("artifact_name") or "").strip()
    provider = str(payload.get("provider") or "").strip()
    if not artifact_name or not provider:
        raise ValueError("artifact_name and provider are required")

    def require_list(key: str) -> list[Any]:
        value = payload.get(key, [])
        if not isinstance(value, list):
            raise ValueError(f"{key} must be a list")
        return value

    symbols = tuple(ElfSymbolEvidence(
        name=str(item["name"]),
        base_name=str(item.get("base_name") or _base_symbol_name(str(item["name"]))),
        value=_address(item["value"]),
        size=int(item["size"]),
        symbol_type=str(item["symbol_type"]),
        binding=str(item["binding"]),
        visibility=str(item["visibility"]),
        section_index=str(item["section_index"]),
        provenance=str(item.get("provenance") or "READELF_SYMBOL_TABLE"),
    ) for item in require_list("symbols"))
    relocations = tuple(ElfRelocationEvidence(
        offset=_address(item["offset"]),
        relocation_type=str(item["relocation_type"]),
        symbol_value=_address(item.get("symbol_value", 0)),
        symbol_name=str(item["symbol_name"]),
        symbol_base_name=str(item.get("symbol_base_name") or _base_symbol_name(str(item["symbol_name"]))),
        addend=int(item.get("addend", 0)),
        provenance=str(item.get("provenance") or "READELF_RELOCATION_TABLE"),
    ) for item in require_list("relocations"))
    memory_ranges = tuple(ElfMemoryRangeEvidence(
        kind=str(item["kind"]),
        start=_address(item["start"]),
        end=_address(item["end"]),
        file_offset=_address(item.get("file_offset", 0)),
        flags=str(item.get("flags") or ""),
        provenance=str(item.get("provenance") or "READELF_PROGRAM_HEADERS"),
    ) for item in require_list("memory_ranges"))
    if any(item.end < item.start for item in memory_ranges):
        raise ValueError("memory range end must not precede start")
    instructions = tuple(ElfInstructionEvidence(
        address=_address(item["address"]),
        mnemonic=str(item["mnemonic"]),
        operands=str(item.get("operands") or ""),
        function_name=(str(item["function_name"]) if item.get("function_name") is not None else None),
        provenance=str(item.get("provenance") or "OBJDUMP_DISASSEMBLY"),
    ) for item in require_list("instructions"))
    tools = payload.get("tool_versions") or {}
    if not isinstance(tools, dict):
        raise ValueError("tool_versions must be an object")
    notes = payload.get("degrade_notes") or []
    if not isinstance(notes, list):
        raise ValueError("degrade_notes must be a list")
    return ElfArtifactSnapshot(
        schema_version=SCHEMA_VERSION,
        artifact_sha256=digest.lower(),
        artifact_name=artifact_name,
        elf_class=str(payload.get("elf_class") or ""),
        data_encoding=str(payload.get("data_encoding") or ""),
        elf_type=str(payload.get("elf_type") or ""),
        machine=str(payload.get("machine") or ""),
        entry_point=_address(payload.get("entry_point", 0)),
        provider=provider,
        tool_versions={str(k): str(v) for k, v in tools.items()},
        symbols=symbols,
        relocations=relocations,
        memory_ranges=memory_ranges,
        instructions=instructions,
        degraded=bool(payload.get("degraded", False)),
        degrade_notes=tuple(str(note) for note in notes),
    )


def resolve_symbol(
    snapshot: ElfArtifactSnapshot,
    name: str,
    *,
    require_defined: bool = True,
) -> ElfSymbolEvidence | None:
    """Resolve an exact/base symbol name without inventing offsets."""
    query = str(name).strip()
    if not query:
        return None
    candidates = [item for item in snapshot.symbols if item.name == query]
    if not candidates:
        candidates = [item for item in snapshot.symbols if item.base_name == query]
    if require_defined:
        candidates = [item for item in candidates if item.defined]
    if not candidates:
        return None
    # Prefer GLOBAL/WEAK function/object definitions over local aliases and then
    # choose the lowest exact value for deterministic behavior.
    rank = {"GLOBAL": 0, "WEAK": 1, "LOCAL": 2}
    candidates.sort(key=lambda item: (rank.get(item.binding, 9), item.value, item.name))
    return candidates[0]


def relocations_for_symbol(snapshot: ElfArtifactSnapshot, name: str) -> list[ElfRelocationEvidence]:
    query = str(name).strip()
    if not query:
        return []
    return [item for item in snapshot.relocations if item.symbol_name == query or item.symbol_base_name == query]


def address_is_executable(snapshot: ElfArtifactSnapshot, address: int | str) -> bool:
    value = _address(address)
    return any(item.kind == "LOAD" and "E" in item.flags and item.contains(value) for item in snapshot.memory_ranges)


def address_is_runtime_writable(snapshot: ElfArtifactSnapshot, address: int | str) -> bool:
    """Conservatively check PT_LOAD W and exclude PT_GNU_RELRO-covered bytes."""
    value = _address(address)
    writable_load = any(
        item.kind == "LOAD" and "W" in item.flags and item.contains(value)
        for item in snapshot.memory_ranges
    )
    if not writable_load:
        return False
    in_relro = any(item.kind == "GNU_RELRO" and item.contains(value) for item in snapshot.memory_ranges)
    return not in_relro


def runtime_symbol_address(snapshot: ElfArtifactSnapshot, name: str, *, load_base: int = 0) -> int | None:
    symbol = resolve_symbol(snapshot, name, require_defined=True)
    if symbol is None:
        return None
    base = _address(load_base)
    if snapshot.elf_type == "DYN":
        return base + symbol.value
    if snapshot.elf_type == "EXEC":
        return symbol.value
    return None


def relocation_runtime_address(
    snapshot: ElfArtifactSnapshot,
    relocation: ElfRelocationEvidence,
    *,
    load_base: int = 0,
) -> int | None:
    base = _address(load_base)
    if snapshot.elf_type == "DYN":
        return base + relocation.offset
    if snapshot.elf_type == "EXEC":
        return relocation.offset
    return None


def instruction_window(
    snapshot: ElfArtifactSnapshot,
    start: int | str,
    stop: int | str,
) -> list[ElfInstructionEvidence]:
    low = _address(start)
    high = _address(stop)
    if high < low:
        raise ValueError("instruction window stop must not precede start")
    return [item for item in snapshot.instructions if low <= item.address < high]


def _hash_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tool_version(tool: str) -> str:
    completed = subprocess.run(
        [tool, "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return (completed.stdout or completed.stderr).splitlines()[0].strip()


def _run_tool(command: list[str], *, timeout: int = 20) -> str:
    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return completed.stdout


def collect_elf_artifact_snapshot(
    path: str | Path,
    *,
    disassembly_windows: Sequence[tuple[int, int]] = (),
    readelf: str = "readelf",
    objdump: str = "objdump",
) -> ElfArtifactSnapshot:
    """Collect deterministic local ELF evidence with bounded disassembly.

    Full-library disassembly is intentionally forbidden by default.  Callers
    must request explicit ``(start, stop)`` windows, each at most 0x4000 bytes,
    so later reasoning has a small inspectable provenance surface.
    """
    artifact = Path(path).expanduser().resolve()
    if not artifact.is_file():
        raise FileNotFoundError(str(artifact))
    readelf_path = shutil.which(readelf)
    objdump_path = shutil.which(objdump)
    if readelf_path is None:
        raise RuntimeError("readelf is required for offline ELF artifact collection")
    if disassembly_windows and objdump_path is None:
        raise RuntimeError("objdump is required when disassembly windows are requested")
    if len(disassembly_windows) > 32:
        raise ValueError("at most 32 disassembly windows may be collected at once")
    normalized_windows: list[tuple[int, int]] = []
    for start, stop in disassembly_windows:
        start_i, stop_i = _address(start), _address(stop)
        if stop_i <= start_i or stop_i - start_i > 0x4000:
            raise ValueError("each disassembly window must be within (0, 0x4000] bytes")
        normalized_windows.append((start_i, stop_i))

    header_text = _run_tool([readelf_path, "-hW", str(artifact)])
    symbols_text = _run_tool([readelf_path, "-Ws", str(artifact)])
    relocations_text = _run_tool([readelf_path, "-rW", str(artifact)])
    program_headers_text = _run_tool([readelf_path, "-lW", str(artifact)])
    disassembly_texts: list[str] = []
    if normalized_windows:
        assert objdump_path is not None
        for start_i, stop_i in normalized_windows:
            disassembly_texts.append(_run_tool([
                objdump_path,
                "-d",
                "-w",
                "--no-show-raw-insn",
                f"--start-address={start_i:#x}",
                f"--stop-address={stop_i:#x}",
                str(artifact),
            ]))

    versions = {"readelf": _tool_version(readelf_path)}
    if objdump_path is not None:
        versions["objdump"] = _tool_version(objdump_path)
    return snapshot_from_tool_outputs(
        artifact_sha256=_hash_file(artifact),
        artifact_name=artifact.name,
        header_text=header_text,
        symbols_text=symbols_text,
        relocations_text=relocations_text,
        program_headers_text=program_headers_text,
        disassembly_texts=disassembly_texts,
        provider="local-binutils",
        tool_versions=versions,
    )
