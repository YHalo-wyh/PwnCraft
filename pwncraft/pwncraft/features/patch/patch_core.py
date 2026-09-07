"""Byte-level patch truth: PatchOp model, patch log, instruction lines, code caves.

The Electron surface never computes addresses or bytes.  Every patch here is
applied to the mutable working copy with a timestamped backup and a JSON log
so any single op can be undone; file size never changes (every op replaces
bytes in place).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
import shutil
import struct
import time
import uuid

from pwncraft.core.workbench import elf_geometry, vaddr_to_offset

# objdump -d 行：`  4011a6:\t48 8b 45 f8        \tmov -0x8(%rbp),%rax`
_INSN_ADDR_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s*(.*)$")
_HEX_PAIR_RE = re.compile(r"^[0-9a-fA-F]{2}$")

X86_BITS = (32, 64)


def parse_instruction_lines(assembly_text: str) -> list[dict]:
    """Parse objdump text lines into structured instructions (truth side).

    用分词而非单个贪婪正则：字节列与助记符之间只隔一个制表符时，
    贪婪正则会把 `callq` 的 `ca` 吃进字节列（实测踩坑）。
    """
    instructions: list[dict] = []
    for raw in str(assembly_text).splitlines():
        match = _INSN_ADDR_RE.match(raw)
        if not match:
            continue
        tokens = match[2].split()
        hex_tokens: list[str] = []
        index = 0
        while index < len(tokens) and _HEX_PAIR_RE.match(tokens[index]):
            hex_tokens.append(tokens[index])
            index += 1
        if not hex_tokens or index >= len(tokens):
            continue  # 没有字节列（如重定位行）或只有字节的残行
        blob = bytes.fromhex("".join(hex_tokens))
        instructions.append({
            "address": int(match[1], 16),
            "bytes": blob,
            "size": len(blob),
            "text": " ".join(tokens[index:]),
        })
    return instructions


@dataclass(frozen=True)
class PatchOp:
    """One in-place byte replacement at a known virtual address."""

    kind: str
    vaddr: int
    file_offset: int
    original_bytes: bytes
    new_bytes: bytes
    note: str = ""
    op_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def __post_init__(self) -> None:
        if len(self.original_bytes) != len(self.new_bytes):
            raise ValueError(
                f"patch 长度不一致（{len(self.original_bytes)} → {len(self.new_bytes)}）；"
                "AWDP 补丁不允许改变文件大小")

    def to_dict(self) -> dict:
        return {
            "op_id": self.op_id,
            "kind": self.kind,
            "vaddr": self.vaddr,
            "file_offset": self.file_offset,
            "original_bytes": self.original_bytes.hex(" "),
            "new_bytes": self.new_bytes.hex(" "),
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "PatchOp":
        return cls(
            kind=str(payload.get("kind") or "custom"),
            vaddr=int(payload.get("vaddr") or 0),
            file_offset=int(payload.get("file_offset") or 0),
            original_bytes=bytes.fromhex(str(payload.get("original_bytes") or "").replace(" ", "")),
            new_bytes=bytes.fromhex(str(payload.get("new_bytes") or "").replace(" ", "")),
            note=str(payload.get("note") or ""),
            op_id=str(payload.get("op_id") or uuid.uuid4().hex[:12]),
        )


def _hex_dump(data: bytes) -> str:
    return data.hex(" ")


class PatchLab:
    """Owns one working binary plus its persistent patch log."""

    def __init__(self, binary: Path, *, project_root: Path | None = None) -> None:
        self.binary = Path(binary)
        root = Path(project_root) if project_root else self.binary.parent
        self.log_path = root / ".pwncraft" / "patch_log.json"
        self._geometry: dict | None = None

    # -- geometry ----------------------------------------------------
    def geometry(self) -> dict:
        if self._geometry is None:
            self._geometry = elf_geometry(self.binary)
        return self._geometry

    def offset_of(self, vaddr: int) -> int:
        offset = vaddr_to_offset(self.geometry(), int(vaddr))
        if offset is None:
            raise ValueError(f"虚拟地址 0x{int(vaddr):x} 不在任何 PT_LOAD 文件映像内")
        return offset

    def read(self, offset: int, size: int) -> bytes:
        with self.binary.open("rb") as stream:
            stream.seek(offset)
            return stream.read(size)

    def read_at(self, vaddr: int, size: int) -> bytes:
        return self.read(self.offset_of(vaddr), size)

    # -- patch log ---------------------------------------------------
    def log_ops(self) -> list[PatchOp]:
        import json

        if not self.log_path.is_file():
            return []
        try:
            payload = json.loads(self.log_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        binary_key = str(self.binary)
        entries = payload.get(binary_key) if isinstance(payload, dict) else None
        if not isinstance(entries, list):
            return []
        return [PatchOp.from_dict(entry) for entry in entries if isinstance(entry, dict)]

    def _save_log(self, ops: list[PatchOp]) -> None:
        import json

        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict = {}
        if self.log_path.is_file():
            try:
                loaded = json.loads(self.log_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    payload = loaded
            except (OSError, ValueError):
                payload = {}
        payload[str(self.binary)] = [op.to_dict() for op in ops]
        self.log_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    # -- apply / undo ------------------------------------------------
    def _backup(self) -> Path:
        stamp = time.time_ns() // 1000
        backup = self.binary.with_name(f"{self.binary.name}.patchbak.{stamp}")
        shutil.copy2(self.binary, backup)
        return backup

    def _assert_no_overlap(self, ops: list[PatchOp]) -> None:
        logged = self.log_ops()
        ranges = [(op.vaddr, op.vaddr + len(op.new_bytes)) for op in logged]
        for op in ops:
            start, end = op.vaddr, op.vaddr + len(op.new_bytes)
            for other_id, (lo, hi) in enumerate(ranges):
                if start < hi and lo < end:
                    raise ValueError(
                        f"补丁范围 0x{start:x}-0x{end:x} 与已应用补丁 "
                        f"（0x{lo:x}-0x{hi:x}）重叠；请先撤销旧补丁")

    def apply(self, ops: list[PatchOp]) -> dict:
        """Verify originals, back up, write bytes in place, persist the log."""
        if not ops:
            raise ValueError("没有可应用的补丁")
        self._assert_no_overlap(ops)
        for op in ops:
            current = self.read(op.file_offset, len(op.original_bytes))
            if current != op.original_bytes:
                raise ValueError(
                    f"0x{op.vaddr:x} 处当前字节为 {_hex_dump(current)!r}，"
                    f"与预期的原字节 {_hex_dump(op.original_bytes)!r} 不符；"
                    "文件可能已被外部修改，请重新分析")
        backup = self._backup()
        with self.binary.open("r+b") as stream:
            for op in ops:
                stream.seek(op.file_offset)
                stream.write(op.new_bytes)
        merged = self.log_ops() + list(ops)
        self._save_log(merged)
        return {"applied": [op.to_dict() for op in ops], "backup": str(backup)}

    def undo(self, op_id: str) -> dict:
        logged = self.log_ops()
        target = next((op for op in logged if op.op_id == op_id), None)
        if target is None:
            raise ValueError(f"补丁 {op_id} 不存在")
        current = self.read(target.file_offset, len(target.new_bytes))
        with self.binary.open("r+b") as stream:
            stream.seek(target.file_offset)
            stream.write(target.original_bytes)
        self._save_log([op for op in logged if op.op_id != op_id])
        return {"restored": target.to_dict(), "current_bytes": _hex_dump(current)}

    def undo_all(self) -> dict:
        logged = self.log_ops()
        for op in reversed(logged):
            self.undo(op.op_id)
        return {"count": len(logged)}


# ---------------------------------------------------------------------------
# Code cave discovery（可执行 PT_LOAD 内、未被任何 section 占用的全零空洞）

_SHT_NOBITS = 8


def find_code_cave(binary: Path, min_size: int, *, geometry: dict | None = None) -> dict:
    """Largest all-zero hole inside an executable PT_LOAD, not owned by sections.

    扫描范围延伸到段文件映像的页对齐末尾（加载器整页映射，段间填充在运行时
    可执行——实测有效），但不超过文件长度、下一段文件起点，且不覆盖任何
    section 占用的数据（配合全零校验双重防破坏）。
    """
    geo = geometry or elf_geometry(binary)
    data = Path(binary).read_bytes()
    exec_segments = [h for h in geo["program_headers"]
                     if h["type"] == 1 and (h["flags"] & 0x1)]
    if not exec_segments:
        raise ValueError("没有可执行 PT_LOAD 段，无法注入代码")
    covered: list[tuple[int, int]] = []
    for section in geo["sections"]:
        if section["type"] == _SHT_NOBITS or section["size"] <= 0:
            continue
        covered.append((section["offset"], section["offset"] + section["size"]))
    # ELF 头 + 程序头表永远不可用
    ph_end = geo["phoff"] + geo["phentsize"] * geo["phnum"]
    covered.append((0, max(64, ph_end)))

    page = 0x1000
    best: dict | None = None
    for segment in exec_segments:
        seg_start = int(segment["offset"])
        seg_filesz = int(segment["filesz"])
        next_starts = [int(s["offset"]) for s in geo["program_headers"]
                       if int(s["offset"]) > seg_start]
        scan_end = (seg_start + seg_filesz + page - 1) & ~(page - 1)
        scan_end = min(scan_end, len(data),
                       min(next_starts) if next_starts else scan_end)
        if scan_end <= seg_start:
            continue
        bounds = sorted(covered + [(seg_start, seg_start), (scan_end, scan_end)])
        free_runs: list[tuple[int, int]] = []
        cursor = seg_start
        for lo, hi in bounds:
            lo = max(lo, seg_start)
            hi = min(hi, scan_end)
            if lo > cursor:
                free_runs.append((cursor, lo))
            cursor = max(cursor, hi)
        if cursor < scan_end:
            free_runs.append((cursor, scan_end))
        for lo, hi in free_runs:
            run_start = lo
            for index in range(lo, hi + 1):
                is_zero = index < hi and data[index] == 0
                if not is_zero:
                    if index - run_start >= min_size:
                        candidate = {
                            "offset": run_start,
                            "vaddr": int(segment["vaddr"]) + (run_start - seg_start),
                            "size": index - run_start,
                        }
                        if best is None or candidate["size"] > best["size"]:
                            best = candidate
                    run_start = index + 1
    if best is None:
        raise ValueError(
            f"可执行段内未找到 ≥{min_size} 字节的全零 code cave；"
            "该二进制无法做不改文件大小的注入")
    return best


def page_aware_vaddr_to_offset(geometry: dict, vaddr: int) -> int | None:
    """严格 PT_LOAD 解析失败时，按加载器整页映射语义回退解析（段尾填充区）。

    导出 patched ELF 时 cave 地址常落在段 filesz 之外的页尾，运行时有效
    （整页映射），严格区间判定会拒绝；这里对可执行段做页对齐包含判定。
    """
    vaddr = int(vaddr)
    strict = vaddr_to_offset(geometry, vaddr)
    if strict is not None:
        return strict
    page = 0x1000
    for segment in geometry.get("program_headers") or []:
        if not (int(segment["flags"]) & 0x1):
            continue
        align = int(segment["align"]) or page
        size = int(segment["filesz"])
        start = int(segment["vaddr"])
        mapped_end = (start + size + align - 1) & ~(align - 1)
        if start <= vaddr < mapped_end:
            candidate = int(segment["offset"]) + (vaddr - start)
            if candidate < int(geometry.get("file_size") or 0):
                return candidate
    return None


def entry_prefix_bytes(entry_lines: list[dict]) -> bytes:
    """Instruction-aligned prefix of the entry point, at least 5 bytes long."""
    prefix = b""
    for insn in entry_lines:
        prefix += insn["bytes"]
        if len(prefix) >= 5:
            return prefix
        if len(prefix) > 32:
            break
    raise ValueError("入口指令序列太短，无法放置 5 字节跳转")


def rel32_jmp(source_vaddr: int, target_vaddr: int) -> bytes:
    """`jmp rel32` bytes jumping from source to target (opcode E9)."""
    delta = int(target_vaddr) - (int(source_vaddr) + 5)
    if not -0x80000000 <= delta < 0x80000000:
        raise ValueError(f"跳转距离越界: {delta:#x}")
    return b"\xe9" + struct.pack("<i", delta)
