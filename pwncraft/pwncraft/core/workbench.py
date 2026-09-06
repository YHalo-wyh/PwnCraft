from __future__ import annotations

from ast import literal_eval
from dataclasses import dataclass, field
import hashlib
import re
import struct
from pathlib import Path
from typing import Mapping, Sequence

from .gadgets import Gadget, parse_ropgadget_output, search_gadgets
from .syscalls import SyscallSpec, lookup_syscall, normalize_architecture
from .truth_providers import ELFProvider
from .workspace import AddressKind, PwnWorkspace, TypedAddress, WorkspaceVariable


@dataclass(frozen=True)
class BinaryFacts:
    path: str
    architecture: str
    bits: int
    endian: str
    entry: int
    machine: int
    file_size: int = 0
    sha256: str = ""
    security: dict[str, str] = field(default_factory=dict)
    source: str = "ELFProvider"
    security_source: str = "elf-parser"

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "architecture": self.architecture,
            "bits": self.bits,
            "endian": self.endian,
            "entry": self.entry,
            "machine": self.machine,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "security": dict(self.security),
            "source": self.source,
            "security_source": self.security_source,
        }


_PROTECTION_LABELS = {
    "RELRO": ("RELRO",),
    "CANARY": ("CANARY", "CANARY FOUND"),
    "NX": ("NX",),
    "PIE": ("PIE",),
    "FORTIFY": ("FORTIFY", "FORTIFIED"),
    "STRIPPED": ("STRIPPED",),
}

def parse_checksec_output(text: str) -> dict[str, str]:
    """Parse only explicit checksec values; missing protections remain unknown."""
    result: dict[str, str] = {}
    # Parse bounded fields so neighbouring values cannot change the state of
    # another protection such as NX: enabled.
    key_pattern = "|".join(_PROTECTION_LABELS)
    label_re = re.compile(rf"\b({key_pattern})\b\s*[:=]\s*", re.IGNORECASE)
    for raw_line in str(text).splitlines():
        upper_line = raw_line.upper()
        matches = list(label_re.finditer(upper_line))
        if matches:
            segments = [
                (
                    match.group(1).upper(),
                    upper_line[match.end() : (matches[index + 1].start() if index + 1 < len(matches) else len(upper_line))],
                )
                for index, match in enumerate(matches)
            ]
        else:
            # Accommodate human-readable forms such as Canary found.
            segments = []
            for key in _PROTECTION_LABELS:
                match = re.search(rf"^\s*{key}\b", upper_line)
                if match:
                    segments.append((key, upper_line[match.end() :]))
            # Some checksec releases label canary as Stack and put the word
            # only in the value (Stack: No canary found). Keep this bounded.
            if not segments and re.search(r"\b(?:STACK|CANARY)\b", upper_line):
                canary = re.search(r"\bCANARY\b", upper_line)
                if canary:
                    segments.append(("CANARY", upper_line))
        for key, tail in segments:
            if key in result:
                continue
            if key == "RELRO":
                if "FULL" in tail:
                    result[key] = "FULL"
                elif "PARTIAL" in tail:
                    result[key] = "PARTIAL"
                elif "NONE" in tail or "NO RELRO" in tail:
                    result[key] = "NONE"
                else:
                    result[key] = "UNKNOWN"
                continue
            if re.search(r"\b(?:NOT\s+FOUND|NO|NONE|DISABLED)\b", tail):
                result[key] = "OFF"
            elif re.search(r"\b(?:FOUND|ENABLED|YES|FORTIFIED)\b", tail):
                result[key] = "ON"
            else:
                result[key] = "UNKNOWN"
    return result


# ELF 常量（本地保护解析用，值域与 parse_checksec_output 一致）
_PT_GNU_STACK = 0x6474E551
_PT_GNU_RELRO = 0x6474E552
_PT_DYNAMIC = 2
_PF_X = 0x1
_DT_FLAGS = 30
_DT_FLAGS_1 = 0x6FFFFFFB
_DT_BIND_NOW = 24
_DT_BIND_NOW_MASK = 0x8
_DT_FLAGS_1_NOW_MASK = 0x1
_MAX_SYM_SCAN_BYTES = 8 * 1024 * 1024  # 符号表扫描上限，防止畸形文件拖死导入


def _elf_header_layout(data: bytes) -> tuple[str, int, int, int, int, int, int, int] | None:
    """Return (order, e_type, phoff, phentsize, phnum, shoff, shentsize, shnum) or None."""
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return None
    endian = "little" if data[5] == 1 else "big"
    if data[4] == 1:  # ELF32
        return (endian,
                int.from_bytes(data[16:18], endian),
                int.from_bytes(data[28:32], endian),
                int.from_bytes(data[42:44], endian),
                int.from_bytes(data[44:46], endian),
                int.from_bytes(data[32:36], endian),
                int.from_bytes(data[46:48], endian),
                int.from_bytes(data[48:50], endian))
    if data[4] == 2:  # ELF64
        return (endian,
                int.from_bytes(data[16:18], endian),
                int.from_bytes(data[32:40], endian),
                int.from_bytes(data[54:56], endian),
                int.from_bytes(data[56:58], endian),
                int.from_bytes(data[40:48], endian),
                int.from_bytes(data[58:60], endian),
                int.from_bytes(data[60:62], endian))
    return None


def _program_headers(stream, order: str, phoff: int, phentsize: int, phnum: int) -> list[dict[str, int]]:
    headers: list[dict[str, int]] = []
    if phentsize not in (32, 56):
        return headers
    stream.seek(phoff)
    blob = stream.read(min(phentsize * phnum, 1 * 1024 * 1024))
    is64 = phentsize == 56
    fmt = order + ("IIQQQQQQ" if is64 else "IIIIIIII")
    fields = ("type", "flags", "offset", "vaddr", "paddr", "filesz", "memsz", "align")
    for index in range(len(blob) // phentsize):
        chunk = blob[index * phentsize:(index + 1) * phentsize]
        if len(chunk) < phentsize:
            break
        values = struct.unpack(fmt, chunk)
        if not is64:  # ELF32: flags 在 p_type 之后第 8 字节
            values = (values[0], values[6]) + values[1:6] + (values[7],)
        headers.append(dict(zip(fields, values)))
    return headers


def _section_headers(stream, order: str, shoff: int, shentsize: int, shnum: int) -> list[dict[str, int]]:
    sections: list[dict[str, int]] = []
    if shnum == 0 or shentsize not in (40, 64):
        return sections
    stream.seek(shoff)
    blob = stream.read(min(shentsize * shnum, 2 * 1024 * 1024))
    is64 = shentsize == 64
    fmt = order + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII")
    fields = ("name", "type", "flags", "addr", "offset", "size", "link", "info", "addralign", "entsize")
    for index in range(len(blob) // shentsize):
        chunk = blob[index * shentsize:(index + 1) * shentsize]
        if len(chunk) < shentsize:
            break
        values = struct.unpack(fmt, chunk)
        sections.append(dict(zip(fields, values)))
    return sections


def _vaddr_to_offset(program_headers: list[dict[str, int]], vaddr: int) -> int | None:
    for header in program_headers:
        if header["type"] == 1 and header["vaddr"] <= vaddr < header["vaddr"] + header["filesz"]:
            return header["offset"] + (vaddr - header["vaddr"])
    return None


def _dynamic_flags(stream, program_headers: list[dict[str, int]], order: str, is64: bool) -> tuple[bool, bool]:
    """Scan PT_DYNAMIC for (bind_now, flags1_now)."""
    dynamic = next((h for h in program_headers if h["type"] == _PT_DYNAMIC), None)
    if dynamic is None:
        return False, False
    file_off = _vaddr_to_offset(program_headers, dynamic["vaddr"])
    if file_off is None:
        file_off = dynamic["offset"]
    entry = 16 if is64 else 8
    stream.seek(file_off)
    blob = stream.read(min(dynamic.get("filesz", 0) or 4096, 256 * 1024))
    bind_now = flags1_now = False
    for index in range(len(blob) // entry):
        chunk = blob[index * entry:(index + 1) * entry]
        if len(chunk) < entry:
            break
        if is64:
            tag, value = struct.unpack(order + "QQ", chunk)
        else:
            tag, value = struct.unpack(order + "II", chunk)
        if tag == 0:
            break
        if tag == _DT_BIND_NOW:
            bind_now = True
        elif tag == _DT_FLAGS:
            bind_now = bind_now or bool(value & _DT_BIND_NOW_MASK)
        elif tag == _DT_FLAGS_1:
            flags1_now = bool(value & _DT_FLAGS_1_NOW_MASK)
    return bind_now, flags1_now


def _scan_symbols(stream, sections: list[dict[str, int]], order: str, is64: bool) -> tuple[bool, bool, bool]:
    """Scan .dynsym（优先）/ .symtab for (canary, fortify, has_symtab)."""
    canary = fortify = False
    has_symtab = any(s["type"] == 2 for s in sections)
    symtab = next((s for s in sections if s["type"] == 11), None)  # SHT_DYNSYM
    if symtab is None:
        symtab = next((s for s in sections if s["type"] == 2), None)
    if symtab is None:
        return canary, fortify, has_symtab
    strtab = sections[symtab["link"]] if 0 <= symtab["link"] < len(sections) else None
    if strtab is None:
        return canary, fortify, has_symtab
    entry_size = symtab["entsize"] or (24 if is64 else 16)
    if entry_size not in (16, 24):
        return canary, fortify, has_symtab
    stream.seek(symtab["offset"])
    blob = stream.read(min(symtab["size"], _MAX_SYM_SCAN_BYTES))
    stream.seek(strtab["offset"])
    strings = stream.read(min(strtab["size"], _MAX_SYM_SCAN_BYTES))
    for index in range(len(blob) // entry_size):
        chunk = blob[index * entry_size:(index + 1) * entry_size]
        if len(chunk) < entry_size:
            break
        st_name = struct.unpack(order + "I", chunk[0:4])[0]
        if st_name == 0 or st_name >= len(strings):
            continue
        end = strings.find(b"\x00", st_name)
        name = strings[st_name:end if end != -1 else len(strings)]
        if not name:
            continue
        if b"__stack_chk" in name or b"__intel_security_cookie" in name:
            canary = True
        if name.startswith(b"__") and name.endswith(b"_chk"):
            fortify = True
        if canary and fortify:
            break
    return canary, fortify, has_symtab


def parse_elf_security(path: str | Path) -> dict[str, str]:
    """Parse binary protections straight from the ELF — no WSL / checksec tool.

    Same normalized vocabulary as ``parse_checksec_output`` so the renderer's
    ``secInfo`` handles both sources identically.  Anything unparseable stays
    UNKNOWN (honest display) instead of guessing.
    """
    result = {"PIE": "UNKNOWN", "NX": "UNKNOWN", "CANARY": "UNKNOWN",
              "RELRO": "UNKNOWN", "FORTIFY": "UNKNOWN", "STRIPPED": "UNKNOWN"}
    target = Path(path)
    try:
        with target.open("rb") as stream:
            header = stream.read(64)
            layout = _elf_header_layout(header)
            if layout is None:
                return result
            order, e_type, phoff, phentsize, phnum, shoff, shentsize, shnum = layout
            order = "<" if order == "little" else ">"
            phnum = min(phnum, 65535)
            shnum = min(shnum, 65535)
            program_headers = _program_headers(stream, order, phoff, phentsize, phnum)
            sections = _section_headers(stream, order, shoff, shentsize, shnum)
            is64 = phentsize == 56

            # PIE：ET_DYN（含 INTERP 的可执行）→ ON；ET_EXEC → OFF
            if e_type == 3:
                result["PIE"] = "ON"
            elif e_type == 2:
                result["PIE"] = "OFF"

            # NX：GNU_STACK 段缺省或可执行 → NX 关闭
            gnu_stack = next((h for h in program_headers if h["type"] == _PT_GNU_STACK), None)
            result["NX"] = "OFF" if gnu_stack is None or (gnu_stack["flags"] & _PF_X) else "ON"

            # RELRO：GNU_RELRO + BIND_NOW → FULL；仅有 GNU_RELRO → PARTIAL；没有 → NONE
            has_relro = any(h["type"] == _PT_GNU_RELRO for h in program_headers)
            if has_relro:
                bind_now, flags1_now = _dynamic_flags(stream, program_headers, order, is64)
                result["RELRO"] = "FULL" if (bind_now or flags1_now) else "PARTIAL"
            else:
                result["RELRO"] = "NONE"

            canary, fortify, has_symtab = _scan_symbols(stream, sections, order, is64)
            result["CANARY"] = "ON" if canary else "OFF"
            result["FORTIFY"] = "ON" if fortify else "OFF"
            # 有节表且带 .symtab → 未剥离；否则（无节表 / 只有 dynsym）→ 已剥离
            result["STRIPPED"] = "OFF" if (sections and has_symtab) else "ON"
    except OSError:
        return {key: "UNKNOWN" for key in result}
    return result


class BinaryInspector:
    """Read static ELF facts and optionally merge explicit checksec output."""

    def inspect(self, path: str | Path, *, checksec_output: str = "") -> BinaryFacts:
        candidate = Path(path).resolve()
        provider = ELFProvider(candidate)
        facts = {
            key: provider.query(key).value  # type: ignore[union-attr]
            for key in ("path", "architecture", "bits", "endian", "entry", "machine")
        }
        digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        # 保护事实：WSL checksec 输出优先（工具级判定），缺项由本地 ELF 解析兜底
        # ——checksec 工具未装/WSL 不可用时保护显示依然完整、准确。
        parsed = parse_checksec_output(checksec_output)
        local = parse_elf_security(candidate)
        security = dict(local)
        for key, value in parsed.items():
            if value != "UNKNOWN":
                security[key] = value
        source = "checksec" if parsed and any(v != "UNKNOWN" for v in parsed.values()) else "elf-parser"
        if parsed and local and any(v != "UNKNOWN" for v in parsed.values()) \
                and any(v != "UNKNOWN" for v in local.values()):
            source = "checksec+elf-parser"
        return BinaryFacts(
            path=str(facts["path"]),
            architecture=str(facts["architecture"]),
            bits=int(facts["bits"]),
            endian=str(facts["endian"]),
            entry=int(facts["entry"]),
            machine=int(facts["machine"]),
            file_size=candidate.stat().st_size,
            sha256=digest,
            security=security,
            security_source=source,
        )

    def apply(self, workspace: PwnWorkspace, facts: BinaryFacts) -> None:
        workspace.set_binary(**facts.to_dict())
        workspace.set_variable(
            WorkspaceVariable(
                "entry",
                TypedAddress(facts.entry, AddressKind.STATIC_ADDRESS, module=Path(facts.path).name),
                facts.source,
                f"ELF header: e_entry={facts.entry:#x}",
                address_kind=AddressKind.STATIC_ADDRESS,
            )
        )
        workspace.set_variable(WorkspaceVariable("binary_bits", facts.bits, facts.source, f"ELF class: {facts.bits}-bit"))


class GadgetExplorer:
    """Semantic query facade over structured Gadget facts."""

    def __init__(self, gadgets: Sequence[Gadget] = ()) -> None:
        self.gadgets = tuple(gadgets)

    @classmethod
    def from_ropgadget_output(cls, output: str, *, source: str = "ROPgadget", bits: int = 64, base: int | None = None) -> "GadgetExplorer":
        return cls(parse_ropgadget_output(output, source=source, bits=bits, base=base))

    def search(self, query: str) -> tuple[Gadget, ...]:
        return search_gadgets(self.gadgets, query)

    def update(self, gadgets: Sequence[Gadget]) -> None:
        self.gadgets = tuple(gadgets)

    def apply(self, workspace: PwnWorkspace, *, source: str = "") -> None:
        workspace.set_gadgets(self.gadgets, source=source)


@dataclass(frozen=True)
class SyscallPlan:
    spec: SyscallSpec
    arguments: dict[str, object]
    registers: dict[str, object]
    missing_registers: tuple[str, ...] = ()
    seccomp_verdict: str = "UNKNOWN"
    blockers: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return not self.missing_registers

    @property
    def executable(self) -> bool:
        """Executable means provable: complete registers, gadget control,
        and a seccomp verdict that is not BLOCKED."""
        return self.complete and not self.blockers and self.seccomp_verdict == "ALLOWED"

    def to_dict(self) -> dict[str, object]:
        return {
            "syscall": self.spec.to_dict(),
            "arguments": dict(self.arguments),
            "registers": dict(self.registers),
            "missing_registers": list(self.missing_registers),
            "seccomp_verdict": self.seccomp_verdict,
            "blockers": list(self.blockers),
            "complete": self.complete,
            "executable": self.executable,
        }


class SyscallPlanner:
    def plan(self, name: str, arguments: Mapping[object, object], *, architecture: str = "amd64") -> SyscallPlan:
        spec = lookup_syscall(name, architecture)
        if spec is None:
            raise LookupError(f"未知 {normalize_architecture(architecture)} syscall: {name}")
        normalized: dict[str, object] = {}
        aliases = {
            "read": ("fd", "buf", "len"),
            "write": ("fd", "buf", "len"),
            "open": ("path", "flags", "mode"),
            "openat": ("dirfd", "path", "flags", "mode"),
            "execve": ("filename", "argv", "envp"),
        }.get(spec.name, ())
        for index, register in enumerate(spec.registers):
            if register in arguments:
                normalized[register] = arguments[register]
            elif index < len(aliases) and aliases[index] in arguments:
                normalized[register] = arguments[aliases[index]]
            elif index in arguments:
                normalized[register] = arguments[index]
            elif str(index) in arguments:
                normalized[register] = arguments[str(index)]
        missing = tuple(register for register in spec.registers if register not in normalized)
        return SyscallPlan(spec, normalized, dict(normalized), missing)

    @staticmethod
    def validate_gadgets(plan: SyscallPlan, gadgets: Sequence[Gadget]) -> tuple[str, ...]:
        controlled = {register for gadget in gadgets for register in gadget.controls}
        return tuple(register for register in plan.spec.registers if register not in controlled)

    def diagnose(
        self,
        name: str,
        arguments: Mapping[object, object],
        *,
        architecture: str = "amd64",
        gadgets: Sequence[Gadget] = (),
        seccomp_policy: Mapping[str, str] | None = None,
    ) -> SyscallPlan:
        """Full deterministic verdict: registers + gadget control + seccomp."""
        from .syscalls import seccomp_verdict as _verdict

        plan = self.plan(name, arguments, architecture=architecture)
        missing_gadgets = self.validate_gadgets(plan, gadgets) if gadgets else ()
        policy = dict(seccomp_policy or {})
        verdict = _verdict(policy, plan.spec.name) if policy else "UNKNOWN"
        blockers: list[str] = []
        if verdict == "BLOCKED":
            blockers.append(f"seccomp BLOCKED: {plan.spec.name}")
        if missing_gadgets:
            blockers.append("缺少控制 Gadget: " + ", ".join(register.upper() for register in missing_gadgets))
        return SyscallPlan(plan.spec, plan.arguments, plan.registers, plan.missing_registers, verdict, tuple(blockers))


@dataclass(frozen=True)
class EncodingResult:
    input_text: str
    value: int | bytes
    packed: bytes
    word_size: int
    endian: str

    @property
    def hex_bytes(self) -> str:
        return self.packed.hex(" ")

    @property
    def python_expression(self) -> str:
        if isinstance(self.value, int):
            return f"p{self.word_size * 8}({self.value:#x})"
        return repr(self.value)


def _parse_encoding_input(value: str | int | bytes) -> int | bytes:
    if isinstance(value, (int, bytes)):
        return value
    text = str(value).strip()
    if not text:
        raise ValueError("编码输入不能为空")
    if text.startswith(("b'", 'b"')):
        parsed = literal_eval(text)
        if not isinstance(parsed, bytes):
            raise ValueError("输入不是 bytes 字面量")
        return parsed
    try:
        return int(text, 0)
    except ValueError as exc:
        raise ValueError("请输入整数、十六进制或 b'...' 字面量") from exc


def encode_value(value: str | int | bytes, *, word_size: int = 8, endian: str = "little") -> EncodingResult:
    if word_size not in {1, 2, 4, 8}:
        raise ValueError("word_size 必须是 1/2/4/8")
    if endian not in {"little", "big"}:
        raise ValueError("endian 必须是 little 或 big")
    parsed = _parse_encoding_input(value)
    if isinstance(parsed, int) and (parsed < 0 or parsed >= 1 << (word_size * 8)):
        raise ValueError(f"整数超出 p{word_size * 8} 范围")
    packed = parsed.to_bytes(word_size, endian) if isinstance(parsed, int) else parsed
    return EncodingResult(str(value), parsed, packed, word_size, endian)


@dataclass(frozen=True)
class PaletteEntry:
    id: str
    title: str
    description: str
    target: str = ""


def default_palette_entries() -> tuple[PaletteEntry, ...]:
    # `target` is the stable primary-navigation key, not a display string.
    # Pre-v0.15 entry ids stay valid so older dialogs/tests keep resolving.
    return (
        PaletteEntry("binary.inspect", "检查程序", "读取 ELF、保护、符号与 GOT/PLT 事实", "binary"),
        PaletteEntry("goal.build_rop", "构造 ROP", "从 Gadget Shelf 组装并验证 ROP 链", "rop"),
        PaletteEntry("gadget.search", "搜索 Gadget", "按寄存器或指令语义查询真实 Gadget 并收藏", "rop"),
        PaletteEntry("syscall.explorer", "查询 syscall", "查看 syscall 编号、寄存器、原型和 seccomp 约束", "syscall"),
        PaletteEntry("encoding.playground", "编码转换", "计算 p64/u64、字节序和十六进制", "tools"),
        PaletteEntry("heap.timeline", "查看 Heap 时间线", "回放 allocator 状态和运行时快照", "heap"),
        PaletteEntry("debug.open", "打开调试器", "连接隔离的 pwndbg-mogai", "debug"),
        PaletteEntry("exp.edit", "编辑 EXP", "在 EXP 工作区编写和拼装 pwntools 脚本", "exp"),
        PaletteEntry("workspace.variables", "查看变量", "查看跨 Binary、Gadget、Heap 和 EXP 共享的变量", "dashboard"),
        PaletteEntry("project.save", "保存项目", "把 Workspace 变量、Gadget 与分析状态写入 .pwncraft", ""),
        PaletteEntry("project.open", "打开项目", "恢复 .pwncraft 项目文件中的静态事实与变量", ""),
        PaletteEntry("stack.offset", "找溢出 Offset", "cyclic 工作流：Stack 页 Offset Finder", "stack"),
        PaletteEntry("libc.workspace", "泄露地址 / 计算 libc", "Leak Manager 与 Libc Workspace", "libc"),
        PaletteEntry("format.lab", "分析 Format String", "Format String Lab：偏移与写入规划", "format"),
    )


_FIELD_WEIGHTS = (("title", 4), ("id", 3), ("target", 2), ("description", 1))


def search_palette(query: str, entries: Sequence[PaletteEntry] | None = None) -> tuple[PaletteEntry, ...]:
    """Deterministic ranked search: title hits outrank id/target/description."""
    needle = str(query).strip().casefold()
    source = tuple(entries or default_palette_entries())
    if not needle:
        return source
    scored = []
    for entry in source:
        best = max(
            (weight for field, weight in _FIELD_WEIGHTS if needle in str(getattr(entry, field)).casefold()),
            default=0,
        )
        if best:
            scored.append((-best, entry.title.casefold(), entry))
    scored.sort(key=lambda item: (item[0], item[1]))
    return tuple(item[2] for item in scored)
