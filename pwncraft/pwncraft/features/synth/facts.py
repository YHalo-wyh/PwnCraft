"""Deterministic target facts for exploit synthesis (no guessing, no network).

Every fact here is read from the ELF bytes, objdump disassembly, relocations or
the section dump — the module never infers an address from a name alone and
never executes the target.  ``runner`` only needs ``run_tool`` + ``to_wsl_path``
(WslToolRunner on Windows hosts, LocalToolRunner on a WSL/native host); tests
inject fakes.
"""
from __future__ import annotations

import re
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from pwncraft.core.code_analysis import parse_disassembly
from pwncraft.core.workbench import BinaryInspector
from pwncraft.core.wsl import ToolResult
from pwncraft.features.patch.patch_core import parse_instruction_lines
from pwncraft.features.patch.recipes import extract_plt_stubs

# 只认这些字符串作为「可执行命令」的确定性证据（其余字符串不猜）。
INTERESTING_STRINGS: tuple[bytes, ...] = (b"/bin/sh", b"/bin/bash", b"/bin/cat", b"/flag")
EXEC_IMPORTS = ("system", "execve", "execveat", "popen")
LEAK_IMPORTS = ("puts", "printf", "write", "send")
INPUT_IMPORTS = ("read", "gets", "fgets", "scanf", "__isoc99_scanf", "recv", "recvfrom")

_RELOC_RE = re.compile(r"^\s*([0-9a-fA-F]{6,16})\s+(R_\w+)\s+(\S+)\s*$")
_COMMENT_ADDR_RE = re.compile(r"#\s*([0-9a-fA-F]+)\b")
_CALL_RE = re.compile(r"^call[qwl]?\s+[0-9a-fA-F]+\s+<([^>+]+)>")
_RIP_LOADS = {b"\x48\x8d\x3d": 7, b"\x48\x8d\x35": 7}   # lea rdi/rsi,[rip+disp32]
_MOV_EDI_IMM = b"\xbf"                                   # mov edi, imm32


class LocalToolRunner:
    """Run allowlisted tools natively (WSL / Linux host).

    Mirrors WslToolRunner semantics: stdin=DEVNULL (wsl.exe 吞 stdin 的教训),
    fixed timeout, captured output.
    """

    def to_wsl_path(self, path: str | Path) -> str:
        return str(path)

    def run_tool(self, tool: str, args: list[str], timeout: int = 30) -> ToolResult:
        command = [tool, *args]
        try:
            # 字节模式 + 手动 UTF-8 解码：text=True 会用系统 ANSI（GBK）解码，
            # 中文路径/UTF-8 工具输出直接炸掉 reader 线程（--verify 实测踩坑）
            proc = subprocess.run(command, capture_output=True,
                                  stdin=subprocess.DEVNULL, timeout=timeout)
        except (OSError, subprocess.SubprocessError) as error:
            return ToolResult(command, 127, "", str(error))
        return ToolResult(command, proc.returncode,
                          proc.stdout.decode("utf-8", "replace"),
                          proc.stderr.decode("utf-8", "replace"))


@dataclass(frozen=True)
class PltStub:
    name: str
    address: int
    size: int

    def to_dict(self) -> dict:
        return {"name": self.name, "address": self.address, "size": self.size}


@dataclass(frozen=True)
class GotSlot:
    name: str
    address: int
    kind: str

    def to_dict(self) -> dict:
        return {"name": self.name, "address": self.address, "kind": self.kind}


@dataclass(frozen=True)
class CallSite:
    function: str
    address: int
    callee: str

    def to_dict(self) -> dict:
        return {"function": self.function, "address": self.address, "callee": self.callee}


@dataclass(frozen=True)
class FunctionFacts:
    name: str
    address: int
    size: int
    calls: tuple[CallSite, ...] = ()

    def to_dict(self) -> dict:
        return {"name": self.name, "address": self.address, "size": self.size,
                "calls": [call.to_dict() for call in self.calls]}


@dataclass
class TargetFacts:
    path: str
    sha256: str
    architecture: str
    bits: int
    endian: str
    entry: int
    security: dict[str, str] = field(default_factory=dict)
    plt: dict[str, PltStub] = field(default_factory=dict)
    got: dict[str, GotSlot] = field(default_factory=dict)
    functions: list[FunctionFacts] = field(default_factory=list)
    strings: dict[str, int] = field(default_factory=dict)
    syscalls: tuple[int, ...] = ()
    ret_gadgets: tuple[int, ...] = ()
    win_functions: tuple[dict, ...] = ()
    leak_sites: tuple[dict, ...] = ()
    notes: list[str] = field(default_factory=list)

    def has_plt(self, *names: str) -> bool:
        return any(name in self.plt for name in names)

    def call_sites(self, callee: str) -> list[CallSite]:
        return [call for fn in self.functions for call in fn.calls if call.callee == callee]

    def is_pie(self) -> bool:
        return str(self.security.get("PIE") or "UNKNOWN").upper() == "ON"

    def ret_gadget(self) -> int:
        """对齐用裸 ret（x86-64 返回进函数时需要 16 字节栈对齐）。"""
        return self.ret_gadgets[0] if self.ret_gadgets else 0

    def to_dict(self) -> dict:
        return {
            "path": self.path, "sha256": self.sha256,
            "architecture": self.architecture, "bits": self.bits,
            "endian": self.endian, "entry": self.entry, "security": dict(self.security),
            "plt": {name: stub.to_dict() for name, stub in self.plt.items()},
            "got": {name: slot.to_dict() for name, slot in self.got.items()},
            "functions": [fn.to_dict() for fn in self.functions],
            "strings": dict(self.strings), "syscalls": list(self.syscalls),
            "ret_gadgets": list(self.ret_gadgets),
            "win_functions": [dict(item) for item in self.win_functions],
            "leak_sites": [dict(item) for item in self.leak_sites],
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# Parsers (pure text → facts; unit-testable without a toolchain)

def _parse_relocations(text: str) -> list[GotSlot]:
    slots: list[GotSlot] = []
    for line in str(text or "").splitlines():
        match = _RELOC_RE.match(line)
        if not match:
            continue
        address, kind, symbol = int(match[1], 16), match[2], match[3]
        name = symbol.split("@", 1)[0]
        if not name or name.isdigit() or "*" in name:
            continue  # `*ABS*` / 未具名槽位：无符号名可归属，不猜
        slots.append(GotSlot(name=name, address=address, kind=kind))
    return slots


def _parse_dump_line(line: str) -> tuple[int, bytes] | None:
    """objdump -s 单行 → (地址, 字节)。

    格式为 ``<地址> <十六进制组...>  <ASCII>``；ASCII 列可能以看似十六进制的
    文本开头（如 ``652 i18n``），所以必须先按「两个以上空格」把 ASCII 列切开，
    再要求十六进制列每个 token 都是偶数长度的纯十六进制。
    """
    match = re.match(r"^\s*([0-9a-fA-F]{4,16})\s+(.*)$", str(line).rstrip("\n"))
    if not match:
        return None
    hex_column = re.split(r"\s{2,}", match[2], maxsplit=1)[0]
    tokens = hex_column.split()
    if not tokens:
        return None
    for token in tokens:
        if len(token) % 2 or re.fullmatch(r"[0-9a-fA-F]{2,16}", token) is None:
            return None
    return int(match[1], 16), bytes.fromhex("".join(tokens))


def _parse_section_dump(text: str) -> list[tuple[int, bytes]]:
    """objdump -s 行 → (地址, 字节) 段；只合并地址连续的行。"""
    segments: list[tuple[int, bytes]] = []
    for line in str(text or "").splitlines():
        parsed = _parse_dump_line(line)
        if parsed is None:
            continue
        address, blob = parsed
        if segments and segments[-1][0] + len(segments[-1][1]) == address:
            segments[-1] = (segments[-1][0], segments[-1][1] + blob)
        else:
            segments.append((address, blob))
    return segments


def _find_strings(segments: list[tuple[int, bytes]], needles: tuple[bytes, ...]) -> dict[str, int]:
    found: dict[str, int] = {}
    for address, blob in segments:
        for needle in needles:
            offset = blob.find(needle)
            if offset >= 0:
                found.setdefault(needle.decode("utf-8", "replace"), address + offset)
    return found


def _rip_target(insn: dict) -> int | None:
    """lea rdi/rsi,[rip+disp32] 或 mov edi,imm32 的绝对目标；其余形态返回 None。"""
    blob = bytes(insn.get("bytes") or b"")
    for prefix, size in _RIP_LOADS.items():
        if len(blob) == size and blob.startswith(prefix):
            disp = struct.unpack("<i", blob[3:7])[0]
            return int(insn["address"]) + size + disp
    if len(blob) == 5 and blob.startswith(_MOV_EDI_IMM):
        return struct.unpack("<I", blob[1:5])[0]
    return None


def _argument_address(insn: dict) -> int | None:
    """指令加载到第一个参数寄存器（rdi/edi）的绝对地址。"""
    text = str(insn.get("text") or "")
    match = _COMMENT_ADDR_RE.search(text)
    if match:
        return int(match[1], 16)
    return _rip_target(insn)


def _collect_annotations(functions: list[dict]) -> tuple[list[dict], list[dict], tuple[int, ...], tuple[int, ...]]:
    """win/leak 候选、syscall 站点与对齐用 ret：全部要求具体地址证据。"""
    win: list[dict] = []
    leak: list[dict] = []
    syscalls: list[int] = []
    rets: list[int] = []
    for fn in functions:
        name = str(fn.get("name") or "")
        instructions = parse_instruction_lines(fn.get("assembly") or "")
        for index, insn in enumerate(instructions):
            text = str(insn.get("text") or "")
            if text.startswith("syscall"):
                syscalls.append(int(insn["address"]))
            if text in ("ret", "retq"):
                rets.append(int(insn["address"]))
            match = _CALL_RE.match(text)
            if not match:
                continue
            callee = match.group(1).split("@", 1)[0]
            if callee not in EXEC_IMPORTS and callee not in LEAK_IMPORTS:
                continue
            target = None
            for candidate in reversed(instructions[max(0, index - 5):index]):
                if str(candidate.get("text") or "").startswith("call"):
                    break
                target = _argument_address(candidate)
                if target is not None:
                    break
            if target is None:
                continue
            record = {"function": name, "function_address": _int_address(fn.get("address")),
                      "call_address": int(insn["address"]),
                      "callee": callee, "argument_address": target}
            (win if callee in EXEC_IMPORTS else leak).append(record)
    return win, leak, tuple(sorted(set(syscalls))), tuple(sorted(set(rets)))


LIBC_WANTED = ("system", "puts", "read", "write", "printf", "execve", "str_bin_sh")

_SYM_RE = re.compile(r"^\s*([0-9a-fA-F]{4,16})\s+.*?\s(\S+)\s*$")


def collect_libc_symbols(libc: str | Path, *, runner=None, timeout: int = 60) -> dict[str, int]:
    """libc 符号偏移 + 壳字符串虚拟地址（objdump -T / -s，确定性）。

    ``/bin/sh`` 用节内容扫描取 vaddr（同 facts 采集目标二进制的方式），
    其余符号取动态符号表的 st_value。
    """
    path = Path(libc)
    runner = runner or LocalToolRunner()
    wsl_path = runner.to_wsl_path(path)
    resolved: dict[str, int] = {}
    table = runner.run_tool("objdump", ["-T", "--", wsl_path], timeout=timeout)
    if table.ok:
        for line in table.stdout.splitlines():
            match = _SYM_RE.match(line)
            if not match:
                continue
            name = match[2]
            if name in LIBC_WANTED:
                resolved.setdefault(name, int(match[1], 16))
    dump = runner.run_tool("objdump", ["-s", "--", wsl_path], timeout=timeout)
    if dump.ok:
        for text, address in _find_strings(_parse_section_dump(dump.stdout), INTERESTING_STRINGS).items():
            if text == "/bin/sh":
                resolved.setdefault("str_bin_sh", address)
    return resolved


def _int_address(value) -> int:
    """objdump/parse_disassembly 的地址可能是 int 或十六进制字符串。"""
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 16)
    except (TypeError, ValueError):
        return 0


def _functions_from_disassembly(text: str) -> list[dict]:
    parsed = parse_disassembly(text)
    return list(parsed.get("functions") or [])


def _function_facts(functions: list[dict]) -> list[FunctionFacts]:
    result: list[FunctionFacts] = []
    for fn in functions:
        name = str(fn.get("name") or "")
        address = _int_address(fn.get("address"))
        instructions = parse_instruction_lines(fn.get("assembly") or "")
        calls: list[CallSite] = []
        for insn in instructions:
            match = _CALL_RE.match(str(insn.get("text") or ""))
            if match:
                calls.append(CallSite(function=name, address=int(insn["address"]),
                                      callee=match.group(1).split("@", 1)[0]))
        size = (instructions[-1]["address"] + instructions[-1]["size"] - address) if instructions else 0
        result.append(FunctionFacts(name=name, address=address, size=max(size, 0), calls=tuple(calls)))
    return result


# ---------------------------------------------------------------------------
# Collection

def collect_target_facts(binary: str | Path, *, runner=None, timeout: int = 60) -> TargetFacts:
    path = Path(binary)
    facts = BinaryInspector().inspect(path)
    runner = runner or LocalToolRunner()
    wsl_path = runner.to_wsl_path(path)
    notes: list[str] = []

    functions: list[dict] = []
    disasm = runner.run_tool("objdump", ["-d", "--insn-width=16", "--", wsl_path], timeout=timeout)
    if disasm.ok:
        functions = _functions_from_disassembly(disasm.stdout)
    else:
        notes.append(f"反汇编失败：{disasm.combined_output() or disasm.returncode}")

    got: dict[str, GotSlot] = {}
    relocs = runner.run_tool("objdump", ["-R", "--", wsl_path], timeout=timeout)
    if relocs.ok:
        got = {slot.name: slot for slot in _parse_relocations(relocs.stdout)}
    else:
        notes.append(f"重定位读取失败：{relocs.combined_output() or relocs.returncode}")

    strings: dict[str, int] = {}
    dump = runner.run_tool("objdump", ["-s", "--", wsl_path], timeout=timeout)
    if dump.ok:
        strings = _find_strings(_parse_section_dump(dump.stdout), INTERESTING_STRINGS)
    else:
        notes.append(f"节内容读取失败：{dump.combined_output() or dump.returncode}")

    stubs = extract_plt_stubs(functions)
    plt = {name: PltStub(name=name, address=int(item["address"]), size=int(item["size"]))
           for name, item in stubs.items()}
    win_candidates, leak_sites, syscalls, rets = _collect_annotations(functions)
    win: list[dict] = []
    for candidate in win_candidates:
        text = next((value for value, address in strings.items()
                     if address == candidate["argument_address"]), "")
        win.append({**candidate, "string": text})
    leaks: list[dict] = []
    for site in leak_sites:
        got_name = next((name for name, slot in got.items()
                         if slot.address == site["argument_address"]), "")
        leaks.append({**site, "got": got_name})

    return TargetFacts(
        path=str(facts.path), sha256=facts.sha256, architecture=facts.architecture,
        bits=facts.bits, endian=facts.endian, entry=facts.entry,
        security=dict(facts.security), plt=plt, got=got,
        functions=_function_facts(functions), strings=strings,
        syscalls=syscalls, ret_gadgets=tuple(rets),
        win_functions=tuple(win), leak_sites=tuple(leaks), notes=notes)
