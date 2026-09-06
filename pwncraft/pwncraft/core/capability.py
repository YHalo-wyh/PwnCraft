"""Exploit Capability Analyzer (Phase 7, 规划 §三十四).

Rule-based only.  Every capability verdict names the workspace facts it used
and the requirements still missing; the analyzer never invents addresses and
never executes anything.  AI may explain these outputs later (§四十一) but
never produce them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .stack_truth import stack_control_state

if TYPE_CHECKING:
    from .workspace import PwnWorkspace


@dataclass(frozen=True)
class Capability:
    name: str
    state: str  # "available" | "blocked" | "unknown"
    reasons: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "state": self.state, "reasons": list(self.reasons), "missing": list(self.missing)}


def _shelf_roles(workspace: "PwnWorkspace") -> set[str]:
    pinned = workspace.gadgets.get("pinned", []) if isinstance(workspace.gadgets, dict) else []
    return {str(entry.get("role", "")).lower() for entry in pinned if isinstance(entry, dict)}


def _gadget_facts(workspace: "PwnWorkspace") -> tuple[set[str], bool, bool]:
    controls: set[str] = set()
    has_syscall = False
    has_ret = False
    discovered = workspace.gadgets.get("discovered", []) if isinstance(workspace.gadgets, dict) else []
    for raw in discovered:
        if not isinstance(raw, dict):
            continue
        controls.update(str(item).lower() for item in raw.get("controls", ()))
        instructions = [str(item).lower() for item in raw.get("instructions", ())]
        if any("syscall" in item for item in instructions):
            has_syscall = True
        if instructions and instructions[-1].split()[0] == "ret":
            has_ret = True
    controls.update(_shelf_roles(workspace))
    if any(role == "syscall" for role in _shelf_roles(workspace)):
        has_syscall = True
    return controls, has_syscall, has_ret


def _workspace_int_variable(workspace: "PwnWorkspace", name: str) -> int | None:
    """Read a scalar/TypedAddress WorkspaceVariable without inventing a cast."""
    variable = workspace.get_variable(name)
    if variable is None:
        return None
    value = variable.value
    if hasattr(value, "value"):
        value = getattr(value, "value")
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def analyze_capabilities(workspace: "PwnWorkspace") -> tuple[Capability, ...]:
    """Derive rule-based capabilities from the shared workspace facts."""
    binary = workspace.binary if isinstance(workspace.binary, dict) else {}
    security = binary.get("security") if isinstance(binary.get("security"), dict) else {}
    symbols = workspace.symbols if isinstance(workspace.symbols, dict) else {}
    got = symbols.get("got") or {}
    plt = symbols.get("plt") or {}
    functions = symbols.get("functions") or {}
    libraries = workspace.libraries if isinstance(workspace.libraries, dict) else {}
    libc_base = libraries.get("libc_base")
    if libc_base is None:
        # The Stack/Leak page historically published its derivation through a
        # typed WorkspaceVariable while the library loader publishes the same
        # fact in ``libraries``.  Both are evidence-bearing shared Workspace
        # facts, so capability analysis accepts either representation.
        libc_base = _workspace_int_variable(workspace, "libc_base")
    stack = workspace.stack if isinstance(workspace.stack, dict) else {}
    overflow = stack.get("overflow_offset")
    syscalls = workspace.syscalls if isinstance(workspace.syscalls, dict) else {}
    policy = syscalls.get("seccomp_policy") if isinstance(syscalls.get("seccomp_policy"), dict) else {}
    exploit = workspace.exploit if isinstance(workspace.exploit, dict) else {}
    primitives = {str(item.get("name", "")) for item in exploit.get("primitives", []) if isinstance(item, dict)}
    controls, has_syscall, has_ret = _gadget_facts(workspace)

    capabilities: list[Capability] = []

    # --- Control RIP (§三十三) ---
    # Cycle-7 separates "cyclic offset found" from "saved IP control proven".
    # Older projects had no provenance fields and historically treated a saved
    # overflow_offset as confirmed; keep that compatibility path explicitly.
    control_state = stack_control_state(workspace)
    if "Control RIP" in primitives:
        capabilities.append(Capability("Control RIP", "available", ("primitive: Control RIP",)))
    elif control_state == "confirmed_control":
        register = str(stack.get("control_register") or "rip").upper()
        capabilities.append(Capability(
            "Control RIP",
            "available",
            (f"overflow_offset={overflow}", f"{register} overwrite observed"),
        ))
    elif control_state == "legacy_offset":
        capabilities.append(Capability(
            "Control RIP",
            "available",
            (f"overflow_offset={overflow}", "legacy workspace fact (pre-cycle-7 provenance)"),
        ))
    elif control_state == "offset_only":
        capabilities.append(Capability(
            "Control RIP",
            "unknown",
            (f"overflow_offset={overflow}",),
            ("已定位 cyclic 偏移；还需确认保存的 RIP/EIP/PC 确实被该输入覆盖",),
        ))
    else:
        capabilities.append(Capability(
            "Control RIP",
            "unknown",
            (),
            ("先用 Stack → Offset Finder 定位偏移，并用调试器确认保存的 RIP/EIP/PC 覆盖",),
        ))

    # --- ret2libc (§二十三) ---
    leak_symbol = next((name for name in ("puts", "printf", "write", "read") if name in got and name in plt), "")
    has_rdi = "rdi" in controls
    if libc_base is not None and has_rdi and leak_symbol:
        capabilities.append(
            Capability(
                "ret2libc",
                "available",
                (f"pop rdi ✓", f"{leak_symbol}@got/plt ✓", f"libc_base={libc_base:#x} ✓"),
            )
        )
    else:
        missing = []
        if not has_rdi:
            missing.append("收藏 pop rdi Gadget")
        if not leak_symbol:
            missing.append("解析 GOT/PLT（Binary 页「检查程序」）")
        if libc_base is None:
            missing.append("推导 libc_base（Leak Manager / ret2libc 向导）")
        capabilities.append(Capability("ret2libc", "blocked", (), tuple(missing)))

    # --- ORW path (§十六/§十七) ---
    execve_blocked = policy.get("execve") == "BLOCKED"
    orw_syscalls_ok = policy.get("openat") == "ALLOWED" or policy.get("open") == "ALLOWED"
    if policy:
        if execve_blocked and orw_syscalls_ok:
            capabilities.append(Capability("ORW", "available", ("seccomp: execve BLOCKED", "open/openat、read、write 可用", "使用 Syscall → ORW Builder")))
        elif execve_blocked:
            capabilities.append(Capability("ORW", "blocked", ("seccomp: execve BLOCKED",), ("open/read/write 判定不完整，重新解析 seccomp",)))
        else:
            capabilities.append(Capability("ORW", "unknown", (), ("未检测到 execve BLOCKED；ORW 非必需路径",)))
    else:
        capabilities.append(Capability("ORW", "unknown", (), ("未加载 seccomp 策略",)))

    # --- SROP path (§十三) ---
    if has_syscall and "rax" in controls and ("rsp" in controls or "leave" in {item.lower() for item in _shelf_roles(workspace)}):
        capabilities.append(Capability("SROP", "available", ("syscall Gadget ✓", "rax 控制 ✓", "rsp 控制 ✓")))
    else:
        missing = []
        if not has_syscall:
            missing.append("搜索 syscall Gadget")
        if "rax" not in controls:
            missing.append("收藏 pop rax")
        if "rsp" not in controls:
            missing.append("收藏 pop rsp 或 leave ; ret")
        capabilities.append(Capability("SROP", "blocked", (), tuple(missing)))

    # --- ret2win / return to main (§八) ---
    if "main" in functions and security.get("NX") == "ON" and has_ret:
        capabilities.append(Capability("Return-to-main", "available", (f"main={functions['main']:#x}", "ret ✓", "NX ON：ROP/返回复用而非注入")))
    elif "main" in functions:
        capabilities.append(Capability("Return-to-main", "unknown", (), ("缺少 ret Gadget 证据",)))

    # --- Format String (§二十七) ---
    # A non-empty PLT is normal ELF metadata, not format-string evidence.
    # Only an explicit primitive or a recorded probe offset activates this lane.
    fmt_primitives = tuple(name for name in primitives if "format string" in name.lower() or "fmtstr" in name.lower())
    fmt_offset = exploit.get("format_offset")
    if fmt_primitives:
        capabilities.append(Capability(
            "Format String",
            "unknown",
            tuple(f"primitive:{name}" for name in fmt_primitives),
            ("确认读/写能力与目标约束后再升级利用路径",),
        ))
    elif fmt_offset is not None:
        capabilities.append(Capability(
            "Format String",
            "unknown",
            (f"format_offset={fmt_offset}",),
            ("已定位参数偏移，但尚未证明可读/可写 primitive",),
        ))

    return tuple(capabilities)


def available_paths(workspace: "PwnWorkspace") -> tuple[str, ...]:
    return tuple(item.name for item in analyze_capabilities(workspace) if item.state == "available")
