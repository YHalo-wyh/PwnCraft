"""SemanticLens — architecture-aware register role tables (v0.20 Phase E).

Roles are ABI/syscall-convention constants, not guesses (§15): the lens
answers "this register carries which argument / what does it mean" and
never infers exploit intent.  Data sources: the workspace syscall table
(pwnbao/core/syscalls.py) and fixed calling-convention facts.
"""
from __future__ import annotations

from dataclasses import dataclass

from .syscalls import SyscallSpec, lookup_syscall, normalize_architecture

_CALL_ROLES: dict[str, tuple[tuple[str, str, str], ...]] = {
    "amd64": (
        ("RDI", "arg0", "第 1 个整型/指针参数"),
        ("RSI", "arg1", "第 2 个参数"),
        ("RDX", "arg2", "第 3 个参数"),
        ("RCX", "arg3", "第 4 个参数"),
        ("R8", "arg4", "第 5 个参数"),
        ("R9", "arg5", "第 6 个参数"),
        ("RAX", "retval", "返回值"),
    ),
    "i386": (
        ("EAX", "retval", "返回值；调用号也走 EAX"),
        ("栈", "args", "参数通过栈传递：[ebp+8]=arg0, [ebp+12]=arg1 …"),
    ),
    "aarch64": (
        ("X0", "arg0", "第 1 个参数"),
        ("X1", "arg1", "第 2 个参数"),
        ("X2", "arg2", "第 3 个参数"),
        ("X3", "arg3", "第 4 个参数"),
        ("X8", "retval/indirect", "返回值（大结构为间接寄存器）"),
    ),
}

_SYSCALL_ROLES: dict[str, tuple[tuple[str, str, str], ...]] = {
    "amd64": (
        ("RAX", "syscall", "系统调用号"),
        ("RDI", "arg0", "参数 1"),
        ("RSI", "arg1", "参数 2"),
        ("RDX", "arg2", "参数 3"),
        ("R10", "arg3", "参数 4（注意不是 RCX）"),
        ("R8", "arg4", "参数 5"),
        ("R9", "arg5", "参数 6"),
    ),
    "i386": (
        ("EAX", "syscall", "系统调用号"),
        ("EBX", "arg0", "参数 1"),
        ("ECX", "arg1", "参数 2"),
        ("EDX", "arg2", "参数 3"),
        ("ESI", "arg3", "参数 4"),
        ("EDI", "arg4", "参数 5"),
        ("EBP", "arg5", "参数 6"),
    ),
    "aarch64": (
        ("X8", "syscall", "系统调用号"),
        ("X0", "arg0", "参数 1"),
        ("X1", "arg1", "参数 2"),
        ("X2", "arg2", "参数 3"),
        ("X3", "arg3", "参数 4"),
        ("X4", "arg4", "参数 5"),
        ("X5", "arg5", "参数 6"),
    ),
}


@dataclass(frozen=True)
class LensRow:
    register: str
    role: str
    meaning_zh: str
    value_hint: str = ""


def call_lens(architecture: str = "amd64", function_name: str = "") -> tuple[LensRow, ...]:
    """Register roles for a normal C ABI call (§13)."""
    architecture = normalize_architecture(architecture)
    rows = [LensRow(reg, role, meaning) for reg, role, meaning in _CALL_ROLES.get(architecture, ())]
    if function_name:
        rows = [LensRow(row.register, row.role, row.meaning_zh, function_name) for row in rows]
    return tuple(rows)


def syscall_lens(syscall_name: str, architecture: str = "amd64") -> tuple[LensRow, ...]:
    """Register roles for one syscall, numbers from the real table (§14)."""
    architecture = normalize_architecture(architecture)
    spec: SyscallSpec | None = lookup_syscall(syscall_name, architecture)
    roles = _SYSCALL_ROLES.get(architecture, ())
    if spec is None:
        return tuple(LensRow(reg, role, meaning) for reg, role, meaning in roles)
    argument_count = len(spec.registers)
    rows = []
    for reg, role, meaning in roles:
        if role == "syscall":
            rows.append(LensRow(reg, role, meaning, f"SYS_{spec.name} = {spec.number}"))
        elif role.startswith("arg") and int(role[3:]) < argument_count:
            rows.append(LensRow(reg, role, f"{meaning}（{spec.registers[int(role[3:])]}）"))
        else:
            rows.append(LensRow(reg, role, meaning))
    return tuple(rows)


def render_lens(rows: tuple[LensRow, ...], title: str) -> str:
    """Plain-text rendering for the Inspector / debug side panel."""
    lines = [title]
    lines.extend(f"{row.register:<5} {row.value_hint or ''}  {row.role:<8} {row.meaning_zh}" for row in rows)
    return "\n".join(lines)
