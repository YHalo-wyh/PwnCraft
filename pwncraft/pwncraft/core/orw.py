"""ORW Builder (Phase 3, BUILD subset 规划 §十七).

The builder composes ``open/openat -> read -> write`` only from facts the
workspace already holds: the architecture syscall table, gadget shelf /
discovered gadgets and the parsed seccomp policy.  It refuses to emit a
payload when any step is unprovable, and the dynamic fd returned by open
is an explicit ``inferred`` placeholder that the user must confirm.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence

from .gadgets import Gadget
from .syscalls import normalize_architecture
from .workbench import SyscallPlanner

_OPEN_FLAGS = {"open": ("path", "flags", "mode"), "openat": ("dirfd", "path", "flags", "mode")}


@dataclass(frozen=True)
class ORWStep:
    """One syscall step plus its deterministic diagnosis."""

    name: str
    syscall: str
    arguments: dict[str, object]
    registers: dict[str, object]
    missing_registers: tuple[str, ...]
    seccomp_verdict: str
    blockers: tuple[str, ...]
    inferred_fields: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.blockers

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "syscall": self.syscall,
            "arguments": dict(self.arguments),
            "registers": dict(self.registers),
            "missing_registers": list(self.missing_registers),
            "seccomp_verdict": self.seccomp_verdict,
            "blockers": list(self.blockers),
            "inferred_fields": list(self.inferred_fields),
            "ok": self.ok,
        }


@dataclass
class ORWReport:
    architecture: str
    steps: list[ORWStep] = field(default_factory=list)
    warnings: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return bool(self.steps) and all(step.ok for step in self.steps)

    def to_dict(self) -> dict[str, object]:
        return {
            "architecture": self.architecture,
            "steps": [step.to_dict() for step in self.steps],
            "ok": self.ok,
            "warnings": list(self.warnings),
        }


def _step_from_plan(name: str, plan, inferred: Sequence[str] = ()) -> ORWStep:
    return ORWStep(
        name,
        plan.spec.name,
        dict(plan.arguments),
        dict(plan.registers),
        plan.missing_registers,
        plan.seccomp_verdict,
        plan.blockers,
        tuple(inferred),
    )


class ORWBuilder:
    """Plan an ORW chain from provable facts; never emit broken payloads."""

    def __init__(self, *, bits: int = 64, seccomp_policy: Mapping[str, str] | None = None, gadgets: Sequence[Gadget] = ()):
        self.bits = int(bits)
        self.architecture = "amd64" if self.bits == 64 else "i386"
        self.seccomp_policy = dict(seccomp_policy or {})
        self.gadgets = tuple(gadgets)
        self.planner = SyscallPlanner()

    # ------------------------------------------------------------------
    def _diagnose(self, syscall: str, arguments: Mapping[str, object], inferred: Sequence[str] = ()):
        try:
            plan = self.planner.diagnose(
                syscall,
                arguments,
                architecture=self.architecture,
                gadgets=self.gadgets,
                seccomp_policy=self.seccomp_policy,
            )
        except LookupError as exc:
            return ORWStep(syscall, syscall, dict(arguments), {}, (), "UNKNOWN", (str(exc),), tuple(inferred))
        return _step_from_plan(syscall, plan, inferred)

    def plan(
        self,
        *,
        path: str = "/flag",
        buffer: object = 0x0,
        read_size: object = 0x100,
        output_fd: object = 1,
        open_variant: str = "auto",
        flags: object = 0,
        mode: object = 0,
        input_fd: object = 0,
    ) -> ORWReport:
        """Build the three-step plan; every failure stays a diagnostic."""
        warnings: list[str] = []
        try:
            normalize_architecture(self.architecture, strict=True)
        except ValueError as exc:
            return ORWReport(self.architecture, [], (str(exc),))

        variant = open_variant
        if variant == "auto":
            # auto prefers the variant with the fewest argument registers that
            # the architecture actually provides: plain `open` (3 regs) beats
            # `openat` (4 regs incl. r10) when both exist.  Missing syscalls
            # fall through to the other instead of being fabricated.
            candidates = ("open", "openat") if self.architecture == "amd64" else ("openat", "open")
            variant = next((name for name in candidates if lookup_open(self.architecture, name) is not None), "openat")
        if lookup_open(self.architecture, variant) is None:
            return ORWReport(self.architecture, [], (f"{self.architecture} 不支持 {variant}；不伪造替代调用。",))

        open_args: dict[str, object] = {"path": str(path), "flags": flags, "mode": mode}
        if variant == "openat":
            open_args = {"dirfd": -100, **open_args}
        # openat 的 dirfd 用 AT_FDCWD 常量是事实而非猜测；fd 返回值未知。
        open_step = self._diagnose(variant, open_args, inferred=("return_fd",))

        read_args = {"fd": "OPEN_FD", "buf": buffer, "len": read_size}
        read_step = self._diagnose("read", read_args, inferred=("fd=OPEN_FD",))
        write_args = {"fd": output_fd, "buf": buffer, "len": read_size}
        write_step = self._diagnose("write", write_args)

        if open_step.blockers:
            warnings.append("open 步骤不可执行；后续 read/write 仍按同一事实来源诊断。")
        if "fd=OPEN_FD" in read_step.inferred_fields and read_step.ok:
            warnings.append("read 的 fd 依赖 open 返回值；当前为 inferred 占位，需用户确认运行时 fd。")
        return ORWReport(self.architecture, [open_step, read_step, write_step], tuple(warnings))


def lookup_open(architecture: str, name: str):
    from .syscalls import lookup_syscall

    return lookup_syscall(name, architecture)
