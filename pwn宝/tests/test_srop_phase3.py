"""Phase 3 收口: SROP builder plan semantics (规划 §八/§十三)."""
from __future__ import annotations

import unittest

from pwnbao.core.gadgets import parse_gadget_line
from pwnbao.core.srop import FRAME_PLACEHOLDER, SROPBuilder
from pwnbao.core.tool_actions import ActionType, default_tool_actions


def _amd64_gadgets() -> list:
    lines = (
        "0x4012c3 : pop rdi ; ret",
        "0x4012bb : pop rax ; ret",
        "0x4012ad : pop rsp ; ret",
        "0x401180 : syscall ; ret",
    )
    return [parse_gadget_line(line) for line in lines]


def _allow_all() -> dict[str, str]:
    return {"execve": "ALLOWED", "rt_sigreturn": "ALLOWED"}


class SropPlanTests(unittest.TestCase):
    def test_full_facts_yield_executable_plan(self) -> None:
        builder = SROPBuilder(bits=64, seccomp_policy=_allow_all(), gadgets=_amd64_gadgets())
        plan = builder.plan("execve", {"filename": "/bin/sh", "argv": 0, "envp": 0})
        self.assertTrue(plan.ok, plan.blockers)
        self.assertTrue(plan.executable)
        self.assertEqual(plan.frame_registers["rax"], 59)
        self.assertEqual(plan.frame_registers["rip"], 0x401180)
        self.assertEqual(plan.frame_registers["rsp"], FRAME_PLACEHOLDER)
        self.assertIn("rax=15", plan.requirements)
        self.assertIn("rsp→frame", plan.requirements)

    def test_missing_syscall_gadget_blocks(self) -> None:
        gadgets = [g for g in _amd64_gadgets() if "syscall" not in g.text]
        builder = SROPBuilder(bits=64, seccomp_policy=_allow_all(), gadgets=gadgets)
        plan = builder.plan("execve", {"filename": "/bin/sh", "argv": 0, "envp": 0})
        self.assertFalse(plan.ok)
        self.assertTrue(any("syscall Gadget" in item for item in plan.blockers))

    def test_missing_rax_control_blocks(self) -> None:
        gadgets = [g for g in _amd64_gadgets() if "rax" not in g.controls]
        builder = SROPBuilder(bits=64, seccomp_policy=_allow_all(), gadgets=gadgets)
        plan = builder.plan("execve", {"filename": "/bin/sh", "argv": 0, "envp": 0})
        self.assertFalse(plan.ok)
        self.assertTrue(any("rax 控制" in item for item in plan.blockers))
        self.assertIn("未证明", plan.requirements["rax=15"])

    def test_missing_rsp_control_blocks(self) -> None:
        gadgets = [g for g in _amd64_gadgets() if "rsp" not in (g.controls or ("x",))]
        builder = SROPBuilder(bits=64, seccomp_policy=_allow_all(), gadgets=gadgets)
        plan = builder.plan("execve", {"filename": "/bin/sh", "argv": 0, "envp": 0})
        self.assertFalse(plan.ok)
        self.assertTrue(any("rsp 控制" in item for item in plan.blockers))

    def test_leave_ret_counts_as_rsp_control(self) -> None:
        # keep pop-style gadgets that don't control rsp, plus the syscall one
        gadgets = [g for g in _amd64_gadgets() if "rsp" not in (g.controls or ("x",))]
        gadgets.append(parse_gadget_line("0x4012a9 : leave ; ret"))
        builder = SROPBuilder(bits=64, seccomp_policy=_allow_all(), gadgets=gadgets)
        plan = builder.plan("execve", {"filename": "/bin/sh", "argv": 0, "envp": 0})
        self.assertTrue(plan.ok, plan.blockers)
        self.assertIn("leave", plan.requirements["rsp→frame"])

    def test_blocked_target_and_sigreturn_are_blockers(self) -> None:
        blocked = {"execve": "BLOCKED", "rt_sigreturn": "BLOCKED"}
        builder = SROPBuilder(bits=64, seccomp_policy=blocked, gadgets=_amd64_gadgets())
        plan = builder.plan("execve", {"filename": "/bin/sh", "argv": 0, "envp": 0})
        self.assertFalse(plan.executable)
        self.assertTrue(any("execve" in item for item in plan.blockers))
        self.assertTrue(any("rt_sigreturn" in item for item in plan.blockers))

    def test_unknown_verdict_warns_but_never_executable(self) -> None:
        builder = SROPBuilder(bits=64, seccomp_policy={}, gadgets=_amd64_gadgets())
        plan = builder.plan("execve", {"filename": "/bin/sh", "argv": 0, "envp": 0})
        self.assertEqual(plan.seccomp_target, "UNKNOWN")
        self.assertFalse(plan.executable)
        self.assertTrue(any("未知" in item for item in plan.warnings))

    def test_i386_is_honestly_unsupported(self) -> None:
        builder = SROPBuilder(bits=32, seccomp_policy=_allow_all(), gadgets=_amd64_gadgets())
        plan = builder.plan("execve", {"filename": "/bin/sh", "argv": 0, "envp": 0})
        self.assertFalse(plan.ok)
        self.assertIn("仅支持 amd64", plan.blockers[0])

    def test_to_dict_is_json_safe(self) -> None:
        builder = SROPBuilder(bits=64, seccomp_policy=_allow_all(), gadgets=_amd64_gadgets())
        payload = builder.plan("execve", {"filename": "/bin/sh", "argv": 0, "envp": 0}).to_dict()
        self.assertTrue(payload["executable"])
        self.assertEqual(payload["frame_registers"]["rax"], 59)
        self.assertIn("syscall_gadget", payload)

    def test_pwntools_skeleton_delegates_frame_layout(self) -> None:
        builder = SROPBuilder(bits=64, seccomp_policy=_allow_all(), gadgets=_amd64_gadgets())
        plan = builder.plan("execve", {"filename": "/bin/sh", "argv": 0, "envp": 0})
        code = builder.to_pwntools(plan)
        self.assertIn("SigreturnFrame()", code)
        self.assertIn("frame.rax = 0x3b", code)
        self.assertIn("0x401180", code)
        self.assertIn("FRAME_ADDR", code)
        with self.assertRaises(ValueError):
            builder.to_pwntools(builder.plan("execve", {"filename": "/bin/sh", "argv": 0, "envp": 0}).__class__(architecture="i386", target_name="execve", frame_registers={}, requirements={}, seccomp_target="UNKNOWN", seccomp_sigreturn="UNKNOWN", blockers=("x",)))

    def test_srop_build_action_registered_as_build(self) -> None:
        action = default_tool_actions().get("srop.build")
        self.assertEqual(action.action_type, ActionType.BUILD)
        self.assertTrue(action.allows("insert_to_exp"))


if __name__ == "__main__":
    unittest.main()
