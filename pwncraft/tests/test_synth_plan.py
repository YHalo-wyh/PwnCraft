"""Exploit synthesis tests: parsers, primitive graph, planner, renderer, deposit.

纯文本解析与图/策略/渲染用构造的 facts；端到端（真实 ELF + objdump + 运行生成的
EXP）在 gcc/objdump 可用时执行，否则 skip。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, skipUnless

from pwncraft.features.synth.deposit import deposit_case, synth_case_id
from pwncraft.features.synth.facts import (PltStub, TargetFacts, _find_strings, _parse_dump_line,
                                           _parse_relocations, _parse_section_dump)
from pwncraft.features.synth.graph import build_primitive_graph
from pwncraft.features.synth.pipeline import analyze_target, detection_report, generate_exp
from pwncraft.features.synth.render import render_exp
from pwncraft.features.synth.roundtrip import VERDICT_CLEAN, verify_exp
from pwncraft.features.synth.strategy import plan_strategies

# objdump 行含 ASCII 列伪装成十六进制的真实踩坑样本（最后一段以 "652 i18n" 开头）
DUMP_SAMPLE = (
    "Contents of section .rodata:\n"
    " 402000 01000200 00000000 2f62696e 2f736800  ......../bin/sh.\n"
    " 402010 36353220 6931386e 20464443 432d7365  652 i18n FDCC-se\n")

RELOC_SAMPLE = (
    "DYNAMIC RELOCATION RECORDS\n"
    "OFFSET           TYPE              VALUE \n"
    "0000000000404008 R_X86_64_JUMP_SLOT  system@GLIBC_2.2.5\n"
    "0000000000404010 R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5\n"
    "0000000000403ff0 R_X86_64_RELATIVE  *ABS*+0x1130\n")

DISASM_SAMPLE = (
    "Disassembly of section .plt:\n\n"
    "00000000004010c0 <system@plt>:\n"
    "  4010c0:\tff 25 42 2f 00 00    \tjmp    *0x2f42(%rip)        # 404008 <system@GLIBC_2.2.5>\n"
    "Disassembly of section .text:\n\n"
    "0000000000401000 <helper>:\n"
    "  401000:\tf3 0f 1e fa          \tendbr64\n"
    "  401004:\t48 8d 3d f8 0f 00 00 \tlea    0x0ff8(%rip),%rdi        # 402004 <shell>\n"
    "  40100b:\te8 b0 00 00 00       \tcall   4010c0 <system@plt>\n"
    "  401010:\tc3                   \tret\n"
    "0000000000401200 <main>:\n"
    "  401200:\t55                   \tpush   %rbp\n"
    "  401201:\t0f 05                \tsyscall\n"
    "  401203:\tc3                   \tret\n")


class ParserTests(TestCase):
    def test_relocations_skip_unnamed_relatives(self):
        slots = {slot.name: slot for slot in _parse_relocations(RELOC_SAMPLE)}
        self.assertEqual(set(slots), {"system", "puts"})
        self.assertEqual(slots["system"].address, 0x404008)

    def test_section_dump_does_not_eat_ascii_column(self):
        # ASCII 列以 "652 i18n" 开头时，旧正则会把 "652" 当成十六进制组
        segments = _parse_section_dump(DUMP_SAMPLE)
        self.assertEqual(len(segments), 1)
        address, blob = segments[0]
        self.assertEqual(address, 0x402000)
        self.assertEqual(len(blob), 0x20)
        self.assertEqual(blob[:8], b"\x01\x00\x02\x00\x00\x00\x00\x00")
        self.assertEqual(_parse_dump_line("  4010c0:\tff 25\tjmp *0x0(%rip)"), None)

    def test_find_strings_maps_vaddr(self):
        found = _find_strings(_parse_section_dump(DUMP_SAMPLE), (b"/bin/sh", b"/nope"))
        self.assertEqual(found, {"/bin/sh": 0x402008})

    def test_annotation_scan_requires_argument_evidence(self):
        from pwncraft.core.code_analysis import parse_disassembly
        from pwncraft.features.synth.facts import _collect_annotations

        functions = parse_disassembly(DISASM_SAMPLE)["functions"]
        win, leak, syscalls, rets = _collect_annotations(functions)
        self.assertEqual(win[0]["function"], "helper")
        self.assertEqual(win[0]["callee"], "system")
        self.assertEqual(win[0]["argument_address"], 0x402004)   # objdump 注释地址
        self.assertEqual(win[0]["function_address"], 0x401000)
        self.assertEqual(leak, [])
        self.assertIn(0x401201, syscalls)
        self.assertIn(0x401010, rets)


def facts_for_tests() -> TargetFacts:
    """非 PIE amd64：system@plt + /bin/sh + win 调用点 + syscall + 对齐 ret。"""
    return TargetFacts(
        path="/tmp/fake", sha256="a" * 64, architecture="x86-64", bits=64,
        endian="little", entry=0x401000,
        security={"PIE": "OFF", "NX": "ON", "CANARY": "OFF", "RELRO": "PARTIAL", "FORTIFY": "OFF"},
        plt={"system": PltStub("system", 0x4010c0, 16)},
        got={},
        strings={"/bin/sh": 0x402004},
        syscalls=(0x401201,), ret_gadgets=(0x401010,),
        win_functions=({"function": "helper", "function_address": 0x401000,
                        "call_address": 0x40100b, "callee": "system",
                        "argument_address": 0x402004, "string": "/bin/sh"},),
    )


class GraphTests(TestCase):
    def test_graph_marks_unknowns_and_proven_facts(self):
        facts = facts_for_tests()
        graph = build_primitive_graph(facts)
        self.assertTrue(graph.proven("gadget:ret"))
        self.assertTrue(graph.proven("primitive:shell_string"))
        self.assertTrue(graph.proven("primitive:win_function:0"))
        hijack = graph.node("primitive:control_flow_hijack")
        self.assertEqual(hijack.confidence, "unknown")
        self.assertTrue(graph.has("unknown:prerequisites"))
        # 观察到偏移后升级为 proven
        observed = build_primitive_graph(facts, stack_truth={"offset": "0x48"})
        self.assertTrue(observed.proven("primitive:control_flow_hijack"))

    def test_patch_findings_feed_conditional_hypotheses(self):
        facts = facts_for_tests()
        findings = [
            {"id": "length:read:main:401200", "category": "input_length", "title": "read 长度 0x400",
             "evidence": ["0x401200: mov $0x400,%edx"]},
            {"id": "format:printf", "category": "format_review", "title": "printf 待复核"},
        ]
        graph = build_primitive_graph(facts, patch_findings=findings)
        overflow = graph.node("hypothesis:overflow")
        self.assertEqual(overflow.confidence, "conditional")
        self.assertEqual(overflow.provenance, "DERIVED")
        self.assertTrue(graph.has("hypothesis:format_string"))


class StrategyTests(TestCase):
    def test_ret2win_requires_observed_offset_and_alignment(self):
        facts = facts_for_tests()
        blocked = plan_strategies(facts, build_primitive_graph(facts))
        ret2win = next(item for item in blocked if item.id == "ret2win")
        self.assertEqual(ret2win.status, "blocked")
        self.assertTrue(any("控制流劫持" in item for item in ret2win.missing))
        ready = plan_strategies(facts, build_primitive_graph(facts, stack_truth={"offset": "0x48"}))
        ret2win = next(item for item in ready if item.id == "ret2win")
        self.assertEqual(ret2win.status, "ready")
        self.assertTrue(any("栈对齐" in step for step in ret2win.steps))

    def test_missing_ret_gadget_blocks_alignment(self):
        facts = facts_for_tests()
        facts.ret_gadgets = ()
        strategies = plan_strategies(facts, build_primitive_graph(facts, stack_truth={"offset": "0x48"}))
        ret2win = next(item for item in strategies if item.id == "ret2win")
        self.assertEqual(ret2win.status, "blocked")
        self.assertTrue(any("对齐" in item for item in ret2win.missing))

    def test_pie_targets_are_blocked_without_leak(self):
        facts = facts_for_tests()
        facts.security["PIE"] = "ON"
        strategies = plan_strategies(facts, build_primitive_graph(facts, stack_truth={"offset": "0x48"}))
        ret2win = next(item for item in strategies if item.id == "ret2win")
        self.assertEqual(ret2win.status, "blocked")
        self.assertIn("PIE 已开启但无基址泄漏事实", ret2win.missing)


class RenderTests(TestCase):
    def test_ready_skeleton_uses_real_addresses_and_passes_roundtrip(self):
        facts = facts_for_tests()
        strategies = plan_strategies(facts, build_primitive_graph(facts, stack_truth={"offset": "0x48"}))
        rendered = render_exp(facts, next(item for item in strategies if item.id == "ret2win"),
                              stack_truth={"offset": "0x48"})
        self.assertEqual(rendered.unresolved, [])
        self.assertIn("WIN = 0x401000", rendered.source)
        self.assertIn("p64(RET)", rendered.source)
        self.assertIn("provenance  : DERIVED", rendered.source)
        compile(rendered.source, "<synth>", "exec")          # 生成物必须是合法 Python
        verdict = verify_exp(rendered.source, bits=64, pie=False)
        self.assertEqual(verdict["verdict"], VERDICT_CLEAN)
        self.assertEqual(verdict["error_count"], 0)

    def test_unresolved_values_are_explicit(self):
        facts = facts_for_tests()
        facts.ret_gadgets = ()
        strategies = plan_strategies(facts, build_primitive_graph(facts))
        rendered = render_exp(facts, next(item for item in strategies if item.id == "ret2win"))
        self.assertTrue(any(item.startswith("OFFSET") for item in rendered.unresolved))
        self.assertTrue(any(item.startswith("RET") for item in rendered.unresolved))
        self.assertIn("UNRESOLVED", rendered.source)
        compile(rendered.source, "<synth>", "exec")

    def test_pie_uses_base_plus_offset(self):
        facts = facts_for_tests()
        facts.security["PIE"] = "ON"
        strategies = plan_strategies(facts, build_primitive_graph(facts, stack_truth={"offset": "0x48"}))
        rendered = render_exp(facts, next(item for item in strategies if item.id == "ret2win"),
                              stack_truth={"offset": "0x48"})
        self.assertIn("BASE + 0x401000", rendered.constants["WIN"])


class DepositTests(TestCase):
    def _generated(self, dest: Path) -> dict:
        facts = facts_for_tests()
        strategies = plan_strategies(facts, build_primitive_graph(facts, stack_truth={"offset": "0x48"}))
        chosen = next(item for item in strategies if item.id == "ret2win")
        rendered = render_exp(facts, chosen)
        verdict = verify_exp(rendered.source)
        graph = build_primitive_graph(facts, stack_truth={"offset": "0x48"})
        return deposit_case(dest, facts=facts, graph=graph, strategies=strategies,
                            rendered=rendered, verdict=verdict)

    def test_deposit_writes_review_case_and_is_not_trainable(self):
        with TemporaryDirectory() as folder:
            outcome = self._generated(Path(folder))
            case_dir = Path(outcome["dir"])
            for name in ("manifest.json", "facts.json", "graph.json", "strategies.json",
                         "exp.py", "audit.json", "plan.md"):
                self.assertTrue((case_dir / name).is_file(), name)
            manifest = json.loads((case_dir / "manifest.json").read_text(encoding="utf-8"))
            self.assertFalse(manifest["training"]["trainable"])
            self.assertEqual(manifest["provenance"], "DERIVED")
            self.assertEqual(manifest["strategy"]["id"], "ret2win")
            self.assertEqual(manifest["audit"]["verdict"], VERDICT_CLEAN)

    def test_plan_only_deposit_has_no_exp(self):
        facts = facts_for_tests()
        graph = build_primitive_graph(facts)
        strategies = plan_strategies(facts, graph)
        with TemporaryDirectory() as folder:
            outcome = deposit_case(Path(folder), facts=facts, graph=graph,
                                   strategies=strategies, rendered=None,
                                   verdict={"verdict": "NO_STRATEGY", "error_count": 0,
                                            "diagnostic_count": 0})
            manifest = json.loads((Path(outcome["dir"]) / "manifest.json").read_text(encoding="utf-8"))
            self.assertIsNone(manifest["exp"])
            self.assertIn("NO_STRATEGY", (Path(outcome["dir"]) / "exp.py").read_text(encoding="utf-8"))

    def test_case_id_is_deterministic(self):
        self.assertEqual(synth_case_id("a" * 64, "ret2win", "x"), synth_case_id("a" * 64, "ret2win", "x"))
        self.assertNotEqual(synth_case_id("a" * 64, "ret2win", "x"), synth_case_id("b" * 64, "ret2win", "x"))


def _compile_c(source_text: str, folder: Path, name: str) -> Path:
    """编译测试用 ELF；Windows 宿主 gcc 会带 .exe 后缀，按实际产物返回。"""
    source = folder / f"{name}.c"
    source.write_text(source_text, encoding="utf-8")
    binary = folder / name
    subprocess.run(["gcc", "-no-pie", "-fno-stack-protector", "-O0",
                    "-o", str(binary), str(source)], capture_output=True, check=True)
    for candidate in (binary, binary.with_name(binary.name + ".exe")):
        if candidate.is_file():
            return candidate
    raise AssertionError(f"gcc 未产出可执行文件: {binary}")


@skipUnless(os.name == "posix" and shutil.which("gcc") and shutil.which("objdump"),
            "需要 POSIX gcc/objdump（Windows 宿主请在 WSL 内运行本测试）")
class RealElfSynthTests(TestCase):
    C_SOURCE = (
        "#include <stdlib.h>\n#include <unistd.h>\n"
        "__attribute__((noinline)) void helper(void) { system(\"/bin/sh\"); }\n"
        "int main(void) { char buf[64]; read(0, buf, 0x400); return 0; }\n")

    def _compile(self, folder: Path) -> Path:
        return _compile_c(self.C_SOURCE, folder, "target-c")

    def test_detection_report_lists_strategies(self):
        with TemporaryDirectory() as folder_str:
            folder = Path(folder_str)
            binary = self._compile(folder)
            report = detection_report(analyze_target(binary))
            self.assertEqual(report["target"]["bits"], 64)
            self.assertEqual(report["summary"]["win_functions"], 1)
            self.assertTrue(any(item["id"] == "ret2win" for item in report["strategies"]))
            self.assertIn("graph", report)
            self.assertIn("/bin/sh", report["summary"]["strings"])

    def test_detect_plan_render_and_run_generated_exp(self):
        with TemporaryDirectory() as folder_str:
            folder = Path(folder_str)
            binary = self._compile(folder)
            blocked = generate_exp(binary, strategy="ret2win")
            self.assertEqual(blocked["strategy"].status, "blocked")
            self.assertTrue(any("控制流劫持" in item for item in blocked["strategy"].missing))
            self.assertEqual(blocked["verdict"]["verdict"], VERDICT_CLEAN)

            generated = generate_exp(binary, strategy="ret2win", stack_truth={"offset": "0x48"})
            self.assertEqual(generated["strategy"].status, "ready")
            self.assertEqual(generated["rendered"].unresolved, [])
            self.assertEqual(generated["verdict"]["verdict"], VERDICT_CLEAN)
            self.assertIn("helper", generated["facts"].win_functions[0]["function"])

            try:
                import pwn  # noqa: F401
            except Exception:
                self.skipTest("pwntools 不可用，跳过生成 EXP 的运行时验证")
            script = folder / "generated_exp.py"
            script.write_text(generated["rendered"].source, encoding="utf-8")
            proc = subprocess.run([sys.executable, str(script)],
                                  input=b"echo SYNTH_OK; exit\n",
                                  capture_output=True, timeout=90)
            self.assertIn(b"SYNTH_OK", proc.stdout + proc.stderr,
                          f"生成的 EXP 未打通目标（stdout={proc.stdout[-200:]!r} stderr={proc.stderr[-200:]!r}）")

    def test_unknown_binary_still_produces_negative_sample(self):
        with TemporaryDirectory() as folder_str:
            folder = Path(folder_str)
            binary = _compile_c("int main(void) { return 0; }\n", folder, "plain")
            generated = generate_exp(binary, allow_missing=True)
            if generated["best"] is None:
                self.assertEqual(generated["verdict"]["verdict"], "NO_STRATEGY")
                self.assertIsNone(generated["rendered"])
            else:
                # 有候选也只允许是 blocked/unknown：无运行时证据不得 ready
                self.assertIn(generated["best"].status, ("blocked", "unknown"))
