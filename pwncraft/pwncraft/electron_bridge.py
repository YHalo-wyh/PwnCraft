"""Electron bridge — stdio JSON-RPC host for the Electron Workbench (v0.29).

The Electron renderer never re-implements Pwn truth.  This bridge owns one
``PwnWorkspace`` plus the headless feature sessions and exposes them over
line-delimited JSON on stdin/stdout, so Electron is only ever a surface:

    {"id": 1, "method": "import_target", "params": {"path": "C:/.../pwn"}}
    -> {"id": 1, "ok": true, "result": {...}}

Async side: {"event": "log", "message": "..."} lines.  Everything stays
offline; WSL tools run through the existing ``WslToolRunner``.

Surface map (v0.29):
- target/workspace: ping / import_target / workspace_get / workspace_save /
  workspace_open / recent_dirs / variable_set / exp_get / exp_set / exp_save
- cli tools: cli_run (ROPgadget / ropper / one_gadget / seccomp-tools …),
  cli_env_doctor, auto_triage（导入时后台 WSL 扫描，triage_stage 事件推送）
- rop: rop_build / srop_plan / orw_plan / syscall_table
- libc/fmt/stack: leak_derive / cyclic_pattern / cyclic_find / fmt_offset /
  fmt_plan / convert
- reference: clib_catalog（C 函数速查目录）
- heap: heap_templates / heap_load / heap_correct / heap_undo_correction /
  heap_learn / heap_rule_toggle / heap_save / heap_open
- iofile: iofile_layout / iofile_validate / iofile_analyze
- debugger: pwndbg_status / pwndbg_ensure / debug_launch
- awdp patch (v0.33): patch_recipes / patch_audit / patch_preview / patch_apply / patch_list /
  patch_undo / patch_clear / patch_reconcile / patch_export / patch_probe / patch_instructions / patch_disasm_raw /
  patch_bytecode_lookup / patch_encode
- exploit synthesis（VNext.4）: synth_analyze（检测+原语图+策略）/ synth_generate（EXP 骨架 + 往返审计）/
  synth_verify（gdb 测偏移 + 真跑生成的 EXP）/ synth_deposit（沉淀 review_queue）
"""
from __future__ import annotations

import json
import shlex
import sys
import threading
import time
import traceback
import uuid
from datetime import datetime
from pathlib import Path

from pwncraft import APP_NAME, APP_VERSION
from pwncraft.core.elf_runtime import auto_patch_elf, is_elf_file
from pwncraft.core.workspace import PwnWorkspace, AddressKind, TypedAddress, WorkspaceVariable
from pwncraft.core.workbench import BinaryInspector
from pwncraft.core.session import TargetContext, import_target
from pwncraft.core.wsl import WslToolRunner
from pwncraft.core.cli_runner import CliToolService, WslCliExecutor
from pwncraft.core.gadgets import Gadget, GadgetShelf, parse_ropgadget_output, search_gadgets
from pwncraft.core.rop_builder import RopChainBuilder, chain_to_pwntools
from pwncraft.core.srop import SROPBuilder
from pwncraft.core.orw import ORWBuilder
from pwncraft.core.syscalls import (parse_seccomp_policy_structured, parse_seccomp_tools_dump,
                                    syscall_table, normalize_architecture)
from pwncraft.core.leaks import derive_base
from pwncraft.core.cyclic import cyclic_pattern, cyclic_find
from pwncraft.core.fmtlab import find_fmt_offset, plan_fmt_writes
from pwncraft.core.workbench import SyscallPlanner
from pwncraft.features.conversion.converters import int_report, bytes_report
from pwncraft.features.iofile.layouts import GlibcFileLayoutDatabase
from pwncraft.features.iofile.snapshot import FileSnapshot
from pwncraft.features.iofile.constraints import FileConstraintEngine
from pwncraft.features.iofile.analyzer import analyze_file_source
from pwncraft.features.heapviz.allocators.profiles import ALLOCATOR_PROFILE_REVISION, profile_list
from pwncraft.features.heapviz.bridge_session import HeapSession
from pwncraft.features.heapviz.dataset import validate_case
from pwncraft.features.heapviz.templates import HEAP_TEMPLATES
from pwncraft.features.patch.patch_core import PatchLab, PatchOp, parse_instruction_lines
from pwncraft.features.patch.recipes import (
    RECIPE_CATALOG, build_code_cave_hook, build_custom_bytes, build_instruction_patch,
    build_jcc_mode, build_nop_function,
    build_nop_range, build_plt_call_redirect, build_plt_stub_redirect,
    build_read_length, build_ret_function, build_return_constant, build_skip_call_result,
    normalize_patch_arch)
from pwncraft.features.patch.seccomp_inject import SECCOMP_PRESETS, build_seccomp_ops
from pwncraft.features.patch.bytecode_catalog import assemble, catalog_entries, disasm_raw, encode_template
from pwncraft.features.patch.ida_link import IdaCliLink, IdaLinkError
from pwncraft.features.patch.audit import audit_patch_surface
from pwncraft.features.patch.exporters import (
    export_competition_bundle, export_diff_text, export_pwntools_script, materialize_patched)
from pwncraft.core.pwndbg_manager import PWNDBG_MOGAI_VERSION, PwndbgManager


def _gadget_to_dict(gadget: Gadget) -> dict:
    payload = gadget.to_dict()
    payload["text"] = gadget.text
    payload["stars"] = gadget.stars
    return payload


class ElectronBridge:
    def __init__(self) -> None:
        self.workspace = PwnWorkspace(project={"project_name": APP_NAME})
        self._runner = WslToolRunner()
        self._cli = CliToolService(WslCliExecutor(self._runner))
        self._pwndbg = PwndbgManager()
        self._heap = HeapSession()
        self._gadgets: tuple[Gadget, ...] = ()
        self._shelf = GadgetShelf()
        self._import_cache: dict[str, dict] = {}
        self._triage_lock = threading.Lock()
        self._triage_running: set[str] = set()
        self._triage_cache: dict[str, dict] = {}
        self._patch_labs: dict[str, PatchLab] = {}
        self._patch_previews: dict[str, dict] = {}
        self._patch_targets: dict[str, dict] = {}
        self._disasm_cache: dict[str, list[dict]] = {}
        self._ida_link: IdaCliLink | None = None

    # ------------------------------------------------------------------
    def handle(self, request: dict) -> dict:
        method = str(request.get("method") or "")
        params = request.get("params") if isinstance(request.get("params"), dict) else {}
        handler = getattr(self, "rpc_" + method, None)
        if handler is None:
            raise KeyError(f"未知方法: {method}")
        return handler(params)

    def _log(self, message: str) -> None:
        emit({"event": "log", "message": str(message)})

    def _target_binary(self) -> Path:
        target = self.workspace.target or {}
        path = target.get("working_binary") or target.get("original_binary")
        if not path:
            raise ValueError("尚未绑定 Target；先导入 ELF。")
        return Path(str(path))

    # ------------------------------------------------------------------
    # Target / workspace

    def rpc_ping(self, params: dict) -> dict:
        return {"app": APP_NAME, "version": APP_VERSION, "project": self.workspace.project}

    @staticmethod
    def _import_cache_key(binary: Path) -> str:
        stat = binary.stat()
        return f"{binary}|{stat.st_mtime_ns}|{stat.st_size}"

    @staticmethod
    def _apply_facts_to_context(context: TargetContext, facts: dict) -> None:
        context.architecture = str(facts.get("architecture", context.architecture))
        context.bits = int(facts.get("bits", context.bits) or context.bits)
        context.endian = str(facts.get("endian", context.endian))
        context.entry = int(facts.get("entry", context.entry) or 0)
        security = facts.get("security") or {}
        context.pie = str(security.get("PIE", context.pie))
        context.nx = str(security.get("NX", context.nx))
        context.canary = str(security.get("CANARY", context.canary))
        context.relro = str(security.get("RELRO", context.relro))

    def rpc_import_target(self, params: dict) -> dict:
        path = str(params.get("path") or "").strip()
        if not path or not is_elf_file(path):
            raise ValueError(f"不是有效的 ELF 文件: {path or '(空)'}")
        binary = Path(path).resolve()
        self._log(f"正在绑定 Target: {binary}")

        context = import_target(binary, project_root=binary.parent)
        target_binary = Path(context.working_binary or context.original_binary)

        cached = self._import_cache.get(self._import_cache_key(binary)) if params.get("light") else None
        if cached:
            # 工作区切换（light）：ELF 未变化，复用首次导入的静态结论，
            # 跳过 WSL patch / checksec / readelf 重跑；真值仍完整重绑。
            patch_summary = str(cached.get("patch_summary") or "")
            patch_error = str(cached.get("patch_error") or "")
            static_report = str(cached.get("static_report") or "")
            facts = dict(cached.get("facts") or {})
            context.interpreter = str(cached.get("interpreter") or context.interpreter or "")
            if cached.get("libc"):
                context.libc = str(cached["libc"])
            if facts:
                try:
                    self._apply_facts_to_context(context, facts)
                except Exception:
                    facts = {}
            if not facts:
                cached = None  # 缓存不完整 → 回退完整导入
                self._log("导入缓存不完整，回退完整导入")
        if not cached:
            patch_summary = ""
            patch_error = ""
            try:
                # 运行时对（ld/libc）按 CTF 惯例放在原始附件目录：
                # 工作副本已复制进 .pwncraft/runtime，需回退原始目录发现
                outcome = auto_patch_elf(target_binary, extra_dirs=(binary.parent,))
                patch_summary = outcome.summary()
                if getattr(outcome, "runtime", None):
                    context.interpreter = str(getattr(outcome.runtime, "interpreter", "") or "")
                    if getattr(outcome.runtime, "libc", None):
                        context.libc = str(outcome.runtime.libc)
            except Exception as error:
                patch_error = str(error)
                self._log(f"自动 Patch 未完成：{patch_error}")

            static_sections: list[str] = []
            for title, callback in (
                ("file", lambda: self._runner.file(target_binary)),
                ("readelf -h", lambda: self._runner.readelf_header(target_binary)),
            ):
                # 保护事实不再依赖 WSL checksec 工具：parse_elf_security 本地解析
                # （见 BinaryInspector）。需要工具级输出时 Binary 页有 checksec 按钮。
                try:
                    result = callback()
                    static_sections.append(f"$ {title}\n{result.combined_output() or '(no output)'}")
                except Exception as error:
                    static_sections.append(f"$ {title}\nERROR: {error}")
            static_report = "\n\n".join(static_sections)

            facts: dict = {}
            try:
                facts = BinaryInspector().inspect(target_binary).to_dict()
                self._apply_facts_to_context(context, facts)
            except Exception as error:
                static_report += f"\n\n$ ELFProvider\nERROR: {error}"
            self._import_cache[self._import_cache_key(binary)] = {
                "facts": facts,
                "static_report": static_report,
                "patch_summary": patch_summary,
                "patch_error": patch_error,
                "interpreter": context.interpreter,
                "libc": context.libc,
            }

        # Same truth updates as the desktop shell (§ Single Truth).
        self.workspace.project["project_name"] = binary.stem
        self.workspace.project["project_path"] = str(binary.parent)
        self.workspace.set_target(TargetContext.from_dict(context.to_dict()))
        self._patch_targets[str(target_binary.resolve())] = context.to_dict()
        self.workspace.update_section(
            "binary",
            {
                "path": str(target_binary),
                "static_report": static_report,
                "patch_error": patch_error,
                "source": "ELFProvider",
                "state": "confirmed",
                **facts,
            },
            event="binary_loaded",
        )
        entry = facts.get("entry")
        if isinstance(entry, int):
            self.workspace.set_variable(
                WorkspaceVariable(
                    "entry", TypedAddress(entry, AddressKind.STATIC_ADDRESS, binary.name), "ELFProvider",
                    f"e_entry={entry:#x}", address_kind=AddressKind.STATIC_ADDRESS,
                )
            )
        self._log(f"Target 绑定完成：{binary.name}（{context.architecture} / {context.bits} 位）")
        return {
            "context": context.to_dict(),
            "facts": facts,
            "static_report": static_report,
            "patch_summary": patch_summary,
            "patch_error": patch_error,
            "project": self.workspace.project,
        }

    def rpc_binary_reports(self, params: dict) -> dict:
        """checksec / file / ldd 原文（WSL 真实执行，Binary 页三卡片数据源）。

        刻意不在 import_target 里跑：保护事实的导入路径保持离线本地解析，
        工具级输出由 Binary 页按需拉取，慢/缺失只影响这一排卡片。
        """
        binary = Path(str(params.get("path") or "") or self._target_binary())
        reports: dict[str, str] = {}
        diagnostics: dict[str, dict] = {}
        for key, callback in (
            ("checksec", lambda: self._runner.checksec(binary)),
            ("file", lambda: self._runner.file(binary)),
            ("ldd", lambda: self._runner.run_tool("ldd", [self._runner.to_wsl_path(binary)])),
        ):
            try:
                result = callback()
                # Some tools (notably checksec) legitimately report on stderr.
                # ldd dependencies and Windows/WSL startup notices stay separate.
                reports[key] = (result.stdout.strip() if key == "ldd" and result.ok
                                else result.combined_output())
                diagnostics[key] = {"returncode": result.returncode,
                                    "notice": result.stderr.strip() if key == "ldd" and result.ok else ""}
            except Exception as error:
                reports[key] = f"ERROR: {error}"
        return {"reports": reports, "diagnostics": diagnostics, "binary": str(binary)}

    def rpc_code_analysis(self, params: dict) -> dict:
        """Static disassembly and existing audit diagnostics for the selected workspace."""
        from pwncraft.core.code_analysis import parse_disassembly
        from pwncraft.features.audit.audit import audit_exp

        binary = Path(str(params.get("path") or "") or self._target_binary())
        facts = BinaryInspector().inspect(binary)
        response = {"binary": str(binary), "functions": [], "function_count": 0,
                    "truncated": False, "assembly_error": "", "notice": "",
                    "stripped": facts.security.get("STRIPPED") != "OFF"}
        # The source belongs to the requesting workspace, not bridge-global state.
        response["diagnostics"] = audit_exp(str(params.get("source") or ""),
                                            bits=facts.bits,
                                            pie=facts.security.get("PIE") == "ON")
        if params.get("include_assembly", True):
            try:
                result = self._runner.run_tool("objdump", ["-d", "--insn-width=16", "--",
                                                          self._runner.to_wsl_path(binary)])
                if result.ok:
                    response.update(parse_disassembly(result.stdout))
                    response["notice"] = result.stderr.strip()
                else:
                    response["assembly_error"] = result.combined_output() or f"objdump 退出码 {result.returncode}"
            except Exception as error:
                response["assembly_error"] = str(error)
        return response

    # ------------------------------------------------------------------
    # AWDP patch lab（字节级补丁真值；全部等长替换，不改文件大小）

    def _patch_lab(self, params: dict | None = None) -> PatchLab:
        binary = Path(str((params or {}).get("path") or "") or self._target_binary())
        key = str(binary)
        lab = self._patch_labs.get(key)
        if lab is None:
            target = self._patch_targets.get(str(binary.resolve()), self.workspace.target or {})
            project = str(target.get("project_root") or binary.parent)
            lab = PatchLab(binary, project_root=Path(project))
            self._patch_labs[key] = lab
        return lab

    def _patch_target(self, lab: PatchLab) -> dict:
        return self._patch_targets.get(str(lab.binary.resolve()), self.workspace.target or {})

    def _disassemble_functions(self, binary: Path) -> tuple[list[dict], str]:
        """反汇编工作副本；按（路径+mtime+大小）缓存，补丁写入后自动失效。

        通防流程会连续预览多张卡片、每个建议都重建 ops，缓存避免每次重新
        启动 wsl objdump。缓存键含 mtime_ns 与文件大小，补丁落盘即换键。
        """
        try:
            key = self._import_cache_key(binary)
        except OSError as error:
            return [], str(error)
        cached = self._disasm_cache.get(key)
        if cached is not None:
            return cached, ""
        result = self._runner.run_tool("objdump", ["-d", "--insn-width=16", "--",
                                                   self._runner.to_wsl_path(binary)])
        if not result.ok:
            return [], result.combined_output() or f"objdump 退出码 {result.returncode}"
        from pwncraft.core.code_analysis import parse_disassembly
        functions = parse_disassembly(result.stdout)["functions"]
        if len(self._disasm_cache) >= 4:
            self._disasm_cache.clear()
        self._disasm_cache[key] = functions
        return functions, ""

    def _patch_arch(self, binary: Path) -> str:
        facts = BinaryInspector().inspect(binary)
        return normalize_patch_arch(facts.architecture, facts.bits)

    def _seccomp_policy_names(self, request: dict) -> tuple[tuple[str, ...], tuple[str, ...]]:
        preset = str(request.get("preset") or "").strip()
        if preset and preset != "custom":
            conf = SECCOMP_PRESETS.get(preset)
            if conf is None:
                raise ValueError(f"未知 seccomp 预设: {preset}")
            return tuple(conf["kill"]), tuple(conf["allow"])
        structured = parse_seccomp_policy_structured(str(request.get("policy") or ""))
        verdicts: dict[str, str] = structured["policy"]
        default = str(structured["default_action"] or "allow").lower()
        if default == "kill":
            return (), tuple(name for name, verdict in verdicts.items()
                             if verdict == "ALLOWED")
        return tuple(name for name, verdict in verdicts.items()
                     if verdict == "BLOCKED"), ()

    def _build_patch_ops(self, params: dict) -> tuple[list[PatchOp], list[str]]:
        request = params.get("request") if isinstance(params.get("request"), dict) else params
        kind = str(request.get("kind") or "").strip()
        lab = self._patch_lab(params)
        binary = lab.binary
        arch = self._patch_arch(binary)

        def functions() -> list[dict]:
            found, error = self._disassemble_functions(binary)
            if error:
                raise ValueError(f"反汇编失败，无法构建补丁: {error}")
            return found

        def pick_function(name: str) -> str:
            value = str(request.get("function") or name or "").strip()
            if not value:
                raise ValueError("未选择目标函数")
            return value

        warnings: list[str] = []
        if kind == "seccomp":
            kill, allow = self._seccomp_policy_names(request)
            geometry = lab.geometry()
            result = self._runner.run_tool("objdump", [
                "-d",
                f"--start-address={geometry['entry']}",
                f"--stop-address={geometry['entry'] + 64}",
                "--", self._runner.to_wsl_path(binary)])
            if not result.ok:
                raise ValueError(f"入口反汇编失败: {result.combined_output()}")
            built = build_seccomp_ops(lab, arch=arch, kill=kill, allow=allow,
                                      entry_lines=parse_instruction_lines(result.stdout))
            return built["ops"], built["warnings"] + warnings
        if kind == "plt_call":
            built = build_plt_call_redirect(lab, functions(),
                                            str(request.get("source") or ""),
                                            str(request.get("target") or ""),
                                            function=str(request.get("function") or ""),
                                            vaddr=(int(str(request["vaddr"]), 0)
                                                   if request.get("vaddr") else None))
            return built["ops"], built["warnings"]
        if kind == "plt_stub":
            built = build_plt_stub_redirect(lab, functions(),
                                            str(request.get("source") or ""),
                                            str(request.get("target") or ""))
            return built["ops"], built["warnings"]
        if kind == "readlen":
            built = build_read_length(lab, functions(), pick_function(""),
                                      str(request.get("callee") or "read"),
                                      int(str(request.get("size") or "0"), 0),
                                      vaddr=(int(str(request["vaddr"]), 0)
                                             if request.get("vaddr") else None))
            return built["ops"], built["warnings"]
        if kind == "nop_function":
            built = build_nop_function(lab, functions(), pick_function(""))
            return built["ops"], built["warnings"]
        if kind == "ret_function":
            built = build_ret_function(lab, functions(), pick_function(""))
            return built["ops"], built["warnings"]
        if kind == "return_constant":
            built = build_return_constant(lab, functions(), pick_function(""),
                                          int(str(request.get("value") or "0"), 0))
            return built["ops"], built["warnings"]
        if kind == "cave_hook":
            built = build_code_cave_hook(
                lab, functions(), pick_function(""),
                int(str(request.get("start") or "0"), 0),
                int(str(request.get("end") or "0"), 0),
                str(request.get("text") or ""), str(request.get("mode") or "replace"))
            return built["ops"], built["warnings"]
        if kind == "nop_range":
            built = build_nop_range(lab, int(str(request.get("start") or "0"), 0),
                                    int(str(request.get("end") or "0"), 0))
            return built["ops"], built["warnings"]
        if kind in ("nop_call", "nop_instructions", "assembly", "skip_call_result"):
            start = int(str(request.get("start") or "0"), 0)
            end = int(str(request.get("end") or "0"), 0)
            if kind == "skip_call_result":
                built = build_skip_call_result(
                    lab, functions(), pick_function(""), start, end,
                    int(str(request.get("value") or "0"), 0))
                return built["ops"], built["warnings"]
            replacement = None
            if kind == "assembly":
                encoded = assemble(str(request.get("text") or ""),
                                   bits=64 if lab.geometry()["is64"] else 32, vaddr=start)
                replacement = bytes.fromhex(encoded["bytes"])
            built = build_instruction_patch(lab, functions(), pick_function(""), start, end,
                                            kind=kind, replacement=replacement,
                                            pad=bool(request.get("pad", True)))
            return built["ops"], built["warnings"]
        if kind in ("jcc_invert", "jcc_mode"):
            built = build_jcc_mode(lab, int(str(request.get("vaddr") or "0"), 0),
                                   "invert" if kind == "jcc_invert" else
                                   str(request.get("mode") or "invert"))
            return built["ops"], built["warnings"]
        if kind == "custom":
            expected = request.get("expected_size")
            built = build_custom_bytes(lab, int(str(request.get("vaddr") or "0"), 0),
                                       str(request.get("hex") or ""),
                                       expected_size=(int(expected)
                                                      if expected is not None else None))
            return built["ops"], built["warnings"]
        raise ValueError(f"未知补丁类型: {kind or '(空)'}")

    def rpc_patch_recipes(self, params: dict) -> dict:
        def normalize(recipe: dict) -> dict:
            payload = dict(recipe)
            warnings = payload.get("warnings")
            payload["warnings"] = list(warnings) if isinstance(warnings, (list, tuple)) \
                else ([str(warnings)] if warnings else [])
            return payload
        return {"recipes": [normalize(recipe) for recipe in RECIPE_CATALOG],
                "seccomp_presets": {key: {k: v for k, v in conf.items() if k != "warnings"}
                                    for key, conf in SECCOMP_PRESETS.items()}}

    def rpc_patch_audit(self, params: dict) -> dict:
        lab = self._patch_lab(params)
        before = lab.binary.stat()
        facts = BinaryInspector().inspect(lab.binary)
        functions, error = self._disassemble_functions(lab.binary)
        if error:
            raise ValueError(f"风险扫描反汇编失败: {error}")
        after = lab.binary.stat()
        if (before.st_mtime_ns, before.st_size) != (after.st_mtime_ns, after.st_size):
            raise ValueError("扫描期间文件发生变化，请重新扫描")
        return {**audit_patch_surface(lab, functions, security=facts.security),
                "sha256": facts.sha256, "scanned_at": datetime.now().isoformat(timespec="seconds")}

    def rpc_patch_audit_export(self, params: dict) -> dict:
        dest = str(params.get("dest") or "").strip()
        if not dest:
            raise ValueError("请选择扫描报告保存路径")
        lab = self._patch_lab(params)
        target = self._patch_target(lab)
        protected = [lab.binary, Path(str(target.get("original_binary") or lab.binary))]
        if any(Path(dest).resolve() == path.resolve() for path in protected):
            raise ValueError("报告不能覆盖目标 ELF 或原始副本，请另选 .json 文件")
        report = self.rpc_patch_audit(params)
        Path(dest).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return {"path": dest, "sha256": report["sha256"], "count": report["summary"]["total"]}

    @staticmethod
    def _merge_patch_ops(ops: list[PatchOp]) -> list[PatchOp]:
        """合并多个建议产生的补丁：同地址同字节只保留一条，同地址不同字节明确报错。"""
        merged: dict[int, PatchOp] = {}
        for op in ops:
            existing = merged.get(op.vaddr)
            if existing is None:
                merged[op.vaddr] = op
                continue
            if existing.new_bytes != op.new_bytes:
                raise ValueError(
                    f"0x{op.vaddr:x} 被 {existing.kind} 与 {op.kind} 两个建议同时改写，请分开预览")
        return list(merged.values())

    def rpc_patch_preview(self, params: dict) -> dict:
        """预览单个补丁请求，或把 requests 列表合并成一批「组合通防」补丁。"""
        requests = params.get("requests")
        if isinstance(requests, list):
            ops: list[PatchOp] = []
            warnings: list[str] = []
            if not requests:
                raise ValueError("没有选中任何缓解项")
            for entry in requests:
                if not isinstance(entry, dict):
                    raise ValueError("批量预览的每一项都必须是补丁请求对象")
                built_ops, built_warnings = self._build_patch_ops({**params, "request": entry})
                ops.extend(built_ops)
                warnings.extend(built_warnings)
            ops = self._merge_patch_ops(ops)
        else:
            ops, warnings = self._build_patch_ops(params)
        lab = self._patch_lab(params)
        lab.validate_apply(ops)
        token = uuid.uuid4().hex
        self._patch_previews = {key: value for key, value in self._patch_previews.items()
                                if time.monotonic() - value["created"] < 1800}
        if len(self._patch_previews) >= 32:
            self._patch_previews.pop(next(iter(self._patch_previews)))
        self._patch_previews[token] = {"binary": lab.binary.resolve(), "ops": ops,
                                       "warnings": warnings, "created": time.monotonic()}
        return {"ops": [op.to_dict() for op in ops], "warnings": warnings,
                "binary": str(lab.binary), "preview_id": token}

    def rpc_patch_apply(self, params: dict) -> dict:
        lab = self._patch_lab(params)
        token = str(params.get("preview_id") or "")
        if token:
            saved = self._patch_previews.get(token)
            if saved is None or time.monotonic() - saved["created"] >= 1800:
                raise ValueError("补丁预览已过期或桥已重启，请重新预览")
            if saved["binary"] != lab.binary.resolve():
                raise ValueError("预览属于另一个文件，请切回对应工作区或重新预览")
            ops, warnings = saved["ops"], saved["warnings"]
        else:
            ops, warnings = self._build_patch_ops(params)
        outcome = lab.apply(ops)
        self._disasm_cache.clear()          # 工作副本已变，反汇编缓存全部作废
        if token:
            self._patch_previews.pop(token, None)
        self._log(f"AWDP 补丁已应用 {len(ops)} 条（备份: {Path(outcome['backup']).name}）")
        return {"applied": outcome["applied"], "backup": outcome["backup"],
                "warnings": warnings, "binary": str(lab.binary),
                "batch_id": outcome["batch_id"], "log": lab.inspect_ops()}

    def rpc_patch_list(self, params: dict) -> dict:
        lab = self._patch_lab(params)
        ops = lab.inspect_ops()
        summary = {"total": len(ops), "applied": 0, "restored": 0, "conflict": 0}
        for op in ops:
            summary[op["state"]] += 1
        summary["healthy"] = summary["restored"] == 0 and summary["conflict"] == 0
        return {"ops": ops, "summary": summary,
                "binary": str(lab.binary), "log_path": str(lab.log_path)}

    def rpc_patch_undo(self, params: dict) -> dict:
        lab = self._patch_lab(params)
        outcome = lab.undo(str(params.get("op_id") or ""))
        self._disasm_cache.clear()
        self._log(f"已撤销补丁组 {outcome['batch_id']}（{outcome['count']} 条）")
        return {**outcome, "log": lab.inspect_ops()}

    def rpc_patch_clear(self, params: dict) -> dict:
        lab = self._patch_lab(params)
        outcome = lab.undo_all()
        self._disasm_cache.clear()
        self._log(f"已撤销全部 {outcome['count']} 条补丁")
        return {**outcome, "log": []}

    def rpc_patch_reconcile(self, params: dict) -> dict:
        lab = self._patch_lab(params)
        outcome = lab.reconcile_restored()
        self._log(f"已清理 {outcome['count']} 条外部恢复的补丁记录")
        return {**outcome, "log": lab.inspect_ops()}

    def rpc_patch_export(self, params: dict) -> dict:
        kind = str(params.get("kind") or "").strip()
        lab = self._patch_lab(params)
        ops = lab.log_ops()
        if not ops:
            raise ValueError("当前没有已应用的补丁可导出")
        lab.assert_all_applied()
        # 目标二进制沿用 params["path"]；导出落盘路径单独用 "dest"，避免同名歧义
        dest = str(params.get("dest") or "").strip()
        path = dest
        if kind == "script":
            arch = self._patch_arch(lab.binary)
            text = export_pwntools_script(ops, binary_name=lab.binary.name, arch=arch,
                                          geometry=lab.geometry())
            if path:
                Path(path).write_text(text, encoding="utf-8")
            return {"text": text, "path": path, "count": len(ops)}
        if kind == "diff":
            text = export_diff_text(ops, binary_path=str(lab.binary))
            if path:
                Path(path).write_text(text, encoding="utf-8")
            return {"text": text, "path": path, "count": len(ops)}
        if kind == "patched":
            if not path:
                raise ValueError("导出补丁后 ELF 需要一个保存路径")
            target = self._patch_target(lab)
            original = str(target.get("original_binary") or "")
            if not original or not Path(original).is_file():
                raise ValueError("找不到只读原始副本（original_binary），无法回放生成干净 ELF")
            outcome = materialize_patched(Path(original), ops, Path(path))
            self._log(f"已导出补丁后 ELF: {path}")
            return outcome
        if kind == "bundle":
            if not path:
                raise ValueError("导出比赛提交包需要一个保存路径")
            target = self._patch_target(lab)
            original = str(target.get("original_binary") or "")
            if not original or not Path(original).is_file():
                raise ValueError("找不到只读原始副本（original_binary），无法生成比赛提交包")
            outcome = export_competition_bundle(
                Path(original), ops, Path(path), arch=self._patch_arch(lab.binary))
            self._log(f"已导出 AWDP 比赛提交包: {path}")
            return outcome
        raise ValueError(f"未知导出类型: {kind or '(空)'}（支持 script/diff/patched/bundle）")

    @staticmethod
    def _probe_argv(value: object) -> list[str]:
        if isinstance(value, list):
            argv = [str(item) for item in value]
        else:
            argv = shlex.split(str(value or ""), posix=True)
        if len(argv) > 16 or any(len(item) > 4096 for item in argv):
            raise ValueError("探测参数过多或单个参数过长")
        return argv

    def rpc_patch_probe(self, params: dict) -> dict:
        lab = self._patch_lab(params)
        if lab.log_ops():
            lab.assert_all_applied()
        argv = self._probe_argv(params.get("args"))
        stdin_data = str(params.get("input") or "").encode("utf-8")
        if len(stdin_data) > 65536:
            raise ValueError("探测输入不能超过 64 KiB")
        timeout = max(1, min(15, int(params.get("timeout") or 5)))

        def run(label: str, binary: Path) -> dict:
            started = time.monotonic()
            result, timed_out = self._runner.run_target_capture(
                [self._runner.to_wsl_path(binary), *argv], stdin_data=stdin_data,
                timeout=timeout)
            stdout, stderr = result.stdout, result.stderr
            truncated = len(stdout) > 16384 or len(stderr) > 16384
            return {"label": label, "path": str(binary), "returncode": result.returncode,
                    "timed_out": timed_out, "ok": result.ok and not timed_out,
                    "stdout": stdout[:16384], "stderr": stderr[:16384],
                    "output_truncated": truncated,
                    "elapsed_ms": round((time.monotonic() - started) * 1000)}

        working = run("patched", lab.binary)
        original = None
        target = self._patch_target(lab)
        original_path = Path(str(target.get("original_binary") or ""))
        if bool(params.get("compare", True)) and original_path.is_file():
            original = run("original", original_path)
        comparison = None
        if original:
            comparison = {
                "same_returncode": original["returncode"] == working["returncode"],
                "same_stdout": original["stdout"] == working["stdout"],
                "both_healthy": original["ok"] and working["ok"],
            }
        return {"patched": working, "original": original, "comparison": comparison,
                "input_size": len(stdin_data), "args": argv}

    def rpc_patch_instructions(self, params: dict) -> dict:
        name = str(params.get("function") or "").strip()
        if not name:
            raise ValueError("未选择函数")
        lab = self._patch_lab(params)
        functions, error = self._disassemble_functions(lab.binary)
        if error:
            raise ValueError(f"反汇编失败: {error}")
        fn = next((f for f in functions if str(f.get("name")) == name), None)
        if fn is None:
            raise ValueError(f"函数 {name!r} 不在当前反汇编列表中")
        return {"function": name, "address": fn.get("address"),
                "instructions": [
                    {"address": f"0x{insn['address']:x}", "size": insn["size"],
                     "bytes": insn["bytes"].hex(" "), "text": insn["text"]}
                    for insn in parse_instruction_lines(fn.get("assembly") or "")]}

    def rpc_patch_disasm_raw(self, params: dict) -> dict:
        lab = self._patch_lab(params)
        bits = 64 if lab.geometry()["is64"] else 32
        return disasm_raw(str(params.get("hex") or ""), bits=bits, runner=self._runner,
                          work_dir=lab.binary.parent / ".pwncraft" / "work")

    def rpc_patch_bytecode_lookup(self, params: dict) -> dict:
        return {"entries": catalog_entries(str(params.get("query") or ""))}

    def rpc_patch_encode(self, params: dict) -> dict:
        payload = params.get("params") if isinstance(params.get("params"), dict) else {}
        return encode_template(str(params.get("kind") or ""), payload)

    def _ida(self) -> IdaCliLink:
        if self._ida_link is None:
            self._ida_link = IdaCliLink()
        return self._ida_link

    def _ida_target(self, params: dict) -> Path:
        target = self._patch_target(self._patch_lab(params))
        original = str(target.get("original_binary") or "")
        if original and Path(original).is_file():
            return Path(original)
        return self._patch_lab(params).binary

    def rpc_patch_assemble(self, params: dict) -> dict:
        """Keypatch 式汇编：文本 → 机器码（keystone，vaddr 解析相对跳转）。"""
        lab = self._patch_lab(params)
        bits = 64 if lab.geometry()["is64"] else 32
        vaddr = int(str(params.get("vaddr") or "0"), 0)
        return assemble(str(params.get("text") or ""), bits=bits, vaddr=vaddr)

    # ------------------------------------------------------------------
    # Exploit synthesis（检测 → 原语图 → 策略 → EXP 骨架 → 往返自检 → 评审区）

    def _synth_binary(self, params: dict) -> Path:
        raw = str(params.get("path") or "").strip()
        binary = Path(raw) if raw else self._target_binary()
        if not Path(binary).is_file():
            raise ValueError(f"目标不存在: {binary}")
        return Path(binary)

    def _synth_evidence(self, binary: Path) -> list[dict]:
        """复用 AWDP 风险扫描 findings 作为「输入长度 / 格式化」证据（失败不阻断）。"""
        try:
            functions, error = self._disassemble_functions(binary)
            if error:
                return []
            facts = BinaryInspector().inspect(binary)
            report = audit_patch_surface(self._patch_lab({"path": str(binary)}),
                                         functions, security=facts.security)
            return [dict(item) for item in (report.get("findings") or [])]
        except Exception:
            return []

    def _synth_options(self, params: dict) -> dict:
        options: dict = {}
        if isinstance(params.get("stack_truth"), dict):
            options["stack_truth"] = dict(params["stack_truth"])
        if isinstance(params.get("gadgets"), dict):
            options["gadgets"] = dict(params["gadgets"])
        if params.get("libc"):
            options["libc"] = str(params["libc"])
        return options

    def rpc_synth_analyze(self, params: dict) -> dict:
        """自动检测：ELF 事实 + 原语图 + 策略（确定性，不执行目标）。"""
        from pwncraft.features.synth import analyze_target
        from pwncraft.features.synth.pipeline import detection_report

        binary = self._synth_binary(params)
        analysis = analyze_target(binary, runner=self._runner,
                                  patch_findings=self._synth_evidence(binary),
                                  **self._synth_options(params))
        return detection_report(analysis)

    def rpc_synth_generate(self, params: dict) -> dict:
        """自动构造 EXP 骨架（诚实骨架 + 往返审计），可选写入 EXP 编辑器。"""
        from pwncraft.features.synth import generate_exp
        from pwncraft.features.synth.pipeline import detection_report

        binary = self._synth_binary(params)
        generated = generate_exp(binary, strategy=str(params.get("strategy") or ""),
                                 runner=self._runner,
                                 patch_findings=self._synth_evidence(binary),
                                 **self._synth_options(params))
        result = detection_report(generated)
        result["source"] = generated["rendered"].source
        result["unresolved"] = list(generated["rendered"].unresolved)
        result["constants"] = dict(generated["rendered"].constants)
        result["verdict"] = generated["verdict"]
        result["libc_symbols"] = dict(generated["libc_symbols"])
        if params.get("apply"):
            self.workspace.set_exploit_source(generated["rendered"].source)
            result["applied"] = True
        return result

    def rpc_exploit_chain_plan(self, params: dict) -> dict:
        """把自动识别到的组合链转换为可编辑 EXP 草稿。

        链规划只复用 synth_generate 的事实与渲染器，不在 RPC/前端拼接地址；
        blocked 链也可以输出带 TODO 的诚实骨架，明确列出未满足前置条件。
        """
        from pwncraft.features.synth import generate_exp
        binary = self._synth_binary(params)
        chain_id = str(params.get("chain_id") or "").strip()
        strategy_map = {
            "stack-leak-ret2libc": "ret2libc",
            "stack-ret2syscall": "orw",
            "stack-ret2dlresolve": "ret2libc",
            "stack-pivot-rop": "ret2libc",
            "format-got-overwrite": "fmt_write",
            "format-got-direct": "fmt_write",
        }
        strategy = str(params.get("strategy") or strategy_map.get(chain_id) or "")
        generated = generate_exp(binary, strategy=strategy, runner=self._runner,
                                 allow_missing=True, patch_findings=self._synth_evidence(binary),
                                 **self._synth_options(params))
        chains = []
        try:
            from pwncraft.core.exploit_chain import compose_chains
            report = self.rpc_auto_vuln_scan({"path": str(binary)})
            chains = list(report.get("exploit_chains") or [])
        except Exception:
            chains = []
        chain = next((item for item in chains if item.get("id") == chain_id), None)
        if chain is None:
            raise ValueError(f"未找到利用链 {chain_id!r}")
        rendered = generated.get("rendered")
        missing_items = list(chain.get("missing") or ())
        if not missing_items:
            note = generated.get("verdict", {}).get("note", "unknown")
            missing_items = [str(note)]
        source = rendered.source if (rendered is not None and chain.get("status") == "candidate") else (
            "# AUTO_CHAIN_BLOCKED: 仅生成审计骨架，禁止把 TODO 当成可利用事实\n"
            f"# chain={chain_id}\n"
            + "# missing: " + "; ".join(missing_items) + "\n"
            + "from pwn import *\n\n"
            + "# TODO: 补齐上面的缺口后，再填入 payload 与运行时验证\n")
        return {
            "chain": chain, "strategy": strategy, "source": source,
            "unresolved": list(getattr(rendered, "unresolved", ()) if (rendered is not None and chain.get("status") == "candidate") else missing_items),
            "safe_to_insert": bool(rendered is not None and chain.get("status") == "candidate"),
            "provenance": {"binary": str(binary), "chain_id": chain_id,
                            "strategy": strategy, "status": chain.get("status")},
        }

    def rpc_synth_verify(self, params: dict) -> dict:
        """运行时验证（opt-in）：gdb 测偏移 → 渲染 → 真跑一次生成的 EXP。"""
        from pwncraft.features.synth.pipeline import detection_report, verify_exploit

        binary = self._synth_binary(params)
        result = verify_exploit(binary, runner=self._runner,
                                strategy=str(params.get("strategy") or ""),
                                timeout=int(params.get("timeout") or 60),
                                marker=str(params.get("marker") or "PWN_SYNTH_OK"),
                                patch_findings=list(self._synth_evidence(binary)),
                                **self._synth_options(params))
        report = detection_report(result)
        report["runtime"] = dict(result["runtime"])
        report["execution"] = result["execution"]
        report["verification"] = dict(result["verification"])
        report["verdict"] = result["verdict"]
        if result.get("rendered") is not None:
            report["source"] = result["rendered"].source
            report["unresolved"] = list(result["rendered"].unresolved)
            report["constants"] = dict(result["rendered"].constants)
            if params.get("apply"):
                self.workspace.set_exploit_source(report["source"])
                report["applied"] = True
        verification = result["verification"]
        self._log(f"运行时验证：{verification.get('status')} — {verification.get('summary')}")
        return report

    def rpc_synth_verify_all(self, params: dict) -> dict:
        """一键生成并逐个本地验证全部 EXP 候选；仅成功候选可自动替换。"""
        from pwncraft.features.synth.pipeline import verify_all_exploits

        binary = self._synth_binary(params)
        result = verify_all_exploits(
            binary, runner=self._runner,
            timeout=int(params.get("timeout") or 60),
            marker=str(params.get("marker") or "PWN_SYNTH_OK"),
            patch_findings=list(self._synth_evidence(binary)),
            **self._synth_options(params),
        )
        winner = result.get("winner") or {}
        if winner.get("verified") and params.get("apply"):
            self.workspace.set_exploit_source(str(winner.get("source") or ""))
            result["applied"] = True
            self._log(f"候选 EXP 已打通并替换：{winner.get('strategy')}")
        return result

    def rpc_synth_deposit(self, params: dict) -> dict:
        """把检测 + 骨架沉淀到 review_queue（生成物默认 trainable=false）。"""
        from pwncraft.features.synth import deposit_case as synth_deposit
        from pwncraft.features.synth import generate_exp

        dest = str(params.get("dest") or "").strip()
        if not dest:
            raise ValueError("请选择 review_queue 目录")
        binary = self._synth_binary(params)
        generated = generate_exp(binary, strategy=str(params.get("strategy") or ""),
                                 runner=self._runner,
                                 patch_findings=self._synth_evidence(binary),
                                 **self._synth_options(params))
        outcome = synth_deposit(dest, generated)
        self._log(f"合成样本已写入评审区: {outcome['case_id']}")
        return {**outcome, "strategy": generated["strategy"].id,
                "verdict": generated["verdict"]["verdict"]}

    def rpc_vuln_points(self, params: dict) -> dict:
        """漏洞点确认：输入调用点的 长度 vs 缓冲区边界 静态证明。"""
        from pwncraft.features.synth.vuln_points import scan_vuln_points
        lab = self._patch_lab(params)
        # 不预取函数列表：静态链接需高上限解析，由 scan_vuln_points 自行 objdump
        return scan_vuln_points(lab.binary, self._runner)

    def rpc_auto_vuln_scan(self, params: dict) -> dict:
        """统一自动漏洞识别：合并规则审计、数据流证明与利用面事实。

        该入口只做静态分析，不把危险 API 或缺少保护误报成已确认漏洞；
        每条 finding 保留来源、置信度和原始证据，便于 UI 去重和人工复核。
        """
        from pwncraft.features.patch.audit import audit_patch_surface
        from pwncraft.features.synth.vuln_points import scan_vuln_points
        from pwncraft.core.semantic_behavior import classify_functions, summarize_labels

        lab = self._patch_lab(params)
        binary = lab.binary
        facts = BinaryInspector().inspect(binary)
        functions, error = self._disassemble_functions(binary)
        if error:
            raise ValueError(f"自动漏洞识别反汇编失败: {error}")
        patch = audit_patch_surface(lab, functions, security=facts.security)
        semantic_functions = classify_functions(functions)
        strategy_summary = []
        chain_summary = []
        libc_symbols = {}
        fsop_profile = {"status": "unknown", "reason": "未提供 libc 文件"}
        gadget_facts = {}
        gadget_catalog = []
        gadget_error = ""
        try:
            from pwncraft.core.gadgets import parse_ropgadget_output
            bits = int(getattr(facts, "bits", 64) or 64)
            gadget_args = ["--binary", self._runner.to_wsl_path(binary),
                           "--only", "pop|ret|syscall", "--depth", "10"]
            gadget_result = self._runner.run_tool("ropgadget", gadget_args, timeout=300)
            gadget_text = gadget_result.stdout or gadget_result.stderr
            gadgets = parse_ropgadget_output(gadget_text, source="auto_vuln_scan", bits=bits)
            for gadget in gadgets:
                gadget_catalog.append({"address": hex(gadget.address), "text": gadget.text,
                                       "controls": list(gadget.controls), "score": gadget.score,
                                       "stack_delta": gadget.stack_delta,
                                       "highlight": gadget.score >= 3})
                ins = " ; ".join(item.lower().replace(" ", "") for item in gadget.instructions)
                if "poprdi" in ins and ins.endswith("ret"):
                    gadget_facts.setdefault("rdi", hex(gadget.address))
                if "poprsi" in ins and ins.endswith("ret"):
                    gadget_facts.setdefault("rsi", hex(gadget.address))
                if "poprdx" in ins and ins.endswith("ret"):
                    gadget_facts.setdefault("rdx", hex(gadget.address))
                if "poprax" in ins and ins.endswith("ret"):
                    gadget_facts.setdefault("rax", hex(gadget.address))
                if "syscall" in ins:
                    gadget_facts.setdefault("syscall", hex(gadget.address))
                if ins == "ret":
                    gadget_facts.setdefault("ret", hex(gadget.address))
                if gadget.controls and ins.endswith("ret"):
                    for register in gadget.controls:
                        gadget_facts.setdefault(f"pop_{register}", hex(gadget.address))
            if not gadgets and not gadget_result.ok:
                gadget_error = gadget_result.stderr.strip() or f"ROPgadget 返回码 {gadget_result.returncode}"
        except Exception as error:
            gadget_error = str(error)
        if not gadget_facts:
            # Offline fallback: objdump facts are already available and avoid
            # making the strategy planner depend on ROPgadget installation.
            from pwncraft.features.patch.patch_core import parse_instruction_lines
            for function in functions:
                instructions = parse_instruction_lines(function.get("assembly") or "")
                for index, instruction in enumerate(instructions):
                    text = str(instruction.get("text") or "").strip().lower()
                    address = hex(int(instruction["address"]))
                    next_text = (str(instructions[index + 1].get("text") or "").strip().lower()
                                 if index + 1 < len(instructions) else "")
                    if text in {"pop %rdi", "pop rdi"} and next_text in {"ret", "retq"}:
                        gadget_facts.setdefault("rdi", address)
                    if text in {"pop %rax", "pop rax"} and next_text in {"ret", "retq"}:
                        gadget_facts.setdefault("rax", address)
                    if text in {"pop %rsi", "pop rsi"} and next_text in {"ret", "retq"}:
                        gadget_facts.setdefault("rsi", address)
                    if text in {"pop %rdx", "pop rdx"} and next_text in {"ret", "retq"}:
                        gadget_facts.setdefault("rdx", address)
                    if text in {"ret", "retq"}:
                        gadget_facts.setdefault("ret", address)
                    if text.startswith("syscall"):
                        gadget_facts.setdefault("syscall", address)
                    if text in {"ret", "retq"}:
                        gadget_catalog.append({"address": address, "text": text,
                                               "controls": [], "score": 5, "stack_delta": bits // 8,
                                               "highlight": True})
            if gadget_facts:
                gadget_error = "ROPgadget 不可用，已使用 objdump 相邻指令 fallback"
        try:
            from pwncraft.features.synth.pipeline import analyze_target
            libc = params.get("libc")
            if not libc:
                candidates = sorted(binary.parent.glob("libc*.so*"))
                libc = str(candidates[0]) if candidates else None
            if libc:
                import re
                version_match = re.search(r"(?:libc[-_.]?|glibc[-_.]?)(2\.\d+)", Path(str(libc)).name)
                if version_match:
                    version = tuple(int(item) for item in version_match.group(1).split("."))
                    from pwncraft.features.iofile.layouts import GlibcFileLayoutDatabase
                    layout = GlibcFileLayoutDatabase.get(version, bits=int(facts.bits))
                    fsop_profile = {
                        "status": "candidate",
                        "glibc": f"{version[0]}.{version[1]}",
                        "layout": layout.to_dict() if hasattr(layout, "to_dict") else {
                            "file_size": layout.file_size, "plus_size": layout.plus_size,
                            "wide_size": layout.wide_size,
                            "fields": [{"name": field.name, "offset": field.offset, "width": field.width}
                                       for field in layout.fields],
                            "wide_fields": [{"name": field.name, "offset": field.offset, "width": field.width}
                                             for field in layout.wide_fields],
                        },
                        "routes": (["stdout_leak", "House_of_Apple2"] if version >= (2, 24)
                                   else ["stdout_leak", "_IO_list_all_historical"]),
                        "requirements": ["libc 基址", "可控 FILE/stdio 字段写入原语", "运行时验证"],
                        "confidence": "version_layout_only",
                    }
                else:
                    fsop_profile = {"status": "unknown", "reason": "libc 文件名未解析出 glibc 版本"}
            synthesis = analyze_target(binary, runner=self._runner,
                                       patch_findings=patch.get("findings") or [],
                                       libc=libc, gadgets=gadget_facts)
            strategy_summary = [item.to_dict() for item in synthesis.get("strategies") or []]
            libc_symbols = dict(synthesis.get("libc_symbols") or {})
        except Exception as error:
            strategy_summary = [{"id": "analysis_error", "status": "blocked",
                                 "missing": [f"策略分析失败: {error}"]}]
        # 普通目标复用同一批函数，避免重复启动 objdump；静态链接大目标若触及
        # UI 反汇编的 1000 函数上限，则让扫描器自行以 200000 上限恢复完整函数集。
        scan_functions = None if len(functions) >= 1000 else functions
        points = scan_vuln_points(binary, self._runner, functions=scan_functions)
        # 可选的本地运行时实证回灌：只接受结构化 finding，不执行其中任何命令。
        # 这样 staged WSL 探针（例如 fastbin 重用残留读取）可以与静态
        # 证据合并，并由同一套去重/利用链状态机处理。
        runtime_findings = []
        for raw in (params.get("runtime_findings") or []):
            if not isinstance(raw, dict) or not raw.get("verdict"):
                continue
            item = dict(raw)
            item.setdefault("source", "runtime")
            item.setdefault("confidence", "runtime_dataflow")
            item.setdefault("severity", "medium")
            item.setdefault("category", "runtime_observation")
            item.setdefault("title", str(item.get("verdict")))
            item.setdefault("detail", str(item.get("reason") or item.get("verdict")))
            item.setdefault("evidence", [])
            item.setdefault("locations", [])
            item.setdefault("id", f"runtime:{len(runtime_findings)}")
            item["origin_id"] = item["id"]
            runtime_findings.append(item)
        findings = []
        for item in patch.get("findings") or []:
            findings.append({**dict(item), "source": "surface", "origin_id": item.get("id")})
        for index, item in enumerate(points.get("points") or []):
            point = dict(item)
            point.setdefault("id", f"dataflow:{index}")
            point.setdefault("title", point.get("reason") or point.get("verdict") or "数据流风险")
            point.setdefault("detail", point.get("reason") or "数据流扫描发现需要复核的调用点")
            point.setdefault("evidence", [])
            point["source"] = "dataflow"
            point["origin_id"] = point["id"]
            point["locations"] = point.get("locations") or ([{
                "function": point.get("function", ""),
                "address": point.get("vaddr", ""),
            }] if point.get("vaddr") else [])
            findings.append(point)
        findings.extend(runtime_findings)
        runtime_confirmed = sum(1 for item in runtime_findings
                                if str(item.get("confidence") or "").lower() in
                                {"runtime_proven", "runtime_confirmed", "proven", "confirmed"}
                                or str(item.get("verdict") or "").endswith("_confirmed"))
        semantic_chain_findings = []
        for semantic in semantic_functions:
            if "GLOBAL_POINTER_FREE_NO_CLEAR_CANDIDATE" in (semantic.get("labels") or []):
                semantic_finding = {
                    "id": f"semantic:uaf-no-clear:{semantic.get('address', '0x0')}",
                    "function": semantic.get("function", ""),
                    "vaddr": semantic.get("address", "0x0"),
                    "verdict": "use_after_free_candidate",
                    "category": "heap_lifetime", "severity": "high",
                    "confidence": "dataflow_candidate",
                    "reason": "free 使用全局/表项指针后未观察到同函数清零，存在跨函数 UAF 候选",
                    "evidence": ["semantic:GLOBAL_POINTER_FREE_NO_CLEAR_CANDIDATE"],
                    "title": "全局指针 free 后未清零候选",
                    "detail": "需要结合后续 edit/read 使用点和运行时复现确认",
                    "locations": [{"function": semantic.get("function", ""),
                                    "address": semantic.get("address", "0x0")}],
                    "source": "semantic",
                    "origin_id": f"semantic:uaf-no-clear:{semantic.get('address', '0x0')}",
                }
                findings.append(semantic_finding)
                semantic_chain_findings.append(semantic_finding)

        # 语义 finding 在上面才注入；此处再编排，确保跨函数 UAF 等
        # 语义证据能够真正驱动利用链状态机，而不是只显示在漏洞列表里。
        from pwncraft.core.exploit_chain import compose_chains
        chain_summary = compose_chains(
            findings=[dict(item) for item in points.get("points") or []] +
                     runtime_findings + semantic_chain_findings,
            facts=facts, semantic_functions=semantic_functions,
            gadgets=gadget_facts, libc_symbols=libc_symbols)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        # 同一调用点可能同时命中 surface 和 dataflow；保留证据更强的一条。
        confidence_order = {"proven": 0, "dataflow": 1, "lifecycle": 1,
                            "dangerous_api": 2, "review": 3, "hardening": 4, "info": 5}
        dedup = {}
        for item in findings:
            locations = item.get("locations") or []
            loc = locations[0] if locations else {}
            key = (str(item.get("category") or "unknown"),
                   str(loc.get("function") or ""), str(loc.get("address") or ""),
                   str(item.get("callee") or item.get("title") or ""))
            current = dedup.get(key)
            if current is None or confidence_order.get(str(item.get("confidence")), 9) < confidence_order.get(str(current.get("confidence")), 9):
                dedup[key] = item
        findings = sorted(dedup.values(), key=lambda item: (
            severity_order.get(str(item.get("severity")), 9),
            confidence_order.get(str(item.get("confidence")), 9),
            str(item.get("title") or item.get("id") or "")))
        counts = {name: sum(1 for item in findings if item.get("severity") == name)
                  for name in ("critical", "high", "medium", "low", "info")}
        categories = {}
        confidences = {}
        for item in findings:
            category = str(item.get("category") or "unknown")
            confidence = str(item.get("confidence") or "unknown")
            categories[category] = categories.get(category, 0) + 1
            confidences[confidence] = confidences.get(confidence, 0) + 1
        score = min(100, counts["critical"] * 35 + counts["high"] * 18 + counts["medium"] * 7 + counts["low"] * 2)
        # Pwn 题型画像：只使用 BinaryInspector 已经从 ELF 字节和反汇编中证明的事实。
        categories_seen = set(categories)
        pwn_routes = []
        if "memory_corruption" in categories_seen and getattr(facts, "win_functions", ()):
            pwn_routes.append({"id": "ret2win", "reason": "存在内存破坏证据与可调用 win 函数", "confidence": "conditional"})
        if "memory_corruption" in categories_seen and getattr(facts, "leak_sites", ()):
            pwn_routes.append({"id": "ret2libc", "reason": "存在内存破坏证据与可观测泄漏点", "confidence": "conditional"})
        if "format_string" in categories_seen:
            pwn_routes.append({"id": "format-string", "reason": "格式化参数存在可控性或可写候选", "confidence": "conditional"})
        if getattr(facts, "syscalls", ()) and ("memory_corruption" in categories_seen or getattr(facts, "strings", {}).get("/bin/sh")):
            pwn_routes.append({"id": "syscall-orw", "reason": "发现 syscall 指令且存在输入或敏感字符串事实", "confidence": "conditional"})
        if "heap_lifetime" in categories_seen:
            pwn_routes.append({"id": "heap-lifetime", "reason": "发现 double-free/UAF/invalid-free 生命周期证据", "confidence": "dataflow"})
        recommendations = []
        if counts["critical"] or counts["high"]:
            recommendations.append("优先复核 critical/high 项，再进行运行时偏移和可控性验证")
        if facts.security.get("CANARY") == "ON":
            recommendations.append("CANARY 已开启：栈路线需要先寻找泄漏或改走堆/格式化字符串原语")
        if facts.security.get("NX") == "ON":
            recommendations.append("NX 已开启：优先考虑 ROP、ret2libc 或 syscall/ORW")
        if facts.security.get("PIE") == "ON":
            recommendations.append("PIE 已开启：地址依赖路线需要先获取代码基址")
        if not pwn_routes:
            recommendations.append("暂未形成稳定利用路线，先补充输入可控性或运行时崩溃证据")
        return {
            "binary": str(binary), "sha256": facts.sha256,
            "findings": findings,
            "summary": {**counts, "total": len(findings), "risk_score": score,
                         # 数据流扫描的 confirmed 与运行时回灌证据都纳入总数。
                         "confirmed": points.get("confirmed", 0) + runtime_confirmed},
            "categories": categories, "confidences": confidences,
            "semantic_functions": semantic_functions,
            "semantic_summary": summarize_labels(semantic_functions),
            "strategies": strategy_summary,
            "exploit_chains": chain_summary,
            "gadgets": gadget_facts,
            "gadget_catalog": gadget_catalog[:200],
            "gadget_error": gadget_error,
            "fsop_profile": fsop_profile,
            "pwn_profile": {
                "routes": pwn_routes,
                "syscalls": [hex(int(address)) for address in getattr(facts, "syscalls", ())],
                "ret_gadgets": [hex(int(address)) for address in getattr(facts, "ret_gadgets", ())[:32]],
                "win_functions": [dict(item) for item in getattr(facts, "win_functions", ())],
                "leak_sites": [dict(item) for item in getattr(facts, "leak_sites", ())],
                "shell_strings": {name: hex(int(address)) for name, address in getattr(facts, "strings", {}).items()
                                  if name in {"/bin/sh", "/bin/bash", "/bin/cat", "/flag"}},
                "input_imports": [name for name in ("read", "recv", "recvfrom", "gets", "fgets", "scanf", "__isoc99_scanf") if name in getattr(facts, "plt", {})],
                "recommendations": recommendations,
            },
            "coverage": {"functions": len(functions),
                         "call_sites": (patch.get("coverage") or {}).get("call_sites", 0),
                         "dataflow_points": points.get("total", 0),
                         "rules": (patch.get("coverage") or {}).get("rules", 0),
                         "global_objects": (points.get("coverage") or {}).get("global_objects", 0)},
            "limitations": list(dict.fromkeys((patch.get("limitations") or []) + (points.get("limitations") or []))),
            "security": dict(facts.security),
        }

    def rpc_ida_status(self, params: dict) -> dict:
        link = self._ida()
        try:
            return link.status(self._ida_target(params))
        except IdaLinkError as error:
            return {"available": False, "error": str(error)}

    def rpc_ida_analyze(self, params: dict) -> dict:
        target = self._ida_target(params)
        link = self._ida()
        overview = link.overview(target)
        functions = link.functions(target)
        return {"binary": str(target), "overview": overview, "functions": functions}

    def rpc_ida_disasm(self, params: dict) -> dict:
        name = str(params.get("function") or "").strip()
        if not name:
            raise ValueError("未选择函数")
        limit = int(params.get("limit") or 64)
        return {"function": name,
                "instructions": self._ida().disasm(self._ida_target(params), name, limit)}

    def rpc_ida_decompile(self, params: dict) -> dict:
        name = str(params.get("function") or "").strip()
        if not name:
            raise ValueError("未选择函数")
        try:
            return self._ida().decompile(self._ida_target(params), name)
        except IdaLinkError as error:
            if "cannot resolve IDA name" in str(error):
                raise ValueError(
                    f"IDA 数据库里没有函数 {name!r}（链接器生成的 _init/_fini 等 stub "
                    "或 objdump 符号可能不在 IDA 命名表内）；请选择业务函数（如 main）"
                    ) from error
            raise

    def rpc_ida_patch_bytes(self, params: dict) -> dict:
        """把文件侧补丁同步进 IDA 数据库（Keypatch 反向联动）。"""
        locator = params.get("function")
        if locator is None:
            locator = int(str(params.get("vaddr") or "0"), 0)
        return self._ida().patch_bytes(self._ida_target(params), locator,
                                       str(params.get("hex") or ""))

    def rpc_workspace_get(self, params: dict) -> dict:        return {
            "project": self.workspace.project,
            "binary": self.workspace.binary,
            "target": self.workspace.target,
            "variables": {
                name: variable.to_dict()
                for name, variable in self.workspace.variables.items()
            },
        }

    def rpc_workspace_save(self, params: dict) -> dict:
        path = str(params.get("path") or "").strip()
        if not path:
            raise ValueError("保存路径为空")
        self.workspace.save(Path(path))
        return {"path": path}

    def rpc_workspace_open(self, params: dict) -> dict:
        path = str(params.get("path") or "").strip()
        if not path:
            raise ValueError("打开路径为空")
        self.workspace.load(Path(path))
        return {"project": self.workspace.project, "target": self.workspace.target}

    def rpc_variable_set(self, params: dict) -> dict:
        name = str(params.get("name") or "").strip()
        if not name:
            raise ValueError("变量名为空")
        kind_name = str(params.get("kind") or "STATIC_ADDRESS")
        kind = AddressKind(kind_name) if kind_name in AddressKind.__members__ else AddressKind.STATIC_ADDRESS
        raw_value = params.get("value")
        value = int(str(raw_value), 0) if raw_value is not None else 0
        variable = WorkspaceVariable(
            name,
            TypedAddress(value, kind, str(params.get("symbol") or name)),
            str(params.get("source") or "user"),
            str(params.get("note") or ""),
            address_kind=kind,
        )
        self.workspace.set_variable(variable)
        return {"name": name, "value": value}

    def rpc_exp_get(self, params: dict) -> dict:
        exploit = self.workspace.exploit or {}
        return {"text": str(exploit.get("source") or "")}

    def rpc_exp_set(self, params: dict) -> dict:
        text = str(params.get("text") if params.get("text") is not None else "")
        self.workspace.set_exploit_source(text)
        return {"length": len(text)}

    def rpc_exp_save(self, params: dict) -> dict:
        path = str(params.get("path") or "").strip()
        text = str(params.get("text") if params.get("text") is not None else "")
        if not path:
            raise ValueError("保存路径为空")
        Path(path).write_text(text, encoding="utf-8")
        self._log(f"已保存: {path}")
        return {"path": path}

    def rpc_recent_dirs(self, params: dict) -> dict:
        """Observed target folders, newest first (terminal cwd candidates)."""
        path = self.workspace.project.get("project_path")
        return {"dirs": [str(path)] if path else []}

    def rpc_blocks_list(self, params: dict) -> dict:
        from pwncraft.core.models import BlockCatalog

        catalog = BlockCatalog.load_default()
        return {
            "blocks": [
                {
                    "id": block.id,
                    "title": block.title,
                    "category": block.category,
                    "description": block.description,
                    "snippet": block.snippet,
                    "placeholders": list(block.placeholders),
                    "tags": list(block.tags),
                }
                for block in catalog.blocks
            ],
        }

    def rpc_clib_catalog(self, params: dict) -> dict:
        """C 函数速查目录（clib_catalog.json）——工具箱 / EXP 工具列查询库。"""
        from pwncraft.core.models import CFunctionCatalog

        catalog = CFunctionCatalog.load_default()
        query = str(params.get("query") or "").strip()
        functions = catalog.search(query) if query else catalog.functions
        return {
            "count": len(functions),
            "query": query,
            "categories": catalog.categories(),
            "functions": [fn.to_dict() for fn in functions],
            "operators": [op.to_dict() for op in catalog.operators],
        }

    def rpc_command_templates(self, params: dict) -> dict:
        from pwncraft.features.commands.templates import WSL_COMMAND_TEMPLATES, GDB_COMMAND_TEMPLATES

        return {
            "wsl": [
                {
                    "title": item["title"],
                    "command": item.get("template") or item.get("command") or "",
                    "category": item.get("category") or "",
                    "description": item.get("description") or "",
                }
                for item in WSL_COMMAND_TEMPLATES
                if isinstance(item, dict)
            ],
            "gdb": [
                {"title": item[0], "command": item[1], "category": "", "description": ""}
                for item in GDB_COMMAND_TEMPLATES
                if isinstance(item, (list, tuple)) and len(item) >= 2
            ],
        }

    # ------------------------------------------------------------------
    # CLI tools (run inside WSL — ROPgadget / ropper / one_gadget / …)

    def rpc_cli_run(self, params: dict) -> dict:
        tool_id = str(params.get("tool_id") or "").strip()
        values = dict(params.get("values") or {})
        if not tool_id:
            raise ValueError("tool_id 为空")
        binary = str(self._target_binary())
        # 目标路径按各工具真实参数名注入（ropgadget 是 binary，其余是 file），
        # 之前统一塞 "binary" 导致 seccomp-tools/checksec 空参只打印 usage。
        if tool_id in {"ropgadget", "ropper", "seccomp-tools", "checksec"}:
            tool = self._cli.registry.get(tool_id)
            path_names = [str(p.get("name")) for p in tool.parameters if p.get("path")]
            if path_names and not values.get(path_names[0]):
                values[path_names[0]] = binary
        if tool_id == "one_gadget" and not values.get("libc"):
            values["libc"] = str(self._context_libc() or binary)
        command = self._cli.build_command_line(tool_id, values)
        self._log(f"$ {command}")
        outcome = self._cli.execute_only(
            tool_id, values, parser_options={"bits": int(self._bits()), "source": command}
        )
        # seccomp-tools 对菜单循环的程序必然被 timeout(1) 截停（rc=124），
        # 但 dump 早已打印——有输出就是有效观察，不算失败。
        if outcome.error and not (
            tool_id == "seccomp-tools" and outcome.execution.stdout.strip()
        ):
            raise RuntimeError(outcome.error)
        parsed = []
        if tool_id == "ropgadget":
            gadgets = outcome.parsed if isinstance(outcome.parsed, tuple) else ()
            self._gadgets = tuple(gadgets) or self._gadgets
            self.workspace.set_gadgets(gadgets, source=command)
            parsed = [_gadget_to_dict(item) for item in gadgets]
        elif outcome.parsed is not None:
            items = outcome.parsed
            parsed = [
                item.to_dict() if hasattr(item, "to_dict") else str(item)
                for item in (items if isinstance(items, (list, tuple)) else [items])
            ]
        return {
            "command": command,
            "ok": bool(outcome.execution.ok),
            "exit_code": outcome.execution.returncode,
            "stdout": outcome.execution.stdout,
            "stderr": outcome.execution.stderr,
            "parsed": parsed,
        }

    def rpc_cli_env_doctor(self, params: dict) -> dict:
        """Report which allowlisted WSL tools are on PATH + install hints."""
        tools = ("ROPgadget", "ropper", "one_gadget", "seccomp-tools", "checksec", "patchelf")
        report: list[dict] = []
        for tool in tools:
            try:
                result = self._runner.run_tool("sh", ["-lc", f"command -v {shlex.quote(tool)}"])
                present = result.returncode == 0 and bool(result.stdout.strip())
            except Exception:
                present = False
            report.append({
                "tool": tool,
                "present": present,
                "install": f"pip install --user {'ropgadget' if tool == 'ROPgadget' else tool.lower()}",
            })
        return {"tools": report}

    # ------------------------------------------------------------------
    # Auto triage — import-time WSL analysis (ROPgadget / seccomp / fmt)

    _FMT_SINKS = (
        "printf", "fprintf", "dprintf", "sprintf", "snprintf",
        "vprintf", "vfprintf", "vdprintf", "vsprintf", "vsnprintf", "syslog",
    )
    _TRIAGE_GADGET_CAP = 800

    def rpc_auto_triage(self, params: dict) -> dict:
        """Kick off import-time WSL triage in a worker thread.

        The JSON-RPC loop is single-threaded and serialises requests, so the
        long-running scans run in a daemon thread and publish progress via
        ``triage_stage`` events; this call returns immediately.  Results are
        cached per ELF (path + mtime + size) so workspace switches are free.
        """
        binary = Path(params.get("path") or self._target_binary())
        if not is_elf_file(binary):
            raise ValueError(f"不是有效的 ELF 文件: {binary}")
        binary = binary.resolve()
        try:
            target = self.workspace.target or {}
            working = str(target.get("working_binary") or target.get("original_binary") or "")
        except Exception:
            working = ""
        run_binary = Path(working) if working else binary
        key = self._import_cache_key(binary)
        cached = self._triage_cache.get(key)
        if cached:
            return {"cached": True, "result": cached, "binary": str(run_binary)}
        with self._triage_lock:
            if key in self._triage_running:
                return {"started": False, "reason": "already_running", "binary": str(run_binary)}
            self._triage_running.add(key)
        bits = self._bits()
        arch = "i386" if bits == 32 else "amd64"
        thread = threading.Thread(
            target=self._auto_triage_worker,
            args=(run_binary, key, bits, arch),
            daemon=True,
            name="auto-triage",
        )
        thread.start()
        return {"started": True, "binary": str(run_binary), "bits": bits}

    def _triage_event(self, stage: str, status: str, binary: Path, **payload) -> None:
        emit({
            "event": "triage_stage",
            "stage": stage,
            "status": status,
            "binary": str(binary),
            **payload,
        })

    def _auto_triage_worker(self, binary: Path, key: str, bits: int, arch: str) -> None:
        stages: dict[str, dict] = {}
        try:
            stages["ropgadget"] = self._triage_ropgadget(binary, bits)
        except Exception as error:
            stages["ropgadget"] = {"status": "failed", "error": str(error)}
        try:
            stages["seccomp"] = self._triage_seccomp(binary)
        except Exception as error:
            stages["seccomp"] = {"status": "failed", "error": str(error)}
        try:
            stages["fmt"] = self._triage_fmt(binary, bits)
        except Exception as error:
            stages["fmt"] = {"status": "failed", "error": str(error)}
        result = {
            "binary": str(binary),
            "bits": bits,
            "arch": arch,
            "stages": stages,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
        }
        self._triage_cache[key] = result
        with self._triage_lock:
            self._triage_running.discard(key)
        self._triage_event("done", "done", binary, summary={
            stage: info.get("status") for stage, info in stages.items()
        })

    def _triage_ropgadget(self, binary: Path, bits: int) -> dict:
        wsl_path = self._runner.to_wsl_path(binary)
        self._triage_event("ropgadget", "running", binary)
        args = ["--binary", wsl_path, "--only", "pop|ret|syscall", "--depth", "10"]
        command = "ROPgadget " + " ".join(shlex.quote(part) for part in args)
        result = self._runner.run_tool("ropgadget", args, timeout=300)
        text = result.stdout or ""
        if not text.strip() and result.stderr.strip():
            text = result.stderr
        gadgets = parse_ropgadget_output(text, source=command, bits=bits)
        if gadgets:
            # Mirror rpc_cli_run persistence so Shelf/Chain Builder see them.
            self._gadgets = tuple(gadgets)
            self.workspace.set_gadgets(gadgets, source=command)
        summary = {
            "status": "done" if (result.ok or gadgets) else "failed",
            "command": command,
            "returncode": result.returncode,
            "count": len(gadgets),
            "gadgets": [_gadget_to_dict(item) for item in gadgets[: self._TRIAGE_GADGET_CAP]],
            "truncated": len(gadgets) > self._TRIAGE_GADGET_CAP,
        }
        if not result.ok and not gadgets:
            missing = "not found" in result.stderr.lower() or "No such file" in result.stderr
            summary["error"] = (
                "WSL 中未找到 ROPgadget（pip install --user ropgadget）"
                if missing else (result.stderr.strip() or f"返回码 {result.returncode}")
            )
        self._triage_event("ropgadget", summary["status"], binary, result={
            key: summary[key] for key in ("command", "count", "status", "error", "gadgets")
            if key in summary
        })
        return summary

    def _triage_seccomp(self, binary: Path) -> dict:
        wsl_path = self._runner.to_wsl_path(binary)
        self._triage_event("seccomp", "running", binary)
        argv = ["seccomp-tools", "dump", wsl_path]
        command = "seccomp-tools dump " + wsl_path
        result, timed_out = self._runner.run_target_capture(argv, stdin_data=b"", timeout=12)
        text = result.stdout or ""
        dump = parse_seccomp_tools_dump(text)
        found = int(dump.get("rows") or 0) > 0
        summary: dict = {
            "status": "done",
            "command": command,
            "returncode": result.returncode,
            "timed_out": timed_out,
            "found": found,
            "arch": dump.get("arch", ""),
            "default_action": dump.get("default_action", ""),
            "compared": dump.get("compared", []),
            "rows": dump.get("rows", 0),
            "raw": text[:6000],
        }
        if not text.strip():
            stderr = result.stderr.strip()
            if "not found" in stderr.lower() or "No such file" in stderr:
                summary["status"] = "failed"
                summary["error"] = "WSL 中未找到 seccomp-tools（gem install seccomp-tools）"
            else:
                summary["error"] = stderr or "程序退出且未安装 seccomp 过滤器（未见 dump 输出）"
        elif found:
            # Flat policy for downstream verdicts: compared syscalls pass the
            # filter when the default action is a deny; anything else stays
            # UNKNOWN — absence is never claimed as blocked.
            default_action = str(dump.get("default_action") or "")
            if default_action in ("kill", "kill_process", "trap", "errno"):
                policy = {item["name"]: "ALLOWED" for item in dump.get("compared", []) if item.get("name")}
                if policy:
                    policy_text = command
                    self.workspace.set_seccomp_policy(policy, source=policy_text)
                    self.workspace.update_section(
                        "syscalls",
                        {
                            "seccomp_default_action": default_action,
                            "seccomp_dump_source": policy_text,
                            "seccomp_dump_raw": text[:6000],
                        },
                        event="seccomp_changed",
                    )
        # 事件载荷即完整 summary（raw 已截断）：live 首扫与缓存命中走同一
        # 渲染路径，页面不需要二次拉取。
        self._triage_event("seccomp", summary["status"], binary, result=summary)
        return summary

    def _triage_fmt(self, binary: Path, bits: int) -> dict:
        wsl_path = self._runner.to_wsl_path(binary)
        self._triage_event("fmt", "running", binary)
        sinks: list[str] = []
        try:
            dynsyms = self._runner.run_tool("readelf", ["-sW", wsl_path], timeout=60)
            for line in dynsyms.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 8 and parts[6] == "UND":
                    name = parts[7].split("@")[0]
                    if name in self._FMT_SINKS and name not in sinks:
                        sinks.append(name)
        except Exception:
            pass
        marker = "A" * (8 if bits == 64 else 4)
        probe = marker + ".%p" * 24
        # 探针行喂三遍：第一行常被 name/菜单读走（如 CCTF-pwn3），后续行
        # 才到达 fmt 汇点；对一次 read 全量进缓冲的题也无害。
        stdin_data = ((probe + "\n") * 3).encode()
        command = f"printf {shlex.quote((probe + chr(10)) * 3)} | {wsl_path}"
        result, timed_out = self._runner.run_target_capture([wsl_path], stdin_data=stdin_data, timeout=12)
        output = result.stdout or ""
        # Only the text after the echoed probe is %p output; banner hex
        # addresses before it would shift find_fmt_offset's token count.
        probe_echo = output.find(marker)
        leak_text = output[probe_echo:] if probe_echo >= 0 else output
        offset = find_fmt_offset(leak_text, bits=bits) if leak_text.strip() else None
        summary = {
            "status": "done",
            "command": command,
            "returncode": result.returncode,
            "timed_out": timed_out,
            "sinks": sinks,
            "probe": {
                "input": probe,
                "offset": offset,
                "output": output[:4000],
            },
        }
        if offset is None:
            note = (
                "未从探针回显中定位到标记值：程序可能未把 stdin 直接喂给 printf，"
                "或菜单需要先选择选项；可在本页粘贴探针输出手动计算。"
            )
            if not timed_out and result.returncode not in (0, 124):
                note += f"（程序异常退出 rc={result.returncode}：缺配套 libc/ld 时跑不到 fmt 汇点）"
            summary["probe"]["note"] = note
        self._triage_event("fmt", summary["status"], binary, result=summary)
        return summary

    def _bits(self) -> int:
        target = self.workspace.target or {}
        try:
            return int(target.get("bits") or 64)
        except (TypeError, ValueError):
            return 64

    def _context_libc(self) -> str:
        target = self.workspace.target or {}
        return str(target.get("libc") or "")

    # ------------------------------------------------------------------
    # ROP / syscall / ORW / SROP

    def _known_gadgets(self) -> tuple[Gadget, ...]:
        return self._gadgets

    def rpc_gadget_shelf(self, params: dict) -> dict:
        action = str(params.get("action") or "list")
        if action == "pin":
            role = str(params.get("role") or "").strip()
            index = int(params.get("index") or -1)
            if not role or not 0 <= index < len(self._gadgets):
                raise ValueError("收藏 Gadget 需要 role 与有效 index")
            self._shelf.pin(role, self._gadgets[index])
        elif action == "unpin":
            self._shelf.unpin(str(params.get("role") or ""))
        return {
            "shelf": self._shelf.to_dict(),
            "gadgets": [_gadget_to_dict(item) for item in self._gadgets],
        }

    def rpc_gadget_search(self, params: dict) -> dict:
        query = str(params.get("query") or "")
        return {"gadgets": [_gadget_to_dict(item) for item in search_gadgets(self._gadgets, query)]}

    def rpc_rop_build(self, params: dict) -> dict:
        function = params.get("function")
        arguments = dict(params.get("arguments") or {})
        normalized = {}
        for key, value in arguments.items():
            name = {"arg0": "rdi", "arg1": "rsi", "arg2": "rdx", "arg3": "rcx"}.get(str(key), str(key))
            try:
                normalized[name] = int(str(value), 0)
            except (TypeError, ValueError):
                normalized[name] = str(value)
        return_addr = params.get("return_addr")
        try:
            return_addr = int(str(return_addr), 0) if return_addr not in (None, "") else None
        except (TypeError, ValueError):
            return_addr = str(return_addr)
        function_value: int | str
        try:
            function_value = int(str(function), 0)
        except (TypeError, ValueError):
            function_value = str(function or "system")
        builder = RopChainBuilder(shelf=self._shelf, gadgets=self._known_gadgets(), bits=self._bits())
        report = builder.build_call(
            function_value,
            normalized,
            return_addr=return_addr,
            check_alignment=bool(params.get("check_alignment", True)),
        )
        if report.missing:
            raise ValueError(
                "缺少控制这些寄存器的 gadget: " + ", ".join(report.missing)
                + "。先在 Gadget 页运行一次 ROPgadget。"
            )
        report = builder.fix_alignment(report)
        payload = chain_to_pwntools(report.chain)
        return {
            "entries": [
                {
                    "kind": entry.kind,
                    "value": str(entry.value),
                    "gadget": _gadget_to_dict(entry.gadget) if entry.gadget else None,
                }
                for entry in report.chain.entries
            ],
            "warnings": list(report.warnings),
            "pwntools": payload,
        }

    def rpc_srop_plan(self, params: dict) -> dict:
        builder = SROPBuilder(bits=self._bits(), gadgets=self._known_gadgets())
        plan = builder.plan(target=str(params.get("target") or "execve"))
        payload = {"plan": plan.to_dict()}
        try:
            payload["pwntools"] = builder.to_pwntools(plan)
        except ValueError as error:
            payload["pwntools"] = f"# {error}"
        return payload

    def rpc_orw_plan(self, params: dict) -> dict:
        builder = ORWBuilder(bits=self._bits(), gadgets=self._known_gadgets())
        plan = builder.plan(
            path=str(params.get("path") or "/flag"),
            buffer=params.get("buffer", 0x0),
            read_size=params.get("read_size", 0x100),
            output_fd=params.get("output_fd", 1),
            open_variant=str(params.get("open_variant") or "auto"),
        )
        return {"plan": plan.to_dict()}

    def rpc_syscall_table(self, params: dict) -> dict:
        arch = normalize_architecture(str(params.get("arch") or "amd64"))
        table = syscall_table(arch)
        return {
            "arch": arch,
            "syscalls": [
                {
                    "name": spec.name,
                    "number": spec.number,
                    "registers": list(spec.registers),
                    "prototype": spec.prototype,
                }
                for spec in table.values()
            ],
        }

    def rpc_syscall_plan(self, params: dict) -> dict:
        planner = SyscallPlanner()
        plan = planner.plan(
            str(params.get("name") or ""),
            dict(params.get("arguments") or {}),
            architecture=str(params.get("arch") or "amd64"),
        )
        missing = SyscallPlanner.validate_gadgets(plan, self._known_gadgets())
        return {
            "name": plan.spec.name,
            "number": plan.spec.number,
            "registers": dict(plan.registers),
            "missing_registers": list(plan.missing),
            "missing_gadgets": list(missing),
        }

    # ------------------------------------------------------------------
    # libc / fmtstr / cyclic / conversions

    def rpc_leak_derive(self, params: dict) -> dict:
        leak_address = int(str(params.get("address") or "0"), 0)
        offset = int(str(params.get("offset") or "0"), 0)
        base, formula = derive_base(leak_address, offset)
        self.workspace.set_variable(
            WorkspaceVariable(
                "libc_base",
                TypedAddress(base, AddressKind.LIBC_OFFSET, "libc_base"),
                "LeakManager",
                formula,
                address_kind=AddressKind.LIBC_OFFSET,
            )
        )
        return {"libc_base": base, "formula": formula}

    def rpc_cyclic_pattern(self, params: dict) -> dict:
        size = int(params.get("size") or 200)
        n = int(params.get("n") or 4)
        pattern = cyclic_pattern(size, n=n)
        return {"pattern": pattern.decode("ascii", "replace"), "n": n}

    def rpc_cyclic_find(self, params: dict) -> dict:
        value = params.get("value")
        if value is None:
            raise ValueError("需要崩溃值")
        text = str(value).strip()
        try:
            offset = cyclic_find(int(text, 0))
        except ValueError:
            offset = cyclic_find(text)
        if offset is None:
            raise ValueError(f"该值不在 pattern 中: {text}")
        return {"offset": offset}

    def rpc_fmt_offset(self, params: dict) -> dict:
        offset = find_fmt_offset(
            str(params.get("probe_output") or ""),
            bits=int(params.get("bits") or 64),
        )
        if offset is None:
            raise ValueError("探针输出中未找到标记值；确认先发送 AAAAAAAA + %p 序列")
        return {"offset": offset}

    def rpc_fmt_plan(self, params: dict) -> dict:
        plan = plan_fmt_writes(
            int(str(params.get("target") or "0"), 0),
            int(str(params.get("value") or "0"), 0),
            bits=int(params.get("bits") or 64),
        )
        return {"plan": plan.to_dict()}

    def rpc_convert(self, params: dict) -> dict:
        mode = str(params.get("mode") or "int")
        bits = int(params.get("bits") or 64)
        endian = str(params.get("endian") or "little")
        var_name = str(params.get("var_name") or "value")
        results = (
            int_report(str(params.get("value") or "0"), bits=bits, endian=endian, var_name=var_name)
            if mode == "int"
            else bytes_report(str(params.get("value") or ""), bits=bits, endian=endian)
        )
        return {"results": [{"title": item.title, "value": item.value} for item in results]}

    # ------------------------------------------------------------------
    # Heap demo session (real allocator engine + corrections + learning)

    def rpc_heap_templates(self, params: dict) -> dict:
        return {
            "templates": [
                {
                    "template_id": template.template_id,
                    "title": template.title,
                    "category": template.category,
                    "description": template.description,
                    "operation_count": len(template.operations),
                }
                for template in HEAP_TEMPLATES
            ],
            "op_kinds": [
                "alloc", "free", "edit", "show", "derive_value", "copy", "safe_link_fd",
                "overflow_header", "poison_fd", "fake_chunk", "unlink_prepare", "consolidate",
                "malloc_to_target", "leak_main_arena", "stdout_environ_leak", "setcontext_rop",
                "fill_tcache", "drain_tcache", "note",
            ],
        }

    def rpc_heap_load(self, params: dict) -> dict:
        allocator = params.get("allocator") if isinstance(params.get("allocator"), dict) else None
        state = self._heap.load(
            template_id=str(params.get("template_id") or ""),
            scenario_dict=params.get("scenario"),
            source=str(params.get("source") or ""),
            allocator=allocator,
        )
        self._log(f"堆场景已加载：{state['name']} · {len(state['steps'])} 步")
        return state

    def rpc_heap_profiles(self, params: dict) -> dict:
        """glibc 下拉框单一真值：后端注册表支持的 profile 清单。"""
        return {
            "profiles": profile_list(),
            "default_profile_id": "glibc-2.35-amd64",
            "profile_revision": ALLOCATOR_PROFILE_REVISION,
        }

    def rpc_heap_reprofile(self, params: dict) -> dict:
        """版本切换 = Reprofile 事务：换 profile → 整题重识别重放 → 复验 corrections。

        glibc 下拉框 change 走这里（不是 heap_operation）：普通操作不允许
        换 allocator，普通 heap_load 也不复验人工 corrections。
        """
        allocator = params.get("allocator") if isinstance(params.get("allocator"), dict) else None
        if not allocator:
            raise ValueError("heap_reprofile 需要 allocator（profile_id 或 version）")
        state = self._heap.reprofile(allocator)
        info = state.get("reprofile") or {}
        self._log(
            f"Reprofile 完成：{info.get('requested_version') or '?'} → "
            f"{info.get('profile_id') or '?'} · {info.get('replayed_steps', 0)} 步重放 · "
            f"corrections 保留 {info.get('corrections_kept', 0)} / 失效 "
            f"{len(info.get('corrections_invalidated') or [])}"
        )
        if info.get("clamp_note"):
            self._log(f"⚠ {info['clamp_note']}", "warn")
        for item in info.get("corrections_invalidated") or []:
            self._log(f"⚠ 校正已失效：{item.get('address')} — {item.get('reason')}", "warn")
        return state

    def rpc_heap_reverse_edit(self, params: dict) -> dict:
        """Reverse Operation Solver：画布物理写入 → Canonical EDIT + 本题 EXP 渲染。"""
        return self._heap.reverse_edit(
            int(params.get("step") or 0),
            str(params.get("address") or ""),
            str(params.get("data_hex") or ""),
            int(params.get("length") or 8),
        )

    def rpc_heap_apply_pending(self, params: dict) -> dict:
        """「仅用于推演」：反向求解出的 Canonical Operation 追加进操作模型并重放。"""
        canonical = dict(params.get("canonical") or {})
        canonical["python"] = str(params.get("python") or "")
        return self._heap.apply_pending_edit(
            int(params.get("step") or 0), canonical, simulate=True
        )

    def rpc_heap_field_provenance(self, params: dict) -> dict:
        return self._heap.field_provenance(
            int(params.get("step") or 0), str(params.get("address") or "")
        )

    def rpc_heap_chunk_history(self, params: dict) -> dict:
        return self._heap.chunk_history(
            str(params.get("chunk") or ""),
            int(params["upto"]) if "upto" in params else None,
        )

    def rpc_heap_mapping(self, params: dict) -> dict:
        """helper 别名映射管理：addchunk → add 这类「用户词典」。"""
        action = str(params.get("action") or "list")
        if action == "add":
            state = self._heap.set_helper_mapping(
                str(params.get("alias") or ""),
                str(params.get("target") or ""),
                str(params.get("roles") or ""),
            )
            self._log(f"别名映射已添加：{params.get('alias')} → {params.get('target')}（识别已重算）")
            return state
        if action == "remove":
            state = self._heap.remove_helper_mapping(str(params.get("alias") or ""))
            self._log(f"别名映射已删除：{params.get('alias')}（识别已重算）")
            return state
        return {"mappings": [dict(item) for item in self._heap.scenario.helper_mappings]}

    def rpc_heap_state(self, params: dict) -> dict:
        return self._heap.state()

    def rpc_heap_canonical_python(self, params: dict) -> dict:
        """Canonical Operation → EXP 行（HelperContract 驱动，不可证明则 safe=False）。"""
        return self._heap.live_op_python(
            str(params.get("kind") or ""),
            chunk=str(params.get("chunk") or ""),
            request_size=str(params.get("request_size") or ""),
            data=str(params.get("data") or ""),
            offset=str(params.get("offset") or ""),
        )

    def rpc_heap_operation(self, params: dict) -> dict:
        """操作表单入口：malloc/free/edit/show → HeapOperation → 引擎重放。

        语义全部在 AllocatorEngine 里推导（request2size、bin 搜索顺序、写入
        provenance），这里只转发表单字段；Canvas 拿到的是新 snapshot。
        """
        kind = str(params.get("kind") or "").strip()
        state = self._heap.append_operation(
            kind,
            chunk=str(params.get("chunk") or ""),
            request_size=str(params.get("request_size") or ""),
            data=str(params.get("data") or ""),
            offset=str(params.get("offset") or ""),
            note=str(params.get("label") or params.get("note") or ""),
        )
        appended = state.get("appended_operation") or {}
        self._log(f"堆操作已执行：{appended.get('title') or kind}（共 {len(state.get('steps') or [])} 步）")
        return state

    def rpc_heap_correct(self, params: dict) -> dict:
        step = int(params.get("step") or 0)
        patch = dict(params.get("patch") or {})
        context = dict(params.get("context") or {})
        intent = str(params.get("intent") or "correction")
        result = self._heap.correct(step, patch, context, intent=intent)
        if result.get("accepted"):
            added = result.get("learned_rules_added") or []
            for rule in added:
                self._log(f"识别规则已学会：{rule.get('reason')}")
            # 整包 heap_state 随响应返回：前端 commitSnapshot 原子提交，
            # 画布/操作表/学习面板永远来自同一 snapshot。
            result["heap_state"] = self._heap.state()
            self._log("画布校正已提交，后续状态已实时重算。")
        return result

    def rpc_heap_structural_edit(self, params: dict) -> dict:
        """Atomic allocator-model edit; never routed through memory patching.

        校验失败 / allocator 拒绝 → {ok: False, reason, code}（结构化拒绝，
        不再是裸异常字符串），前端据此在画布上展示拒绝原因。
        """
        try:
            result = self._heap.structural_edit(
                int(params.get("step") or 0),
                kind=str(params.get("kind") or ""),
                chunk_id=str(params.get("chunk_id") or ""),
                physical_id=str(params.get("physical_id") or ""),
                delta=int(str(params.get("delta") or "0x10"), 0),
                edge=str(params.get("edge") or "bottom"),
                data_hex=str(params.get("data_hex") or ""),
                after_user_offset=int(str(params.get("after_user_offset") or "-1"), 0),
            )
        except ValueError as error:
            return {"ok": False, "code": "structural_rejected", "reason": str(error)}
        except Exception as error:  # 兜底：引擎内部异常绝不穿透 bridge
            return {"ok": False, "code": "structural_error",
                    "reason": f"{type(error).__name__}: {error}"}
        edit = result.get("structural_edit") or {}
        self._log(
            f"堆结构编辑已原子提交: {edit.get('kind')} "
            f"{edit.get('chunk_id')} {edit.get('edge') or ''}"
            f"{'@' + str(edit.get('after_user_offset')) if edit.get('after_user_offset') is not None else ''}"
            f"{edit.get('delta')} · {edit.get('exp_status') or ''}"
        )
        if edit.get("exp_status") in {"pending", "pending_inplace"}:
            self._log(f"待确认：{edit.get('exp_reason')}")
        return {"ok": True, **result}

    def rpc_heap_undo_correction(self, params: dict) -> dict:
        outcome = self._heap.undo_correction()
        if not outcome.get("ok", True):
            return outcome
        return {"ok": True, **outcome}

    # ------------------------------------------------------------------
    # Training data layer：Case Export / Agent Review / Recognition 标注

    def rpc_heap_export_case(self, params: dict) -> dict:
        """导出一题为固定 schema 的训练 case（generated 层）。

        target 的 binary/libc/ld sha256 由前端在已知时提供；exp 源码哈希、
        helper CFG 指纹、engine/recognizer/allocator revision 由后端补齐。
        path 给定时同时落盘（调用方负责放进 generated/）。
        """
        target = params.get("target") if isinstance(params.get("target"), dict) else {}
        case = self._heap.export_case(
            target=target,
            challenge_family=str(params.get("challenge_family") or ""),
            include_snapshots=bool(params.get("include_snapshots", True)),
        )
        issues = validate_case(case)
        response = {"case": case, "validation": {"valid": not issues, "issues": issues}}
        path = str(params.get("path") or "").strip()
        if path:
            Path(path).write_text(
                json.dumps({"schema_version": "1.0", "case": case}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            response["path"] = path
            self._log(f"训练 Case 已导出：{path}（{len(case.get('snapshots') or [])} 快照 · "
                      f"{case['engine']['allocator_profile_id']}）")
        else:
            self._log(f"训练 Case 已生成：{case['case_id']}（engine {case['engine']['version']} · "
                      f"{case['engine']['recognizer_revision']}）")
        return response

    def rpc_heap_import_review(self, params: dict) -> dict:
        """导入外部 Agent 审查条目：只进 review 标签层，绝不改 Snapshot。"""
        payload = params.get("review") if isinstance(params.get("review"), dict) else None
        path = str(params.get("path") or "").strip()
        if payload is None and path:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
            if isinstance(payload, dict) and isinstance(payload.get("review"), dict):
                payload = payload["review"]
        if payload is None:
            raise ValueError("heap_import_review 需要 review 对象或 path")
        result = self._heap.import_review(payload)
        review = result["review"]
        self._log(f"Agent Review 已导入：{review['review_id']} · {review['issue_type']} · "
                  f"verdict={review['verdict']}（快照未改动）")
        return result

    def rpc_heap_apply_review(self, params: dict) -> dict:
        """Replay Validator：干跑重放 + hard invariants → proposed/validated/accepted/rejected。"""
        result = self._heap.apply_review(
            str(params.get("review_id") or ""),
            human_confirmed=bool(params.get("human_confirmed", False)),
        )
        review = result["review"]
        validation = review.get("validation") or {}
        self._log(
            f"Review {review['review_id']} 验证完成：verdict={review['verdict']}"
            + (f" · {'；'.join(validation.get('issues') or [])}" if validation.get("issues") else "")
        )
        return result

    def rpc_heap_validate_case(self, params: dict) -> dict:
        payload = params.get("case") if isinstance(params.get("case"), dict) else None
        path = str(params.get("path") or "").strip()
        if payload is None and path:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
            if isinstance(payload, dict) and isinstance(payload.get("case"), dict):
                payload = payload["case"]
        if payload is None:
            raise ValueError("heap_validate_case 需要 case 对象或 path")
        issues = validate_case(payload)
        return {"valid": not issues, "issues": issues,
                "case_id": str((payload or {}).get("case_id") or "")}

    def rpc_heap_label_candidate(self, params: dict) -> dict:
        """ RecognitionCorrection：对 ambiguous/unknown 候选的一等用户标注。"""
        state = self._heap.label_recognition(
            int(params.get("line") or 0),
            str(params.get("function") or ""),
            str(params.get("semantic") or ""),
            # 位置敏感：roles 原样透传（{"arg0": null, ...} / 列表 / 逗号串），
            # 绝不在这里压缩或转字符串 —— arg0 未知必须以 null 占位。
            params.get("roles"),
            source_text=str(params.get("source_text") or ""),
        )
        correction = state.get("recognition_correction") or {}
        bound = [f"{arg}={role}" for arg, role in (correction.get("roles") or {}).items() if role]
        self._log(
            f"识别标注已生效：L{correction.get('source_line')} {correction.get('function')} "
            f"→ {correction.get('semantic')}"
            + (f"（{'，'.join(bound)}）" if bound else "")
            + " · 识别已重算"
        )
        return state

    def rpc_heap_learn(self, params: dict) -> dict:
        roles = params.get("roles") if isinstance(params.get("roles"), list) else None
        return self._heap.learn(
            str(params.get("function") or ""),
            str(params.get("semantic") or ""),
            roles=[str(item) for item in roles or []],
            reason=str(params.get("reason") or ""),
        )

    def rpc_heap_rule_toggle(self, params: dict) -> dict:
        return self._heap.set_rule_enabled(
            str(params.get("rule_id") or ""), bool(params.get("enabled", True))
        )

    def rpc_heap_save(self, params: dict) -> dict:
        path = str(params.get("path") or "").strip()
        if not path:
            raise ValueError("保存路径为空")
        Path(path).write_text(
            json.dumps(self._heap.to_payload(), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return {"path": path}

    def rpc_heap_open(self, params: dict) -> dict:
        path = str(params.get("path") or "").strip()
        if not path:
            raise ValueError("打开路径为空")
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return self._heap.load_payload(payload)

    # ------------------------------------------------------------------
    # IO FILE

    @staticmethod
    def _parse_glibc_version(text: str) -> tuple[int, int]:
        raw = str(text or "2.35").strip().lstrip("glibc ").strip()
        major, _, minor = raw.partition(".")
        try:
            return (int(major or 2), int(minor or 35))
        except ValueError:
            return (2, 35)

    def rpc_iofile_layout(self, params: dict) -> dict:
        layout = GlibcFileLayoutDatabase.get(
            self._parse_glibc_version(str(params.get("version") or "2.35")),
            bits=int(params.get("bits") or 64),
        )
        return {
            "version": f"{layout.version[0]}.{layout.version[1]}",
            # 版本清单单一真值：前端下拉从这里渲染，不再各写一份（2.29 曾经前端有、后端没有）
            "supported_versions": [
                f"{major}.{minor}" for major, minor in GlibcFileLayoutDatabase.SUPPORTED
            ],
            "file_size": layout.file_size,
            "plus_size": layout.plus_size,
            "wide_size": layout.wide_size,
            "fields": [
                {
                    "name": field.name,
                    "offset": field.offset,
                    "width": field.width,
                    "kind": field.kind,
                    "description": field.description,
                }
                for field in layout.fields
            ],
            "wide_fields": [
                {
                    "name": field.name,
                    "offset": field.offset,
                    "width": field.width,
                    "kind": field.kind,
                    "description": field.description,
                }
                for field in layout.wide_fields
            ],
        }

    def rpc_iofile_validate(self, params: dict) -> dict:
        layout = GlibcFileLayoutDatabase.get(
            self._parse_glibc_version(str(params.get("version") or "2.35")),
            bits=int(params.get("bits") or 64),
        )
        snapshot = FileSnapshot.empty(layout, symbol=str(params.get("symbol") or "stdout"))
        # apply any provided observed values first, then validate the edit
        for name, value in dict(params.get("values") or {}).items():
            snapshot = snapshot.edit(name, int(str(value), 0), provenance="observed")
        validation = FileConstraintEngine(
            tuple((int(a, 0), int(b, 0)) for a, b in list(params.get("mapped_ranges") or []))
        ).validate_edit(
            snapshot,
            str(params.get("name") or ""),
            int(str(params.get("value") or "0"), 0),
            observed=bool(params.get("observed", False)),
        )
        return {
            "status": validation.status.value,
            "issues": list(validation.issues),
            "accepted": validation.accepted,
        }

    def rpc_iofile_analyze(self, params: dict) -> dict:
        evidence = analyze_file_source(str(params.get("source") or ""))
        return {
            "evidence": [
                {
                    "line": item.line,
                    "symbol": item.symbol,
                    "expression": item.expression,
                    "provenance": item.provenance,
                }
                for item in evidence
            ]
        }

    # ------------------------------------------------------------------
    # pwndbg-mogai debugger (isolated fork; official pwndbg untouched)

    def rpc_pwndbg_status(self, params: dict) -> dict:
        return {
            "version": PWNDBG_MOGAI_VERSION,
            "installed": self._pwndbg.is_installed(),
        }

    def rpc_pwndbg_ensure(self, params: dict) -> dict:
        path = self._pwndbg.ensure_installed(progress=lambda message: self._log(message))
        return {"command": path, "version": PWNDBG_MOGAI_VERSION}

    def rpc_debug_launch(self, params: dict) -> dict:
        """Prepare the pre-arranged pwndbg-mogai terminal for the Target.

        The Electron main process opens a *new* terminal instance (node-pty)
        that runs the returned launch script: real PTY, pwndbg-mogai, the
        working-copy ELF already loaded, startup flags applied, and
        `starti` for x86/i386 ELFs.
        """
        binary = Path(str(params.get("path") or "") or self._target_binary())
        self._pwndbg.ensure_installed(progress=lambda message: self._log(message))
        spec = self._pwndbg.launch_spec(binary)
        project_path = Path(str(self.workspace.project.get("project_path") or binary.parent))
        work_dir = project_path / ".pwncraft" / "work"
        work_dir.mkdir(parents=True, exist_ok=True)
        script = work_dir / "debug_launch.sh"
        command_text = " ".join(spec.pty_command[2:]) if len(spec.pty_command) > 2 else ""
        script.write_text(
            "#!/bin/sh\n# 由 PwnCraft 生成：pwndbg-mogai 独立调试终端（官方 pwndbg 未改动）\n"
            + command_text + "\n",
            encoding="utf-8",
        )
        script_wsl = self._runner.to_wsl_path(str(script))
        self._log(f"调试终端脚本已生成：{script_wsl}")
        return {
            "script_wsl_path": script_wsl,
            "command": command_text,
            "elf_wsl_path": spec.elf_wsl_path,
            "architecture": spec.target_architecture,
            "auto_start": spec.auto_start,
            "version": spec.version,
        }


_EMIT_LOCK = threading.Lock()


def emit(payload: dict) -> None:
    # Worker threads (auto triage) emit alongside the stdin loop, so writes
    # must stay line-atomic or the renderer would parse split JSON.
    with _EMIT_LOCK:
        sys.stdout.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")
        sys.stdout.flush()


def main() -> int:
    bridge = ElectronBridge()
    emit({"event": "hello", "app": APP_NAME, "version": APP_VERSION})
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            request = json.loads(raw)
        except json.JSONDecodeError as error:
            emit({"id": None, "ok": False, "error": f"JSON 解析失败: {error}"})
            continue
        request_id = request.get("id")
        try:
            result = bridge.handle(request)
            emit({"id": request_id, "ok": True, "result": result})
        except Exception as error:
            emit({
                "id": request_id,
                "ok": False,
                "error": str(error),
                "trace": traceback.format_exc(limit=4),
            })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
