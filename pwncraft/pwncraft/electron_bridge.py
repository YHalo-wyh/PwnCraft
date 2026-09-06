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
"""
from __future__ import annotations

import json
import shlex
import sys
import threading
import traceback
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
from pwncraft.core.syscalls import syscall_table, normalize_architecture, parse_seccomp_tools_dump
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
                outcome = auto_patch_elf(target_binary)
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
                result = self._runner.run_tool("objdump", ["-d", "--",
                                                          self._runner.to_wsl_path(binary)])
                if result.ok:
                    response.update(parse_disassembly(result.stdout))
                    response["notice"] = result.stderr.strip()
                else:
                    response["assembly_error"] = result.combined_output() or f"objdump 退出码 {result.returncode}"
            except Exception as error:
                response["assembly_error"] = str(error)
        return response

    def rpc_workspace_get(self, params: dict) -> dict:
        return {
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
