"""Unified CLI tool execution service for QUERY tools.

The service connects the CliToolRegistry (definitions), an executor
(WSL command line or a test double), result parsers and the PwnWorkspace.
QUERY tools may only publish structured facts; they can never mutate the
exploit source, which is enforced here and not by each page.
"""
from __future__ import annotations

from dataclasses import dataclass
import shlex
from typing import Callable, Mapping, Protocol

from .cli_registry import CliToolRegistry, default_cli_tools
from .wsl import WslToolRunner
from .gadgets import parse_ropgadget_output
from .static_facts import (
    SymbolFacts,
    parse_objdump_plt,
    parse_objdump_relocations,
    parse_readelf_dynsyms,
)


@dataclass(frozen=True)
class CliExecution:
    """Raw command evidence before parsing."""

    tool_id: str
    executable: str
    argv: tuple[str, ...]
    command: str
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def output(self) -> str:
        return "\n".join(part for part in (self.stdout.strip(), self.stderr.strip()) if part)


class CliExecutor(Protocol):
    def execute(self, executable: str, argv: list[str]) -> CliExecution: ...


class WslCliExecutor:
    """Run allowlisted query tools inside WSL through the audited runner."""

    def __init__(self, runner: WslToolRunner | None = None):
        self.runner = runner or WslToolRunner()

    def execute(self, executable: str, argv: list[str]) -> CliExecution:
        result = self.runner.run_tool(executable, argv)
        return CliExecution(
            "",
            executable,
            tuple(result.command),
            " ".join(str(part) for part in result.command),
            result.returncode,
            result.stdout,
            result.stderr,
        )


@dataclass(frozen=True)
class ToolOutcome:
    tool_id: str
    execution: CliExecution
    parsed: object = None
    error: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.execution.ok) and not self.error


_TOOL_FAMILIES: dict[str, str] = {
    "checksec": "checksec",
    "ropgadget": "ropgadget",
    "readelf.dynsyms": "symbols",
    "readelf.notes": "build_id",
    "objdump.relocations": "got",
    "objdump.plt": "plt",
    "seccomp-tools": "seccomp",
    "one_gadget": "one_gadget",
}


class CliToolService:
    """Execute registry tools and apply their parsed facts to one workspace."""

    def __init__(self, executor: CliExecutor | None = None, registry: CliToolRegistry | None = None):
        self.registry = registry or default_cli_tools()
        self.executor = executor

    # ------------------------------------------------------------------
    # Command composition.  The preview string is shell-quoted for humans;
    # ``build_argv`` returns raw tokens because run_tool feeds a list to
    # subprocess without an intermediate shell.

    def build_command_line(self, tool_id: str, values: Mapping[str, object] | None = None) -> str:
        tool = self.registry.get(tool_id)
        merged = self._merge_values(tool.id, values)
        return self.registry.build_command(tool, merged)

    def build_argv(self, tool_id: str, values: Mapping[str, object] | None = None) -> tuple[str, list[str]]:
        tool = self.registry.get(tool_id)
        merged = self._merge_values(tool.id, values)
        converter = getattr(getattr(self.executor, "runner", None), "to_wsl_path", None) or (lambda value: str(value))
        argv: list[str] = []
        for parameter in tool.parameters:
            name = str(parameter.get("name", ""))
            flag = str(parameter.get("flag", name))
            value = merged.get(name)
            if value in (None, "", False):
                continue
            rendered = converter(value) if parameter.get("path") else str(value)
            if flag.endswith("="):
                argv.append(flag + rendered)
            elif flag == "":
                argv.append(rendered)
            elif value is True:
                argv.append(flag)
            else:
                argv.extend((flag, rendered))
        return tool.executable, argv

    def _merge_values(self, tool_id: str, values: Mapping[str, object] | None) -> dict[str, object]:
        tool = self.registry.get(tool_id)
        merged: dict[str, object] = {}
        for parameter in tool.parameters:
            name = str(parameter.get("name", ""))
            declared = parameter.get("value")
            if declared is not None:
                merged[name] = declared
        if values:
            merged.update({key: item for key, item in dict(values).items() if item not in (None, "")})
        return merged

    # ------------------------------------------------------------------
    # Parsing

    def _parser_for(self, tool_id: str, options: Mapping[str, object]) -> Callable[[str], object] | None:
        if tool_id == "ropgadget":
            bits = int(options.get("bits") or 64)
            base_raw = options.get("base")
            base = int(base_raw) if base_raw is not None else None
            source = str(options.get("source") or "ROPgadget")

            def parse_gadgets(text: str) -> object:
                return parse_ropgadget_output(text, source=source, bits=bits, base=base)

            return parse_gadgets
        parsers: dict[str, Callable[[str], object]] = {
            "checksec": self._checksec_parser(),
            "readelf.dynsyms": parse_readelf_dynsyms,
            "readelf.notes": self._build_id_parser(),
            "objdump.relocations": parse_objdump_relocations,
            "objdump.plt": parse_objdump_plt,
            "seccomp-tools": self._seccomp_parser(),
            "one_gadget": self._one_gadget_parser(),
        }
        return parsers.get(tool_id)

    @staticmethod
    def _build_id_parser() -> Callable[[str], object]:
        from .libc import parse_build_id

        return parse_build_id

    @staticmethod
    def _one_gadget_parser() -> Callable[[str], object]:
        from .libc import parse_one_gadget_output

        return parse_one_gadget_output

    @staticmethod
    def _checksec_parser() -> Callable[[str], object]:
        from .workbench import parse_checksec_output

        return parse_checksec_output

    @staticmethod
    def _seccomp_parser() -> Callable[[str], object]:
        from .syscalls import parse_seccomp_policy

        return parse_seccomp_policy

    # ------------------------------------------------------------------
    # Execution

    def execute_only(
        self,
        tool_id: str,
        values: Mapping[str, object] | None = None,
        *,
        parser_options: Mapping[str, object] | None = None,
    ) -> ToolOutcome:
        if self.executor is None:
            raise RuntimeError("当前没有可用的命令执行器（WSL 未配置时只允许复制命令）")
        executable, argv = self.build_argv(tool_id, values)
        started = self.executor.execute(executable, argv)
        execution = CliExecution(
            str(tool_id),
            started.executable,
            tuple(started.argv),
            started.command,
            started.returncode,
            started.stdout,
            started.stderr,
        )
        parsed = None
        error = ""
        parser = self._parser_for(str(tool_id), dict(parser_options or {}))
        if parser is not None:
            try:
                parsed = parser(execution.output())
            except Exception as exc:  # a broken parser must never invent facts
                error = f"解析失败: {exc}"
        if not execution.ok and not error:
            error = f"返回码 {execution.returncode}"
        return ToolOutcome(str(tool_id), execution, parsed, error)

    # ------------------------------------------------------------------
    # Workspace application.  QUERY results publish explicit events with
    # provenance and never touch exploit state.

    def apply_outcome(self, workspace, outcome: ToolOutcome) -> None:
        apply_tool_outcome(workspace, outcome)

    def run_and_apply(
        self,
        workspace,
        tool_id: str,
        values: Mapping[str, object] | None = None,
        **options: object,
    ) -> ToolOutcome:
        outcome = self.execute_only(tool_id, values, parser_options=options)
        apply_tool_outcome(workspace, outcome)
        return outcome


def apply_tool_outcome(workspace, outcome: ToolOutcome) -> None:
    """Publish one parsed QUERY outcome into the workspace.

    Module-level on purpose: worker threads must compute only, and the
    GUI thread calls this inside a queued slot where synchronous workspace
    event listeners are safe.
    """
    from .workspace import PwnWorkspace

    assert isinstance(workspace, PwnWorkspace)
    family = _TOOL_FAMILIES.get(outcome.tool_id)
    evidence = outcome.execution.command
    if outcome.tool_id == "checksec":
        security = outcome.parsed if isinstance(outcome.parsed, dict) else {}
        known = {key: value for key, value in security.items() if value != "UNKNOWN"}
        if known:
            workspace.update_section(
                "binary",
                {"security": known, "security_source": evidence},
                event="binary_loaded",
            )
    elif family == "ropgadget":
        gadgets = tuple(outcome.parsed) if isinstance(outcome.parsed, (tuple, list)) else ()
        workspace.set_gadgets(gadgets, source=evidence)
    elif family == "symbols" and isinstance(outcome.parsed, SymbolFacts):
        functions = dict(workspace.symbols.get("functions") or {})
        functions.update(outcome.parsed.functions)
        objects_merged = dict(workspace.symbols.get("objects") or {})
        objects_merged.update(outcome.parsed.objects)
        imports = sorted(set(workspace.symbols.get("imports") or ()) | set(outcome.parsed.imports))
        workspace.update_section(
            "symbols",
            {
                "functions": functions,
                "objects": objects_merged,
                "imports": imports,
                "functions_source": evidence,
            },
            event="symbols_changed",
        )
    elif family in ("got", "plt") and isinstance(outcome.parsed, dict):
        key = "got" if family == "got" else "plt"
        section_key = f"{key}_source"
        merged = dict(workspace.symbols.get(key) or {})
        merged.update(outcome.parsed)
        workspace.update_section(
            "symbols",
            {key: merged, section_key: evidence},
            event="symbols_changed",
        )
    elif family == "seccomp" and isinstance(outcome.parsed, dict):
        if outcome.parsed:
            workspace.set_seccomp_policy(dict(outcome.parsed), source=evidence)
    elif family == "build_id" and isinstance(outcome.parsed, str) and outcome.parsed:
        workspace.update_section(
            "binary",
            {"build_id": outcome.parsed, "build_id_source": evidence},
            event="binary_loaded",
        )
    elif family == "one_gadget" and isinstance(outcome.parsed, (tuple, list)):
        gadgets = [item.to_dict() if hasattr(item, "to_dict") else item for item in outcome.parsed]
        workspace.set_one_gadgets(gadgets, source=evidence)
