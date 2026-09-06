from __future__ import annotations

from dataclasses import dataclass
import shlex
from typing import Iterable

from .tool_actions import ActionType


@dataclass(frozen=True)
class CliTool:
    id: str
    name: str
    executable: str
    category: str
    action_type: ActionType
    description_zh: str
    parameters: tuple[dict[str, object], ...] = ()
    examples: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "executable": self.executable,
            "category": self.category,
            "action_type": self.action_type.value,
            "description_zh": self.description_zh,
            "parameters": [dict(item) for item in self.parameters],
            "examples": list(self.examples),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "CliTool":
        return cls(
            id=str(payload.get("id", "")),
            name=str(payload.get("name", "")),
            executable=str(payload.get("executable", "")),
            category=str(payload.get("category", "")),
            action_type=ActionType(str(payload.get("action_type", ActionType.QUERY.value)).upper()),
            description_zh=str(payload.get("description_zh", "")),
            parameters=tuple(dict(item) for item in payload.get("parameters", ()) if isinstance(item, dict)),
            examples=tuple(str(item) for item in payload.get("examples", ())),
        )


class CliToolRegistry:
    def __init__(self, tools: Iterable[CliTool] = ()):
        self._tools: dict[str, CliTool] = {}
        for tool in tools:
            self.register(tool)

    def register(self, tool: CliTool) -> CliTool:
        key = str(tool.id).strip()
        if not key:
            raise ValueError("CLI 工具必须有 id")
        if key in self._tools:
            raise ValueError(f"重复 CLI 工具: {key}")
        if not isinstance(tool.action_type, ActionType):
            raise TypeError("CLI 工具 action_type 必须是 ActionType")
        self._tools[key] = tool
        return tool

    def get(self, tool_id: str) -> CliTool:
        key = str(tool_id).strip()
        try:
            return self._tools[key]
        except KeyError as exc:
            raise KeyError(f"未知 CLI 工具: {tool_id}") from exc

    def find(self, query: str = "") -> tuple[CliTool, ...]:
        needle = str(query).strip().casefold()
        return tuple(item for item in self._tools.values() if not needle or needle in " ".join((item.id, item.name, item.description_zh)).casefold())

    def values(self) -> tuple[CliTool, ...]:
        return tuple(self._tools.values())

    def to_dict(self) -> list[dict[str, object]]:
        return [item.to_dict() for item in self._tools.values()]

    @staticmethod
    def build_command(tool: CliTool, values: dict[str, object]) -> str:
        parts = [tool.executable]
        for parameter in tool.parameters:
            name = str(parameter.get("name", ""))
            value = values.get(name)
            if value in (None, "", False):
                continue
            flag = str(parameter.get("flag", name))
            if value is True:
                parts.append(flag)
            elif flag.endswith("="):
                # Styles like checksec --file=PATH must stay one token.
                parts.append(flag + shlex.quote(str(value)))
            elif flag in ("", "--"):
                # Positional arguments carry no option prefix.
                parts.append(shlex.quote(str(value)))
            else:
                parts.extend((flag, shlex.quote(str(value))))
        return " ".join(parts)


def default_cli_tools() -> CliToolRegistry:
    return CliToolRegistry(
        (
            CliTool(
                "ropgadget",
                "ROPgadget",
                "ROPgadget",
                "ROP",
                ActionType.QUERY,
                "查询目标文件中的 Gadget。",
                (
                    {"name": "binary", "flag": "--binary", "description_zh": "目标 ELF 文件路径", "path": True},
                    {"name": "only", "flag": "--only", "description_zh": "只保留由指定指令组成的 Gadget，例如 pop|ret"},
                    {"name": "badbytes", "flag": "--badbytes", "description_zh": "排除包含这些坏字节的地址，例如 000a"},
                    {"name": "filter", "flag": "--filter", "description_zh": "按子串过滤反汇编文本，例如 'pop rdi'"},
                    {"name": "string", "flag": "--string", "description_zh": "搜索包含指定字符串的 Gadget"},
                    {"name": "depth", "flag": "--depth", "description_zh": "搜索深度（字节），越大越慢"},
                    {"name": "range", "flag": "--range", "description_zh": "限制地址范围 start-end，例如 0x1000-0x2000"},
                    {"name": "nop_count", "flag": "--norop", "description_zh": "跳过 ROP 搜索（组合开关）", "kind": "advanced"},
                ),
                (
                    'ROPgadget --binary ./pwn --only "pop|ret"',
                    'ROPgadget --binary ./pwn --only "pop|ret" --badbytes "000a" --depth 10',
                ),
            ),
            CliTool(
                "ropper",
                "ropper",
                "ropper",
                "ROP",
                ActionType.QUERY,
                "交互式查询并筛选 Gadget。",
                (
                    {"name": "file", "flag": "--file", "description_zh": "目标 ELF 文件路径", "path": True},
                    {"name": "search", "flag": "--search", "description_zh": "按模式搜索 Gadget"},
                ),
                ('ropper --file ./pwn --search "pop rdi"',),
            ),
            CliTool(
                "readelf.header",
                "readelf -h",
                "readelf",
                "ELF",
                ActionType.QUERY,
                "读取 ELF 头：类型、架构、入口地址。",
                ({"name": "file", "flag": "-h", "description_zh": "ELF 文件路径", "path": True, "fixed_value": True},),
                ("readelf -h ./pwn",),
            ),
            CliTool(
                "readelf.dynsyms",
                "readelf 动态符号",
                "readelf",
                "ELF",
                ActionType.QUERY,
                "读取动态符号表：导出函数、导入符号与版本信息。",
                ({"name": "file", "flag": "-sW", "description_zh": "ELF 文件路径", "path": True},),
                ("readelf -sW ./pwn",),
            ),
            CliTool(
                "readelf.notes",
                "readelf Build ID",
                "readelf",
                "ELF",
                ActionType.QUERY,
                "读取 ELF notes，获取 Build ID 用于确认 libc 与题目的配对。",
                ({"name": "file", "flag": "-nW", "description_zh": "ELF/libc 文件路径", "path": True},),
                ("readelf -nW libc.so.6",),
            ),
            CliTool(
                "objdump.relocations",
                "objdump -R（GOT）",
                "objdump",
                "ELF",
                ActionType.QUERY,
                "读取动态重定位表，得到 puts 等符号的 GOT 槽位地址。",
                ({"name": "file", "flag": "-R", "description_zh": "ELF 文件路径", "path": True},),
                ("objdump -R ./pwn",),
            ),
            CliTool(
                "objdump.plt",
                "objdump .plt",
                "objdump",
                "ELF",
                ActionType.QUERY,
                "从反汇编中读取 PLT 桩地址，例如 puts@plt。",
                (
                    {"name": "file", "flag": "-d", "description_zh": "ELF 文件路径", "path": True},
                    {"name": "section_plt", "flag": "-j", "value": ".plt", "description_zh": "只看 .plt 节"},
                ),
                ("objdump -d -j .plt ./pwn",),
            ),
            CliTool(
                "strings",
                "strings",
                "strings",
                "ELF",
                ActionType.QUERY,
                "提取可打印字符串，常用于找 /bin/sh。",
                ({"name": "file", "flag": "", "description_zh": "目标文件路径", "path": True},),
                ("strings ./pwn | grep /bin/sh",),
            ),
            CliTool("checksec", "checksec", "checksec", "ELF", ActionType.QUERY, "检查 ELF 安全保护。", ({"name": "file", "flag": "--file=", "description_zh": "ELF 文件路径", "path": True},), ("checksec --file=./pwn",)),
            CliTool("one_gadget", "one_gadget", "one_gadget", "Libc", ActionType.QUERY, "列出 one_gadget 及其约束。", ({"name": "libc", "flag": "", "description_zh": "libc 文件路径", "path": True},), ("one_gadget libc.so.6",)),
            CliTool("seccomp-tools", "seccomp-tools", "seccomp-tools", "Syscall", ActionType.QUERY, "解析 seccomp 过滤器。", ({"name": "action", "flag": "", "value": "dump", "description_zh": "固定为 dump 子命令"}, {"name": "file", "flag": "", "description_zh": "目标程序路径", "path": True},), ("seccomp-tools dump ./pwn",)),
            CliTool("patchelf", "patchelf", "patchelf", "ELF", ActionType.QUERY, "读取或验证 ELF loader/rpath。"),
            CliTool("ldd", "ldd", "ldd", "ELF", ActionType.QUERY, "查看动态库依赖。", ({"name": "file", "flag": "", "description_zh": "ELF 文件路径", "path": True},), ("ldd ./pwn",)),
            CliTool("gdb", "gdb", "gdb", "Debug", ActionType.RUNTIME, "启动或连接隔离调试会话。"),
            CliTool("pwndbg-mogai", "pwndbg-mogai", "pwndbg-mogai", "Debug", ActionType.RUNTIME, "启动 PwnCraft 隔离的中文化 pwndbg。"),
        )
    )
