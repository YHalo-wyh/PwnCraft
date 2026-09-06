from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class SnippetParameter:
    name: str
    default: str = ""
    description: str = ""


@dataclass(frozen=True)
class SnippetDefinition:
    snippet_id: str
    title: str
    category: str
    description: str
    source_template: str
    operations: tuple[str, ...] = ()
    parameters: tuple[SnippetParameter, ...] = ()
    minimum_glibc: tuple[int, int] | None = None
    maximum_glibc: tuple[int, int] | None = None
    historical_after: tuple[int, int] | None = None
    structure_type: str = "heap"

    def compatibility(self, version: tuple[int, int]) -> tuple[str, str]:
        if self.minimum_glibc and version < self.minimum_glibc:
            return "unsupported", f"需要 glibc >= {self.minimum_glibc[0]}.{self.minimum_glibc[1]}"
        if self.maximum_glibc and version > self.maximum_glibc:
            return "historical", f"当前 glibc {version[0]}.{version[1]} 仅作历史/学习模板"
        if self.historical_after and version >= self.historical_after:
            return "historical", f"glibc >= {self.historical_after[0]}.{self.historical_after[1]} 检查已变化"
        return "supported", "生成真实 EXP 调用；最终状态仍由 Analyzer/allocator/runtime 判定"

    def render(self, values: Mapping[str, str], helper_names: Mapping[str, str] | None = None) -> str:
        context = {item.name: values.get(item.name, item.default) for item in self.parameters}
        context.update({
            "alloc": "add",
            "free": "delete",
            "edit": "edit",
            "show": "show",
            **dict(helper_names or {}),
        })
        # str.format only; snippets never evaluate Python at generation time.
        return self.source_template.format_map(_SafeFormat(context)).rstrip() + "\n"


class _SafeFormat(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"
