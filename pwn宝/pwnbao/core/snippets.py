from __future__ import annotations

import re

from .models import CodeBlock


PLACEHOLDER_RE = re.compile(r"\{\{([^{}]+)\}\}")


class SnippetRenderer:
    def find_placeholders(self, snippet: str) -> list[str]:
        seen: list[str] = []
        for match in PLACEHOLDER_RE.finditer(snippet):
            name = match.group(1)
            if name not in seen:
                seen.append(name)
        return seen

    def placeholders_for(self, block: CodeBlock) -> list[str]:
        configured = list(block.placeholders)
        discovered = self.find_placeholders(block.snippet)
        for name in discovered:
            if name not in configured:
                configured.append(name)
        return configured

    def render(self, block: CodeBlock, values: dict[str, str] | None = None) -> str:
        values = values or {}
        snippet = block.snippet
        for name in self.placeholders_for(block):
            snippet = snippet.replace("{{" + name + "}}", str(values.get(name, "")))
        return snippet.rstrip() + "\n"
