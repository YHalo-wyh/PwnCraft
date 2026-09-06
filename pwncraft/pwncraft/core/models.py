from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Iterable


ALLOWED_BLOCK_KEYS = {"id", "title", "category", "description", "snippet", "placeholders", "tags"}
PLACEHOLDER_RE = re.compile(r"\{\{([^{}]+)\}\}")
PLACEHOLDER_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


class CatalogValidationError(ValueError):
    pass


@dataclass(frozen=True)
class CodeBlock:
    id: str
    title: str
    category: str
    description: str
    snippet: str
    placeholders: list[str]
    tags: list[str]


class BlockCatalog:
    def __init__(self, blocks: Iterable[CodeBlock]):
        self.blocks = list(blocks)
        self.by_id = {block.id: block for block in self.blocks}

    @classmethod
    def load_default(cls) -> "BlockCatalog":
        path = Path(__file__).resolve().parents[1] / "data" / "block_catalog.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        cls._validate_payload(payload)
        blocks = [
            CodeBlock(
                id=str(item["id"]),
                title=str(item["title"]),
                category=str(item["category"]),
                description=str(item.get("description", "")),
                snippet=str(item["snippet"]),
                placeholders=list(item.get("placeholders", [])),
                tags=list(item.get("tags", [])),
            )
            for item in payload.get("blocks", [])
        ]
        return cls(blocks)

    @classmethod
    def _validate_payload(cls, payload: dict) -> None:
        errors: list[str] = []
        seen_ids: set[str] = set()
        for index, item in enumerate(payload.get("blocks", []), 1):
            unknown = set(item) - ALLOWED_BLOCK_KEYS
            if unknown:
                errors.append(f"block #{index} contains unknown keys: {', '.join(sorted(unknown))}")
            block_id = str(item.get("id") or "")
            if not block_id:
                errors.append(f"block #{index} missing id")
            elif block_id in seen_ids:
                errors.append(f"duplicate block id: {block_id}")
            seen_ids.add(block_id)
            placeholders = [str(name) for name in item.get("placeholders", [])]
            discovered = [match.group(1) for match in PLACEHOLDER_RE.finditer(str(item.get("snippet", "")))]
            for name in placeholders + discovered:
                if not PLACEHOLDER_NAME_RE.fullmatch(name):
                    errors.append(f"{block_id or '#'+str(index)} has invalid placeholder: {name}")
        if errors:
            raise CatalogValidationError("代码块目录校验失败:\n" + "\n".join(errors))

    def categories(self) -> list[str]:
        seen: list[str] = []
        for block in self.blocks:
            if block.category not in seen:
                seen.append(block.category)
        return seen

    def blocks_for_category(self, category: str) -> list[CodeBlock]:
        return [block for block in self.blocks if block.category == category]

    def search(self, query: str) -> list[CodeBlock]:
        text = query.strip().lower()
        if not text:
            return self.blocks
        result = []
        for block in self.blocks:
            haystack = " ".join(
                [block.id, block.title, block.category, block.description, " ".join(block.tags)]
            ).lower()
            if text in haystack:
                result.append(block)
        return result


# ---------------------------------------------------------------------------
# C 函数速查目录（clib_catalog.json）——与 BlockCatalog 同一加载/校验模式

ALLOWED_CLIB_FUNCTION_KEYS = {
    "name", "prototype", "header", "category", "summary", "params", "returns", "notes", "tags",
}
ALLOWED_CLIB_PARAM_KEYS = {"name", "type", "note"}
ALLOWED_CLIB_RETURN_KEYS = {"condition", "value"}
ALLOWED_CLIB_OPERATOR_KEYS = {
    "symbol", "name", "kind", "short_circuit", "description", "example",
}


@dataclass(frozen=True)
class CFunctionParam:
    name: str
    type: str = ""
    note: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "type": self.type, "note": self.note}


@dataclass(frozen=True)
class CFunctionReturn:
    condition: str
    value: str

    def to_dict(self) -> dict:
        return {"condition": self.condition, "value": self.value}


@dataclass(frozen=True)
class CFunction:
    name: str
    prototype: str
    category: str = ""
    summary: str = ""
    header: str = ""
    params: tuple[CFunctionParam, ...] = ()
    returns: tuple[CFunctionReturn, ...] = ()
    notes: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "prototype": self.prototype,
            "header": self.header,
            "category": self.category,
            "summary": self.summary,
            "params": [param.to_dict() for param in self.params],
            "returns": [item.to_dict() for item in self.returns],
            "notes": list(self.notes),
            "tags": list(self.tags),
        }


@dataclass(frozen=True)
class COperator:
    symbol: str
    name: str
    kind: str
    short_circuit: bool
    description: str
    example: str

    def to_dict(self) -> dict:
        return {
            "symbol": self.symbol,
            "name": self.name,
            "kind": self.kind,
            "short_circuit": self.short_circuit,
            "description": self.description,
            "example": self.example,
        }


class CFunctionCatalog:
    def __init__(
        self,
        functions: Iterable[CFunction],
        operators: Iterable[COperator] = (),
    ) -> None:
        self.functions = list(functions)
        self.operators = list(operators)
        self.by_name = {fn.name: fn for fn in self.functions}

    @classmethod
    def load_default(cls) -> "CFunctionCatalog":
        path = Path(__file__).resolve().parents[1] / "data" / "clib_catalog.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        cls._validate_payload(payload)
        functions = [
            CFunction(
                name=str(item["name"]),
                prototype=str(item["prototype"]),
                category=str(item.get("category", "")),
                summary=str(item.get("summary", "")),
                header=str(item.get("header", "")),
                params=tuple(
                    CFunctionParam(
                        name=str(param["name"]),
                        type=str(param.get("type", "")),
                        note=str(param.get("note", "")),
                    )
                    for param in item.get("params", [])
                ),
                returns=tuple(
                    CFunctionReturn(
                        condition=str(ret.get("condition", "")),
                        value=str(ret["value"]),
                    )
                    for ret in item.get("returns", [])
                ),
                notes=tuple(str(note) for note in item.get("notes", [])),
                tags=tuple(str(tag) for tag in item.get("tags", [])),
            )
            for item in payload.get("functions", [])
        ]
        operators = [
            COperator(
                symbol=str(item["symbol"]),
                name=str(item["name"]),
                kind=str(item.get("kind", "")),
                short_circuit=bool(item.get("short_circuit", False)),
                description=str(item.get("description", "")),
                example=str(item.get("example", "")),
            )
            for item in payload.get("operators", [])
        ]
        return cls(functions, operators)

    @classmethod
    def _validate_payload(cls, payload: dict) -> None:
        errors: list[str] = []
        unknown_top = set(payload) - {"functions", "operators"}
        if unknown_top:
            errors.append(f"unknown top-level keys: {', '.join(sorted(unknown_top))}")
        seen_names: set[str] = set()
        for index, item in enumerate(payload.get("functions", []), 1):
            fn_name = str(item.get("name") or "")
            unknown = set(item) - ALLOWED_CLIB_FUNCTION_KEYS
            if unknown:
                errors.append(f"function #{index} contains unknown keys: {', '.join(sorted(unknown))}")
            if not fn_name:
                errors.append(f"function #{index} missing name")
            elif fn_name in seen_names:
                errors.append(f"duplicate function name: {fn_name}")
            seen_names.add(fn_name)
            if not str(item.get("prototype") or "").strip():
                errors.append(f"{fn_name or '#'+str(index)} missing prototype")
            for pos, param in enumerate(item.get("params", []), 1):
                unknown = set(param) - ALLOWED_CLIB_PARAM_KEYS
                if unknown:
                    errors.append(f"{fn_name} param #{pos} unknown keys: {', '.join(sorted(unknown))}")
                if not str(param.get("name") or "").strip():
                    errors.append(f"{fn_name} param #{pos} missing name")
            for pos, ret in enumerate(item.get("returns", []), 1):
                unknown = set(ret) - ALLOWED_CLIB_RETURN_KEYS
                if unknown:
                    errors.append(f"{fn_name} return #{pos} unknown keys: {', '.join(sorted(unknown))}")
                if not str(ret.get("value") or "").strip():
                    errors.append(f"{fn_name} return #{pos} missing value")
        for index, item in enumerate(payload.get("operators", []), 1):
            unknown = set(item) - ALLOWED_CLIB_OPERATOR_KEYS
            if unknown:
                errors.append(f"operator #{index} contains unknown keys: {', '.join(sorted(unknown))}")
            if not str(item.get("symbol") or "").strip():
                errors.append(f"operator #{index} missing symbol")
        if errors:
            raise CatalogValidationError("C 函数目录校验失败:\n" + "\n".join(errors))

    def categories(self) -> list[str]:
        seen: list[str] = []
        for fn in self.functions:
            if fn.category and fn.category not in seen:
                seen.append(fn.category)
        return seen

    def search(self, query: str) -> list[CFunction]:
        text = query.strip().lower()
        if not text:
            return self.functions
        result = []
        for fn in self.functions:
            haystack = " ".join(
                [
                    fn.name, fn.prototype, fn.header, fn.category, fn.summary,
                    " ".join(fn.tags), " ".join(fn.notes),
                    " ".join(f"{param.name} {param.note}" for param in fn.params),
                ]
            ).lower()
            if text in haystack:
                result.append(fn)
        return result
