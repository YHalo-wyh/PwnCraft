from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class FileWriteEvidence:
    line: int
    symbol: str
    expression: str
    provenance: str = "STATIC_AST"


def analyze_file_source(source: str) -> tuple[FileWriteEvidence, ...]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ()
    tokens = ("stdout", "stderr", "stdin", "_IO_FILE", "_IO_list_all", "vtable", "wide_data")
    result = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.Call)):
            continue
        text = ast.get_source_segment(source, node) or ""
        hit = next((token for token in tokens if token in text), "")
        if hit:
            result.append(FileWriteEvidence(getattr(node, "lineno", 0), hit, text))
    return tuple(result)
