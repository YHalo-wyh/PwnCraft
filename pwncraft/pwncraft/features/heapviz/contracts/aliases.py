from __future__ import annotations

import ast
import re


_VERBS = {
    "alloc": ("add", "alloc", "allocate", "malloc", "new", "create", "buy", "register", "take", "make"),
    "edit": ("edit", "modify", "rewrite", "change", "update", "write", "fill", "set"),
    "show": ("show", "view", "read", "dump", "display", "leak", "reveal"),
    "delete": ("delete", "del", "remove", "destroy", "drop", "release", "free", "erase"),
    "copy": ("copy", "clone", "duplicate", "move"),
}


def tokenize_helper_name(name: str) -> tuple[str, ...]:
    expanded = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(name or ""))
    lowered = re.sub(r"[^a-zA-Z0-9]+", "_", expanded).lower().strip("_")
    tokens = [item for item in lowered.split("_") if item]
    if len(tokens) <= 1:
        compact = lowered
        for words in _VERBS.values():
            match = next((word for word in sorted(words, key=len, reverse=True) if compact.startswith(word)), "")
            if match and compact != match:
                tokens = [match, compact[len(match):]]
                break
    return tuple(tokens or ([lowered] if lowered else []))


def name_candidate(name: str) -> str:
    tokens = tokenize_helper_name(name)
    for kind, words in _VERBS.items():
        if tokens and tokens[0] in words:
            return kind
        if len(tokens) > 1 and tokens[-1] in words:
            return kind
    return ""


def assignment_aliases(tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if isinstance(value, ast.Name):
            for target in targets:
                if isinstance(target, ast.Name):
                    aliases[target.id] = value.id
    changed = True
    while changed:
        changed = False
        for alias, target in tuple(aliases.items()):
            resolved = aliases.get(target, target)
            if resolved != target:
                aliases[alias] = resolved
                changed = True
    return aliases


def partial_aliases(tree: ast.Module) -> dict[str, tuple[str, tuple[str, ...], dict[str, str]]]:
    result: dict[str, tuple[str, tuple[str, ...], dict[str, str]]] = {}
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or not isinstance(node.value, ast.Call):
            continue
        name = _call_name(node.value.func)
        if name not in {"partial", "functools.partial"} or not node.value.args:
            continue
        callee = _call_name(node.value.args[0])
        if not callee:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        fixed = tuple(_unparse(item) for item in node.value.args[1:])
        keywords = {str(item.arg): _unparse(item.value) for item in node.value.keywords if item.arg}
        for target in targets:
            if isinstance(target, ast.Name):
                result[target.id] = (callee, fixed, keywords)
    return result


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node).strip()
    except Exception:
        return ""
