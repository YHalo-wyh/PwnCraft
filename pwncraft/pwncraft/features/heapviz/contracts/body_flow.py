"""Public structural-body helpers used by resolver tests and profile tooling."""

from __future__ import annotations

import ast


def outbound_parameter_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    parameters = {item.arg for item in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)}
    result: list[str] = []
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        name = child.func.attr if isinstance(child.func, ast.Attribute) else child.func.id if isinstance(child.func, ast.Name) else ""
        if "send" not in name.lower() and name.lower() not in {"sa", "sla", "sl", "s", "write"}:
            continue
        for argument in child.args:
            for nested in ast.walk(argument):
                if isinstance(nested, ast.Name) and nested.id in parameters and nested.id not in result:
                    result.append(nested.id)
    return tuple(result)
