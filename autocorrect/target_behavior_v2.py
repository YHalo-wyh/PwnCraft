#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deterministic TargetBehavior lowering for the formal training pipeline.

Cycle-5 closes the separation between EXP-level CanonicalIR and target-internal
1:N actions.  The source recognizer still emits one canonical operation for one
EXP helper call.  A reviewed ``behavior_bindings.json`` may then lower that one
call into N target actions (for example create -> malloc(struct)+malloc(content)).

Important boundaries:
- no challenge/case-name hardcoding;
- no execution/import of EXP source;
- bindings are strict input: malformed entries raise instead of being ignored;
- this stage consumes canonical ``source_call`` strings from the authoritative
  run and therefore does not perform a second source analysis;
- absence of a reviewed binding preserves the legacy identity mapping and marks
  ``internals_not_modeled=True``.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any, Mapping

TARGET_BEHAVIOR_REVISION = "target-behavior-2026.09-r1"

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_EFFECT_ACTION = {
    "alloc": "malloc",
    "allocate": "malloc",
    "free": "free",
    "delete": "free",
    "edit": "write",
    "show": "print",
    "copy": "copy",
}


def _abstract_expression(text: object) -> dict[str, Any]:
    source = str(text or "").strip()
    if not source:
        return {"kind": "unknown", "reason": "expression absent", "source": ""}
    try:
        node = ast.parse(source, mode="eval").body
        value = ast.literal_eval(node)
    except (SyntaxError, ValueError, TypeError):
        return {"kind": "symbolic", "expression": source, "source": source}
    if isinstance(value, bool):
        value = int(value)
    if isinstance(value, int):
        return {"kind": "concrete", "value": value, "source": source}
    return {"kind": "symbolic", "expression": source, "source": source}


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _parse_call(source_call: str) -> ast.Call | None:
    text = str(source_call or "").strip()
    if not text:
        return None
    try:
        node = ast.parse(text, mode="eval").body
    except SyntaxError:
        return None
    return node if isinstance(node, ast.Call) else None


def _render(node: ast.AST) -> str:
    try:
        return ast.unparse(node).strip()
    except Exception:
        return ""


def _substitute_expression(template: object, values: Mapping[str, str]) -> str:
    text = str(template or "").strip()
    if not text:
        return ""
    # {size} style placeholders are supported in addition to Python names.
    text = re.sub(
        r"\{([A-Za-z_][A-Za-z0-9_]*)\}",
        lambda match: values.get(match.group(1), match.group(0)),
        text,
    )
    try:
        tree = ast.parse(text, mode="eval")
    except SyntaxError:
        return text

    class Binder(ast.NodeTransformer):
        def visit_Name(self, node: ast.Name):  # noqa: N802 - AST visitor API
            replacement = values.get(node.id)
            if replacement is None:
                return node
            try:
                return ast.copy_location(ast.parse(replacement, mode="eval").body, node)
            except SyntaxError:
                return node

    bound = ast.fix_missing_locations(Binder().visit(tree))
    try:
        return ast.unparse(bound.body).strip()
    except Exception:
        return text


def _normalize_binding(raw: Mapping[str, object], index: int) -> dict[str, Any]:
    helper = str(raw.get("function") or raw.get("helper") or "").strip()
    if not helper or not _IDENTIFIER.match(helper):
        raise ValueError(
            f"behavior_bindings.bindings[{index}] helper/function 必须是 Python 函数名: "
            f"{helper or '<empty>'}"
        )

    parameters_raw = raw.get("parameters") or []
    if not isinstance(parameters_raw, (list, tuple)):
        raise TypeError(f"behavior binding {helper}: parameters 必须是 array")
    parameters = [str(item).strip() for item in parameters_raw]
    if any(not _IDENTIFIER.match(item) for item in parameters):
        raise ValueError(f"behavior binding {helper}: parameters 含非法参数名 {parameters!r}")
    if len(parameters) != len(set(parameters)):
        raise ValueError(f"behavior binding {helper}: parameters 不允许重复")

    defaults_raw = raw.get("defaults") or {}
    if not isinstance(defaults_raw, Mapping):
        raise TypeError(f"behavior binding {helper}: defaults 必须是 object")

    effects_raw = raw.get("effects") or []
    if not isinstance(effects_raw, (list, tuple)):
        raise TypeError(f"behavior binding {helper}: effects 必须是 array")
    effects: list[dict[str, Any]] = []
    for effect_index, effect_raw in enumerate(effects_raw):
        if not isinstance(effect_raw, Mapping):
            raise TypeError(
                f"behavior binding {helper}: effects[{effect_index}] 必须是 object"
            )
        effect = dict(effect_raw)
        kind = str(effect.get("kind") or "").strip().lower()
        if kind not in _EFFECT_ACTION:
            raise ValueError(
                f"behavior binding {helper}: effects[{effect_index}] 未知 kind "
                f"{kind or '<empty>'}"
            )
        effect["kind"] = kind
        effects.append(effect)

    return {
        "function": helper,
        "receiver": str(raw.get("receiver") or "").strip(),
        "parameters": parameters,
        "defaults": {str(key): str(value) for key, value in defaults_raw.items()},
        "effects": effects,
        "evidence": str(
            raw.get("evidence")
            or raw.get("bindings_provenance")
            or "reviewed behavior binding"
        ),
        "binary_handler": str(raw.get("binary_handler") or ""),
    }


def load_bindings(path: str | Path) -> tuple[dict[str, Any], ...]:
    binding_path = Path(path)
    payload = json.loads(binding_path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise TypeError("behavior_bindings.json 顶层必须是 object")
    raw_bindings = payload.get("bindings") or []
    if not isinstance(raw_bindings, (list, tuple)):
        raise TypeError("behavior_bindings.bindings 必须是 array")
    normalized = tuple(
        _normalize_binding(item, index)
        for index, item in enumerate(raw_bindings)
        if isinstance(item, Mapping)
    )
    if len(normalized) != len(raw_bindings):
        raise TypeError("behavior_bindings.bindings 每一项都必须是 object")
    keys = [(item["receiver"], item["function"]) for item in normalized]
    if len(keys) != len(set(keys)):
        raise ValueError("behavior_bindings 不允许重复 receiver/function")
    return normalized


def _binding_for_call(
    call: ast.Call,
    bindings: tuple[dict[str, Any], ...],
) -> dict[str, Any] | None:
    name = _call_name(call)
    # Canonical source_call currently stores direct helper calls.  Receiver
    # binding remains explicit for future method-call cases; we never guess it.
    receiver = ""
    if isinstance(call.func, ast.Attribute):
        receiver = _render(call.func.value)
    for binding in bindings:
        if binding["function"] != name:
            continue
        expected_receiver = str(binding.get("receiver") or "")
        if expected_receiver and expected_receiver != receiver:
            continue
        return binding
    return None


def _argument_values(call: ast.Call, binding: Mapping[str, Any]) -> dict[str, str]:
    parameters = list(binding.get("parameters") or [])
    if len(call.args) > len(parameters):
        raise ValueError(
            f"behavior binding {binding.get('function')}: 调用实参数 "
            f"{len(call.args)} 超过参数数 {len(parameters)}"
        )
    values = dict(binding.get("defaults") or {})
    for name, argument in zip(parameters, call.args):
        values[name] = _render(argument)
    for keyword in call.keywords:
        if keyword.arg is None:
            raise ValueError(
                f"behavior binding {binding.get('function')}: **kwargs 无法确定性绑定"
            )
        if keyword.arg not in parameters and keyword.arg not in values:
            raise ValueError(
                f"behavior binding {binding.get('function')}: 未声明关键字参数 "
                f"{keyword.arg}"
            )
        values[keyword.arg] = _render(keyword.value)
    missing = [name for name in parameters if name not in values]
    if missing:
        raise ValueError(
            f"behavior binding {binding.get('function')}: 缺少参数绑定 {missing}"
        )
    return values


def _effect_action(
    effect: Mapping[str, Any],
    values: Mapping[str, str],
    binding: Mapping[str, Any],
    effect_index: int,
) -> dict[str, Any]:
    kind = str(effect.get("kind") or "").lower()
    action = _EFFECT_ACTION[kind]
    item: dict[str, Any] = {
        "action": action,
        "effect_index": effect_index,
        "source": "reviewed_behavior_binding",
        "evidence": str(binding.get("evidence") or ""),
    }
    role = str(
        effect.get("role")
        or (effect.get("meta") or {}).get("role") if isinstance(effect.get("meta"), Mapping)
        else effect.get("role")
        or ""
    ).strip()
    if role:
        item["role"] = role
    note = str(effect.get("note") or "").strip()
    if note:
        item["note"] = note

    if action == "malloc":
        request = effect.get("request_size", effect.get("size", ""))
        item["request"] = _abstract_expression(_substitute_expression(request, values))
    elif action == "free":
        target = effect.get("target") or effect.get("chunk") or effect.get("index") or ""
        item["target"] = _abstract_expression(_substitute_expression(target, values))
    elif action == "write":
        target = effect.get("target") or effect.get("index") or ""
        data = effect.get("data") or ""
        item["target"] = _abstract_expression(_substitute_expression(target, values))
        item["data"] = _substitute_expression(data, values)
    elif action == "print":
        target = effect.get("target") or effect.get("index") or ""
        item["target"] = _abstract_expression(_substitute_expression(target, values))
    return item


def derive_target_behavior(
    canonical_ops: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
    bindings: tuple[dict[str, Any], ...] = (),
) -> dict[str, Any]:
    """Lower one canonical helper call to reviewed 1:N target actions."""
    per_op: list[dict[str, Any]] = []
    for raw_op in canonical_ops:
        op = dict(raw_op)
        kind = str(op.get("kind") or "")
        source_call = str(op.get("source_call") or "")
        call = _parse_call(source_call)
        binding = _binding_for_call(call, bindings) if call is not None else None
        entry: dict[str, Any] = {
            "op_id": op.get("op_id"),
            "kind": kind,
            "source_line": op.get("source_line") or 0,
            "source_call": source_call,
            "actions": [],
            "internals_not_modeled": True,
            "target_behavior_revision": TARGET_BEHAVIOR_REVISION,
        }

        if binding is not None and call is not None:
            values = _argument_values(call, binding)
            entry["actions"] = [
                _effect_action(effect, values, binding, index)
                for index, effect in enumerate(binding["effects"], 1)
            ]
            entry["internals_not_modeled"] = False
            entry["binding"] = {
                "function": binding["function"],
                "binary_handler": binding.get("binary_handler") or "",
                "evidence": binding.get("evidence") or "",
            }
        elif kind in {"alloc", "allocate"}:
            entry["actions"] = [{
                "action": "malloc",
                "request": op.get("allocator_request")
                or {"kind": "unknown", "reason": "allocator request absent"},
                "source": "canonical_identity_fallback",
            }]
        elif kind in {"free", "delete"}:
            entry["actions"] = [{
                "action": "free",
                "target": op.get("handle")
                or {"kind": "unknown", "reason": "handle absent"},
                "source": "canonical_identity_fallback",
            }]
        per_op.append(entry)

    return {
        "revision": TARGET_BEHAVIOR_REVISION,
        "derivation": (
            "CanonicalIR helper call -> reviewed behavior binding -> target-internal actions; "
            "unbound calls retain explicit identity fallback"
        ),
        "per_op": per_op,
    }


def apply_case_bindings(actual: dict[str, Any], case_dir: str | Path) -> bool:
    """Replace only TargetBehavior in an authoritative run result.

    Returns True when a reviewed behavior_bindings.json was present.  Analyzer,
    replay, allocator, physical memory and canvas artifacts are intentionally
    untouched; Cycle-5 validates only the TARGET_BEHAVIOR stage.
    """
    cdir = Path(case_dir)
    path = cdir / "behavior_bindings.json"
    if not path.exists():
        return False
    bindings = load_bindings(path)
    analyzer = actual.get("analyzer") or {}
    target = derive_target_behavior(analyzer.get("canonical_ops") or [], bindings)
    run_id = (actual.get("run_manifest") or {}).get("run_id") or actual.get("run_id")
    target["run_id"] = run_id
    actual["target_behavior"] = target
    return True


def persist_target_behavior(actual: Mapping[str, Any], artifact_dir: str | Path) -> None:
    """Keep fresh sidecars consistent with the in-memory formal comparison."""
    root = Path(artifact_dir)
    target = actual.get("target_behavior") or {}
    (root / "target_behavior.json").write_text(
        json.dumps(target, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    (root / "pwncraft_output.json").write_text(
        json.dumps(dict(actual), ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
