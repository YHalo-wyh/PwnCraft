"""Deterministic extraction of literal payloads that actually flow to send APIs.

Cycle-14 was motivated by SCTF 2026 ``slang``: the Python exploit embeds a
second-language program in a multiline string, derives ``source`` from that
literal, then transmits ``source.encode()`` with ``socket.sendall``.  Treating
that exploit as "just a Python SEND expression" loses the most important input
artifact.

This module deliberately solves only a small, reviewable data-flow subset:

* module/function assignments of literal ``str``/``bytes`` values;
* concatenation where both operands are already concrete literals;
* ``.encode()`` of a concrete string with default/constant encoding;
* outbound calls ``send``/``sendall``/``sendline``.

No user code is executed.  Dynamic values, function returns, file reads,
formatting and unknown encodings remain UNKNOWN rather than being guessed.
"""
from __future__ import annotations

import ast
import hashlib
from dataclasses import asdict, dataclass
from typing import Any


_SEND_NAMES = {"send", "sendall", "sendline"}
_ENTRY_NAMES = {"main", "exp", "pwn", "solve", "attack"}


@dataclass(frozen=True)
class OutboundLiteralPayload:
    expression: str
    content: str | bytes
    content_kind: str
    byte_length: int
    sha256: str
    line: int
    scope: str
    provenance: str = "EXP_AST_LITERAL_DATAFLOW"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _expr_text(node: ast.AST) -> str:
    try:
        return ast.unparse(node).strip()
    except Exception:
        return ""


def _encoding_name(node: ast.AST | None) -> str | None:
    if node is None:
        return "utf-8"
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        try:
            "".encode(node.value)
        except LookupError:
            return None
        return node.value
    return None


def _coerce_bytes(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8")


def _eval_literal(node: ast.AST, env: dict[str, str | bytes]) -> str | bytes | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        return node.value
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _eval_literal(node.left, env)
        right = _eval_literal(node.right, env)
        if left is None or right is None or type(left) is not type(right):
            return None
        return left + right  # type: ignore[operator]
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr != "encode":
            return None
        receiver = _eval_literal(node.func.value, env)
        if not isinstance(receiver, str):
            return None
        if len(node.args) > 1 or node.keywords:
            return None
        encoding = _encoding_name(node.args[0] if node.args else None)
        if encoding is None:
            return None
        try:
            return receiver.encode(encoding)
        except (LookupError, UnicodeEncodeError):
            return None
    return None


def _record_assignment(node: ast.Assign | ast.AnnAssign, env: dict[str, str | bytes]) -> None:
    if isinstance(node, ast.Assign):
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            return
        target = node.targets[0].id
        value_node = node.value
    else:
        if not isinstance(node.target, ast.Name) or node.value is None:
            return
        target = node.target.id
        value_node = node.value
    value = _eval_literal(value_node, env)
    if value is None:
        env.pop(target, None)
    else:
        env[target] = value


def _payload_fact(node: ast.Call, env: dict[str, str | bytes], scope: str) -> OutboundLiteralPayload | None:
    if not isinstance(node.func, ast.Attribute) or node.func.attr not in _SEND_NAMES:
        return None
    if not node.args:
        return None
    value_node = node.args[0]
    value = _eval_literal(value_node, env)
    if value is None:
        return None
    raw = _coerce_bytes(value)
    return OutboundLiteralPayload(
        expression=_expr_text(value_node),
        content=value,
        content_kind="bytes" if isinstance(value, bytes) else "str",
        byte_length=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
        line=int(getattr(node, "lineno", 0) or 0),
        scope=scope,
    )


def _walk_statements(statements: list[ast.stmt], base_env: dict[str, str | bytes], scope: str) -> list[OutboundLiteralPayload]:
    """Evaluate statements in source order without pretending to execute branches.

    Only straight-line assignments in the current statement list update the
    environment.  Nested control-flow bodies are inspected with a copy of the
    incoming environment so branch-dependent writes cannot leak back as facts.
    """
    env = dict(base_env)
    result: list[OutboundLiteralPayload] = []
    for statement in statements:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            _record_assignment(statement, env)
        for node in ast.walk(statement):
            if isinstance(node, ast.Call):
                fact = _payload_fact(node, env, scope)
                if fact is not None:
                    result.append(fact)
        if isinstance(statement, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
            bodies: list[list[ast.stmt]] = []
            for attr in ("body", "orelse", "finalbody"):
                body = getattr(statement, attr, None)
                if isinstance(body, list):
                    bodies.append(body)
            if isinstance(statement, ast.Try):
                bodies.extend(handler.body for handler in statement.handlers)
            for body in bodies:
                result.extend(_walk_statements(body, env, scope))
    return result


def extract_outbound_literal_payloads(source: str) -> tuple[list[OutboundLiteralPayload], ast.SyntaxError | None]:
    """Return literal payloads proven to reach an outbound send call."""
    try:
        tree = ast.parse(source or "")
    except SyntaxError as error:
        return [], error

    module_env: dict[str, str | bytes] = {}
    module_statements: list[ast.stmt] = []
    for statement in tree.body:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            _record_assignment(statement, module_env)
            module_statements.append(statement)
        elif not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            module_statements.append(statement)

    result = _walk_statements(module_statements, module_env, "main")
    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)) and statement.name in _ENTRY_NAMES:
            result.extend(_walk_statements(statement.body, module_env, statement.name))

    unique: list[OutboundLiteralPayload] = []
    seen: set[tuple[int, str, str]] = set()
    for fact in result:
        key = (fact.line, fact.scope, fact.sha256)
        if key not in seen:
            seen.add(key)
            unique.append(fact)
    return unique, None
