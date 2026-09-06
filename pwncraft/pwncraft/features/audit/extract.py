"""AST → ExploitIR extraction with helper-body inlining (VNext.3).

Only the FULL-AST canonical path lives here (used after the editor's typing
pause). Incremental/tree-sitter parsing is an editor-layer concern and never
changes the semantics produced by this module.

Helper inlining: calling a user-defined helper walks its body once with
positional argument bindings (param → argument source text), so menu
interactions written inside helpers are understood at the call site — the
prerequisite for the heap state machine.
"""
from __future__ import annotations

import ast

from pwncraft.features.audit.model import (
    ExploitIR, Hardcode, HelperCall, Interaction, PackOp, SymbolRef,
)

_RECV_WAIT = {"recvuntil", "recvuntilrepeat", "recvuntil_then", "recvuntil_regex"}
_RECV_PLAIN = {"recv", "recvn", "recvline", "recvall", "recvrepeat"}
_SEND_WAIT = {"sendafter", "sendlineafter", "sendthen", "sendlinethen"}
_SEND_PLAIN = {"send", "sendline", "sendlinethen"}
_PACK = {"p64", "p32", "u64", "u32"}
_ADDR_NAME_HINTS = ("addr", "address", "gadget", "ptr", "pointer", "leak",
                    "system", "hook", "rdi", "rsi", "rdx", "ret", "win",
                    "func", "got", "plt")
_ADDR_VALUE_MIN = 0x400000


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _arg_text(node: ast.AST) -> str:
    try:
        return ast.unparse(node).strip()
    except Exception:
        return ""


def _literal_int(node: ast.AST) -> int | None:
    try:
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return int(node.value)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub) and \
                isinstance(node.operand, ast.Constant):
            return -int(node.operand.value)
    except Exception:
        pass
    return None


def _literal_byte_width(node: ast.AST) -> int | None:
    """Return an exact byte width only when a literal is byte-countable.

    Python2-era pwntools exploits often use ``'\\0\\0'`` rather than a bytes
    literal. Counting latin-1-range str literals keeps those historical EXPs
    analyzable without pretending arbitrary Unicode text has a byte width.
    """
    if not isinstance(node, ast.Constant):
        return None
    value = node.value
    if isinstance(value, bytes):
        return len(value)
    if isinstance(value, str) and all(ord(ch) <= 0xFF for ch in value):
        return len(value)
    return None


def _exact_unpack_input_width(node: ast.AST) -> tuple[int | None, list[dict]]:
    """Derive exact byte width for a small, deterministic EXP expression set.

    Supported facts are intentionally narrow:
      * fixed bytes / latin-1-range string literals;
      * ``tube.recvn(N)`` with literal non-negative N (recvn is exact-length);
      * concatenation where both sides are independently exact.

    ``recv(N)`` is deliberately NOT treated as exact here because pwntools may
    return fewer than N bytes. Unknown subexpressions keep the whole result
    UNKNOWN instead of guessing.
    """
    literal = _literal_byte_width(node)
    if literal is not None:
        return literal, [{"kind": "LITERAL_WIDTH", "bytes": literal}]

    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "recvn" and node.args:
            length = _literal_int(node.args[0])
            if length is not None and length >= 0:
                return length, [{"kind": "RECVN_EXACT", "bytes": length}]

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, left_evidence = _exact_unpack_input_width(node.left)
        right, right_evidence = _exact_unpack_input_width(node.right)
        if left is not None and right is not None:
            return left + right, left_evidence + right_evidence + [
                {"kind": "CONCAT_WIDTH", "bytes": left + right}
            ]

    return None, []


def _attribute_parts(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        base = _attribute_parts(node.value)
        return base + [node.attr] if base else []
    return []


def _symbol_reference(node: ast.AST, *, scope: str) -> SymbolRef | None:
    """Recognize pwntools-style ``ELF.sym`` references without resolving them.

    Both ``libc.sym.system`` and legacy ``libc.sym['puts']`` forms are kept as
    source facts.  A symbol reference proves only that the EXP names a symbol;
    address existence, target reachability and runtime success stay outside
    this extractor.
    """
    expression = _arg_text(node)
    line = int(getattr(node, "lineno", 0) or 0)
    if isinstance(node, ast.Attribute):
        parts = _attribute_parts(node)
        if len(parts) >= 3 and parts[-2] == "sym":
            return SymbolRef(
                expression=expression,
                namespace=".".join(parts[:-2]),
                symbol=parts[-1],
                line=line,
                scope=scope,
            )
    if isinstance(node, ast.Subscript):
        parts = _attribute_parts(node.value)
        key = node.slice
        if parts and parts[-1] == "sym" and isinstance(key, ast.Constant) \
                and isinstance(key.value, str):
            return SymbolRef(
                expression=expression,
                namespace=".".join(parts[:-1]),
                symbol=key.value,
                line=line,
                scope=scope,
            )
    return None


class _Extractor(ast.NodeVisitor):
    ENTRY_NAMES = {"main", "exp", "pwn", "solve", "attack"}

    def __init__(self, helpers: dict[str, ast.FunctionDef], ir: ExploitIR):
        self.helpers = helpers
        self.ir = ir
        self._walked_bodies: set[int] = set()
        self._symbol_ref_seen: set[tuple[str, int, str]] = set()

    def _collect_symbol_refs(self, root: ast.AST, *, scope: str) -> None:
        for node in ast.walk(root):
            ref = _symbol_reference(node, scope=scope)
            if ref is None:
                continue
            key = (ref.expression, ref.line, ref.scope)
            if key in self._symbol_ref_seen:
                continue
            self._symbol_ref_seen.add(key)
            self.ir.symbol_refs.append(ref)

    # -- module pass: module-level statements + entry function bodies only.
    # Helper definition bodies are intentionally NOT walked here — they are
    # recorded through inlined expansion at their call sites.
    def visit_Module(self, node: ast.Module) -> None:  # noqa: N802
        for node_any in ast.walk(node):
            if isinstance(node_any, ast.Constant) and isinstance(node_any.value, str):
                self.ir.strings.append(node_any.value)
        for statement in node.body:
            if isinstance(statement, ast.FunctionDef):
                if statement.name in self.ENTRY_NAMES and \
                        id(statement) not in self._walked_bodies:
                    self._walked_bodies.add(id(statement))
                    self._collect_symbol_refs(statement, scope=statement.name)
                    for child in ast.walk(statement):
                        if isinstance(child, ast.Call):
                            self._record_call(child)
                        elif isinstance(child, ast.Assign):
                            self._record_assign_facts(child)
            else:
                self._collect_symbol_refs(statement, scope="main")
                self.visit(statement)

    # -- statement pass: assignments seed leak dataflow + hardcode detection
    def _record_assign_facts(self, node: ast.Assign) -> None:
        value = node.value
        target = _name(node.targets[0]) if node.targets and \
            isinstance(node.targets[0], ast.Name) else ""
        if target and isinstance(value, ast.Call):
            verb = _name(value.func) or (
                value.func.attr if isinstance(value.func, ast.Attribute) else "")
            if verb in _RECV_PLAIN:
                length = _literal_int(value.args[0]) if value.args else None
                if length is not None:
                    self.ir.var_recv_length[target] = length
                elif verb in ("recvline", "recvall", "recvrepeat"):
                    self.ir.var_recv_unknown.append(target)
        if target and isinstance(value, ast.Constant) and \
                isinstance(value.value, int) and \
                any(h in target.lower() for h in _ADDR_NAME_HINTS) and \
                value.value >= _ADDR_VALUE_MIN:
            self.ir.hardcodes.append(Hardcode(var=target, value=int(value.value),
                                              line=node.lineno))

    # -- call pass
    def visit_Call(self, node: ast.Call) -> None:
        self._record_call(node)
        self.generic_visit(node)

    def _record_call(self, node: ast.Call) -> None:
        func = node.func
        if not isinstance(func, ast.Attribute):
            if isinstance(func, ast.Name):
                name = func.id
                if name in _PACK:
                    # u64/p64 are imported from pwn — plain Name calls
                    arg_node = node.args[0] if node.args else None
                    op = PackOp(fn=name,
                                arg=_arg_text(arg_node) if arg_node is not None else "",
                                line=node.lineno)
                    if name[0] == "u":
                        self.ir.unpacks.append(op)
                        if arg_node is not None:
                            self._attach_inline_unpack_width(op, arg_node)
                        self._link_leak(op)
                    else:
                        self.ir.packs.append(op)
                    return
                self._maybe_helper(node, name)
            return
        verb = func.attr
        if verb in _RECV_WAIT:
            self.ir.interactions.append(Interaction(
                action="RECVUNTIL",
                wait_for=_arg_text(node.args[0]) if node.args else "",
                line=node.lineno))
        elif verb in _RECV_PLAIN:
            length = _literal_int(node.args[0]) if node.args and \
                verb in ("recv", "recvn") else None
            self.ir.interactions.append(Interaction(
                action="RECVLINE" if verb == "recvline" else "RECVN" if verb == "recvn"
                else "RECV",
                length=length, line=node.lineno))
        elif verb in _SEND_WAIT:
            self.ir.interactions.append(Interaction(
                action="SENDLINE" if "line" in verb else "SEND",
                wait_for=_arg_text(node.args[0]) if node.args else "",
                value=_arg_text(node.args[1]) if len(node.args) > 1 else "",
                line=node.lineno))
        elif verb in _SEND_PLAIN:
            self.ir.interactions.append(Interaction(
                action="SENDLINE" if verb == "sendline" else "SEND",
                value=_arg_text(node.args[0]) if node.args else "",
                line=node.lineno))
        elif verb in _PACK:
            arg_node = node.args[0] if node.args else None
            op = PackOp(fn=verb,
                        arg=_arg_text(arg_node) if arg_node is not None else "",
                        line=node.lineno)
            if verb[0] == "u":
                self.ir.unpacks.append(op)
                if arg_node is not None:
                    self._attach_inline_unpack_width(op, arg_node)
                self._link_leak(op)
            else:
                self.ir.packs.append(op)

    def _attach_inline_unpack_width(self, op: PackOp, arg_node: ast.AST) -> None:
        width, evidence = _exact_unpack_input_width(arg_node)
        if width is None:
            return
        # Dynamic metadata intentionally stays out of PackOp serialization for
        # now, avoiding a schema/baseline churn while the evaluator consumes it.
        op.meta_input_width = width  # type: ignore[attr-defined]
        op.meta_input_width_evidence = evidence  # type: ignore[attr-defined]
        # Compatibility bridge for the existing leak rule.  The value is the
        # exact total input-expression width, not merely the raw recv count.
        op.meta_recv_length = width  # type: ignore[attr-defined]

    def _link_leak(self, op: PackOp) -> None:
        """Attach the feeding recv length to an unpack when the argument is a
        tracked variable (u64(leak) with leak <- recv(6))."""
        # Inline exact-width evidence is stronger than variable-name linkage.
        if getattr(op, "meta_input_width", None) is not None:
            return
        arg_name = op.arg.split(".")[0].strip()
        if arg_name in self.ir.var_recv_length:
            op.meta_recv_length = self.ir.var_recv_length[arg_name]  # type: ignore[attr-defined]
        elif arg_name in self.ir.var_recv_unknown:
            op.meta_recv_length = None  # type: ignore[attr-defined]
            op.meta_recv_unknown = True  # type: ignore[attr-defined]

    known_external: set[str] = set()

    def _maybe_helper(self, node: ast.Call, name: str, depth: int = 0,
                      bindings: dict[str, str] | None = None,
                      scope: str = "main") -> None:
        """Inline-expand user helper calls so menu semantics are visible.
        Externally-known helpers (defined in the BehaviorProfile, possibly
        imported by the EXP) are recorded without a body to walk."""
        if depth > 2:
            return
        if name not in self.helpers and name in self.known_external:
            self.ir.helper_calls.append(HelperCall(
                function=name,
                args=[_arg_text(a) for a in node.args],
                line=node.lineno, scope=scope))
            return
        if name not in self.helpers:
            return
        args = [_arg_text(a) for a in node.args]
        self.ir.helper_calls.append(HelperCall(
            function=name, args=args, line=node.lineno, scope=scope))
        definition = self.helpers[name]
        params = [p.arg for p in definition.args.args]
        local = dict(zip(params, args))
        if bindings:  # resolve nested helper args through outer bindings
            local = {k: bindings.get(v, v) for k, v in local.items()}
        for child in ast.walk(definition):
            if isinstance(child, ast.Call):
                func = child.func
                if isinstance(func, ast.Attribute):
                    self._record_inlined(child, scope=name, bindings=local)
                elif isinstance(func, ast.Name):
                    self._maybe_helper(child, func.id, depth=depth + 1,
                                       bindings=local, scope=name)

    def _record_inlined(self, node: ast.Call, scope: str,
                        bindings: dict[str, str]) -> None:
        verb = node.func.attr  # type: ignore[attr-defined]

        def substitute(text: str) -> str:
            result = text or ""
            for param, value in bindings.items():
                # repl 用 lambda: 值里的 \\x00 等序列不会被当作模板转义
                result = re.sub(rf"\b{re.escape(param)}\b",
                                lambda _m: value, result)
            return result

        if verb in _RECV_WAIT:
            self.ir.interactions.append(Interaction(
                action="RECVUNTIL", wait_for=substitute(_arg_text(node.args[0])),
                line=node.lineno, scope=scope))
        elif verb in _RECV_PLAIN:
            length = _literal_int(node.args[0]) if node.args and \
                verb in ("recv", "recvn") else None
            self.ir.interactions.append(Interaction(
                action="RECVLINE" if verb == "recvline" else "RECVN" if verb == "recvn"
                else "RECV", length=length, line=node.lineno, scope=scope))
        elif verb in _SEND_WAIT:
            self.ir.interactions.append(Interaction(
                action="SENDLINE" if "line" in verb else "SEND",
                wait_for=substitute(_arg_text(node.args[0]) if node.args else ""),
                value=substitute(_arg_text(node.args[1]) if len(node.args) > 1 else ""),
                line=node.lineno, scope=scope))
        elif verb in _SEND_PLAIN:
            self.ir.interactions.append(Interaction(
                action="SENDLINE" if verb == "sendline" else "SEND",
                value=substitute(_arg_text(node.args[0]) if node.args else ""),
                line=node.lineno, scope=scope))


import re  # noqa: E402  (word-boundary binding substitution above)


def extract_exploit_ir(source: str, *, known_helpers=None) -> tuple[ExploitIR, ast.SyntaxError | None]:
    """Full-AST extraction. Returns (ir, syntax_error) — exactly one non-None.
    A syntax error becomes an EXP_PARSE diagnostic upstream; the editor layer
    (tree-sitter) owns incomplete-code tolerance.

    known_helpers: EXP-side helper names whose semantics live in the
    ChallengeBehaviorProfile (helpers may be imported/undefined in the EXP);
    calls to them are recorded so the heap state machine can replay them."""
    ir = ExploitIR()
    try:
        tree = ast.parse(source or "")
    except SyntaxError as error:
        return ir, error
    helpers = {node.name: node for node in tree.body
               if isinstance(node, ast.FunctionDef)}
    extractor = _Extractor(helpers, ir)
    extractor.known_external = set(known_helpers or ())
    extractor.visit(tree)
    # 事件身份 (阶段 1 EventRecord): 同一 (scope, line, action) 组合分配
    # 迭代序号 —— 循环/重复调用各自独立, 禁止 source_line 单键覆盖。
    seen: dict[tuple, int] = {}
    events: list[dict] = []
    for i in ir.interactions:
        key = (i.scope, i.line, i.action)
        seen[key] = seen.get(key, 0) + 1
        ordinal = seen[key]
        events.append({
            "event_id": f"{i.scope}:L{i.line}:{i.action}#{ordinal}",
            "scope": i.scope, "line": i.line, "action": i.action,
            "ordinal": ordinal, "callee": "",
            "args": [x for x in (i.value, i.wait_for) if x],
        })
    for c in ir.helper_calls:
        key = (c.scope, c.line, f"HELPER:{c.function}")
        seen[key] = seen.get(key, 0) + 1
        ordinal = seen[key]
        events.append({
            "event_id": f"{c.scope}:L{c.line}:HELPER:{c.function}#{ordinal}",
            "scope": c.scope, "line": c.line,
            "action": f"HELPER:{c.function}", "ordinal": ordinal,
            "callee": c.function, "args": list(c.args),
        })
    ir.events = events
    return ir, None
