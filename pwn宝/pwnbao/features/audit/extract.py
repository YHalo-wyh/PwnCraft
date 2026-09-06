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

from pwnbao.features.audit.model import (
    ExploitIR, Hardcode, HelperCall, Interaction, PackOp,
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


class _Extractor(ast.NodeVisitor):
    ENTRY_NAMES = {"main", "exp", "pwn", "solve", "attack"}

    def __init__(self, helpers: dict[str, ast.FunctionDef], ir: ExploitIR):
        self.helpers = helpers
        self.ir = ir
        self._walked_bodies: set[int] = set()

    # -- module pass: module-level statements + entry function bodies only.
    # Helper definition bodies are intentionally NOT walked here — they are
    # recorded through inlined expansion at their call sites.
    def visit_Module(self, node: ast.Module) -> None:  # noqa: N802
        for statement in node.body:
            if isinstance(statement, ast.FunctionDef):
                if statement.name in self.ENTRY_NAMES and \
                        id(statement) not in self._walked_bodies:
                    self._walked_bodies.add(id(statement))
                    for child in ast.walk(statement):
                        if isinstance(child, ast.Call):
                            self._record_call(child)
                        elif isinstance(child, ast.Assign):
                            self._record_assign_facts(child)
            else:
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
                    op = PackOp(fn=name,
                                arg=_arg_text(node.args[0]) if node.args else "",
                                line=node.lineno)
                    if name[0] == "u":
                        self.ir.unpacks.append(op)
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
            op = PackOp(fn=verb, arg=_arg_text(node.args[0]) if node.args else "",
                        line=node.lineno)
            if verb[0] == "u":
                self.ir.unpacks.append(op)
                self._link_leak(op)
            else:
                self.ir.packs.append(op)

    def _link_leak(self, op: PackOp) -> None:
        """Attach the feeding recv length to an unpack when the argument is a
        tracked variable (u64(leak) with leak <- recv(6))."""
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
                result = re.sub(rf"\b{re.escape(param)}\b", value, result)
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
    return ir, None
