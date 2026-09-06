"""Deterministic structure extraction for simple typed embedded programs.

Pwn exploits increasingly ship a second program inside the Python transport:
compiler/VM/DSL challenges, SQL-like payload languages, protocol scripts, and
small interpreters.  Cycle-14 made the outbound bytes visible; this module adds
one deliberately narrow structural layer for C-ish ``function`` DSLs without
executing either the wrapper or the embedded language.

Supported syntax is intentionally small and evidence-preserving:

* ``function name(type arg, ...) : type local, ... -> rettype {`` headers;
* ``name := expression;`` assignments;
* direct ``callee(arg, ...);`` calls;
* ``do { ... } while (...);`` loop membership/order.

The parser does *not* infer runtime aliasing, compiler slot allocation, type
confusion, memory corruption, or exploitability.  Those require target/compiler
semantics beyond source structure and therefore remain separate truth layers.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
from typing import Any


_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
_FUNCTION_RE = re.compile(
    rf"^\s*function\s+(?P<name>{_IDENT})\s*\((?P<params>.*?)\)\s*:\s*"
    rf"(?P<locals>.*?)\s*->\s*(?P<ret>{_IDENT})\s*\{{\s*$"
)
_DECL_RE = re.compile(rf"^\s*(?P<type>{_IDENT})\s+(?P<name>{_IDENT})\s*$")
_ASSIGN_RE = re.compile(rf"^\s*(?P<target>{_IDENT})\s*:=\s*(?P<expr>.+?)\s*;\s*$")
_CALL_RE = re.compile(rf"^\s*(?P<callee>{_IDENT})\s*\((?P<args>.*)\)\s*;\s*$")
_SIMPLE_CALL_EXPR_RE = re.compile(rf"^\s*(?P<callee>{_IDENT})\s*\((?P<args>.*)\)\s*$")


@dataclass(frozen=True)
class EmbeddedDeclaration:
    name: str
    type_name: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EmbeddedStatement:
    kind: str
    function: str
    line: int
    order: int
    loop_depth: int = 0
    target: str = ""
    expression: str = ""
    callee: str = ""
    arguments: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["arguments"] = list(self.arguments)
        return data


@dataclass
class EmbeddedFunction:
    name: str
    return_type: str
    line: int
    parameters: list[EmbeddedDeclaration] = field(default_factory=list)
    locals: list[EmbeddedDeclaration] = field(default_factory=list)
    statements: list[EmbeddedStatement] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "return_type": self.return_type,
            "line": self.line,
            "parameters": [item.to_dict() for item in self.parameters],
            "locals": [item.to_dict() for item in self.locals],
            "statements": [item.to_dict() for item in self.statements],
        }


@dataclass
class EmbeddedProgram:
    syntax_family: str = "typed_function_dsl"
    functions: list[EmbeddedFunction] = field(default_factory=list)
    provenance: str = "OUTBOUND_LITERAL_EMBEDDED_STRUCTURE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "syntax_family": self.syntax_family,
            "functions": [fn.to_dict() for fn in self.functions],
            "provenance": self.provenance,
        }


def _split_top_level(text: str) -> list[str]:
    """Split a comma list without breaking nested calls or quoted strings."""
    items: list[str] = []
    start = 0
    depth = 0
    quote = ""
    escaped = False
    for index, char in enumerate(text):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in ("'", '"'):
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            item = text[start:index].strip()
            if item:
                items.append(item)
            start = index + 1
    tail = text[start:].strip()
    if tail:
        items.append(tail)
    return items


def _parse_declarations(text: str) -> list[EmbeddedDeclaration] | None:
    stripped = text.strip()
    if not stripped:
        return []
    result: list[EmbeddedDeclaration] = []
    for item in _split_top_level(stripped):
        match = _DECL_RE.match(item)
        if match is None:
            return None
        result.append(EmbeddedDeclaration(
            name=match.group("name"),
            type_name=match.group("type"),
        ))
    return result


def _call_parts(expression: str) -> tuple[str, tuple[str, ...]]:
    match = _SIMPLE_CALL_EXPR_RE.match(expression.strip())
    if match is None:
        return "", ()
    return match.group("callee"), tuple(_split_top_level(match.group("args")))


def extract_embedded_function_program(
    content: str | bytes,
) -> EmbeddedProgram | None:
    """Parse the supported typed-function DSL subset from concrete payload bytes.

    Detection requires at least one fully valid function header.  Unknown lines
    are ignored as structure we do not yet understand; they are never converted
    into vulnerability facts.  Malformed declarations in a recognized function
    header reject that function rather than guessing its types.
    """
    if isinstance(content, bytes):
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            return None
    else:
        text = content

    lines = text.splitlines()
    functions: list[EmbeddedFunction] = []
    current: EmbeddedFunction | None = None
    brace_depth = 0
    loop_depth = 0
    statement_order = 0

    for line_no, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if current is None:
            match = _FUNCTION_RE.match(raw_line)
            if match is None:
                continue
            parameters = _parse_declarations(match.group("params"))
            locals_ = _parse_declarations(match.group("locals"))
            if parameters is None or locals_ is None:
                continue
            current = EmbeddedFunction(
                name=match.group("name"),
                return_type=match.group("ret"),
                line=line_no,
                parameters=parameters,
                locals=locals_,
            )
            functions.append(current)
            brace_depth = raw_line.count("{") - raw_line.count("}")
            loop_depth = 0
            statement_order = 0
            continue

        # A do/while closing line leaves loop context before any later statement.
        closes_do_while = bool(re.match(r"^\s*}\s*while\s*\(", raw_line))
        if closes_do_while:
            loop_depth = max(0, loop_depth - 1)

        assignment = _ASSIGN_RE.match(raw_line)
        call = _CALL_RE.match(raw_line)
        if assignment is not None:
            statement_order += 1
            expression = assignment.group("expr").strip()
            callee, arguments = _call_parts(expression)
            current.statements.append(EmbeddedStatement(
                kind="assignment",
                function=current.name,
                line=line_no,
                order=statement_order,
                loop_depth=loop_depth,
                target=assignment.group("target"),
                expression=expression,
                callee=callee,
                arguments=arguments,
            ))
        elif call is not None:
            statement_order += 1
            current.statements.append(EmbeddedStatement(
                kind="call",
                function=current.name,
                line=line_no,
                order=statement_order,
                loop_depth=loop_depth,
                callee=call.group("callee"),
                arguments=tuple(_split_top_level(call.group("args"))),
                expression=stripped[:-1].strip(),
            ))

        # ``do {`` starts loop context for subsequent statements on following lines.
        if re.match(r"^\s*do\s*\{\s*$", raw_line):
            loop_depth += 1

        brace_depth += raw_line.count("{") - raw_line.count("}")
        if brace_depth <= 0:
            current = None
            brace_depth = 0
            loop_depth = 0

    return EmbeddedProgram(functions=functions) if functions else None
