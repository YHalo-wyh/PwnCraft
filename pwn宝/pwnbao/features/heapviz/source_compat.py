"""Tolerant EXP source parsing.

Public CTF exploits are frequently written in the Python 2 dialect (print
statements). Recognition is static data-flow analysis, so the runtime
semantics of print are irrelevant: a tokenize-guided, line-preserving rewrite
of print statements lets the standard :mod:`ast` parser accept these sources
without touching any other construct.

Guarantees:
  * tokenize-guided: string/bytes literals containing ``print`` text are
    never modified (only real statement-initial ``print`` NAME tokens are);
  * line-preserving: no lines are added or removed, so diagnostics and
    source bindings keep pointing at the original source;
  * conservative: if the rewrite does not make the source parse, the original
    SyntaxError is reported unchanged.
"""
from __future__ import annotations

import ast
import io
import tokenize

_SKIP_NEXT_OPS = {"(", "=", ",", ".", ")", "]", ":", ">>", "*"}  # already-py3 / non-statement forms


def _line_starts(source: str) -> list[int]:
    starts = [0]
    for line in source.splitlines(True):
        starts.append(starts[-1] + len(line))
    return starts


def rewrite_py2_print_statements(source: str) -> str:
    """Wrap statement-initial py2 print statements in parentheses.

    ``print x`` -> ``print(x)``; ``print a, b`` -> ``print(a, b)``;
    bare ``print`` -> ``print()``. Analysis-only rewrite: the runtime
    difference (tuple printing, newline suppression) does not matter for
    static recognition.
    """
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        return source
    starts = _line_starts(source)

    def _abs(pos) -> int:
        row, col = pos
        return starts[row - 1] + col if 0 < row <= len(starts) else 0

    edits: list[tuple[int, str]] = []  # (offset, text-to-insert)
    prev_significant = None
    for i, tok in enumerate(tokens):
        if tok.type == tokenize.NAME and tok.string == "print":
            prev_ok = prev_significant is None or prev_significant.type in (
                tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT,
            ) or (prev_significant.type == tokenize.OP and prev_significant.string in (";", ":"))
            if prev_ok:
                j = i + 1
                while j < len(tokens) and tokens[j].type in (tokenize.NL, tokenize.COMMENT):
                    j += 1
                nxt = tokens[j] if j < len(tokens) else None
                if nxt is not None and not (nxt.type == tokenize.OP and nxt.string in _SKIP_NEXT_OPS):
                    # statement extends to the last real token before NEWLINE
                    k = j
                    end_tok = None
                    while k < len(tokens) and tokens[k].type != tokenize.NEWLINE:
                        if tokens[k].type not in (tokenize.NL, tokenize.COMMENT):
                            end_tok = tokens[k]
                        k += 1
                    if end_tok is None:
                        edits.append((_abs(tok.end), "()"))
                    else:
                        edits.append((_abs(tok.end), "("))
                        edits.append((_abs(end_tok.end), ")"))
        if tok.type not in (tokenize.NL, tokenize.COMMENT):
            prev_significant = tok
    if not edits:
        return source
    out = source
    for offset, text in sorted(edits, key=lambda e: -e[0]):
        out = out[:offset] + text + out[offset:]
    return out


def parse_module_source(source: str) -> tuple[ast.Module | None, SyntaxError | None]:
    """Parse EXP source with py2-print tolerance.

    Returns ``(tree, None)`` or ``(None, error)`` — exactly one non-None. The
    reported error always carries positions valid for the *original* source
    (the rewrite is line-preserving)."""
    text = str(source or "")
    try:
        return ast.parse(text), None
    except SyntaxError as first_error:
        rewritten = rewrite_py2_print_statements(text)
        if rewritten == text:
            return None, first_error
        try:
            return ast.parse(rewritten), None
        except SyntaxError:
            return None, first_error
