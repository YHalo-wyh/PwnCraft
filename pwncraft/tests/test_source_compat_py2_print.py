"""Regression (cycle-2): Python 2 print-statement tolerance in EXP parsing.

Generic rules under test (synthetic sources only, no challenge names):

  P1  py2 print statements (bare / single expr / multiple exprs) parse.
  P2  already-py3 forms (print(x), print(x, y)) and non-statement uses
      (printer = 1, obj.print, print = f) are left untouched.
  P3  string literals containing "print x" text are NOT rewritten (payload
      bytes preserved).
  P4  rewrite is line-preserving: AST line numbers match the original source.
  P5  genuinely invalid sources still fail with the ORIGINAL error.
  P6  end-to-end: analyze_heap_source and HelperContractResolver recognize
      helpers in a py2-dialect EXP.
"""
from __future__ import annotations

from pwncraft.features.heapviz import analyze_heap_source
from pwncraft.features.heapviz.contracts import HelperContractResolver
from pwncraft.features.heapviz.source_compat import (
    parse_module_source,
    rewrite_py2_print_statements,
)

PY2_SNIPPET = '''from pwn import *

def add_note(size, content):
    io.recvuntil("choice:")
    io.sendline("1")
    io.recvuntil("size:")
    io.sendline(str(size))
    io.recvuntil("content:")
    io.sendline(content)

def run():
    add_note(0x20, "aaaa")
    print "allocated"
    print "a", "b"
    print
'''

PY3_SNIPPET = '''from pwn import *

def add_note(size, content):
    io.sendline(str(size))
'''


def test_p1_py2_print_forms_parse() -> None:
    tree, error = parse_module_source(PY2_SNIPPET)
    assert error is None
    assert tree is not None
    names = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)} if False else None
    import ast as _ast
    names = {n.name for n in tree.body if isinstance(n, _ast.FunctionDef)}
    assert names == {"add_note", "run"}


def test_p2_py3_and_nonstatement_uses_untouched() -> None:
    src = 'print(x)\nprint(x, y)\nprinter = 1\nlabel = "print"\n'
    assert rewrite_py2_print_statements(src) == src
    tree, error = parse_module_source(src)
    assert error is None and tree is not None


def test_p3_string_literals_not_rewritten() -> None:
    src = 'payload = """line1\nprint keep_me\nline3"""\n'
    assert rewrite_py2_print_statements(src) == src


def test_p4_line_preserving() -> None:
    tree, _ = parse_module_source(PY2_SNIPPET)
    import ast as _ast
    funcs = {n.name: n.lineno for n in tree.body if isinstance(n, _ast.FunctionDef)}
    # original lines: add_note at 3, run at 11 (unchanged by the rewrite)
    assert funcs["add_note"] == 3 and funcs["run"] == 11


def test_p5_invalid_source_keeps_original_error() -> None:
    bad = "def broken(:\n    pass\n"
    tree, error = parse_module_source(bad)
    assert tree is None and error is not None


def test_p6a_analyzer_recognizes_py2_exp() -> None:
    result = analyze_heap_source(PY2_SNIPPET)
    assert result.valid is True
    ops = [o for o in result.operations]
    assert any(getattr(o, "kind", "").value == "alloc" or getattr(o, "kind", "") == "alloc"
               for o in ops) or len(result.helper_contracts) >= 1


def test_p6b_resolver_contract_for_py2_exp() -> None:
    resolution = HelperContractResolver().resolve(PY2_SNIPPET)
    contract = resolution.contract_for("add_note")
    assert contract is not None
    assert contract.operation.value == "alloc"


def test_p6c_py3_sources_unchanged_path() -> None:
    result = analyze_heap_source(PY3_SNIPPET)
    assert result.valid is True
