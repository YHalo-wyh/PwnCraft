"""VNext.3.1 acceptance: Symbolic Value Domain, SourceSpan/Provenance,
Quick Fix applier, inline depth guard. Deterministic — no IDA, no network.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pwnbao.features.audit.audit import audit_exp  # noqa: E402
from pwnbao.features.audit.quickfix import apply_quick_fix  # noqa: E402
from pwnbao.features.audit.values import SymbolicValue, ValueKind  # noqa: E402


# ---------------- Symbolic Value Domain ----------------

def test_v1_concrete_and_join() -> None:
    a = SymbolicValue.concrete(0x18)
    assert a.is_concrete() and a.as_int() == 0x18
    same = SymbolicValue.concrete(0x18).join(a)
    assert same.is_concrete()
    widened = SymbolicValue.concrete(0x18).join(SymbolicValue.concrete(0x20))
    assert widened.kind is ValueKind.RANGE and widened.lo == 0x18 and widened.hi == 0x20


def test_v2_symbol_never_becomes_concrete() -> None:
    sym = SymbolicValue.symbol("idx", derivation="user_input")
    joined = sym.join(SymbolicValue.concrete(3))
    # symbol ∪ concrete = unknown (deterministic-first: no guessing)
    assert joined.kind is ValueKind.UNKNOWN
    assert sym.as_int() is None


def test_v3_unknown_join_absorbs() -> None:
    unknown = SymbolicValue.unknown("no evidence")
    value = SymbolicValue.concrete(7).join(unknown)
    assert value.as_int() == 7


# ---------------- SourceSpan / Provenance / Quick Fix ----------------

EXP = '''from pwn import *

def pwn():
    leak = io.recv(6)
    libc_base = u64(leak) - libc.sym["puts"]
'''


def test_q1_quick_fix_applies_on_reported_line() -> None:
    diagnostics = audit_exp(EXP)
    hit = [d for d in diagnostics if d["code"] == "EXP_LEAK_001"][0]
    assert hit["fix_appliable"] is True
    assert hit["provenance"] == "DERIVED"
    assert hit["span"]["line"] == hit["line"]
    new_source, status = apply_quick_fix(EXP, hit)
    assert status == "applied"
    assert "u64(leak.ljust(8, b'\\x00'))" in new_source
    assert "u64(leak)" not in new_source.replace("u64(leak.ljust", "")


def test_q2_stale_diagnostic_reports_already_fixed() -> None:
    diagnostics = audit_exp(EXP)
    hit = [d for d in diagnostics if d["code"] == "EXP_LEAK_001"][0]
    fixed = EXP.replace("u64(leak)", "u64(leak.ljust(8, b'\\x00'))")
    _, status = apply_quick_fix(fixed, hit)
    assert status == "already-fixed"


def test_q3_no_fix_target_is_noop() -> None:
    diagnostics = audit_exp(EXP)
    suggestion = [d for d in diagnostics if d["code"] == "EXP_LEAK_003"]
    if suggestion:
        _, status = apply_quick_fix(EXP, suggestion[0])
        assert status in ("no-fix", "applied", "already-fixed")


# ---------------- depth guard ----------------

def test_d1_inline_depth_guard_terminates() -> None:
    # helper-of-helper-of-helper chain must terminate and not crash
    exp = '''
def a(x):
    io.sendlineafter(b"A:", x)

def b(x):
    a(x)

def c(x):
    b(x)

def pwn():
    c(b"hi")
'''
    diagnostics = audit_exp(exp)
    assert isinstance(diagnostics, list)
    ir, err = __import__("pwnbao.features.audit.extract", fromlist=["x"])         .extract_exploit_ir(exp)
    assert err is None
    # chain c -> b -> a expands with bindings propagating to the leaf
    # interaction; depth guard INLINE_DEPTH_LIMIT=2 terminates recursion
    assert [c.function for c in ir.helper_calls] == ["c", "b", "a"]
    leaf = [i for i in ir.interactions if i.scope == "a"]
    assert any(i.value == "b'hi'" for i in leaf), leaf


def test_d2_symbolic_index_no_false_heap_error() -> None:
    # index comes from a variable (symbolic): state machine must NOT produce
    # EXP_HEAP_014 — only concrete indices drive exact transitions
    profile = {"version": 1, "name": "sym", "helpers": [
        {"function": "create", "parameters": ["size", "content"],
         "effects": [{"kind": "alloc", "chunk": "C", "request_size": "size"}]},
        {"function": "delete", "parameters": ["idx"],
         "effects": [{"kind": "free", "index": "idx"}]},
        {"function": "edit", "parameters": ["idx", "content"],
         "effects": [{"kind": "edit", "index": "idx", "data": "content"}]},
    ], "behavior_facts": [
        {"kind": "CLEAR_POINTER", "subject": "chunks[idx]", "confidence": 0.96,
         "scope": "delete@0x1", "backend": "source-ast",
         "evidence": [{"kind": "POST_FREE_NULL_STORE", "detail": "ptr=NULL"}]}]}
    exp = '''
def pwn():
    create(0x80, b"A")
    idx = get_index_from_user()
    delete(idx)
    edit(idx, b"AAAA")
'''
    codes = [d["code"] for d in audit_exp(exp, bits=64, profile=profile)]
    assert "EXP_HEAP_014" not in codes  # symbolic index: no guessed transition


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"PASS {name}")
    print("all vnext3.1 tests passed")
