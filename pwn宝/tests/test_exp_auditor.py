"""EXP Live Auditor tests (VNext.3) — deterministic rules, UNKNOWN ≠ FALSE."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pwnbao.features.audit.audit import audit_exp  # noqa: E402

PROFILE_LAB13_STYLE = {
    "version": 1,
    "name": "auditor-test",
    "helpers": [
        {"function": "create", "parameters": ["size", "content"],
         "effects": [{"kind": "alloc", "chunk": "C", "request_size": "size"}]},
        {"function": "delete", "parameters": ["idx"],
         "effects": [{"kind": "free", "index": "idx"}]},
        {"function": "edit", "parameters": ["idx", "content"],
         "effects": [{"kind": "edit", "index": "idx", "data": "content"}]},
        {"function": "show", "parameters": ["idx"],
         "effects": [{"kind": "show", "index": "idx"}]},
    ],
    "behavior_facts": [
        {"kind": "CLEAR_POINTER", "subject": "chunks[idx]", "confidence": 0.96,
         "scope": "delete@0x4012A0", "backend": "source-ast",
         "evidence": [{"kind": "POST_FREE_NULL_STORE",
                       "detail": "free(chunks[idx]); chunks[idx] = NULL"}]},
    ],
}


def _codes(diagnostics):
    return [d["code"] for d in diagnostics]


def test_r1_u64_short_recv_error_with_fix() -> None:
    exp = '''
def pwn():
    leak = io.recv(6)
    libc_base = u64(leak) - libc.sym["puts"]
'''
    diagnostics = audit_exp(exp)
    hit = [d for d in diagnostics if d["code"] == "EXP_LEAK_001"]
    assert hit, diagnostics
    d = hit[0]
    assert d["severity"] == "error" and d["confidence"] == 0.99
    assert "ljust(8" in d["suggested_fix"]
    assert d["evidence"][0]["detail"].endswith("recv(6)")


def test_r2_u64_with_ljust_is_clean() -> None:
    exp = '''
def pwn():
    leak = io.recv(6)
    libc_base = u64(leak.ljust(8, b"\\x00")) - libc.sym["puts"]
'''
    assert "EXP_LEAK_001" not in _codes(audit_exp(exp))


def test_r3_recvline_unknown_length_is_suggestion() -> None:
    exp = '''
def pwn():
    leak = io.recvline()
    libc_base = u64(leak) - libc.sym["puts"]
'''
    diagnostics = audit_exp(exp)
    hit = [d for d in diagnostics if d["code"] == "EXP_LEAK_003"]
    assert hit and hit[0]["severity"] == "suggestion"


def test_r4_arch_mismatch_p32_on_64bit() -> None:
    exp = '''
def pwn():
    payload = p32(system)
    io.send(payload)
'''
    diagnostics = audit_exp(exp, bits=64)
    hit = [d for d in diagnostics if d["code"] == "EXP_ARCH_001"]
    assert hit and hit[0]["severity"] == "error"
    assert "p64(system)" in hit[0]["suggested_fix"]


def test_r5_p32_on_32bit_is_clean() -> None:
    exp = '''
def pwn():
    payload = p32(system)
    io.send(payload)
'''
    assert "EXP_ARCH_001" not in _codes(audit_exp(exp, bits=32))


def test_r6_pie_hardcode_suggestion() -> None:
    exp = '''
def pwn():
    pop_rdi = 0x4012a3
    io.send(p64(pop_rdi))
'''
    diagnostics = audit_exp(exp, bits=64, pie=True)
    hit = [d for d in diagnostics if d["code"] == "EXP_PIE_001"]
    assert hit and hit[0]["severity"] == "suggestion"


def test_r7_heap_uaf_conflict_with_clear_pointer_evidence() -> None:
    exp = '''
def pwn():
    create(0x80, b"A")
    delete(0)
    edit(0, b"AAAA")
'''
    diagnostics = audit_exp(exp, bits=64, profile=PROFILE_LAB13_STYLE)
    hit = [d for d in diagnostics if d["code"] == "EXP_HEAP_014"]
    assert hit, diagnostics
    d = hit[0]
    assert d["severity"] == "error"
    assert any(e["kind"] == "POST_FREE_NULL_STORE" for e in d["evidence"])


def test_r8_unknown_clearing_is_suggestion_not_error() -> None:
    profile = {"version": 1, "name": "unknown-clear", "helpers": [
        {"function": "create", "parameters": ["size", "content"],
         "effects": [{"kind": "alloc", "chunk": "C", "request_size": "size"}]},
        {"function": "delete", "parameters": ["idx"],
         "effects": [{"kind": "free", "index": "idx"}]},
        {"function": "edit", "parameters": ["idx", "content"],
         "effects": [{"kind": "edit", "index": "idx", "data": "content"}]},
    ], "behavior_facts": []}   # no facts: clearing UNKNOWN
    exp = '''
def pwn():
    create(0x80, b"A")
    delete(0)
    edit(0, b"AAAA")
'''
    diagnostics = audit_exp(exp, bits=64, profile=profile)
    codes = _codes(diagnostics)
    assert "EXP_HEAP_014" not in codes          # UNKNOWN must not be an error
    hit = [d for d in diagnostics if d["code"] == "EXP_HEAP_021"]
    assert hit and hit[0]["severity"] == "suggestion"
    assert hit[0]["confidence"] < 1.0


def test_r9_keep_dangling_is_clean_for_uaf() -> None:
    profile = {"version": 1, "name": "uaf-ok", "helpers":
               PROFILE_LAB13_STYLE["helpers"], "behavior_facts": [
        {"kind": "KEEP_DANGLING_POINTER", "subject": "chunks[idx]",
         "confidence": 0.97, "scope": "delete@0x4012A0",
         "backend": "source-ast", "evidence": [
             {"kind": "CALL", "detail": "free(chunks[idx]); no store after"}]}]}
    exp = '''
def pwn():
    create(0x80, b"A")
    delete(0)
    show(0)
'''
    assert "EXP_HEAP_014" not in _codes(audit_exp(exp, bits=64, profile=profile))


def test_r10_helper_interactions_are_inlined() -> None:
    exp = '''
def create(size, content):
    io.recvuntil(b"Choice:")
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Size:", str(size).encode())
    io.send(content)

def pwn():
    create(0x18, b"dada")
'''
    ir, error = __import__("pwnbao.features.audit.extract", fromlist=["x"]) \
        .extract_exploit_ir(exp)
    assert error is None
    inlined = [i for i in ir.interactions if i.scope == "create"]
    actions = [(i.action, i.wait_for) for i in inlined]
    assert ("RECVUNTIL", "b'Choice:'") in actions
    assert ("SENDLINE", "b'> '") in actions
    assert ("SENDLINE", "b'Size:'") in actions
    # argument binding reached the inlined value (ast.unparse renders 0x18 as 24)
    assert any("24" in i.value for i in inlined)


def test_r11_syntax_error_is_single_parse_diagnostic() -> None:
    diagnostics = audit_exp("payload = flat(\n    0,\n    pop_rdi,\n")
    assert _codes(diagnostics) == ["EXP_PARSE_001"]


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"PASS {name}")
    print("all exp auditor tests passed")
