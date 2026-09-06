from pwncraft.core.pwn_surface import PwnDomain, analyze_pwn_surface
from pwncraft.core.workspace import PwnWorkspace
from pwncraft.features.audit.extract import extract_exploit_ir
from pwncraft.features.audit.semantic_facts import (
    analyze_exp_semantics,
    apply_exp_semantics_to_workspace,
    infer_exp_primitives,
)


def _io_file_state(workspace: PwnWorkspace) -> str:
    return {
        item.domain: item.state for item in analyze_pwn_surface(workspace)
    }[PwnDomain.IO_FILE]


def test_symbol_refs_capture_dot_and_subscript_elf_sym_forms() -> None:
    source = """
from pwn import *
libc = ELF('./libc.so.6')
a = libc.sym._IO_2_1_stdout_
b = libc.sym['_IO_2_1_stderr_']
c = libc.sym._IO_wfile_jumps
"""
    ir, error = extract_exploit_ir(source)
    assert error is None
    refs = {(item.namespace, item.symbol) for item in ir.symbol_refs}
    assert ("libc", "_IO_2_1_stdout_") in refs
    assert ("libc", "_IO_2_1_stderr_") in refs
    assert ("libc", "_IO_wfile_jumps") in refs


def test_file_object_plus_io_vtable_derives_fsop_intent_only() -> None:
    source = """
from pwn import *
libc = ELF('./libc.so.6')
pl = p64(libc.sym._IO_2_1_stderr_)
pl += p64(libc.sym._IO_wfile_jumps)
pl += p64(libc.sym.system)
"""
    ir, error = extract_exploit_ir(source)
    assert error is None
    primitives = infer_exp_primitives(ir)
    assert len(primitives) == 1
    primitive = primitives[0]
    assert primitive["name"] == "FSOP / FILE corruption intent"
    assert primitive["domain"] == "io_file"
    assert primitive["state"] == "derived"
    symbols = {item["symbol"] for item in primitive["evidence"]}
    assert {"_IO_2_1_stderr_", "_IO_wfile_jumps", "system"} <= symbols


def test_single_symbol_or_system_alone_does_not_claim_fsop() -> None:
    for source in (
        "x = libc.sym.system\n",
        "x = libc.sym._IO_2_1_stdout_\n",
        "x = libc.sym._IO_wfile_jumps\n",
    ):
        result = analyze_exp_semantics(source)
        assert result["status"] == "ok"
        assert result["primitives"] == []


def test_exp_derived_fsop_is_partial_until_target_or_runtime_proof() -> None:
    source = """
pl = p64(libc.sym._IO_2_1_stderr_)
pl += p64(libc.sym._IO_wfile_jumps)
"""
    workspace = PwnWorkspace()
    result = apply_exp_semantics_to_workspace(workspace, source)
    assert result["status"] == "ok"
    assert _io_file_state(workspace) == "partial"

    workspace.add_primitive(
        "FSOP / FILE corruption intent",
        evidence="independently proven target/runtime evidence",
        source="runtime",
        state="confirmed",
    )
    assert _io_file_state(workspace) == "evidenced"


def test_parse_failure_never_produces_semantic_primitives() -> None:
    result = analyze_exp_semantics("x = (")
    assert result["status"] == "blocked"
    assert result["reason"] == "EXP_PARSE"
    assert result["primitives"] == []
