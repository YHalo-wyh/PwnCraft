from pwncraft.core.elf_artifact_provider import snapshot_from_tool_outputs
from pwncraft.features.audit.reviewed_libc_symbols import (
    ReviewedLibcBaseAnchor,
    ReviewedLibcSymbolPolicy,
    ReviewedLibcSymbolRequest,
    derive_reviewed_runtime_libc_symbols,
)


HEADER = """\
ELF Header:
  Class: ELF64
  Data: 2's complement, little endian
  Type: DYN (Shared object file)
  Machine: Advanced Micro Devices X86-64
  Entry point address: 0x27490
"""
SYMBOLS = """\
Symbol table '.dynsym' contains 4 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     1: 00000000002045c0   224 OBJECT  GLOBAL DEFAULT   28 _IO_2_1_stdout_@@GLIBC_2.2.5
     2: 00000000002046e0   224 OBJECT  GLOBAL DEFAULT   28 _IO_2_1_stderr_@@GLIBC_2.2.5
     3: 0000000000052290    45 FUNC    GLOBAL DEFAULT   16 system@@GLIBC_2.2.5
"""
PHDRS = """\
Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x100000 0x100000 R E 0x1000
  LOAD           0x200000 0x0000000000200000 0x0000000000200000 0x100000 0x100000 RW  0x1000
  GNU_RELRO      0x200000 0x0000000000200000 0x0000000000200000 0x001000 0x001000 R   0x1
"""


def _libc(symbols=SYMBOLS, degraded=False):
    return snapshot_from_tool_outputs(
        artifact_sha256="61" * 32,
        artifact_name="libc.so.6",
        header_text=HEADER,
        symbols_text=symbols,
        relocations_text="",
        program_headers_text=PHDRS,
        degraded=degraded,
        degrade_notes=["incomplete"] if degraded else [],
    )


def _base_fact(stdout_offset=0x2045C0):
    return {
        "kind": "runtime_stdout_libc_base_derivation",
        "runtime_observed": True,
        "capabilities": ["libc_base_derived_from_stdout_observation"],
        "facts": [{
            "kind": "libc_base_formula",
            "stdout_symbol_offset": stdout_offset,
            "observed_field_offset": 0x84,
            "result": 0x7F4567000000,
        }],
    }


def _policy():
    return ReviewedLibcSymbolPolicy(
        name="heapmage-runtime-libc-symbols",
        base_anchor=ReviewedLibcBaseAnchor(symbol="_IO_2_1_stdout_"),
        requests=(
            ReviewedLibcSymbolRequest(role="dispatch", symbol="system", require_executable=True),
            ReviewedLibcSymbolRequest(
                role="fake_file_target",
                symbol="_IO_2_1_stderr_",
                require_runtime_writable=True,
            ),
        ),
    )


def test_cycle39_runtime_base_is_reanchored_to_exact_libc_before_symbol_resolution():
    result = derive_reviewed_runtime_libc_symbols(_libc(), _base_fact(), _policy())
    assert result is not None
    base = 0x7F4567000000
    assert result["facts"][0]["anchor_symbol_offset"] == 0x2045C0
    assert result["bindings"]["dispatch"] == base + 0x52290
    assert result["bindings"]["fake_file_target"] == base + 0x2046E0
    assert result["artifact"]["libc_sha256"] == "61" * 32
    assert result["capabilities"] == ["reviewed_runtime_libc_symbols_resolved"]


def test_cycle39_base_from_different_libc_artifact_is_rejected():
    wrong_artifact = _libc(SYMBOLS.replace("00000000002045c0", "00000000002055c0", 1))
    assert derive_reviewed_runtime_libc_symbols(wrong_artifact, _base_fact(), _policy()) is None


def test_cycle39_nonexecutable_system_or_relro_stderr_is_rejected():
    no_exec = _libc(SYMBOLS.replace("0000000000052290", "0000000000203000", 1))
    assert derive_reviewed_runtime_libc_symbols(no_exec, _base_fact(), _policy()) is None

    relro_stderr = _libc(SYMBOLS.replace("00000000002046e0", "00000000002006e0", 1))
    assert derive_reviewed_runtime_libc_symbols(relro_stderr, _base_fact(), _policy()) is None


def test_cycle39_degraded_libc_snapshot_never_produces_runtime_symbols():
    assert derive_reviewed_runtime_libc_symbols(_libc(degraded=True), _base_fact(), _policy()) is None
