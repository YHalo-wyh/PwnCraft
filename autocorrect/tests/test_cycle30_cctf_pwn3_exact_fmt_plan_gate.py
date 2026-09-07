import json
from pathlib import Path

from pwncraft.features.audit.reviewed_format_plan import (
    ExactFormatWritePolicy,
    derive_exact_format_write_plan,
)

ROOT = Path(__file__).resolve().parents[1]
TRUTH = ROOT / "cases" / "fmtstr-pwn-linux-user-mode-fmtstr-2016-CCTF-pwn3-4fddf60b" / "expected_truth_cycle30.json"


def test_cycle30_cctf_symbolic_exp_stays_deferred_until_numeric_facts_exist():
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    offset = truth["expected_pwncraft_semantics"]["required_argument_start"]
    assert derive_exact_format_write_plan(ExactFormatWritePolicy(
        name="cctf-pwn3-deferred",
        target_address=None,
        desired_value=None,
        first_pointer_argument=offset,
        total_bits=32,
        atom_bits=16,
        target_writable_reviewed=None,
    )) is None


def test_cycle30_resolved_numeric_facts_produce_exact_modulo_plan_not_magic():
    result = derive_exact_format_write_plan(ExactFormatWritePolicy(
        name="resolved-runtime-instance",
        target_address=0x804A020,
        desired_value=0xF7E12420,
        first_pointer_argument=7,
        total_bits=32,
        atom_bits=16,
        target_writable_reviewed=True,
    ))
    assert result is not None
    writes = result["facts"][2]["writes"]
    assert all(w["specifier"] == "hn" for w in writes)
    assert len(writes) == 2
    assert result["capabilities"] == ["exact_format_write_plan"]
