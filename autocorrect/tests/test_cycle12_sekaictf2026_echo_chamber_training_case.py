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
from pwncraft.core.c_source_ir import extract_c_integer_flows

CASE_ID = "integer-sekaictf-2026-echo-chamber-99fc2e72"
TRUTH = ROOT / "autocorrect" / "cases" / CASE_ID / "expected_truth.json"

# Source-derived excerpt from the official SekaiCTF 2026 echo-chamber chal.c.
SOURCE_EXCERPT = r'''
void *handle_connection(void *arg) {
    Worker *self = (Worker *)arg;
    Header *content_length = find_header(headers, "Content-Length");
    if (strcmp(method, "POST") == 0) {
      char *end = NULL;
      size_t body_len = strtoll(content_length->val, &end, 10);
      body = malloc(body_len + 1);
      size_t nbytes = readn(self->fd, body, body_len);
    }
    return NULL;
}
'''


def test_sekaictf2026_official_case_is_train_split() -> None:
    assert split_for_case(CASE_ID, load_splits()) == "train"


def test_truth_is_locked_to_official_source_and_solution() -> None:
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    assert truth["source_class"] == "official_challenge_archive"
    assert truth["event"]["name"] == "SekaiCTF 2026"
    assert truth["event"]["challenge"] == "echo-chamber"
    assert truth["materials"]["source_git_blob_sha1"] == \
        "99fc2e7230831ec5970b0a8540936bbac7a7c23c"
    assert truth["materials"]["official_solution_git_blob_sha1"] == \
        "ce9aeef6fdf962468adb624202ff45fd621ec367"


def test_official_source_signedness_chain_is_recovered_without_name_only_claims() -> None:
    facts = extract_c_integer_flows(SOURCE_EXCERPT)
    by_kind = {fact.kind: fact for fact in facts}
    assert set(by_kind) == {
        "SIGNED_PARSE_TO_UNSIGNED",
        "UNSIGNED_LENGTH_ALLOCATION_USE",
        "UNSIGNED_LENGTH_COPY_BOUND_USE",
    }
    seed = by_kind["SIGNED_PARSE_TO_UNSIGNED"]
    assert seed.variable == "body_len"
    assert seed.details["parser"] == "strtoll"
    assert seed.details["destination_type"] == "size_t"
    assert "body_len + 1" in by_kind["UNSIGNED_LENGTH_ALLOCATION_USE"].expression
    assert by_kind["UNSIGNED_LENGTH_COPY_BOUND_USE"].details["callee"] == "readn"


def test_official_solution_negative_input_is_truth_evidence_not_runtime_observation() -> None:
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    layer = truth["truth_layers"]["OFFICIAL_SOLUTION_INPUT"]
    assert layer["status"] == "EXP_SUPPORTED"
    assert layer["facts"][0]["value"] == -1
    assert layer["facts"][0]["request_fragment"] == "Content-Length: -1"
    assert all("runtime" not in fact.get("provenance", "").lower()
               for fact in layer["facts"])
