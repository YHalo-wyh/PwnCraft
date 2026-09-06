import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROJECT = ROOT / "pwncraft"
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

from pwncraft.features.audit.integer_flow import analyze_c_integer_exp_flow

CASE_ID = "integer-sekaictf-2026-echo-chamber-99fc2e72"
TRUTH = ROOT / "autocorrect" / "cases" / CASE_ID / "expected_truth_cycle13.json"

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

# Source-derived minimal form of the official solution's reset request.  It
# preserves only the literal input needed by this truth layer.
OFFICIAL_SOLUTION_INPUT = r'''
io.send(b"POST /reset HTTP/1.1\r\nContent-Length: -1\r\n\r\n")
'''


def test_cycle13_truth_revision_is_non_destructive_and_officially_grounded() -> None:
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    lock = truth["truth_lock"]
    assert lock["truth_revision"] == 2
    assert lock["supersedes"] == "truth-sekaictf2026-echo-chamber-integer-v1"
    assert truth["source_class"] == "official_challenge_archive"
    assert truth["materials"]["source_git_blob_sha1"] == \
        "99fc2e7230831ec5970b0a8540936bbac7a7c23c"
    assert truth["materials"]["official_solution_git_blob_sha1"] == \
        "ce9aeef6fdf962468adb624202ff45fd621ec367"


def test_pointer_return_handler_keeps_real_function_provenance() -> None:
    result = analyze_c_integer_exp_flow(SOURCE_EXCERPT, OFFICIAL_SOLUTION_INPUT)
    assert result["status"] == "ok"
    relevant = [
        fact for fact in result["source_facts"]
        if fact["kind"] in {
            "SIGNED_PARSE_TO_UNSIGNED",
            "UNSIGNED_LENGTH_ALLOCATION_USE",
            "UNSIGNED_LENGTH_COPY_BOUND_USE",
        }
    ]
    assert relevant
    assert {fact["function"] for fact in relevant} == {"handle_connection"}


def test_official_minus_one_input_closes_the_exact_modular_relation() -> None:
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    required = set(truth["expected_pwncraft_semantics"]["required_composed_fact_kinds"])
    result = analyze_c_integer_exp_flow(SOURCE_EXCERPT, OFFICIAL_SOLUTION_INPUT)
    actual = {fact["kind"] for fact in result["composed_facts"]}
    assert required <= actual

    by_kind = {fact["kind"]: fact for fact in result["composed_facts"]}
    assert by_kind["EXP_INPUT_REACHES_SIGNED_PARSER"]["input_field"] == "Content-Length"
    assert by_kind["EXP_INPUT_REACHES_SIGNED_PARSER"]["input_value"] == -1
    assert by_kind["UNSIGNED_CONVERSION_EXACT_MAX"]["relation"] == \
        "(-1) mod 2^N = 2^N - 1"
    assert by_kind["ALLOCATION_ARGUMENT_WRAP_TO_ZERO"]["result"] == 0
    assert by_kind["COPY_BOUND_REMAINS_UNSIGNED_MAX"]["result"] == "UNSIGNED_MAX(N)"


def test_cycle13_keeps_runtime_and_allocator_claims_out_of_the_fact_layer() -> None:
    result = analyze_c_integer_exp_flow(SOURCE_EXCERPT, OFFICIAL_SOLUTION_INPUT)
    rendered = json.dumps(result["composed_facts"], ensure_ascii=False).lower()
    assert "runtime delivery is not observed" in rendered
    assert "does not claim malloc(0) result" in rendered
    assert "allocator-bin" not in rendered
