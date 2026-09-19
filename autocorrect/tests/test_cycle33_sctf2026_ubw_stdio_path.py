import json
from pathlib import Path

from pwncraft.features.audit.reviewed_stdio_path import (
    ReviewedFileFieldWrite,
    ReviewedStdioPathPolicy,
    ReviewedStdioTrigger,
    derive_reviewed_stdio_path,
)

ROOT = Path(__file__).resolve().parents[1]
TRUTH = ROOT / "cases" / "heap-sctf-2026-ubw-1b3b161e" / "expected_truth_cycle33.json"


def _upstream(stdout_ptr: int, fake_file: int):
    return {
        "capabilities": ["reviewed_largebin_pointer_write"],
        "facts": [
            {
                "kind": "largebin_insertion_pointer_write",
                "address": stdout_ptr,
                "value": fake_file,
                "width": 8,
            }
        ],
    }


def _policy(stdout_ptr: int, fake_file: int):
    libc = 0x7F1200000000
    wide = 0x555550008000
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    rel = truth["relative_policy"]
    fields = rel["required_file_fields"]
    return ReviewedStdioPathPolicy(
        name="sctf-ubw-stdio-path",
        allocator_family=rel["allocator_family"],
        allocator_version=rel["allocator_version"],
        stream_pointer_address=stdout_ptr,
        file_object_address=fake_file,
        payload_write_address=fake_file + rel["payload_start_offset"],
        payload_start_offset=rel["payload_start_offset"],
        field_writes=(
            ReviewedFileFieldWrite("write_base", fields["write_base"]["offset"], fields["write_base"]["value"]),
            ReviewedFileFieldWrite("write_ptr", fields["write_ptr"]["offset"], fields["write_ptr"]["value"]),
            ReviewedFileFieldWrite("lock", fields["lock"]["offset"], libc + 0x205700),
            ReviewedFileFieldWrite("wide_data", fields["wide_data"]["offset"], wide),
            ReviewedFileFieldWrite("vtable", fields["vtable"]["offset"], libc + 0x202228),
            ReviewedFileFieldWrite("continuation", 0xA8, libc + 0x12DFBA),
            ReviewedFileFieldWrite("post_vtable", 0xE0, fake_file + 0x300),
        ),
        trigger=ReviewedStdioTrigger(
            call_kind=rel["trigger"]["call_kind"],
            stream=rel["trigger"]["stream"],
            site_label=rel["trigger"]["site_label"],
            reaches_stream_reviewed=rel["trigger"]["reaches_stream_reviewed"],
            provenance="OFFICIAL_WRITEUP_PLUS_EXP",
        ),
        file_layout_reviewed=True,
    )


def test_cycle33_exact_stdout_binding_plus_reviewed_file_and_trigger_reaches_stdio_only():
    stdout_ptr = 0x7F12002046A8
    fake_file = 0x555550006000
    result = derive_reviewed_stdio_path(_upstream(stdout_ptr, fake_file), _policy(stdout_ptr, fake_file))
    assert result is not None
    assert result["capabilities"] == [
        "stdout_rebound_to_reviewed_file_object",
        "reviewed_stdio_path_reachable",
    ]
    kinds = {fact["kind"] for fact in result["facts"]}
    assert "stdout_pointer_binds_reviewed_file_object" in kinds
    assert "reviewed_file_field_state" in kinds
    assert "reviewed_stdout_write_window" in kinds
    assert "reviewed_stdio_trigger_reaches_stream" in kinds
    caps = " ".join(result["capabilities"]).lower()
    assert "control" not in caps
    assert "shell" not in caps
    assert "orw" not in caps


def test_cycle33_wrong_upstream_stdout_binding_stays_unknown():
    stdout_ptr = 0x7F12002046A8
    fake_file = 0x555550006000
    upstream = _upstream(stdout_ptr, fake_file)
    upstream["facts"][0]["value"] += 0x10
    assert derive_reviewed_stdio_path(upstream, _policy(stdout_ptr, fake_file)) is None


def test_cycle33_missing_required_file_field_stays_unknown():
    stdout_ptr = 0x7F12002046A8
    fake_file = 0x555550006000
    policy = _policy(stdout_ptr, fake_file)
    fields = tuple(field for field in policy.field_writes if field.role != "vtable")
    policy = ReviewedStdioPathPolicy(**{**policy.__dict__, "field_writes": fields})
    assert derive_reviewed_stdio_path(_upstream(stdout_ptr, fake_file), policy) is None


def test_cycle33_nonempty_write_window_and_reviewed_stdout_trigger_are_both_required():
    stdout_ptr = 0x7F12002046A8
    fake_file = 0x555550006000
    policy = _policy(stdout_ptr, fake_file)
    bad_fields = tuple(
        ReviewedFileFieldWrite(field.role, field.offset, 0 if field.role == "write_ptr" else field.value, field.width)
        for field in policy.field_writes
    )
    bad_window = ReviewedStdioPathPolicy(**{**policy.__dict__, "field_writes": bad_fields})
    assert derive_reviewed_stdio_path(_upstream(stdout_ptr, fake_file), bad_window) is None

    bad_trigger = ReviewedStdioTrigger("printf", "stdout", "blade prompt", reaches_stream_reviewed=False)
    no_reach = ReviewedStdioPathPolicy(**{**policy.__dict__, "trigger": bad_trigger})
    assert derive_reviewed_stdio_path(_upstream(stdout_ptr, fake_file), no_reach) is None
