import json
from pathlib import Path

from pwncraft.features.audit.reviewed_wide_dispatch import (
    ReviewedWideDispatchPolicy,
    derive_reviewed_wide_dispatch,
)

ROOT = Path(__file__).resolve().parents[1]
TRUTH = ROOT / "cases" / "heap-sctf-2026-ubw-1b3b161e" / "expected_truth_cycle34.json"


def _upstream(file_addr: int, wide: int, file_vtable: int):
    return {
        "capabilities": [
            "stdout_rebound_to_reviewed_file_object",
            "reviewed_stdio_path_reachable",
        ],
        "facts": [
            {
                "kind": "reviewed_file_field_state",
                "file_object_address": file_addr,
                "fields": [
                    {"role": "write_base", "offset": 0x20, "value": 0, "width": 8},
                    {"role": "write_ptr", "offset": 0x28, "value": 1, "width": 8},
                    {"role": "lock", "offset": 0x88, "value": 0x7F0000205700, "width": 8},
                    {"role": "wide_data", "offset": 0xA0, "value": wide, "width": 8},
                    {"role": "vtable", "offset": 0xD8, "value": file_vtable, "width": 8},
                ],
            }
        ],
    }


def _policy(file_addr: int, wide: int, file_vtable: int, setcontext: int):
    return ReviewedWideDispatchPolicy(
        name="sctf-ubw-wide-dispatch",
        allocator_family="glibc",
        allocator_version="official-target-reviewed",
        file_object_address=file_addr,
        wide_data_address=wide,
        file_vtable_address=file_vtable,
        wide_vtable_address=wide + 0x100,
        dispatch_target_address=setcontext,
        file_vtable_semantics_reviewed=True,
        wide_dispatch_semantics_reviewed=True,
        target_identity_reviewed=True,
        target_symbol="setcontext",
    )


def test_cycle34_official_geometry_resolves_setcontext_dispatch_only():
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    file_addr = 0x555550005000
    wide = 0x555550006000
    libc = 0x7F0000000000
    file_vtable = libc + 0x202228
    setcontext = libc + 0x4A960
    policy = _policy(file_addr, wide, file_vtable, setcontext)
    writes = (
        {"address": wide + 0xE0, "value": wide + 0x100, "width": 8},
        {"address": wide + 0x168, "value": setcontext, "width": 8},
    )

    result = derive_reviewed_wide_dispatch(
        _upstream(file_addr, wide, file_vtable),
        policy,
        wide_writes=writes,
    )
    assert result is not None
    assert result["facts"][-1]["slot_address"] == wide + 0x100 + 0x68
    assert result["facts"][-1]["target_address"] == setcontext
    assert result["facts"][-1]["target_symbol"] == "setcontext"
    assert result["capabilities"] == [
        "reviewed_wide_vtable_dispatch_target",
        "reviewed_stdio_dispatch_target_reachable",
    ]
    forbidden = " ".join(result["capabilities"] + result["limitations"]).lower()
    assert "stack pivot" in forbidden
    assert "rop/orw" in forbidden
    assert truth["relative_policy"]["wide_vtable_pointer_offset"] == 0xE0
    assert truth["relative_policy"]["dispatch_slot_offset"] == 0x68


def test_cycle34_wrong_wide_vtable_pointer_stays_unknown():
    file_addr = 0x5000
    wide = 0x7000
    file_vtable = 0x9000
    setcontext = 0xA000
    writes = (
        {"address": wide + 0xE0, "value": wide + 0x200, "width": 8},
        {"address": wide + 0x168, "value": setcontext, "width": 8},
    )
    assert derive_reviewed_wide_dispatch(
        _upstream(file_addr, wide, file_vtable),
        _policy(file_addr, wide, file_vtable, setcontext),
        wide_writes=writes,
    ) is None


def test_cycle34_wrong_dispatch_slot_target_stays_unknown():
    file_addr = 0x5000
    wide = 0x7000
    file_vtable = 0x9000
    setcontext = 0xA000
    writes = (
        {"address": wide + 0xE0, "value": wide + 0x100, "width": 8},
        {"address": wide + 0x168, "value": setcontext + 1, "width": 8},
    )
    assert derive_reviewed_wide_dispatch(
        _upstream(file_addr, wide, file_vtable),
        _policy(file_addr, wide, file_vtable, setcontext),
        wide_writes=writes,
    ) is None


def test_cycle34_unreviewed_dispatch_semantics_stay_unknown():
    file_addr = 0x5000
    wide = 0x7000
    file_vtable = 0x9000
    setcontext = 0xA000
    base = _policy(file_addr, wide, file_vtable, setcontext)
    policy = ReviewedWideDispatchPolicy(
        **{**base.__dict__, "wide_dispatch_semantics_reviewed": False}
    )
    writes = (
        {"address": wide + 0xE0, "value": wide + 0x100, "width": 8},
        {"address": wide + 0x168, "value": setcontext, "width": 8},
    )
    assert derive_reviewed_wide_dispatch(
        _upstream(file_addr, wide, file_vtable),
        policy,
        wide_writes=writes,
    ) is None


def test_cycle34_mismatched_file_wide_binding_stays_unknown():
    file_addr = 0x5000
    wide = 0x7000
    file_vtable = 0x9000
    setcontext = 0xA000
    writes = (
        {"address": wide + 0xE0, "value": wide + 0x100, "width": 8},
        {"address": wide + 0x168, "value": setcontext, "width": 8},
    )
    assert derive_reviewed_wide_dispatch(
        _upstream(file_addr, wide + 0x1000, file_vtable),
        _policy(file_addr, wide, file_vtable, setcontext),
        wide_writes=writes,
    ) is None
