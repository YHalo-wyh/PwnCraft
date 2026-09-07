from pwncraft.features.audit.reviewed_format_plan import (
    ExactFormatWritePolicy,
    derive_exact_format_write_plan,
)


def test_exact_halfword_plan_binds_addresses_arguments_and_modulo_padding():
    policy = ExactFormatWritePolicy(
        name="exact two-halfword write",
        target_address=0x404040,
        desired_value=0x12345678,
        first_pointer_argument=7,
        total_bits=32,
        atom_bits=16,
        initial_count=0,
        target_writable_reviewed=True,
    )
    result = derive_exact_format_write_plan(policy)
    assert result is not None
    writes = result["facts"][2]["writes"]
    assert writes[0]["address"] == 0x404042
    assert writes[0]["value"] == 0x1234
    assert writes[0]["padding"] == 0x1234
    assert writes[0]["argument_index"] == 7
    assert writes[1]["address"] == 0x404040
    assert writes[1]["value"] == 0x5678
    assert writes[1]["padding"] == 0x4444
    assert writes[1]["argument_index"] == 8
    assert result["capabilities"] == ["exact_format_write_plan"]


def test_exact_plan_preserves_unknown_and_requires_writable_target():
    common = dict(
        name="deferred",
        first_pointer_argument=7,
        total_bits=32,
        atom_bits=16,
        target_writable_reviewed=True,
    )
    assert derive_exact_format_write_plan(
        ExactFormatWritePolicy(target_address=None, desired_value=1, **common)
    ) is None
    assert derive_exact_format_write_plan(
        ExactFormatWritePolicy(target_address=0x404040, desired_value=None, **common)
    ) is None
    assert derive_exact_format_write_plan(
        ExactFormatWritePolicy(
            target_address=0x404040,
            desired_value=1,
            **{**common, "target_writable_reviewed": False},
        )
    ) is None
