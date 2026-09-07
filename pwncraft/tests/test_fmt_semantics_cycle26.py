from pwncraft.core.fmt_semantics import fmt_facts_from_strings, parse_format


def test_counted_positional_n_write_has_exact_width_target_and_value():
    parsed = parse_format("%1$1001c%7$n")
    assert parsed["has_write"] is True
    write = parsed["writes"][0]
    assert write["target_argument_index"] == 7
    assert write["write_width"] == 4
    assert write["exact_value_known"] is True
    assert write["value_modulo"] == 1001


def test_hhn_hn_and_ln_widths_are_separate_under_reviewed_amd64_abi():
    assert parse_format("%9$hhn")["writes"][0]["write_width"] == 1
    assert parse_format("%9$hn")["writes"][0]["write_width"] == 2
    assert parse_format("%9$n")["writes"][0]["write_width"] == 4
    assert parse_format("%9$ln")["writes"][0]["write_width"] == 8


def test_value_dependent_output_keeps_later_n_value_unknown():
    parsed = parse_format("%31$pAAAA%6$n")
    write = parsed["writes"][0]
    assert write["target_argument_index"] == 6
    assert write["write_width"] == 4
    assert write["exact_value_known"] is False
    assert write["value_modulo"] is None


def test_write_conversion_is_not_promoted_to_arbitrary_write_fact():
    facts = fmt_facts_from_strings(["%6$n"])
    assert len(facts) == 1
    fact = facts[0]
    assert fact["kind"] == "WRITE_FORMAT_STRING"
    assert fact["target_argument_index"] == 6
    assert fact["write_width"] == 4
    assert "arbitrary" not in str(fact).lower()


def test_dynamic_width_keeps_count_unknown():
    parsed = parse_format("%1$*2$c%7$n")
    assert parsed["writes"][0]["exact_value_known"] is False
