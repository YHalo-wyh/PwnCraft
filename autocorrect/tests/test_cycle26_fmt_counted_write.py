import json
from pathlib import Path

from pwncraft.core.fmt_semantics import fmt_facts_from_strings, parse_format

ROOT = Path(__file__).resolve().parents[1]
TRUTH = ROOT / "cases" / "fmtstr-pwn-linux-user-mode-fmtstr-2015-CSAW-contacts-96707ed2" / "expected_truth_cycle26.json"


def test_cycle26_csaw_positional_n_target_and_width_are_known_but_value_is_not_in_runtime_composed_payload():
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    parsed = parse_format("%31$pAAAA%6$n")
    write = parsed["writes"][0]
    assert write["target_argument_index"] == truth["expected_pwncraft_semantics"]["required"]["target_argument_index"]
    assert write["write_width"] == 4
    assert write["exact_value_known"] is False


def test_cycle26_static_c_width_can_prove_exact_n_value_without_arbitrary_write_promotion():
    parsed = parse_format("%1$1001c%7$n")
    write = parsed["writes"][0]
    assert write["value_modulo"] == 1001
    facts = fmt_facts_from_strings(["%1$1001c%7$n"])
    assert facts[0]["write_value_modulo"] == 1001
    assert "arbitrary" not in json.dumps(facts[0]).lower()
