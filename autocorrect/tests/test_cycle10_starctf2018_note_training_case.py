import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUTOCORRECT = ROOT / "autocorrect"
PROJECT = ROOT / "pwncraft"
for path in (AUTOCORRECT, PROJECT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from challenge_intake import decide_case
from pwncraft.features.audit.audit import audit_exp
from pwncraft.features.audit.extract import extract_exploit_ir

CASE_ID = "stack_rop-pwn-linux-user-mode-stackoverflow-fake_frame-StarCTF2018-not-97cad9a0"
CASE_DIR = ROOT / "heap-corpus" / "corpus" / CASE_ID
EXP = CASE_DIR / "original" / "solution" / "exp.py"


def test_starctf_case_is_registered_train_material() -> None:
    decision = decide_case(CASE_DIR, purpose="train")
    assert decision.allowed is True
    assert decision.split == "train"
    assert decision.domain == "stack"
    assert decision.material_ready is True


def test_starctf_direct_recvn_padding_is_not_a_false_unknown_leak() -> None:
    source = EXP.read_text(encoding="utf-8")
    ir, error = extract_exploit_ir(source)
    assert error is None
    leak_op = next(
        op for op in ir.unpacks
        if op.fn == "u64" and "recvn(6)" in op.arg
    )
    assert getattr(leak_op, "meta_input_width", None) == 8
    evidence = getattr(leak_op, "meta_input_width_evidence", [])
    assert [item["kind"] for item in evidence] == [
        "RECVN_EXACT", "LITERAL_WIDTH", "CONCAT_WIDTH"
    ]

    codes = [item["code"] for item in audit_exp(source, bits=64, pie=False)]
    assert "EXP_LEAK_001" not in codes
    assert "EXP_LEAK_003" not in codes
