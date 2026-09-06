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


def test_starctf_upstream_exp_parse_defect_stays_visible() -> None:
    """Do not silently repair the curator copy.

    The archived EXP contains ``remoteAddr = 47.89.18.224`` without quotes,
    which is invalid Python.  Full-file PwnCraft audit therefore has to remain
    EXP_PARSE-blocked until the material is explicitly normalized/replaced.
    """
    source = EXP.read_text(encoding="utf-8")
    _ir, error = extract_exploit_ir(source)
    assert error is not None
    assert error.lineno == 11
    assert "47.89.18.224" in (error.text or "")


def test_starctf_exact_raw_leak_expression_has_eight_byte_input() -> None:
    """Train from the exact source expression without hiding the file defect.

    This is a source-derived subcase: the RHS is copied verbatim from the real
    StarCTF archive line, while the malformed unrelated remoteAddr assignment
    remains documented by the test above.  No challenge-specific address or
    name enters the generic width rule.
    """
    source = EXP.read_text(encoding="utf-8")
    line = next(
        row.strip() for row in source.splitlines()
        if row.strip().startswith("libc.address = u64(io.recvn(6)")
    )
    rhs = line.split("=", 1)[1].strip()
    assert rhs == "u64(io.recvn(6) + '\\0\\0') - libc.sym['puts']"

    snippet = "from pwn import *\nvalue = " + rhs + "\n"
    ir, error = extract_exploit_ir(snippet)
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

    codes = [item["code"] for item in audit_exp(snippet, bits=64, pie=False)]
    assert "EXP_LEAK_001" not in codes
    assert "EXP_LEAK_003" not in codes
