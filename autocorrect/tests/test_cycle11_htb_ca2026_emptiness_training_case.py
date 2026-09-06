import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUTOCORRECT = ROOT / "autocorrect"
PROJECT = ROOT / "pwncraft"
for path in (AUTOCORRECT, PROJECT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from challenge_intake import decide_case
from pwncraft.core.pwn_surface import PwnDomain, analyze_pwn_surface
from pwncraft.core.workspace import PwnWorkspace
from pwncraft.features.audit.audit import audit_exp
from pwncraft.features.audit.extract import extract_exploit_ir
from pwncraft.features.audit.semantic_facts import apply_exp_semantics_to_workspace

CASE_ID = "io_file-htb-cyber-apocalypse-2026-the-emptiness-machine-exp-32b6c777"
CASE_DIR = ROOT / "heap-corpus" / "corpus" / CASE_ID
EXP = CASE_DIR / "original" / "solution" / "solver_subcase.py"


def test_ca2026_case_is_split_safe_exp_only_train_material() -> None:
    decision = decide_case(CASE_DIR, purpose="train")
    assert decision.allowed is True
    assert decision.split == "train"
    assert decision.domain == "io_file"
    assert decision.material_ready is True
    assert decision.gaps == ()


def test_official_solver_subcase_yields_only_exp_supported_fsop_intent() -> None:
    source = EXP.read_text(encoding="utf-8")
    ir, error = extract_exploit_ir(source)
    assert error is None
    symbols = {item.symbol for item in ir.symbol_refs}
    assert {
        "_IO_2_1_stdout_",
        "_IO_2_1_stderr_",
        "_IO_wfile_jumps",
        "system",
    } <= symbols

    workspace = PwnWorkspace()
    result = apply_exp_semantics_to_workspace(workspace, source)
    assert result["status"] == "ok"
    primitives = workspace.exploit["primitives"]
    assert len(primitives) == 1
    assert primitives[0]["name"] == "FSOP / FILE corruption intent"
    assert primitives[0]["state"] == "derived"

    surfaces = {item.domain: item for item in analyze_pwn_surface(workspace)}
    assert surfaces[PwnDomain.IO_FILE].state == "partial"
    assert "target/runtime FILE corruption not independently proven" in \
        surfaces[PwnDomain.IO_FILE].missing


def test_plain_recv8_keeps_uncertainty_instead_of_learning_false_exactness() -> None:
    source = EXP.read_text(encoding="utf-8")
    diagnostics = audit_exp(source, bits=64, pie=False)
    codes = [item["code"] for item in diagnostics]
    assert "EXP_LEAK_003" in codes
    assert "EXP_LEAK_001" not in codes
