import sys
from pathlib import Path

AUTOCORRECT = Path(__file__).resolve().parents[1]
ROOT = AUTOCORRECT.parent
if str(AUTOCORRECT) not in sys.path:
    sys.path.insert(0, str(AUTOCORRECT))
PROJECT = ROOT / "pwncraft"
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

import case_manifest
import challenge_intake
import domain_adapters


CASE_ID = "stack_rop-pwn-linux-user-mode-stackoverflow-ret2libc-ret2libc1-c5603c89"
CASE_DIR = ROOT / "heap-corpus" / "review_queue" / CASE_ID


def test_registered_real_train_case_preserves_unknown_pie() -> None:
    decision = challenge_intake.assert_allowed(CASE_DIR, purpose="train")
    assert decision.split == "train"
    assert decision.domain == "stack"
    assert decision.material_ready is True

    material = case_manifest.load_case_material(CASE_DIR)
    assert material is not None
    assert material.domain == "stack"
    assert material.arch == "x86"

    exp_files = sorted((CASE_DIR / "original" / "solution").glob("*.py"))
    assert len(exp_files) == 1
    exp_source = exp_files[0].read_text(encoding="utf-8")

    # Clean-room truth for this case intentionally has no independently
    # observed PIE fact.  The real challenge therefore exercises the generic
    # tri-state path: omitted PIE must remain UNKNOWN, never become False.
    report = domain_adapters.run_domain(
        "stack", material, exp_source, bits=32,
    )
    layer = next(item for item in report["layer_results"]
                 if item["layer"] == "BINARY_FACTS")

    assert report["binary_facts"]["bits"] == 32
    assert report["binary_facts"]["pie"] is None
    assert "pie" in report["binary_facts"]["unknown_fields"]
    assert layer["evidence"]["pie"] is None
    assert "pie=UNKNOWN" in layer["detail"]
