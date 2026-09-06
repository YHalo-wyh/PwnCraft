import sys
from pathlib import Path

AUTOCORRECT = Path(__file__).resolve().parents[1]
if str(AUTOCORRECT) not in sys.path:
    sys.path.insert(0, str(AUTOCORRECT))
PROJECT = AUTOCORRECT.parent / "pwncraft"
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

from domain_adapters import _stack_runtime_result
from pwncraft.core.cyclic import cyclic_pattern


def test_runtime_layer_matches_only_cyclic_correlated_rip() -> None:
    pattern = cyclic_pattern(512, n=8)
    value = int.from_bytes(pattern[144:152], "little")
    result, truth = _stack_runtime_result(
        {
            "register": "rip",
            "value": value,
            "source": "pwndbg",
            "signal": "SIGSEGV",
            "stop_reason": "SignalEvent",
        },
        8,
    )
    assert result["status"] == "MATCH"
    assert truth is not None
    assert truth["overflow_offset"] == 144
    assert truth["overflow_evidence_state"] == "confirmed_control"


def test_signal_without_correlated_ip_is_not_promoted() -> None:
    result, truth = _stack_runtime_result(
        {"register": "rip", "value": 0x4141414141414141, "signal": "SIGSEGV"},
        8,
    )
    assert result["status"] == "SKIPPED"
    assert truth is None
    assert "未证明" in result["detail"]


def test_missing_runtime_observation_stays_optional() -> None:
    result, truth = _stack_runtime_result(None, 8)
    assert result["status"] == "SKIPPED"
    assert truth is None
    assert result["optional_missing"]
