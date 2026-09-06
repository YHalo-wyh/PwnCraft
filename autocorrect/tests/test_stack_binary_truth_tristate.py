import sys
from pathlib import Path
from types import SimpleNamespace

AUTOCORRECT = Path(__file__).resolve().parents[1]
if str(AUTOCORRECT) not in sys.path:
    sys.path.insert(0, str(AUTOCORRECT))
PROJECT = AUTOCORRECT.parent / "pwncraft"
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

from domain_adapters import run_domain


EXP = """from pwn import *\nio = process('./demo')\npayload = b'A' * 64\nio.sendline(payload)\n"""


def _material():
    return SimpleNamespace(case_id="synthetic-stack-case")


def _binary_layer(report):
    return next(item for item in report["layer_results"]
                if item["layer"] == "BINARY_FACTS")


def test_missing_pie_fact_stays_unknown_not_false() -> None:
    report = run_domain("stack", _material(), EXP, bits=32)
    layer = _binary_layer(report)

    assert report["binary_facts"]["pie"] is None
    assert report["binary_facts"]["unknown_fields"] == ["pie"]
    assert report["binary_facts"]["provenance"]["pie"] == "UNKNOWN"
    assert layer["evidence"]["pie"] is None
    assert layer["unknown_fields"] == ["pie"]
    assert "pie=UNKNOWN" in layer["detail"]


def test_explicit_pie_false_remains_observed_false() -> None:
    report = run_domain("stack", _material(), EXP, bits=32, pie=False)
    layer = _binary_layer(report)

    assert report["binary_facts"]["pie"] is False
    assert report["binary_facts"]["unknown_fields"] == []
    assert report["binary_facts"]["provenance"]["pie"] == "CALLER_FACT"
    assert "pie=False" in layer["detail"]


def test_explicit_pie_true_remains_observed_true() -> None:
    report = run_domain("stack", _material(), EXP, bits=64, pie=True)
    layer = _binary_layer(report)

    assert report["binary_facts"]["pie"] is True
    assert report["binary_facts"]["unknown_fields"] == []
    assert report["binary_facts"]["provenance"]["pie"] == "CALLER_FACT"
    assert "pie=True" in layer["detail"]
