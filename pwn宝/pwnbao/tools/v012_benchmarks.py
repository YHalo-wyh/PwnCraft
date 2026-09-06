from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from pwnbao.features.heapviz import build_allocator_config
from pwnbao.features.heapviz.constraints import ConstraintEngine, EditRequest, ValidationStatus
from pwnbao.features.heapviz.contracts import (
    ArgumentBinding,
    ContractConfidence,
    ContractEvidence,
    ContractEvidenceSource,
    HelperContractResolver,
    lower_source_calls,
)
from pwnbao.features.heapviz.corrections import CorrectionEngine, HelperContractPatch, ObservedMemoryPatch
from pwnbao.features.heapviz.corrections.rebase import rebase_fingerprint
from pwnbao.features.heapviz.semantics import CanonicalOperationKind
from pwnbao.features.heapviz.memory import MemoryProvenance, PhysicalMemory


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    category: str
    expected: str
    actual: str
    passed: bool


def helper_variant_benchmark() -> dict[str, object]:
    blocks: list[str] = []
    calls: list[str] = []
    for index in range(30):
        variants = (
            ("alloc", "idx, content, size", "index=idx data=content size=size", f"h_alloc_{index}(1,b'A',0x40)"),
            ("edit", "payload, slot, off", "data=payload index=slot offset=off", f"h_edit_{index}(b'B',1,3)"),
            ("show", "length, slot", "length=length index=slot", f"h_show_{index}(8,1)"),
            ("delete", "slot", "index=slot", f"h_delete_{index}(1)"),
        )
        for kind, parameters, roles, call in variants:
            name = f"h_{kind}_{index}"
            blocks.append(f"# pwnbao: op={kind} {roles}\ndef {name}({parameters}):\n    io.sendline(b'1')")
            calls.append(call)
    source = "\n\n".join(blocks) + "\n\n" + "\n".join(calls)
    resolution = HelperContractResolver().resolve(source)
    operations = lower_source_calls(source, resolution)
    cases = [
        CaseResult(
            contract.contract_id,
            contract.operation.value,
            "proven and lowered once",
            f"proven={contract.proven}, calls={sum(op.contract_id == contract.contract_id for op in operations)}",
            contract.proven and sum(op.contract_id == contract.contract_id for op in operations) == 1,
        )
        for contract in resolution.contracts
    ]
    return _report("helper_variant", cases)


def correction_benchmark() -> dict[str, object]:
    cases: list[CaseResult] = []
    for index in range(8):
        memory = _memory()
        engine = CorrectionEngine()
        address = 0x4010 + index
        outcome = engine.apply(
            ObservedMemoryPatch(f"memory-{index}", address=hex(address), data=bytes([0x41 + index]), length=1),
            memory=memory,
        )
        actual = memory.read(address, 1).data
        cases.append(CaseResult(f"memory_patch_{index}", "memory patch", repr(bytes([0x41 + index])), repr(actual), outcome.result.accepted and actual == bytes([0x41 + index])))

    constraints = ConstraintEngine(replace(build_allocator_config(), safe_linking=True))
    memory = _memory()
    invalid_sizes = (0, 0x8, 0x10, 0x18)
    for index, value in enumerate(invalid_sizes):
        result = constraints.validate(EditRequest("size", 0x4008, value, 8), memory)
        cases.append(CaseResult(f"invalid_size_{index}", "validation", "invalid", result.status.value, result.status is ValidationStatus.INVALID))

    for index, pointer in enumerate((0x123, 0x345, 0x567, 0x789)):
        result = constraints.validate(EditRequest("next", 0x4010, pointer, 8, decoded_pointer=True), memory)
        cases.append(CaseResult(f"corrupt_next_{index}", "validation", "representable_corruption", result.status.value, result.status is ValidationStatus.REPRESENTABLE_CORRUPTION))

    for index in range(4):
        memory = _memory()
        engine = CorrectionEngine()
        before = memory.read(0x4020 + index, 1).data
        engine.apply(
            ObservedMemoryPatch(f"undo-{index}", address=hex(0x4020 + index), data=b"Z", length=1),
            memory=memory,
        )
        engine.undo_memory(memory)
        undone = memory.read(0x4020 + index, 1).data
        engine.redo_memory(memory)
        redone = memory.read(0x4020 + index, 1).data
        passed = before == undone and redone == b"Z"
        cases.append(CaseResult(f"undo_redo_{index}", "undo", f"{before!r} -> b'Z'", f"{undone!r} -> {redone!r}", passed))

    valid_values = (0x21, 0x31, 0x91, 0x101)
    for index, value in enumerate(valid_values):
        result = constraints.validate(EditRequest("size", 0x4008, value, 8), memory)
        cases.append(CaseResult(f"valid_size_{index}", "validation", "valid", result.status.value, result.status is ValidationStatus.VALID))

    for index in range(2):
        source = (
            f"def helper_{index}(slot, payload):\n"
            "    io.send(payload)\n\n"
            f"helper_{index}(1, b'A')\nhelper_{index}(2, b'B')\n"
        )
        base = HelperContractResolver().resolve(source).contract_for(f"helper_{index}")
        assert base is not None
        confirmed = replace(
            base,
            operation=CanonicalOperationKind.EDIT,
            roles={
                "index": ArgumentBinding("index", "slot", "slot", 0),
                "offset": ArgumentBinding("offset", expression="0", fixed=True),
                "data": ArgumentBinding("data", "payload", "payload", 1),
            },
            evidence=(ContractEvidence(ContractEvidenceSource.USER_CONFIRMED, "benchmark", score=1.0),),
            confidence=ContractConfidence.CONFIRMED,
        )
        outcome = CorrectionEngine().apply(
            HelperContractPatch(f"contract-{index}", contract=confirmed),
            memory=_memory(),
            source=source,
        )
        affected = outcome.result.normalized.get("affected_calls")
        cases.append(CaseResult(
            f"contract_correction_{index}",
            "contract correction",
            "affected_calls=2",
            f"affected_calls={affected}",
            outcome.result.accepted and affected == 2,
        ))

    for index, (old, new, expected) in enumerate((("same", "same", "matched"), ("old", "new", "stale"))):
        result = rebase_fingerprint(old, new)
        cases.append(CaseResult(
            f"rebase_{index}",
            "rebase",
            expected,
            result.status,
            result.status == expected,
        ))
    return _report("correction", cases)


def _memory() -> PhysicalMemory:
    memory = PhysicalMemory()
    memory.register_object("chunk", 0x4000, 0x100)
    memory.write(0x4000, b"A" * 0x100, MemoryProvenance.derived("benchmark"))
    return memory


def _report(name: str, cases: list[CaseResult]) -> dict[str, object]:
    passed = sum(item.passed for item in cases)
    return {
        "benchmark": name,
        "total": len(cases),
        "passed": passed,
        "failed": len(cases) - passed,
        "pass_rate": passed / len(cases) if cases else 0.0,
        "cases": [asdict(item) for item in cases],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Pwn宝 v0.12 deterministic offline benchmarks")
    parser.add_argument("--output-dir", default="artifacts")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    reports = {
        "helper": helper_variant_benchmark(),
        "correction": correction_benchmark(),
    }
    (output / "helper_v012.json").write_text(json.dumps(reports["helper"], ensure_ascii=False, indent=2), encoding="utf-8")
    (output / "correction_v012.json").write_text(json.dumps(reports["correction"], ensure_ascii=False, indent=2), encoding="utf-8")
    if args.json:
        print(json.dumps(reports, ensure_ascii=False, indent=2))
    else:
        for name, report in reports.items():
            print(f"{name}: {report['passed']}/{report['total']}")
    return 0 if all(report["failed"] == 0 for report in reports.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
