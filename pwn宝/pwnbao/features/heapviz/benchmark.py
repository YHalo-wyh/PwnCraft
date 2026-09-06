from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from pwnbao.features.heapviz.allocators.profiles import build_allocator_config
from pwnbao.features.heapviz.analyzer import analyze_heap_source
from pwnbao.features.heapviz.engine import GlibcHeapEngine
from pwnbao.features.heapviz.expressions import parse_int_expr


@dataclass(frozen=True)
class MetricCount:
    passed: int = 0
    total: int = 0

    @property
    def score(self) -> float:
        return self.passed / self.total if self.total else 1.0


@dataclass(frozen=True)
class BenchmarkCaseResult:
    case_id: str
    operation_precision: float
    operation_recall: float
    operation_f1: float
    argument: MetricCount
    payload_span: MetricCount
    write_range: MetricCount
    overwrite_field: MetricCount
    allocator_checkpoint: MetricCount
    bin_membership: MetricCount
    field_value: MetricCount
    bin_transition: MetricCount
    metadata_decision: MetricCount
    consolidation_decision: MetricCount
    tcache_duplicate_decision: MetricCount
    top_transition: MetricCount
    freelist_traversal: MetricCount
    integrity_abort: MetricCount
    partial_overwrite: MetricCount
    passed: bool
    failures: tuple[str, ...] = ()


@dataclass(frozen=True)
class SemanticBenchmarkReport:
    cases: tuple[BenchmarkCaseResult, ...]
    metrics: Mapping[str, float] = field(default_factory=dict)

    @property
    def whole_case_pass_rate(self) -> float:
        return sum(item.passed for item in self.cases) / len(self.cases) if self.cases else 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_count": len(self.cases),
            "whole_case_pass_rate": self.whole_case_pass_rate,
            "metrics": dict(self.metrics),
            "cases": [
                {
                    "id": item.case_id,
                    "passed": item.passed,
                    "operation_precision": item.operation_precision,
                    "operation_recall": item.operation_recall,
                    "operation_f1": item.operation_f1,
                    "argument_accuracy": item.argument.score,
                    "payload_span_accuracy": item.payload_span.score,
                    "write_range_accuracy": item.write_range.score,
                    "overwrite_field_accuracy": item.overwrite_field.score,
                    "allocator_checkpoint_accuracy": item.allocator_checkpoint.score,
                    "bin_membership_accuracy": item.bin_membership.score,
                    "field_value_accuracy": item.field_value.score,
                    "bin_transition_accuracy": item.bin_transition.score,
                    "metadata_decision_accuracy": item.metadata_decision.score,
                    "consolidation_decision_accuracy": item.consolidation_decision.score,
                    "tcache_duplicate_decision_accuracy": item.tcache_duplicate_decision.score,
                    "top_transition_accuracy": item.top_transition.score,
                    "freelist_traversal_accuracy": item.freelist_traversal.score,
                    "integrity_abort_accuracy": item.integrity_abort.score,
                    "partial_overwrite_accuracy": item.partial_overwrite.score,
                    "failures": list(item.failures),
                }
                for item in self.cases
            ],
        }


class SemanticBenchmarkRunner:
    """Ground-truth benchmark for the deterministic frontend + allocator.

    A case passes only when every declared truth item passes.  Merely parsing
    without an exception is intentionally not a success criterion.
    """

    def run_file(self, path: str | Path) -> SemanticBenchmarkReport:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        cases = payload.get("cases", payload) if isinstance(payload, dict) else payload
        return self.run(cases)

    def run(self, cases: Iterable[Mapping[str, Any]]) -> SemanticBenchmarkReport:
        results = tuple(self.run_case(case) for case in cases)
        metrics = {
            "operation_precision": _mean(item.operation_precision for item in results),
            "operation_recall": _mean(item.operation_recall for item in results),
            "operation_f1": _mean(item.operation_f1 for item in results),
            "argument_accuracy": _ratio(results, "argument"),
            "payload_span_accuracy": _ratio(results, "payload_span"),
            "write_range_accuracy": _ratio(results, "write_range"),
            "overwrite_field_accuracy": _ratio(results, "overwrite_field"),
            "allocator_checkpoint_accuracy": _ratio(results, "allocator_checkpoint"),
            "bin_membership_accuracy": _ratio(results, "bin_membership"),
            "field_value_accuracy": _ratio(results, "field_value"),
            "bin_transition_accuracy": _ratio(results, "bin_transition"),
            "metadata_decision_accuracy": _ratio(results, "metadata_decision"),
            "consolidation_decision_accuracy": _ratio(results, "consolidation_decision"),
            "tcache_duplicate_decision_accuracy": _ratio(results, "tcache_duplicate_decision"),
            "top_transition_accuracy": _ratio(results, "top_transition"),
            "freelist_traversal_accuracy": _ratio(results, "freelist_traversal"),
            "integrity_abort_accuracy": _ratio(results, "integrity_abort"),
            "partial_overwrite_accuracy": _ratio(results, "partial_overwrite"),
            "whole_case_pass_rate": sum(item.passed for item in results) / len(results) if results else 1.0,
        }
        return SemanticBenchmarkReport(results, metrics)

    def run_case(self, case: Mapping[str, Any]) -> BenchmarkCaseResult:
        case_id = str(case.get("id") or "unnamed")
        source = str(case.get("source") or "")
        truth = dict(case.get("ground_truth") or {})
        analysis = analyze_heap_source(source)
        operations = list(analysis.operations)
        config = build_allocator_config(str(case.get("arch") or "amd64"), str(case.get("glibc") or "glibc 2.35"))
        variables = {str(key): value for key, value in dict(case.get("variables") or {}).items()}
        config_overrides = dict(case.get("config") or {})
        if case.get("heap_base") or config_overrides:
            from dataclasses import replace
            if case.get("heap_base"):
                config_overrides["heap_base"] = str(case["heap_base"])
            allowed = {name for name in config.__dataclass_fields__ if name not in {"family", "version", "arch", "bits", "alignment"}}
            config = replace(config, **{key: value for key, value in config_overrides.items() if key in allowed})
        snapshots = GlibcHeapEngine(config, variables).replay(operations)
        failures: list[str] = []

        operations_declared = "operations" in truth
        expected_kinds = [str(item.get("kind")) for item in truth.get("operations", [])]
        actual_kinds = [item.kind.value for item in operations]
        common = _lcs_length(expected_kinds, actual_kinds) if operations_declared else len(actual_kinds)
        precision = common / len(actual_kinds) if actual_kinds else 1.0
        recall = common / len(expected_kinds) if operations_declared and expected_kinds else 1.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        if operations_declared and expected_kinds != actual_kinds:
            failures.append(f"operations expected={expected_kinds} actual={actual_kinds}")

        argument = MetricCount()
        for index, expected in enumerate(truth.get("operations", [])):
            for name, value in expected.items():
                if name == "kind":
                    continue
                actual = getattr(operations[index], name, None) if index < len(operations) else None
                argument = _add(argument, _same_value(actual, value))
                if not _same_value(actual, value):
                    failures.append(f"operation[{index}].{name}: expected {value!r}, got {actual!r}")

        events = [event for snapshot in snapshots for event in snapshot.write_events]
        operation_ids = [item.op_id for item in operations]
        payload_span = MetricCount()
        for expected in truth.get("payload_segments", []):
            event = _event_for_ordinal(events, operation_ids, int(expected["operation"]))
            match = False
            if event is not None:
                for segment in event.payload.segments:
                    if segment.offset != int(expected["offset"]) or segment.length != int(expected["length"]):
                        continue
                    if "raw_hex" in expected and (segment.raw_bytes or b"").hex() != str(expected["raw_hex"]).lower():
                        continue
                    if "symbolic_contains" in expected and str(expected["symbolic_contains"]) not in (segment.symbolic_value or segment.expression):
                        continue
                    match = True
                    break
            payload_span = _add(payload_span, match)
            if not match:
                failures.append(f"payload span not found: {expected}")

        write_range = MetricCount()
        for expected in truth.get("writes", []):
            event = _event_for_ordinal(events, operation_ids, int(expected["operation"]))
            match = bool(event and event.length == int(expected["length"]))
            if match and expected.get("destination"):
                match = _same_address(event.destination_address, str(expected["destination"]), variables)
            write_range = _add(write_range, match)
            if not match:
                failures.append(f"write range not found: {expected}")

        edges = snapshots[-1].overwrite_history if snapshots else ()
        overwrite_field = MetricCount()
        for expected in truth.get("overwrites", []):
            op_id = operation_ids[int(expected["operation"])] if int(expected["operation"]) < len(operation_ids) else ""
            match = any(
                edge.writer_operation == op_id
                and edge.target_chunk == str(expected["target_chunk"])
                and edge.target_field == str(expected["target_field"])
                and edge.source_payload_offset == int(expected["payload_offset"])
                and ("before" not in expected or edge.before == str(expected["before"]))
                and ("after" not in expected or edge.after == str(expected["after"]))
                for edge in edges
            )
            overwrite_field = _add(overwrite_field, match)
            if not match:
                failures.append(f"overwrite not found: {expected}")

        allocator_checkpoint = MetricCount()
        for expected in truth.get("checkpoints", []):
            step = int(expected["step"])
            snapshot = snapshots[step] if 0 <= step < len(snapshots) else None
            chunk = snapshot.chunks.get(str(expected["chunk"])) if snapshot else None
            match = chunk is not None
            for name in ("lifecycle", "chunk_size", "address", "user_address", "view_kind"):
                if name in expected:
                    actual = getattr(chunk, name, None) if chunk else None
                    match = match and _same_value(actual, expected[name])
            allocator_checkpoint = _add(allocator_checkpoint, match)
            if not match:
                failures.append(f"checkpoint mismatch: {expected}")

        bin_membership = MetricCount()
        for expected in truth.get("bins", []):
            step = int(expected["step"])
            snapshot = snapshots[step] if 0 <= step < len(snapshots) else None
            members: tuple[str, ...] = ()
            if snapshot:
                kind = str(expected["kind"])
                if kind == "unsorted":
                    members = snapshot.bins.unsorted
                else:
                    mapping = getattr(snapshot.bins, kind, {})
                    members = mapping.get(str(expected.get("size") or ""), ())
            match = tuple(expected.get("members") or ()) == tuple(members)
            bin_membership = _add(bin_membership, match)
            if not match:
                failures.append(f"bin mismatch: {expected}; actual={members}")

        field_value = MetricCount()
        for expected in truth.get("fields", []):
            step = int(expected["step"])
            snapshot = snapshots[step] if 0 <= step < len(snapshots) else None
            chunk = snapshot.chunks.get(str(expected["chunk"])) if snapshot else None
            field_item = next((item for item in (chunk.fields if chunk else ()) if item.name == str(expected["name"])), None)
            match = field_item is not None and _same_value(field_item.value, expected.get("value"))
            field_value = _add(field_value, match)
            if not match:
                failures.append(f"field mismatch: {expected}; actual={getattr(field_item, 'value', None)!r}")

        bin_transition = MetricCount()
        for expected in truth.get("transitions", []):
            step = int(expected["step"])
            snapshot = snapshots[step] if 0 <= step < len(snapshots) else None
            candidates = snapshot.bin_transition_events if snapshot else ()
            match = any(
                event.action == str(expected.get("action"))
                and ("bin_kind" not in expected or event.bin_kind == str(expected["bin_kind"]))
                and ("node" not in expected or event.node == str(expected["node"]))
                and ("moved_nodes" not in expected or event.moved_nodes == tuple(expected["moved_nodes"]))
                for event in candidates
            )
            bin_transition = _add(bin_transition, match)
            if not match:
                failures.append(f"bin transition not found: {expected}")

        metadata_decision = MetricCount()
        for expected in truth.get("metadata_decisions", []):
            snapshot = _snapshot_at(snapshots, expected)
            chunk = snapshot.chunks.get(str(expected.get("chunk") or "")) if snapshot else None
            field_item = next((item for item in (chunk.fields if chunk else ()) if item.name == str(expected.get("field") or "")), None)
            actual = field_item.value if field_item else ""
            match = field_item is not None
            if "value" in expected:
                match = match and _same_value(actual, expected["value"])
            if "contains" in expected:
                match = match and str(expected["contains"]) in actual
            metadata_decision = _add(metadata_decision, match)
            if not match:
                failures.append(f"metadata decision mismatch: {expected}; actual={actual!r}")

        consolidation_decision = MetricCount()
        for expected in truth.get("consolidations", []):
            snapshot = _snapshot_at(snapshots, expected)
            representative = snapshot.chunks.get(str(expected.get("representative") or "")) if snapshot else None
            match = representative is not None
            if "chunk_size" in expected:
                match = match and representative is not None and _same_value(representative.chunk_size, expected["chunk_size"])
            for alias in expected.get("merged", []):
                item = snapshot.chunks.get(str(alias)) if snapshot else None
                match = match and item is not None and item.lifecycle == "stale" and "merged into" in item.bin_location
            for separate in expected.get("not_merged", []):
                item = snapshot.chunks.get(str(separate)) if snapshot else None
                match = match and item is not None and item.lifecycle != "stale"
            consolidation_decision = _add(consolidation_decision, match)
            if not match:
                failures.append(f"consolidation mismatch: {expected}")

        tcache_duplicate_decision = MetricCount()
        for expected in truth.get("tcache_duplicates", []):
            snapshot = _snapshot_at(snapshots, expected)
            abort = snapshot.allocator_abort if snapshot else None
            match = bool(abort) == bool(expected.get("abort"))
            if expected.get("reason"):
                match = match and abort is not None and abort.reason == str(expected["reason"])
            tcache_duplicate_decision = _add(tcache_duplicate_decision, match)
            if not match:
                failures.append(f"tcache duplicate mismatch: {expected}")

        top_transition = MetricCount()
        for expected in truth.get("top_transitions", []):
            snapshot = _snapshot_at(snapshots, expected)
            match = snapshot is not None
            if "address" in expected:
                match = match and _same_address(snapshot.top_address, str(expected["address"]), variables)
            if "size" in expected:
                match = match and _same_value(snapshot.top_size, expected["size"])
            top_transition = _add(top_transition, match)
            if not match:
                failures.append(f"top transition mismatch: {expected}")

        freelist_traversal = MetricCount()
        for expected in truth.get("freelist_traversals", []):
            snapshot = _snapshot_at(snapshots, expected)
            events_at_step = snapshot.bin_transition_events if snapshot else ()
            match = any(
                ("action" not in expected or event.action == str(expected["action"]))
                and ("bin_kind" not in expected or event.bin_kind == str(expected["bin_kind"]))
                and ("node" not in expected or event.node == str(expected["node"]))
                for event in events_at_step
            )
            freelist_traversal = _add(freelist_traversal, match)
            if not match:
                failures.append(f"freelist traversal mismatch: {expected}")

        integrity_abort = MetricCount()
        for expected in truth.get("integrity_aborts", []):
            snapshot = _snapshot_at(snapshots, expected)
            abort = snapshot.allocator_abort if snapshot else None
            match = abort is not None and abort.reason == str(expected.get("reason") or "")
            integrity_abort = _add(integrity_abort, match)
            if not match:
                failures.append(f"integrity abort mismatch: {expected}")

        partial_overwrite = MetricCount()
        for expected in truth.get("partial_overwrites", []):
            ordinal = int(expected["operation"])
            op_id = operation_ids[ordinal] if 0 <= ordinal < len(operation_ids) else ""
            match = any(
                edge.writer_operation == op_id
                and edge.target_chunk == str(expected["target_chunk"])
                and edge.target_field == str(expected["target_field"])
                and edge.target_field_offset == int(expected.get("field_offset", 0))
                and edge.target_field_length == int(expected["length"])
                and edge.source_payload_offset == int(expected["payload_offset"])
                and ("mask" not in expected or edge.changed_byte_mask == str(expected["mask"]))
                for edge in edges
            )
            partial_overwrite = _add(partial_overwrite, match)
            if not match:
                failures.append(f"partial overwrite mismatch: {expected}")

        declared = sum(item.total for item in (
            argument, payload_span, write_range, overwrite_field,
            allocator_checkpoint, bin_membership, field_value, bin_transition,
            metadata_decision, consolidation_decision, tcache_duplicate_decision,
            top_transition, freelist_traversal, integrity_abort, partial_overwrite,
        ))
        operation_match = not operations_declared or expected_kinds == actual_kinds
        # An explicitly declared empty operation sequence is a valid negative
        # ground truth (for example a ROP/file payload false-positive case).
        passed = operation_match and not failures and (declared > 0 or "operations" in truth)
        return BenchmarkCaseResult(
            case_id, precision, recall, f1, argument, payload_span, write_range,
            overwrite_field, allocator_checkpoint, bin_membership, field_value,
            bin_transition, metadata_decision, consolidation_decision,
            tcache_duplicate_decision, top_transition, freelist_traversal,
            integrity_abort, partial_overwrite, passed, tuple(failures),
        )


def default_benchmark_path() -> Path:
    return Path(__file__).resolve().parents[3] / "datasets" / "semantic_benchmark" / "v0.10.json"


def _snapshot_at(snapshots: list[Any], expected: Mapping[str, Any]):
    step = int(expected.get("step", len(snapshots) - 1))
    return snapshots[step] if 0 <= step < len(snapshots) else None


def _event_for_ordinal(events: list[Any], operation_ids: list[str], ordinal: int):
    if ordinal < 0 or ordinal >= len(operation_ids):
        return None
    return next((event for event in events if event.operation_id == operation_ids[ordinal]), None)


def _add(count: MetricCount, passed: bool) -> MetricCount:
    return MetricCount(count.passed + int(bool(passed)), count.total + 1)


def _ratio(results: tuple[BenchmarkCaseResult, ...], name: str) -> float:
    passed = sum(getattr(item, name).passed for item in results)
    total = sum(getattr(item, name).total for item in results)
    return passed / total if total else 1.0


def _mean(values: Iterable[float]) -> float:
    items = tuple(values)
    return sum(items) / len(items) if items else 1.0


def _same_value(actual: Any, expected: Any) -> bool:
    if str(actual) == str(expected):
        return True
    left, right = parse_int_expr(str(actual)), parse_int_expr(str(expected))
    return left is not None and right is not None and left == right


def _same_address(actual: str, expected: str, variables: Mapping[str, Any]) -> bool:
    if actual.replace(" ", "") == expected.replace(" ", ""):
        return True
    left, right = parse_int_expr(actual, variables), parse_int_expr(expected, variables)
    return left is not None and right is not None and left == right


def _lcs_length(left: list[str], right: list[str]) -> int:
    row = [0] * (len(right) + 1)
    for a in left:
        previous = 0
        for index, b in enumerate(right, 1):
            saved = row[index]
            row[index] = previous + 1 if a == b else max(row[index], row[index - 1])
            previous = saved
    return row[-1]
