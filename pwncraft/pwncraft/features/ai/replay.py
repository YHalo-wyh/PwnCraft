from __future__ import annotations

import ast
import hashlib
from collections import Counter
from dataclasses import asdict, dataclass, replace
from typing import Iterable, Mapping

from pwncraft.features.heapviz import (
    AllocatorConfig,
    ChallengeBehaviorProfile,
    GlibcHeapEngine,
    HeapAnalysisResult,
    HeapApiProfile,
    HeapOperation,
    HeapOperationKind,
    HeapSnapshot,
    ObservedHeapState,
    TimelineOverride,
    analyze_heap_source,
)
from pwncraft.features.heapviz.analyzer import HeapSourceAnalyzer
from pwncraft.features.heapviz.expressions import parse_int_expr
from pwncraft.features.heapviz.validation import validate_operation

from .models import AIProposal


_BOUND_ACTIONS = {
    "replace_operation",
    "value_fact",
    "insert_before",
    "insert_after",
    "ignore_operation",
}
_OPERATION_ACTIONS = {
    "replace_operation",
    "value_fact",
    "insert_before",
    "insert_after",
}


@dataclass(frozen=True)
class ProposalReplayResult:
    proposal_id: str
    action: str
    accepted: bool
    message: str
    operation_count: int = 0
    chunk_count: int = 0
    aborted: bool = False
    warnings: tuple[str, ...] = ()
    current_effect: object = None
    replayed_effect: object = None
    observed_verified: bool | None = None
    replay_snapshot: dict[str, object] | None = None
    learned_rule: dict[str, object] | None = None
    semantic_changed: bool = False

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class StrictProposalReplayer:
    """Prove an AI semantic proposal by replaying a private allocator copy."""

    def __init__(
        self,
        source: str,
        analysis: HeapAnalysisResult,
        config: AllocatorConfig,
        *,
        variables: Mapping[str, str | int] | None = None,
        branch_choices: Mapping[str, str] | None = None,
        overrides: Iterable[TimelineOverride] = (),
        learned_rules: Iterable[Mapping[str, object]] = (),
        observed: ObservedHeapState | None = None,
        api_profile: HeapApiProfile | None = None,
        behavior_profile: ChallengeBehaviorProfile | None = None,
    ) -> None:
        self.source = source
        self.analysis = analysis
        self.config = config
        self.variables = dict(variables or {})
        self.branch_choices = dict(branch_choices or {})
        self.overrides = tuple(overrides)
        self.learned_rules = tuple(dict(item) for item in learned_rules)
        self.observed = observed
        self.api_profile = api_profile
        self.behavior_profile = behavior_profile
        self.base_snapshots = GlibcHeapEngine(config, variables=self.variables).replay(analysis.operations)

    def preview(self, proposal: AIProposal) -> ProposalReplayResult:
        current_effect: object = None
        try:
            self._validate_anchor(proposal)
            if proposal.snapshot_effect:
                current_effect = self._effect_value(self._effect_snapshot(self.base_snapshots, proposal), proposal.snapshot_effect)
                if not self._values_equal(current_effect, proposal.snapshot_effect.get("current")):
                    raise ValueError(
                        "snapshot effect 当前值不匹配: "
                        f"declared={proposal.snapshot_effect.get('current')!s}, actual={current_effect!s}"
                    )
                if self._values_equal(current_effect, proposal.snapshot_effect.get("expected")):
                    raise ValueError("snapshot effect 没有声明任何状态变化")

            operations = list(self.analysis.operations)
            learned_rule: dict[str, object] | None = None
            binding_index = self._binding_index(proposal)
            if proposal.action in _BOUND_ACTIONS and binding_index < 0:
                raise ValueError("无法绑定到当前 AST 源码范围")
            if proposal.action in _OPERATION_ACTIONS and not proposal.operation:
                raise ValueError("候选缺少 HeapOperation")
            if proposal.action in _OPERATION_ACTIONS:
                self._validate_catalog_context(proposal, binding_index)
                self._validate_non_lossy_replacement(proposal, binding_index)
                self._validate_no_duplicate_insert(proposal)

            if proposal.action in {"replace_operation", "value_fact"}:
                operations[binding_index] = self._materialize_operation(proposal, binding_index)
            elif proposal.action == "insert_before":
                operations.insert(binding_index, self._materialize_operation(proposal, binding_index))
            elif proposal.action == "insert_after":
                operations.insert(binding_index + 1, self._materialize_operation(proposal, binding_index))
            elif proposal.action == "ignore_operation":
                operations.pop(binding_index)
            elif proposal.action in {"helper_mapping", "rule_candidate"}:
                learned_rule = self._proposal_rule(proposal)
                matcher = dict(learned_rule.get("matcher") or {})
                if not (
                    matcher.get("call_shape")
                    or matcher.get("parameter_names")
                    or matcher.get("argument_equals")
                ):
                    raise ValueError("规则缺少可复现的调用形态或 helper 参数签名")
                changed = analyze_heap_source(
                    self.source,
                    self.api_profile,
                    variables=self.variables,
                    branch_choices=self.branch_choices,
                    overrides=self.overrides,
                    learned_rules=(learned_rule, *self.learned_rules),
                    behavior_profile=self.behavior_profile,
                )
                if not changed.valid:
                    raise ValueError("规则预览无法生成有效 AST 时间线")
                operations = list(changed.operations)
                rule_id = str(learned_rule.get("rule_id") or "")
                if not any(str(item.meta.get("learned_rule_id") or "") == rule_id for item in operations):
                    raise ValueError("精确规则没有匹配当前源码")
            elif proposal.action == "branch_choice":
                branch_id = str(proposal.branch_choice.get("branch_id") or "")
                choice = str(proposal.branch_choice.get("choice") or "")
                branches = {item.branch_id: item for item in self.analysis.branch_groups}
                if branch_id not in branches or choice not in {"true", "false"}:
                    raise ValueError("分支候选无法绑定到当前未决分支")
                changed = analyze_heap_source(
                    self.source,
                    self.api_profile,
                    variables=self.variables,
                    branch_choices={**self.branch_choices, branch_id: choice},
                    overrides=self.overrides,
                    learned_rules=self.learned_rules,
                    behavior_profile=self.behavior_profile,
                )
                if not changed.valid:
                    raise ValueError("选择分支后 AST 时间线无效")
                operations = list(changed.operations)
            elif proposal.action == "memory_annotation":
                return self._preview_memory_annotation(proposal, current_effect)
            elif proposal.action not in _BOUND_ACTIONS:
                raise ValueError("不支持的 AI action")

            semantic_changed = self._operation_facts(operations) != self._operation_facts(self.analysis.operations)
            if proposal.action != "memory_annotation" and not semantic_changed:
                raise ValueError("候选未改变 Heap IR，拒绝无效校正")
            snapshots = GlibcHeapEngine(self.config, variables=self.variables).replay(operations)
            final = snapshots[-1]
            candidate_step = -1
            if proposal.action in {"replace_operation", "value_fact", "insert_before"}:
                candidate_step = binding_index + 1
            elif proposal.action == "insert_after":
                candidate_step = binding_index + 2
            if 0 <= candidate_step < len(snapshots):
                target_errors = [
                    item.code
                    for item in snapshots[candidate_step].warnings
                    if item.severity.upper() == "ERROR"
                ]
                if target_errors:
                    raise ValueError("候选步骤无法严格执行: " + ", ".join(target_errors))
            base_errors = Counter(
                item.code
                for snapshot in self.base_snapshots
                for item in snapshot.warnings
                if item.severity.upper() == "ERROR"
            )
            replay_errors = Counter(
                item.code
                for snapshot in snapshots
                for item in snapshot.warnings
                if item.severity.upper() == "ERROR"
            )
            added_errors = replay_errors - base_errors
            if added_errors:
                details = ", ".join(
                    f"{code}x{count}" if count > 1 else code
                    for code, count in sorted(added_errors.items())
                )
                raise ValueError("候选引入新的 allocator ERROR: " + details)
            replayed_effect: object = None
            observed_verified: bool | None = None
            if proposal.snapshot_effect:
                replayed_effect = self._effect_value(self._effect_snapshot(snapshots, proposal), proposal.snapshot_effect)
                expected = proposal.snapshot_effect.get("expected")
                if not self._values_equal(replayed_effect, expected):
                    raise ValueError(
                        "严格重放未产生声明效果: "
                        f"expected={expected!s}, actual={replayed_effect!s}"
                    )
                if str(proposal.snapshot_effect.get("evidence_kind") or "") == "pwndbg":
                    observed_verified = bool(
                        self.observed
                        and self._pwndbg_supports_effect(
                            proposal.snapshot_effect,
                            self._effect_snapshot(snapshots, proposal),
                            self.observed,
                        )
                    )
                    if not observed_verified:
                        raise ValueError("Pwndbg 输入不能证明该 snapshot effect")

            warning_codes = tuple(dict.fromkeys(
                item.code
                for snapshot in snapshots
                for item in snapshot.warnings
            ))
            return ProposalReplayResult(
                proposal.proposal_id,
                proposal.action,
                True,
                "strict replay accepted",
                len(operations),
                len(final.chunks),
                final.aborted,
                warning_codes,
                current_effect,
                replayed_effect,
                observed_verified,
                self._snapshot_summary(final),
                learned_rule,
                semantic_changed,
            )
        except Exception as error:
            return ProposalReplayResult(
                proposal.proposal_id,
                proposal.action,
                False,
                str(error),
                current_effect=current_effect,
        )

    def _validate_non_lossy_replacement(self, proposal: AIProposal, binding_index: int) -> None:
        if proposal.action not in {"replace_operation", "value_fact"}:
            return
        if not 0 <= binding_index < len(self.analysis.operations):
            return
        current = self.analysis.operations[binding_index]
        replacement = HeapOperation.from_dict(proposal.operation)
        if current.kind != replacement.kind:
            return
        for field_name in ("chunk", "index", "request_size", "data", "field", "value", "target", "fd_storage"):
            current_value = str(getattr(current, field_name) or "").strip()
            replacement_value = str(getattr(replacement, field_name) or "").strip()
            if not self._is_known_fact(current_value):
                continue
            if not self._is_known_fact(replacement_value):
                raise ValueError(f"候选会丢失已有静态事实: {field_name}={current_value}")

    def _validate_no_duplicate_insert(self, proposal: AIProposal) -> None:
        if proposal.action not in {"insert_before", "insert_after"}:
            return
        operation = HeapOperation.from_dict(proposal.operation)
        for index, binding in enumerate(self.analysis.bindings):
            overlaps = (
                proposal.source_start <= binding.start < proposal.source_end
                or binding.start <= proposal.source_start < binding.end
            )
            if not overlaps or index >= len(self.analysis.operations):
                continue
            if self._is_duplicate_operation(operation, self.analysis.operations[index]):
                raise ValueError("候选重复了源码范围内已有 Heap IR")

    def _validate_catalog_context(self, proposal: AIProposal, binding_index: int) -> None:
        operation = HeapOperation.from_dict(proposal.operation)
        source = str(operation.meta.get("source") or "")
        if (
            proposal.action in {"insert_before", "insert_after"}
            and source.startswith("heap_rule:op.")
            and 0 <= binding_index < len(self.analysis.operations)
        ):
            bound = self.analysis.operations[binding_index]
            if bound.kind != operation.kind:
                raise ValueError(
                    "op.* 候选源码锚点语义不匹配: "
                    f"source={bound.kind.value}, candidate={operation.kind.value}"
                )
        if source != "heap_rule:allocator.consolidate":
            return
        bound = self.analysis.operations[binding_index] if 0 <= binding_index < len(self.analysis.operations) else None
        snapshot_index = binding_index + 1 if proposal.action in {"insert_after", "replace_operation"} else binding_index
        snapshot_index = max(0, min(snapshot_index, len(self.base_snapshots) - 1))
        snapshot = self.base_snapshots[snapshot_index]
        has_fastbin = any(bool(chain) for chain in snapshot.bins.fastbins.values())
        if has_fastbin or (bound is not None and bound.kind == HeapOperationKind.FREE):
            return
        raise ValueError("allocator.consolidate 缺少可证明触发点: 需要绑定到 free 或已有 fastbin 状态")

    @staticmethod
    def _is_known_fact(value: str) -> bool:
        return bool(value and value.lower() not in {"unknown", "未知", "null", "none"})

    def _is_duplicate_operation(self, candidate: HeapOperation, existing: HeapOperation) -> bool:
        if candidate.kind != existing.kind:
            return False
        if candidate.kind in {HeapOperationKind.FREE, HeapOperationKind.SHOW, HeapOperationKind.EDIT}:
            same_chunk = bool(candidate.chunk and existing.chunk and candidate.chunk == existing.chunk)
            same_index = bool(
                candidate.index
                and existing.index
                and self._values_equal(candidate.index, existing.index)
            )
            if not (same_chunk or same_index):
                return False
            if candidate.kind == HeapOperationKind.EDIT and candidate.data and existing.data:
                return self._values_equal(candidate.data, existing.data)
            return True
        return self._operation_facts((existing,))[0] == self._operation_facts((candidate,))[0]

    def _validate_anchor(self, proposal: AIProposal) -> None:
        digest = hashlib.sha256(self.source.encode("utf-8", errors="replace")).hexdigest()
        if proposal.source_start < 0 or proposal.source_end < proposal.source_start:
            raise ValueError("源码范围越界")
        if proposal.source_end > len(self.source):
            raise ValueError("源码范围越界")
        if proposal.source_text and self.source[proposal.source_start:proposal.source_end] != proposal.source_text:
            raise ValueError("源码锚点已失效")
        if not digest:
            raise ValueError("EXP source hash 无效")

    def _binding_index(self, proposal: AIProposal) -> int:
        for index, binding in enumerate(self.analysis.bindings):
            if binding.start == proposal.source_start and binding.end == proposal.source_end:
                return index
            if binding.start <= proposal.source_start < binding.end:
                return index
            if proposal.source_start <= binding.start < proposal.source_end:
                return index
        return -1

    def _materialize_operation(self, proposal: AIProposal, binding_index: int) -> HeapOperation:
        operation = HeapOperation.from_dict(proposal.operation)
        if not operation.op_id:
            if proposal.action in {"replace_operation", "value_fact"}:
                operation = replace(operation, op_id=self.analysis.operations[binding_index].op_id)
            else:
                operation = replace(operation, op_id="ai_" + proposal.signature()[:12])
        errors = validate_operation(operation)
        if errors:
            raise ValueError("；".join(errors))
        return replace(
            operation,
            meta={
                **operation.meta,
                "ai_proposal_id": proposal.proposal_id,
                "provenance": "inferred",
            },
        )

    def _proposal_rule(self, proposal: AIProposal) -> dict[str, object]:
        if proposal.rule:
            raw = dict(proposal.rule)
            raw.setdefault("enabled", True)
        else:
            mapping = dict(proposal.helper_mapping)
            roles = [str(item) for item in list(mapping.get("roles") or [])]
            try:
                arity = int(mapping.get("arity") or len(roles))
            except (TypeError, ValueError):
                arity = len(roles)
            raw = {
                "semantic": str(mapping.get("semantic") or ""),
                "matcher": {
                    "function": str(mapping.get("function") or ""),
                    "arity": arity,
                    "keywords": list(mapping.get("keywords") or []),
                    "parameter_names": list(mapping.get("parameter_names") or []),
                },
                "output": {"roles": roles},
                "enabled": True,
                "source": "ai-feedback",
            }
        raw.setdefault("rule_id", "rule_" + proposal.signature()[:16])
        matcher = dict(raw.get("matcher") or {})
        function = str(matcher.get("function") or "")
        call = self._anchored_call(proposal.source_text, function)
        if call is not None:
            matcher.setdefault("arity", len(call.args) + len([item for item in call.keywords if item.arg]))
            matcher.setdefault("keywords", [str(item.arg) for item in call.keywords if item.arg])
            matcher.setdefault("call_shape", HeapSourceAnalyzer.learned_call_shape(call))
        if function and not matcher.get("parameter_names"):
            try:
                tree = ast.parse(self.source)
            except SyntaxError:
                tree = None
            if tree is not None:
                definition = next(
                    (
                        node
                        for node in ast.walk(tree)
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function
                    ),
                    None,
                )
                if definition is not None:
                    matcher["parameter_names"] = [
                        item.arg
                        for item in (
                            *definition.args.posonlyargs,
                            *definition.args.args,
                            *definition.args.kwonlyargs,
                        )
                    ]
        raw["matcher"] = matcher
        return raw

    @staticmethod
    def _anchored_call(source_text: str, function: str) -> ast.Call | None:
        if not source_text.strip() or not function:
            return None
        try:
            tree = ast.parse(source_text)
        except SyntaxError:
            return None
        return next(
            (
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.Call) and HeapSourceAnalyzer._call_name(node.func) == function
            ),
            None,
        )

    def _preview_memory_annotation(
        self,
        proposal: AIProposal,
        current_effect: object,
    ) -> ProposalReplayResult:
        payload = proposal.memory_annotation
        step = int(payload.get("step") or 0)
        if not 0 <= step < len(self.base_snapshots):
            raise ValueError("memory annotation step 越界")
        chunk_id = str(payload.get("chunk") or "")
        chunk = self.base_snapshots[step].chunks.get(chunk_id)
        if chunk is None:
            raise ValueError(f"未找到 chunk `{chunk_id}`")
        provenance = str(payload.get("provenance") or "inferred")
        state = str(payload.get("state") or "unknown")
        if provenance not in {"inferred", "assumed"}:
            raise ValueError("AI 内存标注不能声明 observed/derived")
        if state not in {"known", "unknown", "metadata"}:
            raise ValueError("AI 内存标注 state 无效")
        start = int(payload.get("start") or 0)
        end = int(payload.get("end") or 0)
        chunk_size = parse_int_expr(chunk.chunk_size, self.variables)
        if chunk_size is None or start < 0 or end <= start or end > chunk_size:
            raise ValueError("内存标注超出可证明的 chunk 范围")
        replayed_effect: object = None
        if proposal.snapshot_effect:
            effect = proposal.snapshot_effect
            if str(effect.get("field") or "") != "memory":
                raise ValueError("memory annotation 的 snapshot_effect.field 必须是 memory")
            if str(effect.get("chunk") or "") != chunk_id:
                raise ValueError("memory annotation 与 snapshot effect 的 chunk 不一致")
            replayed_effect = payload.get("value")
            if not self._values_equal(replayed_effect, effect.get("expected")):
                raise ValueError("memory annotation 没有产生声明的 snapshot effect")
        return ProposalReplayResult(
            proposal.proposal_id,
            proposal.action,
            True,
            "bounded memory annotation accepted",
            len(self.analysis.operations),
            len(self.base_snapshots[-1].chunks),
            self.base_snapshots[-1].aborted,
            tuple(item.code for item in self.base_snapshots[-1].warnings),
            current_effect,
            replayed_effect,
            None,
            self._snapshot_summary(self.base_snapshots[-1]),
            semantic_changed=True,
        )

    @staticmethod
    def _operation_facts(operations: Iterable[HeapOperation]) -> tuple[tuple[object, ...], ...]:
        def semantic_value(value: object) -> object:
            if not isinstance(value, str):
                return value
            text = value.strip()
            parsed_int = parse_int_expr(text)
            if parsed_int is not None:
                return ("int", parsed_int)
            try:
                literal = ast.literal_eval(text)
            except (SyntaxError, ValueError):
                return ("text", text)
            if isinstance(literal, (str, bytes, int, float, bool, type(None))):
                return ("literal", literal)
            return ("text", text)

        return tuple(
            (
                item.kind.value,
                item.chunk,
                semantic_value(item.index),
                semantic_value(item.request_size),
                semantic_value(item.data),
                item.field,
                semantic_value(item.value),
                semantic_value(item.target),
                semantic_value(item.fd_storage),
                item.count,
            )
            for item in operations
        )

    @staticmethod
    def _effect_snapshot(snapshots: list[HeapSnapshot], proposal: AIProposal) -> HeapSnapshot:
        step = int(proposal.snapshot_effect.get("step") or 0)
        if not 0 <= step < len(snapshots):
            raise ValueError("snapshot effect step 越界")
        return snapshots[step]

    @staticmethod
    def _effect_value(snapshot: HeapSnapshot, effect: Mapping[str, object]) -> object:
        field_name = str(effect.get("field") or "")
        if field_name == "aborted":
            return snapshot.aborted
        chunk_id = str(effect.get("chunk") or "")
        chunk = snapshot.chunks.get(chunk_id)
        if chunk is None:
            raise ValueError(f"snapshot effect 找不到 chunk `{chunk_id}`")
        if field_name == "memory":
            return ""
        if field_name not in {
            "address",
            "user_address",
            "chunk_size",
            "bin_location",
            "fd",
            "bk",
            "lifecycle",
        }:
            raise ValueError(f"不支持的 snapshot effect 字段 `{field_name}`")
        return getattr(chunk, field_name)

    @staticmethod
    def _values_equal(left: object, right: object) -> bool:
        if isinstance(left, bool) or isinstance(right, bool):
            return str(left).lower() == str(right).lower()
        left_int = parse_int_expr(str(left))
        right_int = parse_int_expr(str(right))
        if left_int is not None and right_int is not None:
            return left_int == right_int
        return str(left).strip() == str(right).strip()

    @staticmethod
    def _pwndbg_supports_effect(
        effect: Mapping[str, object],
        snapshot: HeapSnapshot,
        observed: ObservedHeapState,
    ) -> bool:
        field_name = str(effect.get("field") or "")
        chunk = snapshot.chunks.get(str(effect.get("chunk") or ""))
        if chunk is None:
            return False
        addresses = {item.address for item in observed.chunks}
        for mapping in observed.bins.values():
            for chain in mapping.values():
                addresses.update(chain)
        chunk_addr = parse_int_expr(chunk.address)
        user_addr = parse_int_expr(chunk.user_address)
        if field_name in {"address", "user_address"}:
            expected = parse_int_expr(str(effect.get("expected")))
            return expected is not None and expected in addresses
        if field_name == "chunk_size":
            expected = parse_int_expr(str(effect.get("expected")))
            return any(
                item.address in {chunk_addr, user_addr} and item.size == expected
                for item in observed.chunks
            )
        if field_name == "bin_location":
            expected = str(effect.get("expected") or "").lower()
            aliases = {
                "tcache": "tcache",
                "fastbin": "fastbins",
                "smallbin": "smallbins",
                "largebin": "largebins",
                "unsorted": "unsorted",
            }
            observed_name = next(
                (value for key, value in aliases.items() if expected.startswith(key)),
                "",
            )
            mapping = observed.bins.get(observed_name, {})
            return any(
                address in {chunk_addr, user_addr}
                for chain in mapping.values()
                for address in chain
            )
        if field_name == "lifecycle":
            expected = str(effect.get("expected") or "").lower()
            return any(
                item.address in {chunk_addr, user_addr} and expected in item.status
                for item in observed.chunks
            )
        return False

    @staticmethod
    def _snapshot_summary(snapshot: HeapSnapshot) -> dict[str, object]:
        return {
            "step": snapshot.step,
            "aborted": snapshot.aborted,
            "chunks": {
                chunk_id: {
                    "address": chunk.address,
                    "user_address": chunk.user_address,
                    "chunk_size": chunk.chunk_size,
                    "lifecycle": chunk.lifecycle,
                    "bin_location": chunk.bin_location,
                    "fd": chunk.fd,
                    "bk": chunk.bk,
                    "provenance": chunk.provenance,
                }
                for chunk_id, chunk in snapshot.chunks.items()
            },
            "warnings": [item.code for item in snapshot.warnings],
        }
