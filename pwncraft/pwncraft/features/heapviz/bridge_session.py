"""Headless heap demo session for the Electron Workbench (v0.29).

Owns one ``HeapScenario`` + ``GlibcHeapEngine`` and turns replay snapshots
into plain JSON for the JavaScript canvas.  The physics/animation layer lives
in the renderer; every fact it animates (chunks, bins, links, writes,
corrections) comes from this session — the Electron side never re-implements
allocator semantics.

The self-learning loop lives here too: a canvas correction is validated and
committed through ``CorrectionEngine``, replayed deterministically from the
corrected checkpoint, and turned into recognition rules (``learned_rules``)
that the source analyzer consumes on the next replay — so the *next* replay
already understands what the user just taught it.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import replace
from typing import Any, Mapping

from pwncraft.features.heapviz.analyzer import HeapAnalysisResult, analyze_heap_source
from pwncraft.features.heapviz.allocators.profiles import resolve_allocator_profile
from pwncraft.features.heapviz.contracts import HelperContract
from pwncraft.features.heapviz.corrections import CorrectionEngine, ObservedMemoryPatch
from pwncraft.features.heapviz.dataset import (
    build_case_export,
    normalize_review,
    validate_case,
    validate_review_against_case,
)
from pwncraft.features.heapviz.engine import GlibcHeapEngine
from pwncraft.features.heapviz.learning import (
    CONFIDENCE_ORDER,
    CorrectionEpisode,
    helper_def_text,
    helper_signature,
    parse_call_site,
    resolve_correction_intent,
)
from pwncraft.features.heapviz.memory import PhysicalMemory
from pwncraft.features.heapviz.memory.address import MemoryAddress
from pwncraft.features.heapviz.models import AllocatorConfig
from pwncraft.features.heapviz.operations import HeapOperation, HeapOperationKind
from pwncraft.features.heapviz.presentation.scene_model import build_heap_scene_model
from pwncraft.features.heapviz.presentation.visual_model import HeapVisualModelBuilder
from pwncraft.features.heapviz.scenario import HeapScenario
from pwncraft.features.heapviz.payload import PayloadEvaluator
from pwncraft.features.heapviz.templates import HEAP_TEMPLATES


# ---------------------------------------------------------------------------
# Serialization: frozen dataclasses -> plain JSON


def _int_or(value: object, fallback: Any = None) -> Any:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return fallback


def normalize_role_slots(roles: Any) -> list[str | None]:
    """把 roles 输入归一为「带 None 占位」的位置列表（下标 = 实参下标）。

    接受三种形态：{"arg0": null, "arg1": "size"} / [null, "size", "data"]
    / "index,,data"。位置未知必须保留 None 占位 —— 压缩列表会让 arg1
    错位成 arg0，对训练集是致命错标。全空时返回 []。
    """
    import re as _re

    slots: dict[int, str | None] = {}

    def _clean(value: Any) -> str | None:
        return str(value).strip() if value not in (None, "") else None

    if isinstance(roles, Mapping):
        for key, value in roles.items():
            match = _re.search(r"(\d+)", str(key))
            if match:
                slots[int(match.group(1))] = _clean(value)
    elif isinstance(roles, (list, tuple)):
        for position, value in enumerate(roles):
            slots[position] = _clean(value)
    else:
        for position, item in enumerate(str(roles or "").split(",")):
            slots[position] = _clean(item)
    if not slots:
        return []
    result = [slots.get(index) for index in range(max(slots) + 1)]
    return result if any(item is not None for item in result) else []


def serialize_snapshot(snapshot: Any, semantic_index: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """One replay step as the JSON payload the renderer animates."""
    semantic_index = semantic_index or {}
    step_semantic = dict(semantic_index.get(str(snapshot.operation_id)) or {})
    risk_by_chunk: dict[str, list[dict[str, Any]]] = {}
    step_risks: list[dict[str, Any]] = []
    risk_codes = {
        "double_free": "DOUBLE_FREE", "uaf_edit": "UAF",
        "fd_poison": "TcachePoison", "poison_unknown": "TcachePoison",
        "freelist_poison_inferred": "TcachePoison",
        "tcache_double_free_abort": "DOUBLE_FREE", "fastbin_double_free_abort": "DOUBLE_FREE",
        "malloc_to_target": "TARGET_MALLOC", "malloc_to_target_verified": "TARGET_MALLOC",
        "unlink_prepare": "UNLINK",
    }
    for warning in snapshot.warnings:
        label = risk_codes.get(str(warning.code or ""))
        if not label:
            continue
        item = {"kind": label, "code": warning.code, "severity": warning.severity,
                "title": warning.title, "message": warning.message,
                "operation_id": warning.operation_id, "chunks": list(warning.related_chunks),
                "evidence": "warning"}
        step_risks.append(item)
        for chunk_id in warning.related_chunks:
            risk_by_chunk.setdefault(str(chunk_id), []).append(dict(item))
    for edge in snapshot.overwrite_edges:
        edge_kind = str(edge.kind or "")
        if edge_kind not in {"PHYSICAL_OVERLAP", "CROSS_WRITE"}:
            continue
        label = "OVERLAP" if edge_kind == "PHYSICAL_OVERLAP" else "CROSS_WRITE"
        item = {"kind": label, "code": edge_kind, "severity": "EXPLOIT",
                "title": label, "message": f"{edge.source_chunk} → {edge.target_chunk}.{edge.target_field}",
                "operation_id": edge.writer_operation,
                "chunks": [edge.source_chunk, edge.target_chunk], "evidence": "overwrite_edge"}
        step_risks.append(item)
        for chunk_id in item["chunks"]:
            risk_by_chunk.setdefault(str(chunk_id), []).append(dict(item))
    chunks = []
    for chunk in snapshot.chunks.values():
        chunk_semantic = dict(semantic_index.get(f"chunk:{chunk.chunk_id}") or {})
        if chunk_semantic:
            chunk_semantic["lifecycle_status"] = str(chunk.lifecycle or "unknown")
        chunks.append({
            "chunk_id": chunk.chunk_id,
            "physical_id": chunk.physical_id,
            "address": chunk.address,
            "user_address": chunk.user_address,
            "request_size": chunk.request_size,
            "chunk_size": chunk.chunk_size,
            "original_chunk_size": chunk.original_chunk_size,
            # 尺寸三拆：物理范围 / size 字段原始值 / 解码 chunksize 由
            # PhysicalMemory 独立签发，renderer 不允许再从 header size 推断物理范围。
            "physical_extent_size": chunk.physical_extent_size,
            "header_raw_size": chunk.header_raw_size,
            "decoded_chunksize": chunk.decoded_chunksize,
            "lifecycle": chunk.lifecycle,
            "bin_location": chunk.bin_location,
            "fd": chunk.fd,
            "bk": chunk.bk,
            "data": chunk.data,
            "note": chunk.note,
            "role": chunk.role,
            "menu_indexes": list(chunk.menu_indexes),
            "aliases": list(chunk.aliases),
            "heap_offset": chunk.heap_offset,
            "view_kind": chunk.view_kind,
            "evidence_level": chunk.evidence_level,
            "provenance": chunk.provenance,
            "semantic": chunk_semantic,
            "risk_signals": list(risk_by_chunk.get(str(chunk.chunk_id), ())),
            "fields": [
                {
                    "offset": field.offset,
                    "name": field.name,
                    "value": field.value,
                    "meaning": field.meaning,
                    "address": field.address,
                    "role": field.role,
                    "provenance": field.provenance,
                }
                for field in chunk.fields
            ],
            "regions": [
                {
                    "start": region.start,
                    "end": region.end,
                    "value": region.value,
                    "state": region.state,
                    "name": region.name,
                    "provenance": region.provenance,
                    "meaning": region.meaning,
                }
                for region in chunk.memory_regions
            ],
        })

    # One card per physical allocation.  ``snapshot.chunks`` intentionally
    # retains stale TypedViews for history/UAF reasoning, but those views must
    # never become separate physical heap blocks in the Canvas.  The active
    # allocation instance wins; all generations and menu handles remain
    # attached as identity metadata.
    by_physical: dict[str, list[dict[str, Any]]] = {}
    physical_order: list[str] = []
    for view in chunks:
        physical_id = str(view.get("physical_id") or view.get("chunk_id") or "")
        if physical_id not in by_physical:
            by_physical[physical_id] = []
            physical_order.append(physical_id)
        by_physical[physical_id].append(view)
    lifecycle_rank = {"allocated": 5, "freed": 4, "fake": 3, "reused": 2, "stale": 1}
    physical_chunks: list[dict[str, Any]] = []
    for physical_id in physical_order:
        views = by_physical[physical_id]
        representative = max(
            enumerate(views),
            key=lambda item: (lifecycle_rank.get(str(item[1].get("lifecycle") or ""), 0), item[0]),
        )[1]
        physical = dict(representative)
        physical["current_chunk_id"] = representative.get("chunk_id")
        physical["allocation_generation"] = len(views)
        physical["allocation_instances"] = [
            {
                "chunk_id": view.get("chunk_id"),
                "lifecycle": view.get("lifecycle"),
                "request_size": view.get("request_size"),
                "bin_location": view.get("bin_location"),
                "menu_indexes": list(view.get("menu_indexes") or []),
            }
            for view in views
        ]
        physical["handles"] = [
            {
                "index": handle.index,
                "chunk_id": handle.chunk_id,
                "status": handle.status,
            }
            for handle in snapshot.handles.values()
            if handle.physical_id == physical_id
        ]
        physical["aliases"] = list(dict.fromkeys([
            str(view.get("chunk_id") or "") for view in views
            if str(view.get("chunk_id") or "") != str(representative.get("chunk_id") or "")
        ]))
        # 物理卡片继承当前代表 view 的语义引用；同一 physical_id 的历史
        # generation 仍通过 allocation_instances 保留，不把历史证据伪装成当前事实。
        physical["semantic"] = dict(representative.get("semantic") or {})
        physical["risk_signals"] = list(representative.get("risk_signals") or ())
        physical_chunks.append(physical)

    bins = {
        "tcache": {str(size): list(chain) for size, chain in snapshot.bins.tcache.items()},
        "fastbins": {str(size): list(chain) for size, chain in snapshot.bins.fastbins.items()},
        "smallbins": {str(size): list(chain) for size, chain in snapshot.bins.smallbins.items()},
        "largebins": {str(size): list(chain) for size, chain in snapshot.bins.largebins.items()},
        "unsorted": list(snapshot.bins.unsorted),
    }
    scene = build_heap_scene_model(snapshot)
    visual = HeapVisualModelBuilder().build(snapshot)
    return {
        "step": snapshot.step,
        "op_id": snapshot.operation_id,
        # 语义证据由后端签发；前端不得根据颜色或 chunk 名称反推漏洞结论。
        "semantic": step_semantic,
        "risk_signals": step_risks,
        "title": snapshot.event_title,
        "explanation": list(snapshot.explanation),
        "warnings": [
            {
                "severity": warning.severity,
                "code": warning.code,
                "title": warning.title,
                "message": warning.message,
                "operation_id": warning.operation_id,
                "related_chunks": list(warning.related_chunks),
            }
            for warning in snapshot.warnings
        ],
        "aborted": snapshot.aborted,
        "allocator_abort": {
            "reason": snapshot.allocator_abort.reason,
            "operation_id": snapshot.allocator_abort.operation_id,
            "check": snapshot.allocator_abort.check,
            "address": snapshot.allocator_abort.address,
            "metadata": dict(snapshot.allocator_abort.metadata),
            "glibc_policy": snapshot.allocator_abort.glibc_policy,
        } if snapshot.allocator_abort else None,
        "model_divergences": list(snapshot.model_divergences),
        "heap_base": snapshot.heap_base,
        "top": {
            "address": snapshot.top_address,
            "size": snapshot.top_size,
            "provenance": snapshot.top_provenance,
        },
        "chunks": chunks,
        "physical_chunks": physical_chunks,
        "typed_views": chunks,
        "bins": bins,
        "handles": [
            {
                "index": handle.index,
                "chunk_id": handle.chunk_id,
                "physical_id": handle.physical_id,
                "status": handle.status,
                "note": handle.note,
            }
            for handle in snapshot.handles.values()
        ],
        "observations": [
            {
                "name": observation.name,
                "expression": observation.expression,
                "value": observation.value,
                "source_chunk": observation.source_chunk,
                "source_address": observation.source_address,
                "kind": observation.kind,
                "provenance": observation.provenance,
                "integer_value": observation.integer_value,
                "detail": observation.detail,
            }
            for observation in snapshot.observations
        ],
        "intents": [
            {
                "kind": intent.kind,
                "target": intent.target,
                "status": intent.status,
                "message": intent.message,
                "operation_id": intent.operation_id,
            }
            for intent in snapshot.intents
        ],
        "alloc_events": [
            {
                "chunk": event.chunk,
                "chunk_address": event.chunk_address,
                "user_pointer": event.user_pointer,
                "request_size": event.request_size,
                "chunk_size": event.chunk_size,
                "source": event.source,
                "allocation_source": event.allocation_source_kind,
                "victim_physical_id": event.victim_physical_id,
                "bin_head_before": list(event.bin_head_before),
                "bin_head_after": list(event.bin_head_after),
            }
            for event in snapshot.alloc_events
        ],
        "free_events": [
            {
                "chunk": event.chunk,
                "chunk_address": event.chunk_address,
                "destination_bin": event.destination_bin,
            }
            for event in snapshot.free_events
        ],
        "bin_transitions": [
            {
                "action": event.action,
                "bin_kind": event.bin_kind,
                "size": event.size,
                "node": event.node,
                "before": list(event.before),
                "after": list(event.after),
                "moved_nodes": list(event.moved_nodes),
                "link_mutations": list(event.link_mutations),
                "note": event.note,
            }
            for event in snapshot.bin_transition_events
        ],
        "overwrite_edges": [
            {
                "writer_operation": edge.writer_operation,
                "source_chunk": edge.source_chunk,
                "target_physical_object": edge.target_physical_object,
                "target_chunk": edge.target_chunk,
                "target_field": edge.target_field,
                "physical_start": edge.physical_start,
                "physical_end": edge.physical_end,
                "before": edge.before,
                "after": edge.after,
                "kind": edge.kind,
            }
            for edge in snapshot.overwrite_edges
        ],
        "groups": [
            {
                "group_id": group.group_id,
                "chunk_ids": [chunk.chunk_id for chunk in group.chunks],
                "physical_ids": [chunk.physical_id for chunk in group.chunks],
                "start": group.start,
                "end": group.end,
                "overlap": group.overlap,
                "full_cover": group.full_cover,
                "shared_memory": group.shared_memory,
            }
            for group in scene.groups
        ],
        "bin_rows": [
            {"title": row[0], "size": row[1], "chain": list(row[2]), "doubly": row[3]}
            for row in scene.bin_rows
        ],
        "relations": [
            {
                "left_object": relation.left_object,
                "right_object": relation.right_object,
                "physical_start": relation.physical_start,
                "physical_end": relation.physical_end,
                "kind": relation.kind.value,
                "evidence": relation.evidence,
            }
            for relation in visual.relations
        ],
        "paint_spans": [
            {
                "object_id": span.object_id,
                "field": span.field,
                "physical_start": span.physical_start,
                "physical_end": span.physical_end,
                "visual_kind": span.visual_kind.value,
                "owner": span.owner,
                "writer": span.writer,
                "byte_start": span.byte_start,
                "byte_end": span.byte_end,
            }
            for span in visual.spans
        ],
    }


# ---------------------------------------------------------------------------
# Recognition rule inference — canvas adjustments become analyzer rules


def infer_rules_from_correction(
    context: Mapping[str, Any],
    patch: Mapping[str, Any],
    accepted: bool,
) -> list[dict[str, Any]]:
    """Turn one canvas adjustment into recognition-rule candidates.

    The user adjusts the canvas because recognition was wrong; a single
    well-formed adjustment is enough evidence to *scope a rule to this
    scene* (reversible, requires_confirmation=False).  Bumping to a global
    rule still needs a second identical observation.
    """
    if not accepted:
        return []
    rules: list[dict[str, Any]] = []
    helper = str(context.get("helper") or "").strip()
    if helper.upper() == "UNKNOWN_HELPER":
        # 识别器明确承认不知道 helper 时，这次校正不能生成任何
        # 「function=UNKNOWN_HELPER」的规则 —— 那是往学习数据里投毒。
        helper = ""
    field = str(patch.get("field") or "user_area")
    kind = str(context.get("kind") or "").strip()

    semantic = str(context.get("corrected_kind") or "").strip().lower()
    if helper and semantic in {"alloc", "free", "edit", "show", "copy"} and semantic != kind:
        rules.append({
            "rule_id": f"rule-{uuid.uuid4().hex[:8]}",
            "family": "semantic",
            "enabled": True,
            "scope": "scene",
            "evidence_count": 1,
            "requires_confirmation": False,
            "reason": f"画布校正：{helper} 的调用实际是 {semantic}（识别原为 {kind or '未知'}）",
            "matcher": {"function": helper},
            "output": {"semantic": semantic},
        })

    if helper and field in {"size", "raw_size", "chunk_size"}:
        rules.append({
            "rule_id": f"rule-{uuid.uuid4().hex[:8]}",
            "family": "size_map",
            "enabled": True,
            "scope": "scene",
            "evidence_count": 1,
            "requires_confirmation": False,
            "reason": f"画布校正：{helper} 申请的 chunk 实际规格已在 PhysicalMemory 中修正，回放按修正后字节推进",
            "matcher": {"function": helper},
            "output": {"roles": context.get("parameter_names") or []},
        })

    if helper and field in {"fd", "next", "bk", "key"}:
        rules.append({
            "rule_id": f"rule-{uuid.uuid4().hex[:8]}",
            "family": "freelist_map",
            "enabled": True,
            "scope": "scene",
            "evidence_count": 1,
            "requires_confirmation": False,
            "reason": f"画布校正：{helper} 的 freelist 指针字段按用户观测值重写，safe-linking 解码随字段地址自动推进",
            "matcher": {"function": helper},
            "output": {"roles": context.get("parameter_names") or []},
        })
    return rules


def merge_learned_rules(
    existing: list[dict[str, Any]],
    proposals: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Merge rule proposals; identical evidence upgrades scene → global."""
    merged = [dict(item) for item in existing]
    added: list[dict[str, Any]] = []
    for proposal in proposals:
        duplicate = next(
            (
                item for item in merged
                if item.get("family") == proposal.get("family")
                and (item.get("matcher") or {}).get("function")
                == (proposal.get("matcher") or {}).get("function")
                and (item.get("output") or {}).get("semantic")
                == (proposal.get("output") or {}).get("semantic")
            ),
            None,
        )
        if duplicate is not None:
            duplicate["evidence_count"] = int(duplicate.get("evidence_count") or 0) + 1
            if duplicate.get("scope") == "scene":
                duplicate["scope"] = "global"
                duplicate["requires_confirmation"] = True
                duplicate["reason"] = (
                    str(duplicate.get("reason") or "") + " · 第二次相同观测，规则升级为全局（仍可关闭）"
                )
            continue
        merged.append(dict(proposal))
        added.append(dict(proposal))
    return merged, added


# ---------------------------------------------------------------------------
# Session


_LIVE_KINDS: dict[str, HeapOperationKind] = {
    "malloc": HeapOperationKind.ALLOC,
    "alloc": HeapOperationKind.ALLOC,
    "free": HeapOperationKind.FREE,
    "edit": HeapOperationKind.EDIT,
    "show": HeapOperationKind.SHOW,
}


def build_live_operation(kind: str, op_id: str, *, chunk: str = "", request_size: str = "",
                         data: str = "", offset: str = "", note: str = "") -> HeapOperation:
    """把操作表单（malloc/free/edit/show）翻成一个确定性 HeapOperation。

    这不是第二条真值路径：表单只产生 HeapOperation，语义全部由
    GlibcHeapEngine 按 allocator 规则推导（request2size / bin 搜索 / 写入
    provenance），Canvas 只是显示结果。
    """
    op_kind = _LIVE_KINDS.get(str(kind or "").strip().lower())
    if op_kind is None:
        raise ValueError(f"不支持的堆操作: {kind or '(空)'}")
    if op_kind == HeapOperationKind.ALLOC:
        meta: dict[str, str] = {}
        return HeapOperation(
            op_id=op_id, kind=op_kind, chunk=str(chunk or "").strip(),
            request_size=str(request_size or "0x18").strip(),
            data=str(data or "").strip(), note=str(note or "").strip(), meta=meta,
        )
    if op_kind == HeapOperationKind.EDIT:
        meta = {"offset": str(offset).strip()} if str(offset or "").strip() else {}
        return HeapOperation(
            op_id=op_id, kind=op_kind, chunk=str(chunk or "").strip(),
            data=str(data or "").strip(), note=str(note or "").strip(), meta=meta,
        )
    return HeapOperation(
        op_id=op_id, kind=op_kind, chunk=str(chunk or "").strip(),
        note=str(note or "").strip(),
    )


def _field_for_offset(chunk_relative: int) -> str:
    """chunk 头相对偏移 → 人读字段名（反向求解的 effects 展示用）。"""
    offset = int(chunk_relative)
    if 0 <= offset < 8:
        return "prev_size"
    if offset < 0x10:
        return "size"
    return f"user[{hex(offset - 0x10)}]"


class HeapSession:
    """Replay + correction state for one heap scenario."""

    def __init__(self) -> None:
        self.scenario = HeapScenario()
        self.source = ""
        self.learned_rules: list[dict[str, Any]] = []
        self.engine: GlibcHeapEngine | None = None
        self.snapshots: list[Any] = []
        self.corrections: list[dict[str, Any]] = []
        self.episodes: list[dict[str, Any]] = []
        self.assumptions: list[dict[str, Any]] = []   # VNext.3.1A-completion
        self.helper_contracts: list[dict[str, Any]] = []   # USER_CONFIRMED 优先
        # Review 层：外部 Agent 的审查是独立标签层，绝不直接覆盖 Snapshot。
        # verdict 生命周期 proposed → validated/accepted/rejected，只有
        # accepted 才允许进入训练集 accepted/。
        self.reviews: list[dict[str, Any]] = []
        # RecognitionCorrection：用户对 ambiguous/unknown 候选的一等标注
        # （语义 + 参数角色），静态识别训练数据里最值钱的一类。
        self.recognition_corrections: list[dict[str, Any]] = []
        # Canvas structural edits are allocator-model transactions, not byte
        # patches.  They survive source re-analysis and are reapplied to the
        # freshly recognised operation IR before the whole heap is replayed.
        self.structural_edits: list[dict[str, Any]] = []
        self.analysis: HeapAnalysisResult | None = None
        # Values proven by the currently loaded EXP.  Keep these separate
        # from persisted scenario variables so deleting ``heap_base = ...``
        # from the editor immediately returns the model to symbolic offsets.
        self._source_variables: dict[str, str] = {}

    # -- configuration ------------------------------------------------
    def allocator_profile(self):
        """当前场景的已解析 AllocatorProfile（身份 + 机制真值的唯一来源）。"""
        raw = self.scenario.to_dict().get("allocator") or {}
        try:
            return resolve_allocator_profile(raw)
        except Exception:
            return resolve_allocator_profile(None)

    def config(self) -> AllocatorConfig:
        raw = self.scenario.to_dict().get("allocator") or {}
        try:
            config = resolve_allocator_profile(raw).to_config()
            # ``resolve_allocator_profile`` deliberately supplies a symbolic
            # default.  Preserve a user/runtime supplied base when present;
            # never replace the symbolic root with a decorative fake address.
            return replace(config, heap_base=str(raw.get("heap_base") or "heap_base"))
        except Exception:
            return AllocatorConfig()

    def variables(self) -> dict[str, str]:
        variables = dict(self.scenario.variables)
        variables.update(self._source_variables)
        return variables

    def heap_base_specified(self) -> bool:
        """Whether the base is evidence-backed rather than the symbolic root."""
        base = str(self.config().heap_base or "").strip()
        if base and base != "heap_base" and _int_or(base) is not None:
            return True
        resolved = self.variables().get(base or "heap_base")
        return _int_or(resolved) is not None

    # -- loading ------------------------------------------------------
    def load(
        self,
        *,
        template_id: str = "",
        scenario_dict: Mapping[str, Any] | None = None,
        source: str | None = None,
        allocator: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if scenario_dict:
            self.structural_edits = []
            self.scenario = HeapScenario.from_dict(dict(scenario_dict))
            if source is None:
                self.source = ""
        elif template_id:
            self.structural_edits = []
            template = next(
                (item for item in HEAP_TEMPLATES if item.template_id == template_id), None
            )
            if template is None:
                raise ValueError(f"未知堆模板: {template_id}")
            self.scenario = HeapScenario(
                name=template.title,
                operations=list(template.operations),
            )
            if source is None:
                self.source = ""
        if allocator:
            # 请求完整替换 allocator 身份（version/profile_id），只继承
            # 环境项（heap_base/simulation_mode）——否则旧 wire dict 里的
            # requested_version 会盖过请求里的 profile_id，版本切不动。
            current = self.scenario.to_dict()["allocator"]
            inheritable = {
                key: value for key, value in current.items()
                if key in {"heap_base", "simulation_mode"}
            }
            merged = {**inheritable, **dict(allocator)}
            self.scenario = HeapScenario.from_dict({**self.scenario.to_dict(), "allocator": merged})
        if source is not None:
            self.source = str(source)
        if not self.source:
            self._source_variables = {}
            self.analysis = None
        if self.source:
            self._source_variables = {}
            result = analyze_heap_source(
                self.source,
                api_profile=self.scenario.api_profile,
                variables=self.variables(),
                branch_choices=self.scenario.branch_choices,
                overrides=self.scenario.timeline_overrides,
                learned_rules=[*self.learned_rules, *self._mapping_rules()],
                helper_contracts=[
                    HelperContract.from_dict(dict(item)) for item in self.helper_contracts
                ],
            )
            self.analysis = result
            # Only adopt an exact scalar assignment.  Derived/unknown heap
            # values stay symbolic, so the renderer shows +0x... until the
            # EXP actually establishes a base.
            source_base = result.symbols.get("heap_base")
            if _int_or(source_base) is not None:
                self._source_variables["heap_base"] = hex(int(str(source_base), 0))
            operations = list(result.operations)
            operations = self._apply_derivation_rules(operations)
            operations = self._apply_structural_edits(operations)
            self.scenario.operations = operations
            self.scenario.helper_contracts = [
                contract.to_dict() for contract in result.helper_contracts
            ]
        return self.replay()

    # -- allocator profile switch (Reprofile 事务) ---------------------
    def reprofile(self, allocator: Mapping[str, Any] | None) -> dict[str, Any]:
        """版本切换是一个完整的 Reprofile 事务，不是给 state.allocator 赋值。

        请求 → AllocatorProfile 注册表解析（requested/effective 双版本）
        → 场景以新 profile 整题重分析 + 重回放（识别规则、别名映射、
        HelperContract、结构编辑全部重新生效）→ 人工 corrections 逐条复验：
        新机制下仍成立的保留并重放，不再成立的标记 invalidated 并给出
        原因。任何一步失败整体回滚到旧 profile，绝不留半新半旧状态。
        """
        if not isinstance(allocator, Mapping) or not allocator:
            raise ValueError("reprofile 需要 allocator 请求（profile_id 或 version）")
        old_scenario = self.scenario
        old_snapshots = self.snapshots
        old_analysis = self.analysis
        old_source_vars = dict(self._source_variables)
        try:
            merged_raw = {**self.scenario.to_dict(), "allocator": dict(allocator)}
            self.scenario = HeapScenario.from_dict(merged_raw)
            state = self.load(source=self.source)
        except Exception as error:
            self.scenario = old_scenario
            self.snapshots = old_snapshots
            self.analysis = old_analysis
            self._source_variables = old_source_vars
            self.replay()
            raise ValueError(f"Reprofile 失败（已回滚到原 profile）: {error}") from error

        resolved = self.allocator_profile()
        kept: list[dict[str, Any]] = []
        invalidated: list[dict[str, Any]] = []
        for correction in list(self.corrections):
            if self._reapply_correction(correction):
                kept.append(correction)
            else:
                invalidated.append({
                    **dict(correction),
                    "status": "invalidated",
                    "reason": (
                        f"profile {resolved.profile_id} 下该观测补丁未通过 "
                        "allocator 校验（机制/尺寸语义随版本变化），已从活动集移除。"
                    ),
                })
        self.corrections = kept

        state = self.state()
        state["reprofile"] = {
            "requested_version": resolved.requested_version,
            "effective_version": resolved.effective_version,
            "profile_id": resolved.profile_id,
            "profile_revision": resolved.profile_revision,
            "clamp_note": resolved.clamp_note,
            "corrections_kept": len(kept),
            "corrections_invalidated": invalidated,
            "replayed_steps": len(self.snapshots),
        }
        return state

    def _apply_structural_edits(self, operations: list[HeapOperation]) -> list[HeapOperation]:
        """Apply persisted APPEND_USER_ROW edits to fresh canonical IR.

        Matching prefers the original operation id and falls back to the
        chunk label so small source edits do not silently discard the user's
        structural correction.  Only ordinary ALLOC operations are eligible;
        bulk/fake/intent operations are deliberately never widened here.
        """
        result = list(operations)
        for edit in self.structural_edits:
            if str(edit.get("kind") or "") not in {"APPEND_USER_ROW", "INSERT_USER_ROW"}:
                continue
            op_id = str(edit.get("operation_id") or "")
            chunk_id = str(edit.get("chunk_id") or "")
            delta = _int_or(edit.get("delta"), 0) or 0
            if delta <= 0:
                continue
            index = next((
                i for i, op in enumerate(result)
                if op.kind == HeapOperationKind.ALLOC and op_id and op.op_id == op_id
            ), None)
            if index is None:
                index = next((
                    i for i, op in enumerate(result)
                    if op.kind == HeapOperationKind.ALLOC and chunk_id and op.chunk == chunk_id
                ), None)
            if index is None:
                continue
            source_call = str(edit.get("source_call") or "").strip()
            if source_call and self.analysis is not None:
                binding_call = (
                    self.analysis.bindings[index].source_text.strip()
                    if index < len(self.analysis.bindings) else ""
                )
                if binding_call != source_call:
                    continue
            request = _int_or(result[index].request_size)
            if request is None:
                continue
            extra = bytes.fromhex(str(edit.get("data_hex") or ""))
            new_data = result[index].data
            if str(edit.get("kind") or "") == "INSERT_USER_ROW":
                # 中插：用 flat dict 表达式重建落点（已知段下移、gap 不伪造）。
                pos = _int_or(edit.get("after_user_offset"), 0) or 0
                user_len_after = _int_or(edit.get("user_len_after"), 0) or 0
                if not extra or user_len_after <= 0:
                    continue
                spliced = self._insert_payload_expression(
                    new_data, pos, extra, user_len_after - len(extra),
                )
                if spliced is None:
                    continue
                new_data = spliced[0]
            elif extra:
                payload = PayloadEvaluator(
                    bits=self.config().bits, variables=self.variables(),
                ).evaluate(new_data)
                current = payload.materialize()
                if current is None:
                    continue
                new_data = repr(current + extra)
            result[index] = replace(
                result[index], request_size=hex(request + delta), data=new_data,
            )
        # RESIZE_PHYSICAL：按记录位置重新注入合成操作（位置锚定在
        # after_op_id 之后，EXP 源码小幅编辑导致的位置漂移用 chunk 兜底）。
        for edit in self.structural_edits:
            if str(edit.get("kind") or "") != "RESIZE_PHYSICAL":
                continue
            delta = _int_or(edit.get("delta"), 0) or 0
            if delta == 0:
                continue
            edge = str(edit.get("edge") or "bottom")
            chunk_id = str(edit.get("chunk_id") or "")
            physical_id = str(edit.get("physical_id") or "")
            after_op_id = str(edit.get("after_op_id") or "")
            position = _int_or(edit.get("position"), 0) or 0
            anchor = next((
                i for i, op in enumerate(result)
                if after_op_id and op.op_id == after_op_id
            ), None)
            insert_at = (
                anchor + 1 if anchor is not None
                else min(max(position, 0), len(result))
            )
            result.insert(insert_at, HeapOperation(
                op_id=str(edit.get("operation_id") or f"op_rsz_{insert_at:03d}"),
                kind=HeapOperationKind.RESIZE_PHYSICAL,
                chunk=chunk_id,
                meta={"edge": edge, "delta": hex(delta),
                      "physical_id": physical_id, "origin": "canvas"},
            ))
        return result

    def _apply_derivation_rules(self, operations: list[HeapOperation]) -> list[HeapOperation]:
        """推导规则（如 EDIT.offset=0）在分析之后、回放之前应用 —— 场景级。"""
        import dataclasses

        applied: list[HeapOperation] = []
        for op in operations:
            if op.kind != HeapOperationKind.EDIT:
                applied.append(op)
                continue
            for rule in self.learned_rules:
                if (rule.get("family") != "derivation"
                        or str(rule.get("target")) != "EDIT.offset"
                        or not rule.get("enabled", True)):
                    continue
                if str(op.meta.get("offset") or "").strip():
                    continue  # 显式 offset 永远赢过推导规则
                try:
                    value = int(str(rule.get("expression")), 0)
                except (TypeError, ValueError):
                    continue
                meta = {**op.meta, "offset": str(value)}
                op = dataclasses.replace(op, meta=meta)
                break
            applied.append(op)
        return applied

    # -- helper mappings（别名映射：addchunk → add 等） -----------------
    _MAPPING_TARGETS = {"alloc", "free", "edit", "show", "copy"}

    def _mapping_rules(self) -> list[dict[str, Any]]:
        """helper_mappings → 识别器 learned_rules（别名视为对应语义的 helper）。"""
        rules: list[dict[str, Any]] = []
        for mapping in self.scenario.helper_mappings:
            alias = str(mapping.get("alias") or "").strip()
            target = str(mapping.get("target") or "").strip().lower()
            if not alias or target not in self._MAPPING_TARGETS:
                continue
            output: dict[str, Any] = {"semantic": target}
            roles = normalize_role_slots(mapping.get("roles"))
            if roles:
                # 位置敏感：None 槽位表示该参数角色未知，保留占位 ——
                # 压缩列表会让 arg1 错位成 arg0，是训练集致命错标。
                output["roles"] = roles
            rules.append({
                "rule_id": f"map-{alias}",
                "family": "mapping",
                "enabled": True,
                "scope": "scene",
                "matcher": {"function": alias},
                "output": output,
                "source": "user_mapping",
            })
        return rules

    def set_helper_mapping(self, alias: str, target: str, roles: Any = "") -> dict[str, Any]:
        import re as _re
        alias = str(alias or "").strip()
        target = str(target or "").strip().lower()
        if not _re.match(r"^[A-Za-z_]\w*$", alias):
            raise ValueError(f"别名不是合法函数名: {alias}")
        if target not in self._MAPPING_TARGETS:
            raise ValueError(f"目标语义必须是 {'/'.join(sorted(self._MAPPING_TARGETS))}，收到: {target}")
        slots = normalize_role_slots(roles)
        self.scenario.helper_mappings = [
            dict(item) for item in self.scenario.helper_mappings
            if str(item.get("alias")) != alias
        ]
        entry: dict[str, Any] = {"alias": alias, "target": target}
        if slots:
            # 位置保留存储（None = 该位未知）；旧消费者读到的逗号串里
            # 未知位显示为空段（"index,,data"）。
            entry["roles"] = slots
            entry["roles_text"] = ",".join(role or "" for role in slots)
        self.scenario.helper_mappings.append(entry)
        return self.load(source=self.source) if self.source else self.replay()

    def remove_helper_mapping(self, alias: str) -> dict[str, Any]:
        alias = str(alias or "").strip()
        self.scenario.helper_mappings = [
            dict(item) for item in self.scenario.helper_mappings
            if str(item.get("alias")) != alias
        ]
        return self.load(source=self.source) if self.source else self.replay()

    # -- replay -------------------------------------------------------
    def replay(self) -> dict[str, Any]:
        config = self.config()
        self.engine = GlibcHeapEngine(config, variables=self.variables())
        snapshots = self.engine.replay(self.scenario.operations)
        self.snapshots = snapshots
        try:
            self.engine.assert_cache_consistency()
            self._cache_divergence = ""
        except AssertionError as error:
            self._cache_divergence = str(error)
        return self.state()

    def structural_edit(
        self,
        step: int,
        *,
        kind: str,
        chunk_id: str,
        physical_id: str = "",
        delta: int = 0x10,
        edge: str = "bottom",
        data_hex: str = "",
        after_user_offset: int = -1,
    ) -> dict[str, Any]:
        """Commit a heap-layout transaction and rebuild every derived view.

        三种事务，同一模式：改 scenario IR → 整段 allocator 重放 → 校验 →
        失败整体回滚。画布永远不能只改 UI。

        ``APPEND_USER_ROW``  加宽 allocation 操作（可带 ``data_hex``，让新行
            字节由这次分配亲自写入），然后完整重放；后继偏移、boundary
            tag、bins、top、typed fields 全部来自同一份新 snapshot。
        ``INSERT_USER_ROW``  在 ``after_user_offset``（user 区内字节偏移，
            必须按整行对齐）下方插入真实物理行：request 增长 + 确定性
            payload 在该偏移原位拼接（尾部字节整体下移）。与尾部追加、
            边界拖动是三种不同操作，绝不互相合并。
        ``RESIZE_PHYSICAL`` 拖动 chunk 上/下边界（word 字节步进）：在
            ``step`` 注入一条 RESIZE_PHYSICAL 操作，结果出现在下一步；
            边界侵入相邻 chunk 形成真实 overlap，侵入 top 则同步 top
            账本；首个 chunk 上边界锁定。EXP 反向映射从不编造：结构
            修正一律记 exp_status='pending' 并交给学习引擎记录语义。
        """
        kind_norm = str(kind or "").upper()
        if kind_norm == "APPEND_USER_ROW":
            return self._structural_append(
                int(step), chunk_id=chunk_id, physical_id=physical_id,
                delta=int(delta), data_hex=str(data_hex or ""),
            )
        if kind_norm == "INSERT_USER_ROW":
            return self._structural_insert_row(
                int(step), chunk_id=chunk_id, physical_id=physical_id,
                delta=int(delta), data_hex=str(data_hex or ""),
                after_user_offset=int(after_user_offset),
            )
        if kind_norm == "RESIZE_PHYSICAL":
            return self._structural_resize(
                int(step), chunk_id=chunk_id, physical_id=physical_id,
                delta=int(delta), edge=str(edge or "bottom").lower(),
            )
        raise ValueError(f"未知结构编辑: {kind}")

    def _commit_structural_edit(self, step: int, edit: dict[str, Any], verify,
                                old_operations=None, old_edits=None) -> dict[str, Any]:
        """事务执行：重放 → verify(snapshot) → 失败整体回滚并原样重放。

        ``old_operations/old_edits`` 必须是变更前的快照 —— 由调用方在改动
        scenario 之前捕获后传入，保证回滚真正回到事务前状态。
        """
        if old_operations is None:
            old_operations = list(self.scenario.operations)
        if old_edits is None:
            old_edits = [dict(item) for item in self.structural_edits]
        try:
            state = self.replay()
            problem = verify(self.snapshots[int(step)])
            if problem:
                raise ValueError(problem)
        except ValueError:
            self.scenario.operations = old_operations
            self.structural_edits = old_edits
            self.replay()
            raise
        except Exception as error:
            # 引擎内部异常也必须整体回滚，并转成结构化拒绝；
            # 绝不让 UnboundLocalError/KeyError/... 直接穿透 bridge。
            self.scenario.operations = old_operations
            self.structural_edits = old_edits
            self.replay()
            raise ValueError(f"结构事务执行失败（已回滚）: {type(error).__name__}: {error}") from error
        state["structural_edit"] = dict(edit)
        state["selected_step"] = int(step)
        return state

    @staticmethod
    def _find_layout_target(snapshot: Any, chunk_id: str, physical_id: str) -> Any:
        return next((
            chunk for chunk in snapshot.chunks.values()
            if ((physical_id and chunk.physical_id == physical_id)
                or (not physical_id and chunk.chunk_id == chunk_id))
        ), None)

    def _allocation_op_index(self, step: int, target: Any) -> int:
        """从运行时 alloc 证据解析创建该 chunk 的确切 ALLOC 操作下标。"""
        allocation_op_id = ""
        for prior in self.snapshots[: step + 1]:
            for event in prior.alloc_events:
                if event.chunk == target.chunk_id and event.chunk_address == target.address:
                    allocation_op_id = event.operation_id
        op_index = next((
            i for i, op in enumerate(self.scenario.operations)
            if op.op_id == allocation_op_id and op.kind == HeapOperationKind.ALLOC
        ), None)
        if op_index is None:
            raise ValueError("该 chunk 不是独立 alloc 操作创建，不能单独改变结构")
        return op_index


    def _exp_mapping_for(self, source_line: int, summary: str,
                         canonical_effect: str = "") -> dict[str, Any]:
        """结构编辑的 EXP 反向映射评估：不编造代码，统一返回映射结构。

        返回里同时带：
          exp_status / exp_reason   兼容旧前端的待确认通道
          canonical_effect          本次事务的 Canonical IR 效果描述
          exp_mapping               {safe, python, reason}：safe=True 才允许
                                    前端进入「待写入 EXP」队列；安全与否都
                                    绝不在结构编辑后偷偷直接改 EXP。

        有源码绑定的分配调用需要原位改写 EXP 行（当前编辑器只支持追加，
        不具备原位改写能力）→ pending_inplace；live-op 来源的操作不在 EXP
        里，模型即真值 → pending（无需回写）。两者都不伪造 EXP 行。
        """
        source_line = int(source_line or 0)
        if source_line > 0:
            reason = (
                f"对应 EXP 第 {source_line} 行需要原位改写（{summary}）；"
                "编辑器暂不支持原位改写，模型真值已提交并标记待映射，不编造代码。"
            )
            return {
                "exp_status": "pending_inplace",
                "exp_reason": reason,
                "canonical_effect": canonical_effect,
                "exp_mapping": {"safe": False, "python": "", "reason": reason},
            }
        reason = (
            "画布结构修正没有可证明的对应 EXP 操作：只保留模型真值并标记待映射，不编造代码。"
        )
        return {
            "exp_status": "pending",
            "exp_reason": reason,
            "canonical_effect": canonical_effect,
            "exp_mapping": {"safe": False, "python": "", "reason": reason},
        }

    def _learn_structural_edit(self, target: Any, edge: str, delta: int, kind: str) -> dict[str, Any]:
        """把人工结构修正交给学习引擎：同类语义重复出现即升级全局规则。"""
        helper = ""
        proposal = {
            "rule_id": f"rule-{uuid.uuid4().hex[:8]}",
            "family": "structural_edit",
            "enabled": True,
            "scope": "scene",
            "evidence_count": 1,
            "requires_confirmation": False,
            "reason": f"画布结构编辑：{kind} {target.chunk_id} {edge} {delta:+#x}（人工确认）",
            "matcher": {"function": helper, "chunk": target.chunk_id, "edge": edge},
            "output": {"semantic": f"{kind}:{edge}:{delta:+#x}"},
        }
        self.learned_rules, added = merge_learned_rules(self.learned_rules, [proposal])
        return {"learned_rules_added": added, "learned_rules": self.learned_rules}

    def _structural_append(self, step: int, *, chunk_id: str, physical_id: str,
                           delta: int, data_hex: str) -> dict[str, Any]:
        if not 0 <= step < len(self.snapshots):
            raise ValueError(f"结构编辑步号越界: {step}")
        snapshot = self.snapshots[step]
        target = self._find_layout_target(snapshot, chunk_id, physical_id)
        if target is None:
            raise ValueError(f"当前步找不到 chunk: {chunk_id or physical_id}")
        if target.view_kind in {"top_chunk", "fake_chunk"}:
            raise ValueError("只能给普通 chunk 追加 user row")

        alignment = 16 if self.config().bits >= 64 else 8
        if delta <= 0 or delta % alignment:
            raise ValueError(f"追加大小必须是 {hex(alignment)} 的正整数倍")

        op_index = self._allocation_op_index(step, target)
        request = _int_or(self.scenario.operations[op_index].request_size)
        old_chunk_size = _int_or(target.chunk_size)
        if request is None or old_chunk_size is None:
            raise ValueError("chunk request/size 不是可确定数值，不能结构编辑")

        new_data = self.scenario.operations[op_index].data
        if data_hex:
            try:
                extra = bytes.fromhex(data_hex)
            except ValueError:
                raise ValueError("data_hex 不是合法的十六进制字节串")
            if not extra:
                raise ValueError("追加行内容为空")
            if len(extra) > delta:
                raise ValueError(f"追加行内容 {len(extra)} 字节超出新增空间 {delta}")
            word = 8 if self.config().bits >= 64 else 4
            user_len = old_chunk_size - word * 2
            payload = PayloadEvaluator(
                bits=self.config().bits, variables=self.variables(),
            ).evaluate(new_data)
            current = payload.materialize()
            if current is None or len(current) != user_len:
                raise ValueError(
                    "现有 alloc 数据无法确定地覆盖到新增行起点，不能以单一 data 原子写入；"
                    "请先让分配填满当前 user 区，或不带内容追加后用单元格编辑写入。"
                )
            new_data = repr(current + extra)

        edit = {
            "kind": "APPEND_USER_ROW",
            "chunk_id": target.chunk_id,
            "physical_id": target.physical_id,
            "operation_id": self.scenario.operations[op_index].op_id,
            "delta": hex(delta),
            "data_hex": data_hex,
            "source_call": (
                self.analysis.bindings[op_index].source_text.strip()
                if self.analysis is not None and op_index < len(self.analysis.bindings)
                else ""
            ),
            **self._exp_mapping_for(
                self.analysis.bindings[op_index].line
                if self.analysis is not None and op_index < len(self.analysis.bindings) else 0,
                f"add(size {hex(request)} → {hex(request + delta)})",
                canonical_effect=(
                    f"APPEND_USER_ROW {target.chunk_id}: request "
                    f"{hex(request)} → {hex(request + delta)}；chunk extent "
                    f"{hex(old_chunk_size)} → {hex(old_chunk_size + delta)}，"
                    "后继偏移/boundary tag/bins/top 由整段重放重导"
                ),
            ),
        }
        self.structural_edits.append(edit)
        self.scenario.operations[op_index] = replace(
            self.scenario.operations[op_index],
            request_size=hex(request + delta), data=new_data,
        )

        def verify(rebuilt_snapshot: Any) -> str:
            rebuilt = next((
                chunk for chunk in rebuilt_snapshot.chunks.values()
                if chunk.chunk_id == target.chunk_id
            ), None)
            rebuilt_size = _int_or(rebuilt.chunk_size) if rebuilt is not None else None
            if rebuilt_size != old_chunk_size + delta:
                return (
                    f"结构事务校验失败: chunksize {hex(old_chunk_size)} -> "
                    f"{hex(rebuilt_size) if rebuilt_size is not None else '?'}"
                )
            return ""

        state = self._commit_structural_edit(step, edit, verify)
        learning = self._learn_structural_edit(target, "append", delta, "APPEND_USER_ROW")
        state["learning"] = {**learning, "reanalyzed": False}
        return state

    def _insert_payload_expression(self, original_data: str, pos: int, extra: bytes,
                                   user_len_old: int) -> tuple[str, Any] | None:
        """构造中插后的等价 payload 表达式：pos 之前不动、新行落在 pos、
        已知段原样下移、稀疏 gap 保持稀疏（flat dict 覆盖 + 显式 length）。

        返回 (新表达式, 原 PayloadIR)；payload 长度不确定时返回 None ——
        此时无法诚实声明任何字节的落点，必须硬拒绝而不是猜测。
        """
        payload = PayloadEvaluator(
            bits=self.config().bits, variables=self.variables(),
        ).evaluate(original_data)
        if payload.length is None:
            return None
        pos = max(0, min(pos, user_len_old))
        entries: list[str] = []
        if pos > 0:
            entries.append(f"0x0: ({original_data})[:{pos}]")
        entries.append(f"{hex(pos)}: {extra!r}")
        entries.append(f"{hex(pos + len(extra))}: ({original_data})[{pos}:]")
        expression = (
            "flat({"
            + ", ".join(entries)
            + f"}}, length={user_len_old + len(extra)})"
        )
        return expression, payload

    def _structural_insert_row(self, step: int, *, chunk_id: str, physical_id: str,
                               delta: int, data_hex: str, after_user_offset: int) -> dict[str, Any]:
        """在任意 user 行下方插入真实物理行（≠ 尾部追加，≠ 边界拖动）。

        物理语义：chunk extent 增长 delta，新字节落在 after_user_offset，
        该偏移之后的既有 user 字节整体下移 delta（flat dict 精确落点，
        稀疏 gap 不伪造）；后继 chunk、boundary tag、bins、top 由整段
        重放重新推导。mid-insert 必须给满整行字节：新物理行没有旧值可
        保留，留空一律拒绝而不是补 0。
        """
        if not 0 <= step < len(self.snapshots):
            raise ValueError(f"结构编辑步号越界: {step}")
        snapshot = self.snapshots[step]
        target = self._find_layout_target(snapshot, chunk_id, physical_id)
        if target is None:
            raise ValueError(f"当前步找不到 chunk: {chunk_id or physical_id}")
        if target.view_kind in {"top_chunk", "fake_chunk"}:
            raise ValueError("只能给普通 chunk 插入 user row")

        word = 8 if self.config().bits >= 64 else 4
        row_bytes = word * 2
        if delta <= 0 or delta % row_bytes:
            raise ValueError(f"插入行大小必须是 {hex(row_bytes)}（一物理行）的正整数倍")

        op_index = self._allocation_op_index(step, target)
        request = _int_or(self.scenario.operations[op_index].request_size)
        old_chunk_size = _int_or(target.chunk_size)
        if request is None or old_chunk_size is None:
            raise ValueError("chunk request/size 不是可确定数值，不能结构编辑")
        user_len = old_chunk_size - word * 2
        if not 0 <= after_user_offset <= user_len:
            raise ValueError(
                f"插入位置 0x{after_user_offset:x} 超出 user 区范围 [0, {hex(user_len)}]"
            )
        if after_user_offset % row_bytes:
            raise ValueError(f"插入位置必须按整行（{hex(row_bytes)}）对齐")

        new_data = self.scenario.operations[op_index].data
        is_append_position = after_user_offset == user_len
        try:
            extra = bytes.fromhex(data_hex)
        except ValueError:
            raise ValueError("data_hex 不是合法的十六进制字节串")

        if not is_append_position:
            if len(extra) != delta:
                raise ValueError(
                    "中插的新物理行没有旧值可保留：必须提供完整行字节（"
                    f"{delta} 字节 / 两个格子都填写），留空会被拒绝而不是伪造 0。"
                )
            spliced = self._insert_payload_expression(new_data, after_user_offset, extra, user_len)
            if spliced is None:
                raise ValueError(
                    "现有 payload 长度无法证明，中插无法声明任何字节的落点；"
                    "请先把分配数据改成确定表达式后再插入。"
                )
            new_data = spliced[0]
        elif extra:
            if len(extra) > delta:
                raise ValueError(f"插入行内容 {len(extra)} 字节超出新增空间 {delta}")
            spliced = self._insert_payload_expression(new_data, after_user_offset, extra, user_len)
            if spliced is not None:
                new_data = spliced[0]

        edit = {
            "kind": "INSERT_USER_ROW",
            "chunk_id": target.chunk_id,
            "physical_id": target.physical_id,
            "operation_id": self.scenario.operations[op_index].op_id,
            "delta": hex(delta),
            "after_user_offset": hex(after_user_offset),
            "user_len_after": hex(user_len + delta),
            "data_hex": data_hex,
            "source_call": (
                self.analysis.bindings[op_index].source_text.strip()
                if self.analysis is not None and op_index < len(self.analysis.bindings)
                else ""
            ),
            **self._exp_mapping_for(
                self.analysis.bindings[op_index].line
                if self.analysis is not None and op_index < len(self.analysis.bindings) else 0,
                f"add(size {hex(request)} → {hex(request + delta)}) @user+{hex(after_user_offset)}",
                canonical_effect=(
                    f"INSERT_USER_ROW {target.chunk_id}: request "
                    f"{hex(request)} → {hex(request + delta)}；新字节落点 "
                    f"user+{hex(after_user_offset)}，之后既有 user 字节下移 "
                    f"{hex(delta)}，chunk extent {hex(old_chunk_size)} → "
                    f"{hex(old_chunk_size + delta)}"
                ),
            ),
        }
        self.structural_edits.append(edit)
        self.scenario.operations[op_index] = replace(
            self.scenario.operations[op_index],
            request_size=hex(request + delta), data=new_data,
        )

        def verify(rebuilt_snapshot: Any) -> str:
            rebuilt = next((
                chunk for chunk in rebuilt_snapshot.chunks.values()
                if chunk.chunk_id == target.chunk_id
            ), None)
            rebuilt_size = _int_or(rebuilt.chunk_size) if rebuilt is not None else None
            if rebuilt_size != old_chunk_size + delta:
                return (
                    f"结构事务校验失败: chunksize {hex(old_chunk_size)} -> "
                    f"{hex(rebuilt_size) if rebuilt_size is not None else '?'}"
                )
            return ""

        state = self._commit_structural_edit(step, edit, verify)
        learning = self._learn_structural_edit(target, f"insert@{after_user_offset:#x}", delta, "INSERT_USER_ROW")
        state["learning"] = {**learning, "reanalyzed": False}
        return state

    def _resolve_physical_target(self, snapshot: Any, chunk_id: str, physical_id: str) -> Any:
        """physical_id 唯一解析目标 PhysicalChunk。

        同一 physical_id 可能挂着多个 generation 的 typed view；这里按与
        serialize 一致的 lifecycle 优先级选出唯一代表。解析不出 → None
        （调用方必须拒绝，绝不猜）。
        """
        candidates = [
            chunk for chunk in snapshot.chunks.values()
            if (physical_id and chunk.physical_id == physical_id)
            or (not physical_id and chunk.chunk_id == chunk_id)
        ]
        if not candidates:
            return None
        rank = {"allocated": 5, "freed": 4, "fake": 3, "reused": 2, "stale": 1}
        return max(candidates, key=lambda item: rank.get(str(item.lifecycle or ""), 0))

    def _structural_resize(self, step: int, *, chunk_id: str, physical_id: str,
                           delta: int, edge: str) -> dict[str, Any]:
        if not 0 <= step < len(self.snapshots):
            raise ValueError(f"结构编辑步号越界: {step}")
        snapshot = self.snapshots[step]
        # 进入任何 resize/overlap 分支之前：无条件解析 old_start/old_end/extent。
        target = self._resolve_physical_target(snapshot, chunk_id, physical_id)
        if target is None:
            raise ValueError(f"physical_id 无法唯一解析目标 chunk，拒绝结构编辑: {physical_id or chunk_id}")
        if target.view_kind in {"top_chunk", "fake_chunk"} or target.chunk_id == "TOP":
            raise ValueError("只能 resize 普通 malloc chunk")
        if not physical_id:
            raise ValueError("resize 必须携带 physical_id（物理身份是唯一解析依据）")
        if edge not in {"top", "bottom"}:
            raise ValueError("edge 必须是 top 或 bottom")
        word = 8 if self.config().bits >= 64 else 4
        if delta == 0 or delta % word:
            raise ValueError(f"拖动步进必须是 {word} 字节的非零倍数")

        old_start = _int_or(target.heap_offset)
        old_extent = _int_or(
            target.physical_extent_size or target.decoded_chunksize or target.chunk_size
        )
        if old_start is None or old_extent is None or old_extent <= 0:
            raise ValueError(
                f"chunk {target.chunk_id} 物理范围不可确定（old_start={target.heap_offset}, "
                f"extent={target.physical_extent_size or target.chunk_size}），拒绝结构编辑"
            )
        old_end = old_start + old_extent
        # 统一几何：new_start/new_end 先于一切分支算好
        new_start = old_start if edge == "bottom" else old_start + delta
        new_end = old_end + delta if edge == "bottom" else old_end
        expected_extent = new_end - new_start

        if edge == "top":
            has_predecessor = any(
                other.chunk_id not in {"TOP", target.chunk_id}
                and other.view_kind not in {"top_chunk", "fake_chunk"}
                and (offset := _int_or(other.heap_offset)) is not None
                and offset < old_start
                for other in snapshot.chunks.values()
            )
            if not has_predecessor:
                raise ValueError("第一个 chunk 的上边界锁定：堆起始边界不可拖")

        op_id = f"op_rsz_{len(self.structural_edits) + 1:03d}"
        resize_op = HeapOperation(
            op_id=op_id,
            kind=HeapOperationKind.RESIZE_PHYSICAL,
            chunk=target.chunk_id,
            meta={
                "edge": edge,
                "delta": hex(delta),
                "physical_id": target.physical_id,
                "origin": "canvas",
            },
        )
        edit = {
            "kind": "RESIZE_PHYSICAL",
            "chunk_id": target.chunk_id,
            "physical_id": target.physical_id,
            "operation_id": op_id,
            "edge": edge,
            "delta": hex(delta),
            "after_op_id": (
                self.scenario.operations[step - 1].op_id if 1 <= step <= len(self.scenario.operations) else ""
            ),
            "position": step,
            "source_call": "",
            **self._exp_mapping_for(
                0, f"resize {edge} {delta:+#x}（物理范围 {hex(old_extent)} → {hex(expected_extent)}）",
                canonical_effect=(
                    f"RESIZE_PHYSICAL {target.chunk_id} {edge} {delta:+#x}: "
                    f"physical range [{hex(old_start)},{hex(old_end)}) → "
                    f"[{hex(new_start)},{hex(new_end)})，extent {hex(old_extent)} → "
                    f"{hex(expected_extent)}；侵入相邻 chunk 即真实 overlap，top 邻接走 top 账本"
                ),
            ),
        }
        # 事务前状态先捕获：回滚必须回到「注入 resize 操作之前」。
        old_operations = list(self.scenario.operations)
        old_edits = [dict(item) for item in self.structural_edits]
        self.structural_edits.append(edit)
        operations = list(old_operations)
        operations.insert(min(step, len(operations)), resize_op)
        self.scenario.operations = operations

        def verify(rebuilt_snapshot: Any) -> str:
            if rebuilt_snapshot.aborted:
                abort = rebuilt_snapshot.allocator_abort
                return (
                    "allocator 校验拒绝该结构编辑: "
                    + (f"{abort.reason}（{abort.check}）" if abort else "allocator aborted")
                )
            rebuilt = self._find_layout_target(rebuilt_snapshot, target.chunk_id, target.physical_id)
            if rebuilt is None:
                return f"结构事务校验失败: 重放后找不到 {target.chunk_id}"
            rebuilt_extent = _int_or(rebuilt.physical_extent_size)
            if rebuilt_extent != expected_extent:
                return (
                    f"结构事务校验失败: physical_extent {hex(old_extent)} -> "
                    f"{hex(rebuilt_extent) if rebuilt_extent is not None else '?'}（期望 {hex(expected_extent)}）"
                )
            return ""

        # resize 注入为第 step+1 个操作，其结果出现在 snapshots[step+1]。
        if step + 1 >= len(self.snapshots):
            raise ValueError("该步已是最后一步，边界拖动没有可落位的后续状态")
        state = self._commit_structural_edit(
            step + 1, edit, verify,
            old_operations=old_operations, old_edits=old_edits,
        )
        learning = self._learn_structural_edit(target, edge, delta, "RESIZE_PHYSICAL")
        state["learning"] = {**learning, "reanalyzed": False}
        return state

    def append_operation(self, kind: str, *, chunk: str = "", request_size: str = "",
                         data: str = "", offset: str = "", note: str = "") -> dict[str, Any]:
        """在活会话上执行一个 malloc/free/edit/show 表单操作。

        与模板/EXP 回放完全同一条管线：构造 HeapOperation → 追加进 scenario
        → 整段确定性重放。alloc 未填标签时按已有 ALLOC 次数自动命名 A/B/C…。
        """
        alloc_count = sum(
            1 for op in self.scenario.operations if op.kind == HeapOperationKind.ALLOC
        )
        label = str(chunk or "").strip()
        op_kind = _LIVE_KINDS.get(str(kind or "").strip().lower())
        if op_kind == HeapOperationKind.ALLOC and not label:
            label = "ABCDEFGH"[alloc_count % 8] + (str(alloc_count // 8) if alloc_count >= 8 else "")
        op_id = f"op_{len(self.scenario.operations) + 1:03d}"
        op = build_live_operation(
            kind, op_id, chunk=label, request_size=request_size,
            data=data, offset=offset, note=note,
        )
        self.scenario.operations = [*self.scenario.operations, op]
        state = self.replay()
        last = self.snapshots[-1] if self.snapshots else None
        state["appended_operation"] = {
            "op_id": op.op_id,
            "title": op.title(),
            "explanation": list(last.explanation) if last is not None else [],
            "warnings": [
                {"severity": w.severity, "code": w.code, "title": w.title, "message": w.message}
                for w in (last.warnings if last is not None else [])
            ],
            "step": len(self.snapshots) - 1,
        }
        return state

    # -- Semantic Round Trip: Canonical IR / 反向求解 / 双向定位 --------
    def _parse_addr(self, text: str) -> int | None:
        try:
            return MemoryAddress.parse(text, self.variables()).offset
        except (TypeError, ValueError):
            return None

    def canonical_ops(self, upto: int | None = None) -> list[dict[str, Any]]:
        """Canonical IR 列表 —— EXP 与 Heap 画布共用的同一操作模型。

        每个 operation 带：来源 EXP 行（若有）、关键参数、以及它在物理堆上
        的效果（alloc→chunk 地址；edit→写了哪个 chunk 的哪个字段、物理区间；
        free→进了哪个 bin）。UI 双向定位都以它为坐标。
        """
        limit = len(self.snapshots) if upto is None else min(upto, len(self.snapshots))
        bindings = self.analysis.bindings if self.analysis is not None else []
        result: list[dict[str, Any]] = [{
            "step": 0, "op_id": "", "kind": "init", "title": "初始状态", "index": "",
            "source_call": "", "source_line": 0, "effects": [],
        }]
        for step in range(1, limit):
            snapshot = self.snapshots[step]
            if step > len(self.scenario.operations):
                break
            op = self.scenario.operations[step - 1]
            binding = bindings[step - 1] if step - 1 < len(bindings) else None
            entry: dict[str, Any] = {
                "step": step,
                "op_id": op.op_id,
                "kind": op.kind.value,
                "title": op.title(),
                "index": op.index or op.chunk,
                "chunk": op.chunk,
                "request_size": op.request_size,
                "data": op.data,
                "offset": op.meta.get("offset") or "",
                "note": op.note,
                "source_call": binding.source_text if binding else "",
                "source_line": binding.line if binding else 0,
                "effects": [],
            }
            for event in snapshot.alloc_events:
                if event.operation_id == op.op_id:
                    entry["effects"].append({
                        "kind": "alloc", "chunk": event.chunk,
                        "address": event.chunk_address, "user_pointer": event.user_pointer,
                    })
            for event in snapshot.free_events:
                if event.operation_id == op.op_id:
                    entry["effects"].append({
                        "kind": "free", "chunk": event.chunk, "destination": event.destination_bin,
                    })
            seen_edges: set[tuple[str, str, str]] = set()
            for edge in snapshot.overwrite_edges:
                if edge.writer_operation != op.op_id:
                    continue
                key = (edge.target_chunk, edge.target_field, edge.physical_start)
                if key in seen_edges:
                    continue
                seen_edges.add(key)
                entry["effects"].append({
                    "kind": "write", "chunk": edge.target_chunk, "field": edge.target_field,
                    "start": edge.physical_start, "end": edge.physical_end,
                    "after": edge.after,
                })
            result.append(entry)
        return result

    def reverse_edit(self, step: int, address: str, data_hex: str, length: int) -> dict[str, Any]:
        """Reverse Operation Solver：画布物理写入 → Canonical EDIT Operation。

        反推顺序：哪个存活 chunk 的 user 区能写到该地址 → offset = target − user_addr
        → 数据表达式（p64 / bytes 字面量）→ 本题 EDIT helper（契约优先）→ 渲染形式。
        """
        snapshot = self.snapshots[step]
        target = self._parse_addr(address)
        if target is None:
            raise ValueError(f"无法解析地址: {address}")
        sources: list[dict[str, Any]] = []
        for chunk in snapshot.chunks.values():
            user_addr = self._parse_addr(chunk.user_address)
            size = self._parse_addr(chunk.chunk_size)
            if user_addr is None or size is None or chunk.lifecycle in {"stale", "top"}:
                continue
            user_len = max(0, size - 0x10)
            # 溢出写是本求解器的核心场景：允许越过 user 区末端写入下一个
            # chunk 的 header/user（有界窗口，防误选远端 chunk）。
            overflow_window = user_len + 0x110
            if user_addr <= target < user_addr + overflow_window:
                offset = target - user_addr
                sources.append({
                    "chunk_id": chunk.chunk_id,
                    "handle": (chunk.menu_indexes[0] if chunk.menu_indexes else chunk.chunk_id),
                    "user_address": chunk.user_address,
                    "offset": offset,
                    "overflow": offset >= user_len,
                    "lifecycle": chunk.lifecycle,
                    "live_handle": bool(chunk.menu_indexes) and chunk.lifecycle == "allocated",
                })
        sources.sort(key=lambda item: (not item["live_handle"], item["overflow"], item["offset"]))
        if not sources:
            raise ValueError(
                "没有已分配 chunk 的 user 区能写到该地址（可能是堆外/未初始化区域）——"
                "请改用观测写入。"
            )
        source = sources[0]
        raw = bytes.fromhex(data_hex)
        pointer_width = 8 if self.config().bits >= 64 else 4
        pack_call = "p64" if pointer_width == 8 else "p32"
        if length == pointer_width and len(raw) == pointer_width:
            data_expr = f"{pack_call}({hex(int.from_bytes(raw, 'little'))})"
        else:
            escaped = "".join(f"\\x{byte:02x}" for byte in raw)
            data_expr = f"b'{escaped}'"

        helper, form = self._edit_helper_for_challenge()
        if form == "flat":
            python = f"{helper}({source['handle']}, flat({{{hex(source['offset'])}: {data_expr}}}))" if source["offset"] \
                else f"{helper}({source['handle']}, {data_expr})"
        elif source["offset"]:
            python = f"{helper}({source['handle']}, {hex(source['offset'])}, {data_expr})"
        else:
            python = f"{helper}({source['handle']}, {data_expr})"
        effects = []
        for item in snapshot.chunks.values():
            start = self._parse_addr(item.address)
            size = self._parse_addr(item.chunk_size) or 0
            end = start + size if start is not None else None
            if start is not None and end is not None and start <= target < end:
                effects.append({
                    "chunk": item.chunk_id,
                    "field": _field_for_offset(target - start),
                    "start": hex(target),
                    "end": hex(target + len(raw)),
                })
        return {
            "canonical": {
                "kind": "edit", "index": source["handle"], "chunk": source["chunk_id"],
                "offset": hex(source["offset"]), "length": len(raw),
                "data_hex": data_hex, "data_expr": data_expr,
            },
            "python": python,
            "helper": helper,
            "form": form,
            "source": source,
            "alternatives": sources[1:3],
            "effects": effects,
        }

    def _edit_helper_for_challenge(self) -> tuple[str, str]:
        """本题的 EDIT helper 与渲染形态（HelperContract 优先于 api_profile）。"""
        for contract in self.helper_contracts:
            if str(contract.get("operation")) == "edit":
                function = str(contract.get("function") or "edit")
                roles = set((contract.get("roles") or {}).keys())
                parameters = list((contract.get("signature") or {}).get("parameters") or [])
                if "offset" in roles or len(parameters) >= 3:
                    return function, "3arg"
                return function, "flat"
        profile = self.scenario.api_profile
        return str(profile.edit_function or "edit"), "3arg"

    # -- Canonical Operation → EXP source（HelperContract 驱动） --------
    def live_op_python(
        self,
        kind: str,
        *,
        chunk: str = "",
        request_size: str = "",
        data: str = "",
        offset: str = "",
    ) -> dict[str, Any]:
        """前端提交 Canonical Operation，这里按已确认契约渲染 EXP 行。

        与 ``reverse_edit`` 同一真值：helper 名与参数形态来自
        USER_CONFIRMED HelperContract，退而求其次才是 api_profile（含调用
        模板）。两者都无法证明时 ``safe=False`` —— 前端显示「不可安全回写
        EXP」而不是把写死的 add/delete 塞进用户源码。
        """
        kind = str(kind or "").strip().lower()
        kind = "alloc" if kind == "malloc" else kind
        if kind not in {"alloc", "free", "edit", "show"}:
            return {"safe": False, "python": "", "reason": f"未知操作语义: {kind}"}

        label = str(chunk or "").strip()
        if not label:
            return {"safe": False, "python": "", "reason": "缺少 chunk 标签"}

        data_text = str(data or "").strip()
        offset_text = str(offset or "").strip()

        def data_expr() -> str:
            if not data_text:
                return "b''"
            # The live-op form passes a plain string; keep bytes escaping in
            # one place so p64/p32/flat shortcuts stay readable.
            if data_text.startswith(("b'", 'b"', "p64(", "p32(", "flat(")):
                return data_text
            escaped = "".join(f"\\x{byte:02x}" for byte in data_text.encode("utf-8"))
            return f"b'{escaped}'"

        # ① USER_CONFIRMED HelperContract：角色表就是参数顺序。
        for contract in self.helper_contracts:
            if str(contract.get("operation")) != kind:
                continue
            function = str(contract.get("function") or "").strip()
            if not function:
                continue
            roles = contract.get("roles") or {}
            if kind == "alloc":
                size = request_size or "0x18"
                if roles:
                    order = [role for role in ("index", "size", "data") if role in roles]
                else:
                    order = ["index", "size", "data"]
                args = [
                    label if role == "index" else (size if role == "size" else data_expr())
                    for role in order
                ]
                return {"safe": True, "python": f"{function}({', '.join(args)})",
                        "helper": function, "source": "helper_contract"}
            if kind == "edit":
                has_offset = bool(offset_text and offset_text not in {"0", "0x0"})
                if has_offset:
                    return {"safe": True, "python": f"{function}({label}, {offset_text}, {data_expr()})",
                            "helper": function, "source": "helper_contract"}
                return {"safe": True, "python": f"{function}({label}, {data_expr()})",
                        "helper": function, "source": "helper_contract"}
            return {"safe": True, "python": f"{function}({label})",
                    "helper": function, "source": "helper_contract"}

        # ② api_profile（识别器推断的调用模板）。
        profile = self.scenario.api_profile
        profile_map = {
            "alloc": (profile.alloc_function, profile.alloc_template, {"index": label, "size": request_size or "0x18", "data": data_expr()}),
            "free": (profile.free_function, profile.free_template, {"index": label}),
            "edit": (profile.edit_function, profile.edit_template, {"index": label, "data": data_expr()}),
            "show": (profile.show_function, profile.show_template, {"index": label}),
        }
        from pwncraft.features.heapviz.api_profile import render_api_call
        function, template, values = profile_map[kind]
        if kind == "edit" and offset_text and offset_text not in {"0", "0x0"}:
            template = template.replace("{data}", f"{offset_text}, {{data}}")
        rendered = render_api_call(template, function, **values)
        if function:
            return {"safe": True, "python": rendered, "helper": function, "source": "api_profile"}
        return {"safe": False, "python": "", "reason": "helper 契约未确认且 api_profile 为空"}


    def apply_pending_edit(
        self, step: int, canonical: Mapping[str, Any], *, simulate: bool = True,
    ) -> dict[str, Any]:
        """「仅用于推演」：把反向求解出的 Canonical Operation 追加进操作模型并重放。

        「写入 EXP」由渲染端把 ``python`` 行插入编辑器；两端共用同一 Canonical IR。
        """
        data_hex = str(canonical.get("data_hex") or "")
        raw = bytes.fromhex(data_hex)
        escaped = "".join(f"\\x{byte:02x}" for byte in raw)
        op = HeapOperation(
            op_id=f"op_{len(self.scenario.operations) + 1:03d}",
            kind=HeapOperationKind.EDIT,
            chunk=str(canonical.get("chunk") or ""),
            index=str(canonical.get("index") or ""),
            data=f"b'{escaped}'",
            meta={"offset": str(canonical.get("offset") or "0")},
            note="Heap Canvas correction（反向求解）",
        )
        self.scenario.operations = [*self.scenario.operations, op]
        state = self.replay()
        last = self.snapshots[-1] if self.snapshots else None
        state["appended_operation"] = {
            "op_id": op.op_id,
            "title": op.title(),
            "step": len(self.snapshots) - 1,
            "explanation": list(last.explanation) if last is not None else [],
            "warnings": [
                {"severity": w.severity, "code": w.code, "title": w.title, "message": w.message}
                for w in (last.warnings if last is not None else [])
            ],
            "simulated": bool(simulate),
            "python": str(canonical.get("python") or ""),
        }
        return state

    def field_provenance(self, step: int, address: str) -> dict[str, Any]:
        """字段值溯源链：创建 → 历次写入（含 overflow），每环带操作与物理区间。"""
        target = self._parse_addr(address)
        if target is None:
            raise ValueError(f"无法解析地址: {address}")
        chain: list[dict[str, Any]] = []
        for index, snapshot in enumerate(self.snapshots[: step + 1]):
            for event in snapshot.alloc_events:
                event_addr = self._parse_addr(event.chunk_address)
                event_size = None
                chunk = snapshot.chunks.get(event.chunk)
                if chunk is not None:
                    event_size = self._parse_addr(chunk.chunk_size)
                if event_addr is not None and event_addr <= target < event_addr + (event_size or 0):
                    chain.append({
                        "step": index, "kind": "alloc", "op_id": event.operation_id,
                        "summary": f"malloc {event.request_size} → {event.chunk} @ {event.chunk_address}",
                        "value": "",
                    })
            for edge in snapshot.overwrite_edges:
                start = self._parse_addr(edge.physical_start)
                end = self._parse_addr(edge.physical_end)
                if start is not None and end is not None and start <= target < end:
                    chain.append({
                        "step": index, "kind": edge.kind, "op_id": edge.writer_operation,
                        "summary": (
                            f"{edge.source_chunk} 写 {edge.target_chunk}.{edge.target_field} "
                            f"[{edge.physical_start} ~ {edge.physical_end})"
                        ),
                        "value": edge.after,
                    })
        return {"address": address, "step": step, "chain": chain}

    def chunk_history(self, chunk_id: str, upto: int | None = None) -> dict[str, Any]:
        """chunk 生命周期：谁创建 / 谁改过 / 谁释放（操作流程视图的定位数据）。"""
        limit = len(self.snapshots) if upto is None else min(upto, len(self.snapshots) - 1)
        history: list[dict[str, Any]] = []
        for index, snapshot in enumerate(self.snapshots[: limit + 1]):
            for event in snapshot.alloc_events:
                if event.chunk == chunk_id:
                    history.append({
                        "step": index, "kind": "alloc", "op_id": event.operation_id,
                        "summary": f"{event.request_size} → chunk @ {event.chunk_address}",
                    })
            seen: set[str] = set()
            for edge in snapshot.overwrite_edges:
                if edge.target_chunk != chunk_id or edge.writer_operation in seen:
                    continue
                seen.add(edge.writer_operation)
                history.append({
                    "step": index, "kind": "write", "op_id": edge.writer_operation,
                    "summary": f"{edge.target_field} [{edge.physical_start} ~ {edge.physical_end}) ← {edge.after}",
                })
            for event in snapshot.free_events:
                if event.chunk == chunk_id:
                    history.append({
                        "step": index, "kind": "free", "op_id": event.operation_id,
                        "summary": f"→ {event.destination_bin}",
                    })
        return {"chunk": chunk_id, "history": history}

    def state(self) -> dict[str, Any]:
        canonical = self.canonical_ops()
        report = getattr(self.analysis, "recognition_report", None) or {}
        candidates = list(report.get("candidates") or [])
        by_line = {int(item.get("line") or 0): item for item in candidates}
        semantic_index: dict[str, dict[str, Any]] = {}
        for item in canonical:
            op_id = str(item.get("op_id") or "")
            if not op_id:
                continue
            line = int(item.get("source_line") or 0)
            candidate = by_line.get(line) or {}
            kind = str(item.get("kind") or "unknown")
            verdict = str(candidate.get("verdict") or ("recognized" if line else "unknown"))
            confidence = candidate.get("confidence")
            if confidence is None:
                confidence = item.get("confidence")
            stage = {
                "alloc": "lifecycle.allocate", "free": "lifecycle.free",
                "edit": "primitive.write", "show": "primitive.leak",
                "copy": "primitive.copy",
            }.get(kind, "unknown")
            evidence = [x for x in (item.get("source_call"), candidate.get("reason")) if x]
            semantic = {
                "semantic_kind": kind,
                "semantic_confidence": confidence,
                "semantic_evidence": evidence,
                "source_line": line,
                "source_call": item.get("source_call") or "",
                "recognition_verdict": verdict,
                "chain_stage": stage,
                "lifecycle_status": "unknown",
            }
            semantic_index[op_id] = semantic
            for effect in item.get("effects") or []:
                chunk_id = str(effect.get("chunk") or "")
                if chunk_id:
                    semantic_index[f"chunk:{chunk_id}"] = dict(semantic)
        steps = [serialize_snapshot(snapshot, semantic_index) for snapshot in self.snapshots]
        analysis = None
        if self.analysis is not None:
            analysis = {
                "valid": self.analysis.valid,
                # RecognitionReport：识别能力自身的可观测数据。候选数 /
                # recognized / ambiguous / ignored 是一等结果，前端直接展示
                # 「识别 12/15，⚠ 2 个语义不确定，○ 1 个已忽略」。
                "recognition": dict(report),
                "diagnostics": [
                    {
                        "severity": item.severity,
                        "code": item.code,
                        "message": item.message,
                        "line": item.line,
                        "suggestion": item.suggestion,
                    }
                    for item in self.analysis.diagnostics
                ],
                "bindings": [
                    {
                        "source_id": binding.source_id,
                        "line": binding.line,
                        "end_line": binding.end_line,
                        "source_text": binding.source_text,
                        "confidence": binding.confidence,
                        "match_status": binding.match_status,
                        "start": binding.start,
                        "end": binding.end,
                    }
                    for binding in self.analysis.bindings
                ],
                "symbols": dict(self.analysis.symbols),
            }
        revision = (
            f"{len(steps)}:{len(self.corrections)}:{len(self.learned_rules)}:"
            f"{len(self.structural_edits)}:{len(self.scenario.operations)}"
        )
        return {
            "snapshot_id": uuid.uuid4().hex[:12],
            "memory_revision": revision,
            "name": self.scenario.name,
            "allocator": self.scenario.to_dict()["allocator"],
            "allocator_label": self.config().label,
            "operations": [operation.to_dict() for operation in self.scenario.operations],
            "canonical_ops": canonical,
            "variables": dict(self.variables()),
            "heap_base_specified": self.heap_base_specified(),
            "steps": steps,
            "corrections": [dict(item) for item in self.corrections],
            "learned_rules": [dict(item) for item in self.learned_rules],
            "episodes": [dict(item) for item in self.episodes],
            "assumptions": [dict(item) for item in self.assumptions],
            "canvas_branch_kind": ("MANUAL_ASSUMPTION" if self.assumptions
                                   and self.corrections
                                   and self.corrections[-1].get("intent") == "assumption"
                                   else "TRUTH"),
            "reviews": [dict(item) for item in self.reviews],
            "recognition_corrections": [dict(item) for item in self.recognition_corrections],
            "helper_contracts": [dict(item) for item in self.helper_contracts],
            "structural_edits": [dict(item) for item in self.structural_edits],
            "mappings": [dict(item) for item in self.scenario.helper_mappings],
            "cache_divergence": getattr(self, "_cache_divergence", ""),
            "analysis": analysis,
            "source": self.source,
        }

    # -- correction (canvas -> truth -> replay -> learning) ------------
    def _correction_upstream(self, step: int, patch_payload: Mapping[str, Any]) -> dict[str, Any]:
        """校正前的语义上下文：来源调用点、operation、chunk 字段旧值。"""
        operation = None
        if 1 <= step <= len(self.scenario.operations):
            operation = self.scenario.operations[step - 1].to_dict()
        call_text = ""
        source_line = 0
        if self.analysis is not None and 1 <= step <= len(self.analysis.bindings):
            binding = self.analysis.bindings[step - 1]
            call_text = binding.source_text
            source_line = binding.line
        call = parse_call_site(call_text)
        call["__text__"] = call_text
        chunk = None
        object_id = str(patch_payload.get("object_id") or "")
        address = str(patch_payload.get("address") or "")
        snapshot = self.snapshots[step]
        for item in snapshot.chunks.values():
            if object_id and item.physical_id == object_id:
                chunk = item
                break
            if address and any(
                str(field.address) == address for field in item.fields
            ):
                chunk = item
                break
        before_value = ""
        for field in (chunk.fields if chunk else ()):
            if address and str(field.address) == address:
                before_value = field.value
                break
        # Correction context v2：学习器必须知道「这次调用到底长什么样」。
        # 形参名 / 指纹 / 当前角色绑定 / 邻域调用 / allocator profile 全部
        # 在这里一次性补齐 —— 没有这些数据，人工修改无法变成可靠监督信号。
        function_name = str(call.get("function") or "")
        parameters, function_fingerprint = helper_signature(self.source, function_name)
        call["parameter_names"] = parameters
        call["function_fingerprint"] = function_fingerprint
        matching_contracts = [
            dict(item) for item in self.helper_contracts
            if str(item.get("function") or "") == function_name
        ]
        if matching_contracts:
            role_bindings = dict(matching_contracts[0].get("roles") or {})
            binding_source = "helper_contract"
        else:
            # 无契约时记录「实际生效」的绑定：别名映射的 roles，或者
            # analyzer 对三参 alloc 的既定缺省（index,size,data 顺位）。
            role_bindings = {}
            binding_source = ""
            mapping = next((
                item for item in self.scenario.helper_mappings
                if str(item.get("alias") or "") == function_name and item.get("roles")
            ), None)
            if mapping:
                slots = normalize_role_slots(mapping.get("roles"))
                role_bindings = {role: position for position, role in enumerate(slots) if role}
                binding_source = "helper_mapping"
            elif function_name:
                parameters = call.get("parameter_names") or []
                arity = len(call.get("args") or [])
                if arity >= 3:
                    role_bindings = {"index": 0, "size": 1, "data": 2}
                    binding_source = "analyzer_alloc_default"
            call["role_binding_source"] = binding_source
        call["current_role_bindings"] = role_bindings
        call["candidate_contracts"] = matching_contracts
        bindings = self.analysis.bindings if self.analysis is not None else []
        current_binding = bindings[step - 1] if 1 <= step <= len(bindings) else None
        previous_binding = bindings[step - 2] if 2 <= step <= len(bindings) else None
        next_binding = bindings[step] if 0 <= step < len(bindings) else None
        call["callsite_fingerprint"] = str(getattr(current_binding, "fingerprint", "") or "")
        call["previous_op"] = (
            {"step": step - 1, "source_call": previous_binding.source_text} if previous_binding else {}
        )
        call["next_op"] = (
            {"step": step + 1, "source_call": next_binding.source_text} if next_binding else {}
        )
        call["neighbouring_operations"] = [
            item for item in (call["previous_op"], call["next_op"]) if item
        ]
        # 识别报告在该调用点的语义评分快照：训练样本要能回答
        # 「系统当时为什么得到 A」。
        report: dict[str, Any] = {}
        if self.analysis is not None:
            report = getattr(self.analysis, "recognition_report", None) or {}
        candidates = [
            item for item in (report.get("candidates") or [])
            if int(item.get("line") or 0) == int(source_line or 0)
        ]
        call["role_candidates_before"] = [
            {"kind": kind, "score": score}
            for kind, score in sorted(
                (candidates[0].get("scores") or {}).items(), key=lambda pair: -pair[1]
            )
        ] if candidates else []
        try:
            call["allocator_profile"] = self.allocator_profile().profile_id
        except Exception:
            call["allocator_profile"] = ""
        return {
            "operation": operation,
            "call": call,
            "source_line": source_line,
            "chunk": chunk,
            "before_value": before_value,
        }

    def _merge_helper_contract(self, contract: Mapping[str, Any]) -> bool:
        """按置信度阶梯合并学到的契约：低置信度永不覆盖高置信度。"""
        function = str(contract.get("function") or "")
        if not function:
            return False
        new_conf = str(contract.get("confidence") or "confirmed").upper()
        new_rank = {"CONFIRMED": CONFIDENCE_ORDER["USER_CONFIRMED"]}.get(new_conf, CONFIDENCE_ORDER["CALIBRATED"])
        for index, existing in enumerate(self.helper_contracts):
            if str(existing.get("function")) != function:
                continue
            old_conf = str(existing.get("confidence") or "unknown").upper()
            old_rank = {"CONFIRMED": CONFIDENCE_ORDER["USER_CONFIRMED"]}.get(old_conf, CONFIDENCE_ORDER["STRUCTURAL"])
            if new_rank < old_rank:
                return False
            self.helper_contracts[index] = dict(contract)
            return True
        self.helper_contracts.append(dict(contract))
        return True

    def correct(
        self,
        step: int,
        patch_payload: Mapping[str, Any],
        context: Mapping[str, Any] | None = None,
        intent: str = "correction",
    ) -> dict[str, Any]:
        """Canvas edit intent split (VNext.3.1B).

        intent = "correction" (默认, 向后兼容): 用户断言「分析错了, 真实状态
        如此」→ 走 USER_CONFIRMED_CORRECTION 管线, 可进入 learning。
        intent = "assumption": 用户只是推演「如果 fd 是 X 会怎样」→ 补丁同样
        应用并重建快照 (用户能看到 what-if), 但标注 MANUAL_ASSUMPTION 且
        **禁止进入 learning** —— 假设不污染真值, 更不能成为训练样本。
        intent = "exp_action": 交由既有 heap_reverse_edit/heap_canonical_python
        的 safe 回写链处理 (此处行为与 correction 相同, 由 JS 侧路由)。
        """
        if intent not in ("correction", "assumption", "exp_action"):
            raise ValueError(f"未知 canvas 编辑意图: {intent!r}")
        if not 0 <= step < len(self.snapshots):
            raise ValueError(f"校正步号越界: {step}（当前共 {len(self.snapshots)} 步）")
        context = dict(context or {})
        context.setdefault("canvas_intent", intent)
        checkpoint = self.snapshots[step]
        upstream = self._correction_upstream(step, patch_payload)
        data_hex = str(patch_payload.get("data_hex") or "")
        value_int = patch_payload.get("value_int")
        data: bytes | None = None
        if data_hex:
            data = bytes.fromhex(data_hex)
        elif value_int is not None:
            length = int(patch_payload.get("length") or 8)
            data = int(value_int).to_bytes(length, "little", signed=False)
        symbolic = str(patch_payload.get("symbolic") or "")
        if data is None and not symbolic:
            raise ValueError("校正需要 data_hex / value_int / symbolic 之一")
        patch = ObservedMemoryPatch(
            str(patch_payload.get("patch_id") or f"user:{uuid.uuid4().hex[:12]}"),
            checkpoint=step,
            address=str(patch_payload.get("address") or ""),
            data=data,
            symbolic=symbolic,
            length=int(patch_payload.get("length") or (len(data) if data else 0)),
            field=str(patch_payload.get("field") or "user_area"),
            object_id=str(patch_payload.get("object_id") or ""),
            decoded_pointer=bool(patch_payload.get("decoded_pointer", False)),
            note=str(patch_payload.get("note") or ""),
            intent=intent,
        )
        memory = PhysicalMemory.from_snapshot(checkpoint.memory, self.variables())
        outcome = CorrectionEngine(self.config()).apply(patch, memory=memory)
        if not outcome.result.accepted:
            issues = [issue.message for issue in outcome.result.issues]
            return {"accepted": False, "status": outcome.result.status.value, "issues": issues}

        fresh = GlibcHeapEngine(self.config(), variables=self.variables())
        effective = fresh.rebuild_current_snapshot(checkpoint, memory.snapshot())
        operations = list(self.scenario.operations)
        suffix = operations[step:]
        resumed = GlibcHeapEngine(
            self.config(), variables=self.variables()
        ).replay_from_snapshot(effective, suffix)
        self.snapshots = [*self.snapshots[:step], *resumed]

        self.corrections.append({
            "patch_id": patch.patch_id,
            "checkpoint": step,
            "address": patch.address,
            "data_hex": data.hex() if data is not None else "",
            "symbolic": symbolic,
            "length": patch.length,
            "field": patch.field,
            "object_id": patch.object_id,
            "decoded_pointer": patch.decoded_pointer,
            "note": patch.note,
            "status": "active",
            "intent": intent,
            "provenance": ("USER_CONFIRMED_CORRECTION"
                           if intent != "assumption" else "MANUAL_ASSUMPTION"),
        })

        # -- Correction Intent Resolver（向上追踪 → 意图分类 → 学习） ----
        after_value = ""
        for item in effective.chunks.values():
            if patch.object_id and item.physical_id == patch.object_id:
                for field in item.fields:
                    if str(field.address) == patch.address:
                        after_value = field.value
                        break
                break
        chunk = upstream.get("chunk")
        operation = upstream.get("operation")
        call = upstream.get("call") or {}
        resolved = resolve_correction_intent(
            step=step,
            operation=operation,
            call=call,
            source_line=int(upstream.get("source_line") or 0),
            source_source=self.source,
            chunk=chunk,
            field_name=patch.field,
            before_value=str(upstream.get("before_value") or ""),
            after_value=after_value,
            patch_value_int=value_int if isinstance(value_int, int) else None,
            variables=self.variables(),
            helper_body=helper_def_text(self.source, str(call.get("function") or "")),
            intent_hint=str(context.get("intent_hint") or ""),
        )
        episode = resolved.pop("episode")
        episode.address = patch.address
        # Correction context v2/v3 落盘：episode 本身要携带调用点形态与
        # 角色 before/after —— 训练样本必须能自答「系统为什么得到 A、
        # 用户为什么改成 B、改完是否更自洽」。
        episode.parameter_names = [str(item) for item in (call.get("parameter_names") or [])]
        episode.argument_expressions = [str(item) for item in (call.get("args") or [])]
        episode.function_fingerprint = str(call.get("function_fingerprint") or "")
        episode.callsite_fingerprint = str(call.get("callsite_fingerprint") or "")
        episode.role_candidates_before = [
            dict(item) for item in (call.get("role_candidates_before") or [])
        ]
        episode.role_binding_before = dict(call.get("current_role_bindings") or {})
        episode.role_binding_after = dict(episode.role_binding_before)
        episode.previous_op = dict(call.get("previous_op") or {})
        episode.next_op = dict(call.get("next_op") or {})
        episode.target_fingerprint = hashlib.sha1(
            f"{patch.object_id}|{patch.address}|{patch.field}".encode("utf-8")
        ).hexdigest()[:16]
        episode.allocator_profile = str(call.get("allocator_profile") or "")
        parsed_patch_address = self._parse_addr(patch.address)
        episode.changed_physical_range = [parsed_patch_address] if parsed_patch_address is not None else []
        episode.changed_typed_fields = [patch.field]
        episode.note = patch.note
        if intent == "assumption":
            # MANUAL_ASSUMPTION: 补丁已生效 (用户看到推演结果), 但此编辑是
            # 「利用世界线假设」而非真值断言 —— 禁止进入 learning/训练样本。
            assumption_id = f"asm-{uuid.uuid4().hex[:12]}"
            parent_snapshot_id = f"step-{step}"
            episode.note = f"[MANUAL_ASSUMPTION] {episode.note}"
            episode_dict = episode.to_dict()
            episode_dict.update({
                "provenance": "MANUAL_ASSUMPTION",
                "trainable": False,
                "assumption_id": assumption_id,
                "parent_snapshot_id": parent_snapshot_id,
                "branch_kind": "MANUAL_ASSUMPTION",
            })
            self.assumptions.append({
                "assumption_id": assumption_id,
                "parent_snapshot_id": parent_snapshot_id,
                "patch_id": patch.patch_id,
                "address": patch.address,
                "trainable": False,
            })
            self.episodes.append(episode_dict)
            learning = {
                **resolved,
                "episode": episode_dict,
                "reanalyzed": False,
                "skipped_reason": "MANUAL_ASSUMPTION: canvas 草稿推演不进入学习管线",
            }
            return {
                "accepted": True,
                "status": outcome.result.status.value,
                "issues": [],
                "patch_id": patch.patch_id,
                "corrections": self.corrections,
                "learned_rules": self.learned_rules,
                "helper_contracts": self.helper_contracts,
                "structural_edits": self.structural_edits,
                "learning": learning,
                "intent": intent,
            }
        self.episodes.append(episode.to_dict())

        learning: dict[str, Any] = {
            **resolved,
            "episode": episode.to_dict(),
            "reanalyzed": False,
        }
        proposals = infer_rules_from_correction(context, patch_payload, True)
        self.learned_rules, added = merge_learned_rules(self.learned_rules, proposals)

        response: dict[str, Any] = {
            "accepted": True,
            "status": outcome.result.status.value,
            "issues": [],
            "patch_id": patch.patch_id,
            "corrections": self.corrections,
            "learned_rules": self.learned_rules,
            "helper_contracts": self.helper_contracts,
            "structural_edits": self.structural_edits,
            "learning": learning,
        }

        if resolved["intent"] == "semantic_contract" and resolved.get("helper_contract"):
            # ① 语义识别纠错：学 HelperContract（USER_CONFIRMED），整题重分析。
            #    旧的观测补丁是误识别的症状 —— 换了契约后一并作废，诚实提示。
            merged = self._merge_helper_contract(resolved["helper_contract"])
            if merged:
                self.corrections = []
                episode.role_binding_after = dict(
                    (resolved["helper_contract"] or {}).get("roles") or {}
                )
                response["learning"]["episode"] = episode.to_dict()
                response["corrections"] = self.corrections
                state = self.load(source=self.source)
                response.update({
                    "steps": state["steps"],
                    "step_offset": 0,
                    "operations": state["operations"],
                    "canonical_ops": state["canonical_ops"],
                    "helper_contracts": self.helper_contracts,
                    "reanalyzed": True,
                })
                learning["reanalyzed"] = True
                learning["learned"] = {
                    "kind": "helper_contract",
                    "function": resolved.get("helper"),
                    "roles": (resolved.get("helper_contract") or {}).get("roles"),
                    "confidence": "USER_CONFIRMED",
                    "effect": "本题所有该 helper 调用已按新契约重新识别并回放",
                }
            else:
                learning["learned"] = {
                    "kind": "none",
                    "effect": "已有更高置信度契约，本次未覆盖（USER_CONFIRMED > CALIBRATED > STRUCTURAL > ALIAS > UNKNOWN）",
                }
        elif resolved["intent"] == "derivation_rule" and resolved.get("learned_rule"):
            # ③ 推导规则纠错：LearnedRule 进场景规则，分析后应用（显式 offset 优先）。
            rule = resolved["learned_rule"]
            self.learned_rules = [item for item in self.learned_rules if item.get("rule_id") != rule.get("rule_id")]
            self.learned_rules.append(rule)
            state = self.load(source=self.source)
            response.update({
                "steps": state["steps"],
                "step_offset": 0,
                "operations": state["operations"],
                "canonical_ops": state["canonical_ops"],
                "reanalyzed": True,
            })
            learning["reanalyzed"] = True
            learning["learned"] = {
                "kind": "learned_rule",
                "target": rule.get("target"),
                "expression": rule.get("expression"),
                "evidence": rule.get("evidence"),
                "confidence": "USER_CONFIRMED",
                "effect": "本题该 helper 的后续识别自动引用该规则（显式 offset 仍然优先）",
            }
        else:
            # ② 物理状态纠错：PhysicalMemory 写入 + 后缀重放已完成（不碰契约）。
            learning["learned"] = {
                "kind": "observed_state",
                "checkpoint": step,
                "confidence": "USER_OBSERVED",
                "effect": "影响本题该 checkpoint 之后的全部状态；未修改识别契约",
            }
        response["steps"] = response.get("steps") or [
            serialize_snapshot(snapshot) for snapshot in self.snapshots[step:]
        ]
        response["step_offset"] = response.get("step_offset", step)
        response["learned_rules_added"] = added
        response["episodes"] = self.episodes
        # Atomic commit: the canvas must never splice a suffix into a stale
        # package.  Ship the complete state so the renderer replaces the whole
        # snapshot family (steps + operations + heapState) in one commit.
        response["heap_state"] = self.state()
        return response

    def undo_correction(self) -> dict[str, Any]:
        if not self.corrections:
            return {"ok": False, "message": "没有可撤销的画布校正"}
        last = self.corrections.pop()
        self.learned_rules = [
            rule for rule in self.learned_rules
            if rule.get("rule_id") not in {last.get("patch_id")}
        ]
        return self.replay_correction_state()

    def replay_correction_state(self) -> dict[str, Any]:
        """Replay from scratch re-applying persisted corrections in order."""
        self.replay()
        for correction in list(self.corrections):
            self._reapply_correction(correction)
        return self.state()

    def _reapply_correction(self, correction: Mapping[str, Any]) -> bool:
        """按当前 profile 重放一条历史观测补丁；不再成立时返回 False。"""
        step = int(correction.get("checkpoint") or 0)
        if not 0 <= step < len(self.snapshots):
            return False
        checkpoint = self.snapshots[step]
        memory = PhysicalMemory.from_snapshot(checkpoint.memory, self.variables())
        data_hex = str(correction.get("data_hex") or "")
        patch = ObservedMemoryPatch(
            str(correction.get("patch_id") or f"scene:{uuid.uuid4().hex[:8]}"),
            checkpoint=step,
            address=str(correction.get("address") or ""),
            data=bytes.fromhex(data_hex) if data_hex else None,
            symbolic=str(correction.get("symbolic") or ""),
            length=int(correction.get("length") or 0),
            field=str(correction.get("field") or "user_area"),
            object_id=str(correction.get("object_id") or ""),
            decoded_pointer=bool(correction.get("decoded_pointer", False)),
        )
        outcome = CorrectionEngine(self.config()).apply(patch, memory=memory)
        if not outcome.result.accepted:
            return False
        fresh = GlibcHeapEngine(self.config(), variables=self.variables())
        effective = fresh.rebuild_current_snapshot(checkpoint, memory.snapshot())
        operations = list(self.scenario.operations)
        resumed = GlibcHeapEngine(
            self.config(), variables=self.variables()
        ).replay_from_snapshot(effective, operations[step:])
        self.snapshots = [*self.snapshots[:step], *resumed]
        return True

    # -- explicit teaching ---------------------------------------------
    def learn(
        self,
        matcher_function: str,
        semantic: str,
        *,
        roles: list[str] | None = None,
        reason: str = "",
    ) -> dict[str, Any]:
        if semantic not in {"alloc", "free", "edit", "show", "copy"}:
            raise ValueError(f"未知语义: {semantic}")
        proposal = {
            "rule_id": f"rule-{uuid.uuid4().hex[:8]}",
            "family": "semantic",
            "enabled": True,
            "scope": "scene",
            "evidence_count": 1,
            "requires_confirmation": False,
            "reason": reason or f"用户指认：{matcher_function} 的语义是 {semantic}",
            "matcher": {"function": matcher_function},
            "output": {"semantic": semantic, "roles": roles or []},
        }
        self.learned_rules, added = merge_learned_rules(self.learned_rules, [proposal])
        if self.source:
            self.load(source=self.source)
        else:
            self.replay()
        return {
            "learned_rules": self.learned_rules,
            "learned_rules_added": added,
            **self.state(),
        }

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> dict[str, Any]:
        for rule in self.learned_rules:
            if rule.get("rule_id") == rule_id:
                rule["enabled"] = bool(enabled)
        if self.source:
            self.load(source=self.source)
        return self.state()

    # -------------------------------------------------------------------
    # Case Export / Agent Review / Recognition labeling（训练数据层）
    #
    # heap_save 是用户恢复场景用的；训练样本走这里。三层职责分离：
    #   generated  build_case_export（当前系统输出，固定 schema）
    #   review     外部 Agent 判断（独立标签层，绝不直接覆盖 Snapshot）
    #   accepted   apply_review 通过 Replay Validator + hard invariants
    #              + evidence gate 后的人工/验证真值

    def export_case(
        self,
        *,
        target: Mapping[str, Any] | None = None,
        challenge_family: str = "",
        include_snapshots: bool = True,
    ) -> dict[str, Any]:
        return build_case_export(
            self,
            target=target,
            challenge_family=challenge_family,
            include_snapshots=include_snapshots,
        )

    def validate_exported_case(self, case: Mapping[str, Any]) -> dict[str, Any]:
        issues = validate_case(case)
        return {"valid": not issues, "issues": issues}

    def import_review(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """导入外部 Agent 审查：只进 review 标签层，快照一字不动。"""
        item = normalize_review(payload)
        if not item["issue_type"]:
            raise ValueError("review 缺少 issue_type")
        self.reviews = [r for r in self.reviews if r.get("review_id") != item["review_id"]]
        self.reviews.append(item)
        return {"ok": True, "review": item, "reviews": self.reviews}

    def apply_review(self, review_id: str, human_confirmed: bool = False) -> dict[str, Any]:
        """Replay Validator：proposal → 干跑重放 → hard invariants → 裁决。

        验证的是「提议本身」是否让整题更自洽，**不修改**当前 snapshots：
        干跑在临时 learned_rules/contracts 上进行，通过也只是把该 review
        的 verdict 推进到 accepted/rejected。缺少 evidence（runtime /
        known-solution 证据由外部提供）时最多到 validated；``human_confirmed``
        是人工确认对证据门的补足 —— 只有 proposer 证据或人工确认之一成立，
        才允许进入 accepted（训练真值层）。
        """
        item = next((r for r in self.reviews if r.get("review_id") == str(review_id)), None)
        if item is None:
            raise ValueError(f"未知 review_id: {review_id}")
        if item.get("verdict") in {"accepted", "retired"}:
            return {"ok": True, "review": item, "reviews": self.reviews}

        validation = self._validate_review_proposal(item)
        if validation["issues"]:
            item["verdict"] = "rejected"
        elif not item.get("evidence") and not human_confirmed:
            item["verdict"] = "validated"
            validation["note"] = (
                "重放与不变量全部通过，但缺少 runtime/known-solution 证据；"
                "补证据或人工确认后才进入 accepted（训练真值层）。"
            )
        else:
            item["verdict"] = "accepted"
            if human_confirmed and not item.get("evidence"):
                validation["note"] = "证据门由人工确认补足（accepted）。"
        item["validation"] = validation
        item["validated_profile"] = self.allocator_profile().profile_id
        return {"ok": True, "review": item, "reviews": self.reviews}

    def _validate_review_proposal(self, item: Mapping[str, Any]) -> dict[str, Any]:
        """对提议做干跑验证：换上提议后的规则/契约重新识别 + 重放。

        hard invariants（任一失败即拒绝）：
          ① 静态 gate —— review 引用的行/调用在当前 case 里真实存在；
          ② 分析有效（analysis.valid）；
          ③ allocator abort 不回退 —— 干跑不允许在原本干净的步骤上
             新增 abort（提议让整题更自洽，而不是更崩）；
          ④ 已识别调用不回退 —— 之前 recognized 的调用点不允许变少；
          ⑤ 目标命中 —— semantic/role 类提议必须让 target 行真的被
             绑定到提议的语义上。
        """
        issues: list[str] = []
        source = self.source
        if not source:
            return {"accepted": False, "issues": ["当前会话没有 EXP 源码，无法做重放验证"]}
        case = self.export_case(include_snapshots=False)
        issues.extend(validate_review_against_case(item, case))

        proposed = dict(item.get("proposed") or {})
        function = str((item.get("target") or {}).get("function")
                       or proposed.get("function") or "").strip()
        semantic = str(proposed.get("semantic") or "").strip().lower()
        roles = normalize_role_slots(proposed.get("roles"))
        dry_rules = list(self.learned_rules)
        dry_contracts = list(self.helper_contracts)
        if item.get("issue_type") == "miscalled_candidate" or semantic == "ignore":
            dry_rules = [*dry_rules, {
                "rule_id": f"review-ignore-{function or 'x'}",
                "family": "recognition_ignore",
                "enabled": True,
                "scope": "scene",
                "matcher": {"function": function},
            }]
        elif semantic:
            dry_rules = [*dry_rules, {
                "rule_id": f"review-{function or 'x'}",
                "family": "semantic",
                "enabled": True,
                "scope": "scene",
                "matcher": {"function": function},
                "output": {"semantic": semantic, "roles": roles},
            }]
        elif roles:
            dry_contracts = [*dry_contracts, {
                "function": function,
                "operation": str((item.get("before") or {}).get("semantic") or ""),
                "roles": proposed.get("role_bindings") or {},
                "confidence": "PROPOSED_REVIEW",
            }]
        else:
            issues.append("proposed 里既没有 semantic/roles，也不是 miscalled_candidate，无内容可验证")

        aborted_before = sum(1 for snapshot in self.snapshots if snapshot.aborted)
        recognized_before = {
            entry.get("line")
            for entry in ((self.analysis.recognition_report if self.analysis else {}) or {}).get("candidates", [])
            if entry.get("verdict") == "recognized"
        } if self.analysis is not None else set()

        recognized_after: set[Any] = set()
        target_hit = False
        target_line = int((item.get("target") or {}).get("source_line") or 0)
        if not issues:
            try:
                result = analyze_heap_source(
                    source,
                    api_profile=self.scenario.api_profile,
                    variables=self.variables(),
                    branch_choices=self.scenario.branch_choices,
                    overrides=self.scenario.timeline_overrides,
                    learned_rules=dry_rules,
                    helper_contracts=[HelperContract.from_dict(dict(c)) for c in dry_contracts],
                )
                engine = GlibcHeapEngine(self.config(), variables=self.variables())
                snapshots = engine.replay(result.operations)
            except Exception as error:
                return {"accepted": False, "issues": [f"干跑重放失败: {type(error).__name__}: {error}"]}
            if not result.valid:
                issues.append("干跑分析无效（analysis.valid=False）")
            aborted_after = sum(1 for snapshot in snapshots if snapshot.aborted)
            if aborted_after > aborted_before:
                issues.append(
                    f"hard invariant 违背：干跑新增 allocator abort（{aborted_before} → {aborted_after}）"
                )
            report = result.recognition_report or {}
            by_line: dict[int, dict[str, Any]] = {}
            for entry in report.get("candidates") or []:
                by_line[int(entry.get("line") or 0)] = entry
            recognized_after = {
                entry.get("line") for entry in report.get("candidates") or []
                if entry.get("verdict") == "recognized"
            }
            lost = recognized_before - recognized_after
            if lost:
                issues.append(f"hard invariant 违背：已识别调用回退（行 {sorted(lost)[:5]} 不再 recognized）")
            if semantic and target_line:
                entry = by_line.get(target_line)
                target_hit = bool(entry) and entry.get("verdict") == "recognized" and entry.get("kind") == semantic
                if not target_hit:
                    issues.append(
                        f"目标未命中：行 {target_line} 干跑后没有绑定到提议的 {semantic}"
                    )
        return {
            "accepted": not issues,
            "issues": issues,
            "recognized_before": len(recognized_before),
            "recognized_after": len(recognized_after),
            "target_hit": target_hit,
        }

    def label_recognition(
        self,
        line: int,
        function: str,
        semantic: str,
        roles: Any = None,
        source_text: str = "",
    ) -> dict[str, Any]:
        """用户对 ambiguous/unknown 候选的一等标注（≠ 画布校正）。

        semantic ∈ alloc/free/edit/show/copy → 安装 mapping 式语义规则；
        semantic = ignore → 安装 recognition_ignore 规则（识别器永远不再
        猜这个函数）。before/after 裁决随 RecognitionCorrection 一起落盘
        —— 这是最值钱的静态识别训练数据。
        """
        semantic = str(semantic or "").strip().lower()
        allowed = {"alloc", "free", "edit", "show", "copy", "ignore"}
        if semantic not in allowed:
            raise ValueError(f"标注语义必须是 {'/'.join(sorted(allowed))}，收到: {semantic}")
        function = str(function or "").strip()
        if not function:
            raise ValueError("标注缺少函数名")
        if not re.match(r"^[A-Za-z_]\w*$", function):
            raise ValueError(f"函数名不是合法标识符: {function}")
        line = int(line or 0)
        # 位置敏感归一：{"arg0": null, "arg1": "size"} → [None, "size"]。
        # arg0 未知必须以 None 占位上送/落盘，绝不能压缩对齐。
        role_slots = normalize_role_slots(roles)

        before_entry: dict[str, Any] = {}
        if self.analysis is not None:
            for entry in (self.analysis.recognition_report or {}).get("candidates") or []:
                if int(entry.get("line") or 0) == line:
                    before_entry = {
                        "verdict": entry.get("verdict"),
                        "kind": entry.get("kind"),
                        "scores": entry.get("scores") or {},
                        "reason": entry.get("reason"),
                    }
                    break

        if semantic == "ignore":
            rule = {
                "rule_id": f"ignore-{function}",
                "family": "recognition_ignore",
                "enabled": True,
                "scope": "scene",
                "reason": f"用户标注：{function} 不是堆操作（行 {line}）",
                "matcher": {"function": function},
            }
            self.learned_rules = [r for r in self.learned_rules if r.get("rule_id") != rule["rule_id"]]
            self.learned_rules.append(rule)
        else:
            # 直接写 mapping 条目（roles 保位存储），不走 set_helper_mapping
            # 的逗号字符串往返 —— 那会把 None 槽位压没。
            self.scenario.helper_mappings = [
                item for item in self.scenario.helper_mappings
                if str(item.get("alias")) != function
            ]
            entry: dict[str, Any] = {"alias": function, "target": semantic}
            if role_slots:
                entry["roles"] = role_slots
            self.scenario.helper_mappings.append(entry)

        state = self.load(source=self.source) if self.source else self.replay()
        after_entry: dict[str, Any] = {}
        report = (self.analysis.recognition_report if self.analysis is not None else {}) or {}
        for entry in report.get("candidates") or []:
            if int(entry.get("line") or 0) == line:
                after_entry = {
                    "verdict": entry.get("verdict"),
                    "kind": entry.get("kind"),
                    "reason": entry.get("reason"),
                }
                break
        correction = {
            "recognition_id": f"rc-{uuid.uuid4().hex[:10]}",
            "source_line": line,
            "function": function,
            "source_text": str(source_text or ""),
            "semantic": semantic,
            # 位置保留的角色绑定：{"arg0": null, "arg1": "size", ...}
            "roles": {f"arg{index}": role for index, role in enumerate(role_slots)},
            "before": before_entry,
            "after": after_entry,
            "allocator_profile": self.allocator_profile().profile_id,
            "recognizer_revision": report.get("recognizer_revision") or "",
            "source": "user_label",
        }
        self.recognition_corrections.append(correction)
        state["recognition_correction"] = correction
        return state

    # -- persistence ----------------------------------------------------
    def to_payload(self) -> dict[str, Any]:
        return {
            "schema": "pwncraft-heap-scenario",
            "scenario": self.scenario.to_dict(),
            "source": self.source,
            "learned_rules": self.learned_rules,
            "corrections": self.corrections,
            "episodes": self.episodes,
            "helper_contracts": self.helper_contracts,
            "reviews": self.reviews,
            "recognition_corrections": self.recognition_corrections,
        }

    def load_payload(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        self.scenario = HeapScenario.from_dict(dict(payload.get("scenario") or {}))
        self.source = str(payload.get("source") or "")
        self.learned_rules = [dict(item) for item in list(payload.get("learned_rules") or []) if isinstance(item, dict)]
        self.corrections = [dict(item) for item in list(payload.get("corrections") or []) if isinstance(item, dict)]
        self.episodes = [
            CorrectionEpisode.from_dict(item).to_dict()
            for item in list(payload.get("episodes") or []) if isinstance(item, dict)
        ]
        self.helper_contracts = [
            dict(item) for item in list(payload.get("helper_contracts") or []) if isinstance(item, dict)
        ]
        self.reviews = [
            normalize_review(dict(item)) for item in list(payload.get("reviews") or []) if isinstance(item, dict)
        ]
        self.recognition_corrections = [
            dict(item) for item in list(payload.get("recognition_corrections") or []) if isinstance(item, dict)
        ]
        self.structural_edits = [
            dict(item) for item in list(payload.get("structural_edits") or []) if isinstance(item, dict)
        ]
        state = self.load(source=self.source) if self.source else self.replay()
        for correction in list(self.corrections):
            self._reapply_correction(correction)
        return self.state()
