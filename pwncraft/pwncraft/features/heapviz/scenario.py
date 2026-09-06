from __future__ import annotations

from dataclasses import dataclass, field

from pwncraft.features.heapviz.analyzer import TimelineOverride
from pwncraft.features.heapviz.allocators.profiles import resolve_allocator_profile
from pwncraft.features.heapviz.models import AllocatorConfig, HeapApiProfile
from pwncraft.features.heapviz.operations import HeapOperation
from pwncraft.features.heapviz.semantics import ChallengeBehaviorProfile


@dataclass
class HeapScenario:
    schema_version: int = 5
    name: str = "未命名堆场景"
    allocator: AllocatorConfig = field(default_factory=AllocatorConfig)
    api_profile: HeapApiProfile = field(default_factory=HeapApiProfile)
    behavior_profile: ChallengeBehaviorProfile = field(default_factory=ChallengeBehaviorProfile)
    operations: list[HeapOperation] = field(default_factory=list)
    variables: dict[str, str] = field(default_factory=dict)
    assumptions: list[str] = field(default_factory=list)
    timeline_overrides: list[TimelineOverride] = field(default_factory=list)
    branch_choices: dict[str, str] = field(default_factory=dict)
    helper_mappings: list[dict[str, str]] = field(default_factory=list)
    helper_contracts: list[dict[str, object]] = field(default_factory=list)
    corrections: list[dict[str, object]] = field(default_factory=list)
    ai_review_ids: list[str] = field(default_factory=list)
    ai_instruction: str = ""
    disabled_global_rule_ids: list[str] = field(default_factory=list)
    ai_scene_rules: list[dict[str, object]] = field(default_factory=list)
    ai_memory_annotations: list[dict[str, object]] = field(default_factory=list)
    canvas_layout: dict[str, object] = field(default_factory=dict)
    validation_preferences: dict[str, object] = field(default_factory=dict)
    log_preferences: dict[str, object] = field(default_factory=dict)
    active_snapshot_origin: str = "STATIC"
    pinned_show: dict[str, object] = field(default_factory=dict)
    iofile_typed_views: list[dict[str, object]] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            # allocator 序列化交给 profile 注册表：profile_id / 请求与生效
            # 双版本 / 只读机制表。机制位是后端表的输出，前端只许读。
            "allocator": resolve_allocator_profile({
                "arch": self.allocator.arch,
                "version": f"{self.allocator.version[0]}.{self.allocator.version[1]}",
                "requested_version": self.allocator.requested_version,
                "profile_id": self.allocator.profile_id,
                "heap_base": self.allocator.heap_base,
                "simulation_mode": self.allocator.simulation_mode,
            }).to_wire_dict(),
            "api_profile": {
                "alloc_function": self.api_profile.alloc_function,
                "free_function": self.api_profile.free_function,
                "edit_function": self.api_profile.edit_function,
                "show_function": self.api_profile.show_function,
                "copy_function": self.api_profile.copy_function,
                "alloc_template": self.api_profile.alloc_template,
                "free_template": self.api_profile.free_template,
                "edit_template": self.api_profile.edit_template,
                "show_template": self.api_profile.show_template,
                "copy_template": self.api_profile.copy_template,
                "definitions": self.api_profile.definitions,
            },
            "behavior_profile": self.behavior_profile.to_dict(),
            "operations": [operation.to_dict() for operation in self.operations],
            "variables": dict(self.variables),
            "assumptions": list(self.assumptions),
            "timeline_overrides": [item.to_dict() for item in self.timeline_overrides],
            "branch_choices": dict(self.branch_choices),
            "helper_mappings": [dict(item) for item in self.helper_mappings],
            "helper_contracts": [dict(item) for item in self.helper_contracts],
            "corrections": [dict(item) for item in self.corrections],
            "ai_review_ids": list(self.ai_review_ids),
            "ai_instruction": self.ai_instruction,
            "disabled_global_rule_ids": list(self.disabled_global_rule_ids),
            "ai_scene_rules": [dict(item) for item in self.ai_scene_rules],
            "ai_memory_annotations": [dict(item) for item in self.ai_memory_annotations],
            "canvas_layout": dict(self.canvas_layout),
            "validation_preferences": dict(self.validation_preferences),
            "log_preferences": dict(self.log_preferences),
            "active_snapshot_origin": self.active_snapshot_origin,
            "pinned_show": dict(self.pinned_show),
            "iofile_typed_views": [dict(item) for item in self.iofile_typed_views],
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "HeapScenario":
        allocator_raw = dict(payload.get("allocator") or {})
        # 机制布尔（safe_linking / tcache_* / 检查规则…）一律不信任：
        # 它们从版本 + 架构经 profile 注册表重建。载荷里的同名键只被
        # 忽略 —— 这是消灭「前端 safe_linking 双重真值」的地方。
        allocator = resolve_allocator_profile(allocator_raw).to_config()
        api_raw = dict(payload.get("api_profile") or {})
        api = HeapApiProfile(
            alloc_function=str(api_raw.get("alloc_function") or "add"),
            free_function=str(api_raw.get("free_function") or "delete"),
            edit_function=str(api_raw.get("edit_function") or "edit"),
            show_function=str(api_raw.get("show_function") or "show"),
            copy_function=str(api_raw.get("copy_function") or "copy_chunk"),
            alloc_template=str(api_raw.get("alloc_template") or "{func}({size}, {data})"),
            free_template=str(api_raw.get("free_template") or "{func}({index})"),
            edit_template=str(api_raw.get("edit_template") or "{func}({index}, {data})"),
            show_template=str(api_raw.get("show_template") or "{func}({index})"),
            copy_template=str(api_raw.get("copy_template") or "{func}({src}, {dst}, {length})"),
            definitions=str(api_raw.get("definitions") or ""),
        )
        behavior_profile = ChallengeBehaviorProfile.from_dict(
            dict(payload.get("behavior_profile") or {})
        )
        operations = [
            HeapOperation.from_dict(dict(item))
            for item in list(payload.get("operations") or [])
        ]
        return cls(
            schema_version=int(payload.get("schema_version") or 1),
            name=str(payload.get("name") or "未命名堆场景"),
            allocator=allocator,
            api_profile=api,
            behavior_profile=behavior_profile,
            operations=operations,
            variables={str(k): str(v) for k, v in dict(payload.get("variables") or {}).items()},
            assumptions=[str(item) for item in list(payload.get("assumptions") or [])],
            timeline_overrides=[
                TimelineOverride.from_dict(dict(item))
                for item in list(payload.get("timeline_overrides") or [])
                if isinstance(item, dict)
            ],
            branch_choices={str(k): str(v) for k, v in dict(payload.get("branch_choices") or {}).items()},
            helper_mappings=[
                {str(k): str(v) for k, v in dict(item).items()}
                for item in list(payload.get("helper_mappings") or [])
                if isinstance(item, dict)
            ],
            helper_contracts=[
                dict(item) for item in list(payload.get("helper_contracts") or []) if isinstance(item, dict)
            ],
            corrections=[dict(item) for item in list(payload.get("corrections") or []) if isinstance(item, dict)],
            ai_review_ids=[str(item) for item in list(payload.get("ai_review_ids") or [])],
            ai_instruction=str(payload.get("ai_instruction") or ""),
            disabled_global_rule_ids=[str(item) for item in list(payload.get("disabled_global_rule_ids") or [])],
            ai_scene_rules=[dict(item) for item in list(payload.get("ai_scene_rules") or []) if isinstance(item, dict)],
            ai_memory_annotations=[dict(item) for item in list(payload.get("ai_memory_annotations") or []) if isinstance(item, dict)],
            canvas_layout=dict(payload.get("canvas_layout") or {}),
            validation_preferences=dict(payload.get("validation_preferences") or {}),
            log_preferences=dict(payload.get("log_preferences") or {}),
            active_snapshot_origin=str(payload.get("active_snapshot_origin") or "STATIC"),
            pinned_show=dict(payload.get("pinned_show") or {}),
            iofile_typed_views=[
                dict(item) for item in list(payload.get("iofile_typed_views") or []) if isinstance(item, dict)
            ],
        )
