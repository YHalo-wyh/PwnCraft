from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable


class ActionType(str, Enum):
    QUERY = "QUERY"
    DERIVE = "DERIVE"
    BUILD = "BUILD"
    VERIFY = "VERIFY"
    RUNTIME = "RUNTIME"


@dataclass(frozen=True)
class ToolAction:
    id: str
    title: str
    action_type: ActionType
    allowed_actions: frozenset[str] = field(default_factory=frozenset)
    category: str = ""
    description_zh: str = ""
    parameters: tuple[dict[str, object], ...] = ()
    examples: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not str(self.id).strip():
            raise ValueError("工具 Action 必须有 id")
        if not isinstance(self.action_type, ActionType):
            try:
                object.__setattr__(self, "action_type", ActionType(str(self.action_type).strip().upper()))
            except ValueError as exc:
                raise ValueError(f"未知 Action 类型: {self.action_type}") from exc
        normalized = frozenset(str(item).strip().casefold() for item in self.allowed_actions if str(item).strip())
        object.__setattr__(self, "allowed_actions", normalized)

    def allows(self, action: str) -> bool:
        return str(action).strip().casefold() in self.allowed_actions

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "title": self.title,
            "action_type": self.action_type.value,
            "allowed_actions": sorted(self.allowed_actions),
            "category": self.category,
            "description_zh": self.description_zh,
            "parameters": [dict(item) for item in self.parameters],
            "examples": list(self.examples),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "ToolAction":
        raw_type = str(payload.get("action_type", ActionType.QUERY.value)).strip().upper()
        return cls(
            id=str(payload.get("id", "")),
            title=str(payload.get("title", "")),
            action_type=ActionType(raw_type),
            allowed_actions=frozenset(str(item) for item in payload.get("allowed_actions", ())),
            category=str(payload.get("category", "")),
            description_zh=str(payload.get("description_zh", "")),
            parameters=tuple(dict(item) for item in payload.get("parameters", ()) if isinstance(item, dict)),
            examples=tuple(str(item) for item in payload.get("examples", ())),
        )


class ToolActionRegistry:
    """Central action registry; QUERY actions cannot mutate EXP."""

    def __init__(self, actions: Iterable[ToolAction] = ()):
        self._actions: dict[str, ToolAction] = {}
        for action in actions:
            self.register(action)

    def register(self, action: ToolAction) -> ToolAction:
        key = str(action.id).strip()
        if not key:
            raise ValueError("工具 Action 必须有 id")
        if key in self._actions:
            raise ValueError(f"重复的工具 Action: {key}")
        forbidden = {"insert_to_exp", "auto_generate_exploit"}
        if action.action_type is ActionType.QUERY and forbidden.intersection(action.allowed_actions):
            raise ValueError("QUERY 工具不能插入 EXP 或自动生成利用")
        self._actions[key] = action
        return action

    def get(self, action_id: str) -> ToolAction:
        key = str(action_id).strip()
        try:
            return self._actions[key]
        except KeyError as exc:
            raise KeyError(f"未知工具 Action: {action_id}") from exc

    def find(self, query: str = "") -> tuple[ToolAction, ...]:
        needle = str(query).strip().casefold()
        values = tuple(self._actions.values())
        if not needle:
            return values
        return tuple(item for item in values if needle in " ".join((item.id, item.title, item.category, item.description_zh)).casefold())

    def can(self, action_id: str, operation: str) -> bool:
        return self.get(action_id).allows(operation)

    def values(self) -> tuple[ToolAction, ...]:
        return tuple(self._actions.values())

    def to_dict(self) -> list[dict[str, object]]:
        return [item.to_dict() for item in self._actions.values()]


def default_tool_actions() -> ToolActionRegistry:
    return ToolActionRegistry(
        (
            ToolAction("ropgadget.search", "搜索 Gadget", ActionType.QUERY, frozenset({"run", "copy_command", "copy_value", "pin_result", "open_debugger"}), "ROP", "查询真实二进制中的 Gadget，不构造利用链。"),
            ToolAction("elf.inspect", "检查 ELF", ActionType.QUERY, frozenset({"run", "copy_value", "save_to_workspace"}), "ELF", "读取 ELF、符号和保护属性。"),
            ToolAction("safe-linking.calculate", "计算 Safe-Linking", ActionType.DERIVE, frozenset({"calculate", "save_variable", "copy_expression"}), "Heap", "按真实字段地址计算编码或解码。"),
            ToolAction("rop.build", "构造 ROP Chain", ActionType.BUILD, frozenset({"preview", "validate", "save_stage", "generate_pwntools", "insert_to_exp"}), "ROP", "构造并验证 ROP 链。"),
            ToolAction("srop.build", "构造 SROP", ActionType.BUILD, frozenset({"preview", "validate", "save_stage", "generate_pwntools", "insert_to_exp"}), "ROP", "构造 SigreturnFrame 计划；帧布局由 pwntools 提供。"),
            ToolAction("rop.verify", "验证 ROP 对齐", ActionType.VERIFY, frozenset({"verify", "show_error", "jump_to_problem"}), "ROP", "检查 ABI 栈对齐和寄存器约束。"),
            ToolAction("gdb.runtime", "读取调试器状态", ActionType.RUNTIME, frozenset({"break", "step", "continue", "read_memory", "read_register"}), "调试", "读取 GDB 已确认的运行时事实。"),
        )
    )
