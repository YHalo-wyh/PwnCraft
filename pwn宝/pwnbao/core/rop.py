from __future__ import annotations

from dataclasses import dataclass, field

from .gadgets import Gadget


@dataclass(frozen=True)
class ROPEntry:
    offset: int
    value: int | str
    kind: str = "value"
    gadget: Gadget | None = None

    def to_dict(self) -> dict[str, object]:
        return {"offset": self.offset, "value": self.value, "kind": self.kind, "gadget": self.gadget.to_dict() if self.gadget else None}


@dataclass
class RegisterState:
    values: dict[str, int | str | None] = field(default_factory=dict)

    def set(self, register: str, value: int | str | None) -> None:
        self.values[str(register).lower()] = value

    def get(self, register: str) -> int | str | None:
        return self.values.get(str(register).lower())

    def to_dict(self) -> dict[str, object]:
        return dict(self.values)


@dataclass
class StackState:
    """Word-addressed stack view shared by ROP builders and Stack Canvas."""

    rsp: int = 0
    words: dict[int, int | str | None] = field(default_factory=dict)

    def push(self, value: int | str | None, *, word_size: int = 8) -> int:
        address = self.rsp
        self.words[address] = value
        self.rsp += int(word_size)
        return address

    def read(self, address: int) -> int | str | None:
        return self.words.get(int(address))

    def to_dict(self) -> dict[str, object]:
        return {"rsp": self.rsp, "words": {str(address): value for address, value in self.words.items()}}


@dataclass(frozen=True)
class AlignmentResult:
    aligned: bool
    rsp_mod_16: int
    message: str
    suggested_ret: bool = False


@dataclass
class ROPChain:
    word_size: int = 8
    entries: list[ROPEntry] = field(default_factory=list)

    def append(self, value: int | str, *, kind: str = "value", gadget: Gadget | None = None) -> ROPEntry:
        offset = self.entries[-1].offset + self.word_size if self.entries else 0
        entry = ROPEntry(offset, value, kind, gadget)
        self.entries.append(entry)
        return entry

    @property
    def stack_delta(self) -> int:
        return len(self.entries) * self.word_size

    def validate(self) -> tuple[str, ...]:
        """Return deterministic diagnostics without executing a chain."""
        errors: list[str] = []
        if self.word_size not in {4, 8}:
            errors.append("word_size 必须是 4 或 8")
        for index, entry in enumerate(self.entries):
            expected = index * self.word_size
            if entry.offset != expected:
                errors.append(f"offset[{index}] 应为 {expected:#x}，实际 {entry.offset:#x}")
            if entry.gadget is not None:
                if entry.gadget.memory_side_effect:
                    errors.append(f"不支持带内存副作用的 Gadget: {entry.gadget.text}")
                if not entry.gadget.instructions or entry.gadget.instructions[-1].lower().split()[0] != "ret":
                    errors.append(f"不支持非 ret 结束 Gadget: {entry.gadget.text}")
            if entry.value is None:
                errors.append(f"entry[{index}] 的值未知")
        return tuple(errors)

    def to_stack_state(self, initial_rsp: int = 0) -> StackState:
        """Materialize the same word layout used by Canvas and simulation."""
        state = StackState(int(initial_rsp))
        for entry in self.entries:
            address = state.push(entry.value, word_size=self.word_size)
            if address - int(initial_rsp) != entry.offset:
                raise ValueError("Chain offset 与 StackState 不一致")
        return state

    def simulate(self, initial_rsp: int = 0, initial: RegisterState | None = None) -> tuple[RegisterState, list[dict[str, object]]]:
        state = RegisterState(dict((initial or RegisterState()).values))
        rsp = int(initial_rsp)
        trace: list[dict[str, object]] = []
        for index, entry in enumerate(self.entries):
            trace.append({"offset": entry.offset, "value": entry.value, "rsp": rsp, "registers": dict(state.values)})
            if entry.gadget is not None:
                controls = tuple(entry.gadget.controls)
                consumed: list[dict[str, object]] = []
                for slot, register in enumerate(controls, start=1):
                    value_index = index + slot
                    value = self.entries[value_index].value if value_index < len(self.entries) else None
                    state.set(register, value)
                    consumed.append({"register": register, "value": value, "offset": entry.offset + slot * self.word_size})
                trace[-1]["consumed"] = consumed
                trace[-1]["registers_after"] = dict(state.values)
                rsp += max(self.word_size, entry.gadget.stack_delta or self.word_size)
            else:
                rsp += self.word_size
        return state, trace

    def required_registers(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(register for entry in self.entries if entry.gadget for register in entry.gadget.controls))

    def check_alignment(self, *, initial_rsp: int = 0, before_entry: int | None = None) -> AlignmentResult:
        index = 0 if before_entry is None else max(0, min(len(self.entries), int(before_entry)))
        rsp_mod = (int(initial_rsp) + index * self.word_size) % 16
        aligned = rsp_mod == 8
        message = "system() 入口满足 AMD64 ABI 对齐" if aligned else "system() 入口栈可能未满足 ABI 对齐要求"
        return AlignmentResult(aligned, rsp_mod, message, not aligned)

    def to_dict(self) -> dict[str, object]:
        return {"word_size": self.word_size, "entries": [item.to_dict() for item in self.entries]}

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "ROPChain":
        if not isinstance(payload, dict):
            raise ValueError("Chain 必须是对象")
        word_size = int(payload.get("word_size", 8))
        if word_size not in {4, 8}:
            raise ValueError("word_size 必须是 4 或 8")
        raw_entries = payload.get("entries", ())
        if not isinstance(raw_entries, (list, tuple)):
            raise ValueError("entries 必须是列表")
        chain = cls(word_size=word_size)
        for index, raw in enumerate(raw_entries):
            if not isinstance(raw, dict):
                raise ValueError(f"entry[{index}] 必须是对象")
            gadget_raw = raw.get("gadget")
            gadget = Gadget.from_dict(gadget_raw) if isinstance(gadget_raw, dict) else None
            if "value" not in raw:
                raise ValueError(f"entry[{index}] 缺少 value")
            value = raw.get("value")
            if value is None:
                raise ValueError(f"entry[{index}] 的值未知")
            offset = int(raw.get("offset", index * word_size))
            expected = index * word_size
            if offset != expected:
                raise ValueError(f"entry[{index}] offset 不连续")
            chain.entries.append(ROPEntry(offset, value, str(raw.get("kind", "value")), gadget))
        return chain
