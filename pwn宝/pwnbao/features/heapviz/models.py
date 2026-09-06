from __future__ import annotations

from dataclasses import dataclass, field

from pwnbao.features.heapviz.events import AllocEvent, BinTransitionEvent, FreeEvent, OverwriteEdge, ReadEvent, WriteEvent
from pwnbao.features.heapviz.memory import PhysicalMemorySnapshot


@dataclass(frozen=True)
class AllocatorConfig:
    family: str = "glibc"
    version: tuple[int, int] = (2, 35)
    arch: str = "amd64"
    bits: int = 64
    alignment: int = 0x10
    tcache_enabled: bool = True
    tcache_count_limit: int = 7
    tcache_max_chunk_size: int = 0x410
    safe_linking: bool = False
    tcache_key_check: bool = True
    hooks_available: bool = True
    top_size_check: bool = True
    io_vtable_validation: bool = True
    max_fast_chunk_size: int = 0x80
    heap_base: str = "heap_base"
    simulation_mode: str = "strict"  # strict | plan
    # Profile 身份（allocators/profiles 注册表签发）：快照回传
    # requested/effective 双版本 + profile_revision，UI 只相信 effective。
    profile_id: str = ""
    profile_revision: str = ""
    requested_version: str = ""

    @property
    def label(self) -> str:
        mode = "严格" if self.simulation_mode == "strict" else "演示"
        return f"{self.family} {self.version[0]}.{self.version[1]} / {self.arch} / {mode}"


@dataclass(frozen=True)
class HeapApiProfile:
    alloc_function: str = "add"
    free_function: str = "delete"
    edit_function: str = "edit"
    show_function: str = "show"
    copy_function: str = "copy_chunk"
    alloc_template: str = "{func}({size}, {data})"
    free_template: str = "{func}({index})"
    edit_template: str = "{func}({index}, {data})"
    show_template: str = "{func}({index})"
    copy_template: str = "{func}({src}, {dst}, {length})"
    definitions: str = ""


@dataclass(frozen=True)
class ChunkField:
    offset: str
    name: str
    value: str
    meaning: str = ""
    address: str = ""
    role: str = ""
    provenance: str = "derived"  # observed | derived | inferred | assumed | unknown


@dataclass(frozen=True)
class MemoryRegion:
    """A truth-labelled interval in a chunk's physical memory.

    ``state`` is intentionally separate from ``value``: an unwritten malloc
    tail is ``unknown`` rather than a string containing a made-up ``NULL``.
    Offsets are relative to the malloc chunk header.
    """

    start: int
    end: int
    value: str = ""
    state: str = "unknown"  # known | zero | unknown | metadata
    name: str = ""
    provenance: str = "unknown"
    meaning: str = ""


@dataclass(frozen=True)
class ChunkState:
    chunk_id: str
    address: str
    request_size: str
    chunk_size: str
    lifecycle: str
    menu_indexes: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    bin_location: str = ""
    fd: str = ""
    bk: str = ""
    data: str = ""
    note: str = ""
    role: str = ""
    fields: tuple[ChunkField, ...] = ()
    heap_offset: str = ""
    user_address: str = ""
    physical_id: str = ""
    provenance: str = "derived"
    memory_regions: tuple[MemoryRegion, ...] = ()
    original_chunk_size: str = ""
    # 尺寸三拆（PhysicalMemory 签发，renderer 只读）：
    #   physical_extent_size  注册对象的真实物理范围（布局/行数唯一依据）
    #   header_raw_size       内存里 size 字段当前原始值（含 flags，hex 文本）
    #   decoded_chunksize     raw & ~flags（hex 文本，展示/对比用）
    # 三者互相独立：改写 size 字段只动后两个，物理范围只有 allocator 事务才变。
    physical_extent_size: str = ""
    header_raw_size: str = ""
    decoded_chunksize: str = ""
    view_kind: str = "allocated_chunk"
    evidence_level: str = ""  # candidate | likely | confirmed (fake views)


@dataclass(frozen=True)
class HandleState:
    index: str
    chunk_id: str
    physical_id: str
    status: str = "active"  # active | dangling | alias
    note: str = ""


@dataclass(frozen=True)
class BinState:
    tcache: dict[str, tuple[str, ...]] = field(default_factory=dict)
    fastbins: dict[str, tuple[str, ...]] = field(default_factory=dict)
    smallbins: dict[str, tuple[str, ...]] = field(default_factory=dict)
    largebins: dict[str, tuple[str, ...]] = field(default_factory=dict)
    unsorted: tuple[str, ...] = ()


@dataclass(frozen=True)
class HeapWarning:
    severity: str
    code: str
    title: str
    message: str
    operation_id: str = ""
    related_chunks: tuple[str, ...] = ()


@dataclass(frozen=True)
class AllocatorAbort:
    reason: str
    operation_id: str
    check: str
    address: str = ""
    metadata: dict[str, str] = field(default_factory=dict)
    glibc_policy: str = ""


@dataclass(frozen=True)
class HeapIntent:
    kind: str
    target: str = ""
    status: str = "pending"  # verified | pending | invalid | assumed
    message: str = ""
    operation_id: str = ""


@dataclass(frozen=True)
class ValueObservation:
    """A value produced by EXP code without pretending the EXP was executed.

    ``value`` is either a value the allocator model can prove or a symbolic byte
    layout.  The provenance field deliberately distinguishes that from bytes
    captured from a live process.
    """

    name: str
    expression: str
    value: str = ""
    source_chunk: str = ""
    source_address: str = ""
    kind: str = "show"  # show | derived
    provenance: str = "derived"  # observed | derived | inferred | assumed | unknown
    dependencies: tuple[str, ...] = ()
    integer_value: str = ""
    detail: str = ""


@dataclass(frozen=True)
class HeapSnapshot:
    step: int
    operation_id: str
    chunks: dict[str, ChunkState]
    bins: BinState
    warnings: tuple[HeapWarning, ...] = ()
    explanation: tuple[str, ...] = ()
    focus_chunks: tuple[str, ...] = ()
    event_title: str = ""
    heap_base: str = "heap_base"
    handles: dict[str, HandleState] = field(default_factory=dict)
    intents: tuple[HeapIntent, ...] = ()
    observations: tuple[ValueObservation, ...] = ()
    aborted: bool = False
    memory: PhysicalMemorySnapshot = PhysicalMemorySnapshot()
    write_events: tuple[WriteEvent, ...] = ()
    overwrite_edges: tuple[OverwriteEdge, ...] = ()
    write_history: tuple[WriteEvent, ...] = ()
    overwrite_history: tuple[OverwriteEdge, ...] = ()
    read_events: tuple[ReadEvent, ...] = ()
    alloc_events: tuple[AllocEvent, ...] = ()
    free_events: tuple[FreeEvent, ...] = ()
    bin_transition_events: tuple[BinTransitionEvent, ...] = ()
    top_address: str = ""
    top_size: str = "unknown"
    top_provenance: str = "unknown"
    allocator_abort: AllocatorAbort | None = None
    model_divergences: tuple[str, ...] = ()

    def timeline_label(self) -> str:
        warn = " !" if self.warnings else ""
        aborted = " ⛔" if self.aborted else ""
        return f"{self.step:02d} {self.operation_id}{warn}{aborted}"
