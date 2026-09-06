from __future__ import annotations

import ast
import heapq
import re
from dataclasses import replace
from typing import Any, Iterable, Mapping

from pwnbao.features.heapviz.compatibility import target_compatibility
from pwnbao.features.heapviz.allocators.bin_transitions import (
    ARENA_SENTINEL,
    DoublyChainTransition,
    insert_doubly,
    remove_doubly,
)
from pwnbao.features.heapviz.events import (
    AllocEvent,
    BinTransitionEvent,
    FreeEvent,
    OverwriteEdge,
    ReadEvent,
    WriteEvent,
    WriteImpact,
    WriteImpactKind,
)
from pwnbao.features.heapviz.expressions import display_expr, parse_int_expr, safe_link_encode_expr
from pwnbao.features.heapviz.memory import MemoryAddress, MemoryObject, MemoryProvenance, PhysicalMemory, ProvenanceKind, WriteKind
from pwnbao.features.heapviz.models import (
    AllocatorAbort,
    AllocatorConfig,
    BinState,
    ChunkField,
    ChunkState,
    HandleState,
    HeapIntent,
    HeapSnapshot,
    HeapWarning,
    MemoryRegion,
    ValueObservation,
)
from pwnbao.features.heapviz.operations import HeapOperation, HeapOperationKind
from pwnbao.features.heapviz.semantics.canonical_ir import CanonicalHeapOperation, legacy_from_canonical
from pwnbao.features.heapviz.payload import PayloadEvaluator, PayloadIR, PayloadSegment
from pwnbao.features.heapviz.views import ChunkMemoryView


class GlibcHeapEngine:
    def __init__(self, config: AllocatorConfig, variables: Mapping[str, str | int] | None = None):
        self.config = config
        self.variables = dict(variables or {})
        self._next_offset = 0x290
        self._layout_known = True
        self._chunks: dict[str, ChunkState] = {}
        self._handles: dict[str, HandleState] = {}
        self._physical_seq = 0
        self._tcache: dict[int, list[str]] = {}
        self._fastbins: dict[int, list[str]] = {}
        self._smallbins: dict[int, list[str]] = {}
        self._largebins: dict[int, list[str]] = {}
        self._unsorted: list[str] = []
        self._largebin_nextsize_order: list[str] = []
        self._step_intents: list[HeapIntent] = []
        self._observations: list[ValueObservation] = []
        self._memory = PhysicalMemory(self.variables)
        self._step_write_events: list[WriteEvent] = []
        self._step_overwrite_edges: list[OverwriteEdge] = []
        self._step_read_events: list[ReadEvent] = []
        self._step_alloc_events: list[AllocEvent] = []
        self._step_free_events: list[FreeEvent] = []
        self._step_bin_transition_events: list[BinTransitionEvent] = []
        self._write_history: list[WriteEvent] = []
        self._overwrite_history: list[OverwriteEdge] = []
        self._enriched_cache: dict[str, tuple[object, ChunkState]] = {}
        self._write_sequence = 0
        self._bin_transition_sequence = 0
        self._current_operation_id = ""
        self._aborted = False
        self._allocator_abort: AllocatorAbort | None = None
        self._model_divergences: list[str] = []
        self._initial_top_size = 0x21000 - self._next_offset

    def request2size(self, request_size: str | int) -> int | None:
        request = parse_int_expr(request_size, self.variables)
        if request is None:
            return None
        # glibc request2size adds SIZE_SZ because the user area overlaps the
        # prev_size slot of the next chunk; adding the full malloc_chunk header
        # would over-size common CTF chunks (amd64 malloc(0x68) must be 0x70).
        size_sz = 0x8 if self.config.bits == 64 else 0x4
        minimum = 0x20 if self.config.bits == 64 else 0x10
        align = self.config.alignment
        size = request + size_sz + align - 1
        size &= ~(align - 1)
        return max(size, minimum)

    def assert_cache_consistency(self) -> None:
        """Fail loudly when a Python acceleration cache disagrees with memory.

        This is intentionally an assertion/debug API.  It never repairs the
        bytes, so exploit corruption remains authoritative.
        """
        divergences = self._detect_cache_divergences()
        for detail in divergences:
            if detail not in self._model_divergences:
                self._model_divergences.append(detail)
        if divergences:
            raise AssertionError("allocator cache diverged from PhysicalMemory: " + " | ".join(divergences))

    def _detect_cache_divergences(self) -> tuple[str, ...]:
        failures: list[str] = []
        for kind, bins, user_pointer in (
            ("tcache", self._tcache, True),
            ("fastbin", self._fastbins, False),
        ):
            for size, chain in bins.items():
                if kind == "tcache":
                    walked = self._walk_tcache_from_memory(size)
                    if tuple(chain) != tuple(walked):
                        failures.append(
                            f"tcache[{hex(size)}] cache={tuple(chain)} memory={tuple(walked)}"
                        )
                seen: set[str] = set()
                for index, chunk_id in enumerate(chain):
                    if chunk_id in seen or self._external_target_from_token(chunk_id, kind):
                        continue
                    seen.add(chunk_id)
                    chunk = self._chunks.get(chunk_id)
                    if chunk is None:
                        failures.append(f"{kind}[{hex(size)}] cache references missing {chunk_id}")
                        continue
                    expected_id = chain[index + 1] if index + 1 < len(chain) else "NULL"
                    expected = self._chunk_pointer(expected_id, user=user_pointer)
                    actual = self._decoded_freelist_target(chunk) or "unknown"
                    if not self._same_pointer(actual, expected):
                        failures.append(
                            f"{kind}[{hex(size)}] {chunk_id}.next memory={actual} cache={expected}"
                        )
        for location, chain in self._iter_doubly_caches():
            if not chain:
                continue
            head_address = self._bin_head_address(location)
            head_fd = self._read_pointer_at(head_address)
            head_bk = self._read_pointer_at(self._offset_address(head_address, self._word_size()))
            expected_head = self._chunk_pointer(chain[0], user=False)
            expected_tail = self._chunk_pointer(chain[-1], user=False)
            if not self._same_pointer(head_fd, expected_head):
                failures.append(f"{location}.head.fd memory={head_fd} cache={expected_head}")
            if not self._same_pointer(head_bk, expected_tail):
                failures.append(f"{location}.head.bk memory={head_bk} cache={expected_tail}")
            for index, chunk_id in enumerate(chain):
                chunk = self._chunks.get(chunk_id)
                if chunk is None:
                    failures.append(f"{location} cache references missing {chunk_id}")
                    continue
                expected_fd = head_address if index + 1 == len(chain) else self._chunk_pointer(chain[index + 1], user=False)
                expected_bk = head_address if index == 0 else self._chunk_pointer(chain[index - 1], user=False)
                actual_fd = self._read_raw_pointer(chunk, self._word_size() * 2)
                actual_bk = self._read_raw_pointer(chunk, self._word_size() * 3)
                if not self._same_pointer(actual_fd, expected_fd):
                    failures.append(f"{location} {chunk_id}.fd memory={actual_fd} cache={expected_fd}")
                if not self._same_pointer(actual_bk, expected_bk):
                    failures.append(f"{location} {chunk_id}.bk memory={actual_bk} cache={expected_bk}")
        return tuple(dict.fromkeys(failures))

    def _iter_doubly_caches(self) -> Iterable[tuple[str, list[str]]]:
        yield "unsorted", self._unsorted
        for size, chain in self._smallbins.items():
            yield f"smallbin[{hex(size)}]", chain
        for size, chain in self._largebins.items():
            yield f"largebin[{hex(size)}]", chain

    def _read_pointer_at(self, address: str) -> str:
        read = self._memory.read(address, self._word_size())
        if read.data is not None:
            value = int.from_bytes(read.data, "little")
            return "NULL" if value == 0 else hex(value)
        return (read.symbolic or "unknown").strip()

    @staticmethod
    def _tcache_head_address(size: int) -> str:
        return f"tcache_entries_{size:x}"

    def _ensure_tcache_head(self, size: int) -> str:
        """Materialise the modeled tcache_perthread head/count in memory."""
        address = self._tcache_head_address(size)
        object_id = f"tcache_head:{hex(size)}"
        if not any(item.object_id == object_id for item in self._memory.objects):
            self._memory.register_object(
                object_id, address, self._word_size() * 2,
                kind="tcache_perthread_entry", label=f"tcache[{hex(size)}]",
                provenance="derived",
            )
        return address

    def _write_tcache_head(self, size: int, chain: list[str]) -> None:
        address = self._ensure_tcache_head(size)
        target = self._chunk_pointer(chain[0], user=True) if chain else "0"
        provenance = MemoryProvenance.derived(
            self._current_operation_id, writer="allocator",
            note=f"tcache[{hex(size)}] entries/count update",
        )
        concrete = parse_int_expr(target, self.variables)
        if concrete is not None:
            self._memory.write_uint(address, concrete, self._word_size(), provenance, state="metadata")
        else:
            self._memory.write_symbolic(address, target, self._word_size(), provenance, state="metadata")
        self._memory.write_uint(
            self._offset_address(address, self._word_size()), len(chain),
            self._word_size(), provenance, state="metadata",
        )

    def _tcache_head_token_from_memory(self, size: int) -> str | None:
        object_id = f"tcache_head:{hex(size)}"
        if not any(item.object_id == object_id for item in self._memory.objects):
            return None
        target = self._read_pointer_at(self._tcache_head_address(size))
        if target in {"", "NULL", "0", "0x0"}:
            return ""
        candidates = [
            chunk for chunk in self._chunks.values()
            if chunk.lifecycle != "stale" and self._same_pointer(chunk.user_address, target)
        ]
        if candidates:
            return max(candidates, key=lambda chunk: 1 if chunk.lifecycle == "freed" else 0).chunk_id
        return self._external_target_token("tcache", target)

    def _sync_tcache_from_memory(self, size: int) -> list[str]:
        walked = list(self._walk_tcache_from_memory(size))
        if walked:
            self._tcache[size] = walked
        else:
            self._tcache.pop(size, None)
        return walked

    def replay(self, operations: Iterable[HeapOperation | CanonicalHeapOperation]) -> list[HeapSnapshot]:
        operations = tuple(
            legacy_from_canonical(operation) if isinstance(operation, CanonicalHeapOperation) else operation
            for operation in operations
        )
        self._next_offset = 0x290
        self._layout_known = True
        self._chunks = {}
        self._handles = {}
        self._physical_seq = 0
        self._tcache = {}
        self._fastbins = {}
        self._smallbins = {}
        self._largebins = {}
        self._unsorted = []
        self._largebin_nextsize_order = []
        self._step_intents = []
        self._observations = []
        self._memory = PhysicalMemory(self.variables)
        self._step_write_events = []
        self._step_overwrite_edges = []
        self._step_read_events = []
        self._step_alloc_events = []
        self._step_free_events = []
        self._step_bin_transition_events = []
        self._write_history = []
        self._overwrite_history = []
        self._enriched_cache = {}
        self._write_sequence = 0
        self._bin_transition_sequence = 0
        self._current_operation_id = ""
        self._aborted = False
        self._allocator_abort = None
        self._model_divergences = []
        self._initial_top_size = 0x21000 - self._next_offset
        self._initialize_top_memory("initial")
        snapshots = [self._snapshot(0, "initial", (), ("初始状态：还没有堆操作。",), (), "initial")]
        for step, operation in enumerate(operations, 1):
            self._step_intents = []
            self._step_write_events = []
            self._step_overwrite_edges = []
            self._step_read_events = []
            self._step_alloc_events = []
            self._step_free_events = []
            self._step_bin_transition_events = []
            self._current_operation_id = operation.op_id
            if self._aborted and operation.kind not in {HeapOperationKind.NOTE}:
                warnings = [self._warning("FATAL", "allocator_aborted", "进程已在前一步被 allocator 终止", "严格模式不再继续伪造后续 malloc/free 状态；切到演示模式可只看利用意图。", operation)]
                explanation = ["严格模拟已停止推进 allocator 状态。"]
            else:
                warnings, explanation = self._apply(operation)
            snapshots.append(
                self._snapshot(
                    step,
                    operation.op_id,
                    tuple(warnings),
                    tuple(explanation),
                    self._focus_chunks(operation),
                    operation.title(),
                )
            )
        return snapshots

    def rebuild_current_snapshot(
        self,
        checkpoint: HeapSnapshot,
        corrected_memory,
    ) -> HeapSnapshot:
        """Rebuild every current typed view after an authoritative memory edit.

        This is intentionally separate from replaying the suffix.  The old UI
        used to patch a few ChunkState fields while keeping bin/top caches from
        the pre-edit snapshot, creating two truths.  We now restore the
        allocator checkpoint, replace PhysicalMemory, refresh memory-driven
        singly-linked bins, and regenerate the snapshot from the engine.
        """
        self._restore_checkpoint(checkpoint)
        self._memory = PhysicalMemory.from_snapshot(corrected_memory, self.variables)
        for size in tuple(self._tcache):
            walked = list(self._walk_tcache_from_memory(size))
            if walked:
                self._tcache[size] = walked
            else:
                self._tcache.pop(size, None)
        for size in tuple(self._fastbins):
            walked = list(self._walk_fastbin_from_memory(size))
            if walked:
                self._fastbins[size] = walked
            else:
                self._fastbins.pop(size, None)
        self._enriched_cache.clear()
        rebuilt = self._snapshot(
            checkpoint.step,
            checkpoint.operation_id,
            checkpoint.warnings,
            checkpoint.explanation,
            checkpoint.focus_chunks,
            checkpoint.event_title,
        )
        # Event fields describe how this checkpoint was reached and belong in
        # Logs.  Preserve them while all current-state surfaces above come from
        # corrected PhysicalMemory.
        return replace(
            rebuilt,
            intents=checkpoint.intents,
            read_events=checkpoint.read_events,
            alloc_events=checkpoint.alloc_events,
            free_events=checkpoint.free_events,
            bin_transition_events=checkpoint.bin_transition_events,
            write_events=checkpoint.write_events,
            overwrite_edges=checkpoint.overwrite_edges,
        )

    def replay_from_snapshot(
        self,
        checkpoint: HeapSnapshot,
        operations: Iterable[HeapOperation | CanonicalHeapOperation],
    ) -> list[HeapSnapshot]:
        """Replay only the suffix after an authoritative checkpoint.

        Semantic corrections are applied to ``checkpoint.memory`` before this
        method is called.  Restoring allocator caches, handles and physical
        memory avoids recomputing the unaffected prefix while keeping later
        malloc/free decisions memory-driven.  The returned list includes the
        supplied checkpoint as element zero.
        """
        suffix = tuple(
            legacy_from_canonical(operation) if isinstance(operation, CanonicalHeapOperation) else operation
            for operation in operations
        )
        self._restore_checkpoint(checkpoint)
        snapshots = [checkpoint]
        for offset, operation in enumerate(suffix, 1):
            self._step_intents = []
            self._step_write_events = []
            self._step_overwrite_edges = []
            self._step_read_events = []
            self._step_alloc_events = []
            self._step_free_events = []
            self._step_bin_transition_events = []
            self._current_operation_id = operation.op_id
            if self._aborted and operation.kind not in {HeapOperationKind.NOTE}:
                warnings = [self._warning(
                    "FATAL",
                    "allocator_aborted",
                    "进程已在前一步被 allocator 终止",
                    "严格模式不再继续伪造后续 malloc/free 状态。",
                    operation,
                )]
                explanation = ["严格模拟已停止推进 allocator 状态。"]
            else:
                warnings, explanation = self._apply(operation)
            snapshots.append(self._snapshot(
                checkpoint.step + offset,
                operation.op_id,
                tuple(warnings),
                tuple(explanation),
                self._focus_chunks(operation),
                operation.title(),
            ))
        return snapshots

    def _restore_checkpoint(self, snapshot: HeapSnapshot) -> None:
        self._chunks = dict(snapshot.chunks)
        self._handles = dict(snapshot.handles)
        self._tcache = self._restore_bin_map(snapshot.bins.tcache, "tcache")
        self._fastbins = self._restore_bin_map(snapshot.bins.fastbins, "fastbin")
        self._smallbins = self._restore_bin_map(snapshot.bins.smallbins)
        self._largebins = self._restore_bin_map(snapshot.bins.largebins)
        self._unsorted = list(snapshot.bins.unsorted)
        self._largebin_nextsize_order = [
            chunk_id for _size, chain in sorted(self._largebins.items()) for chunk_id in chain
        ]
        self._observations = list(snapshot.observations)
        self._memory = PhysicalMemory.from_snapshot(snapshot.memory, self.variables)
        self._write_history = list(snapshot.write_history)
        self._overwrite_history = list(snapshot.overwrite_history)
        self._write_sequence = len(self._write_history)
        self._bin_transition_sequence = len(snapshot.bin_transition_events)
        self._current_operation_id = snapshot.operation_id
        self._aborted = snapshot.aborted
        self._allocator_abort = snapshot.allocator_abort
        self._model_divergences = list(snapshot.model_divergences)
        self._enriched_cache = {}
        self._step_intents = []
        self._step_write_events = []
        self._step_overwrite_edges = []
        self._step_read_events = []
        self._step_alloc_events = []
        self._step_free_events = []
        self._step_bin_transition_events = []
        self._next_offset = self._checkpoint_top_offset(snapshot)
        self._layout_known = self._next_offset >= 0
        if not self._layout_known:
            self._next_offset = 0x290
        self._physical_seq = max(
            (
                int(match.group(1))
                for chunk in self._chunks.values()
                for value in (chunk.physical_id, chunk.chunk_id)
                for match in [re.search(r"_(\d+)$", value or "")]
                if match is not None
            ),
            default=len(self._chunks),
        )
        top_size = parse_int_expr(snapshot.top_size, self.variables)
        self._initial_top_size = (top_size + self._next_offset) if top_size is not None else 0x21000 - 0x290

    def _restore_bin_map(self, raw: Mapping[str, tuple[str, ...]], kind: str = "") -> dict[int, list[str]]:
        restored: dict[int, list[str]] = {}
        for size, nodes in raw.items():
            numeric = parse_int_expr(size, self.variables)
            if numeric is None:
                continue
            restored[numeric] = [
                self._external_target_token(kind, node.split("@", 1)[1].strip())
                if kind and str(node).startswith("external @")
                else str(node)
                for node in nodes
            ]
        return restored

    def _checkpoint_top_offset(self, snapshot: HeapSnapshot) -> int:
        try:
            top = self._memory.address(snapshot.top_address)
            base = self._memory.address(self.config.heap_base)
            if top.root == base.root:
                return top.offset - base.offset
        except ValueError:
            pass
        offsets = []
        for chunk in snapshot.chunks.values():
            start = parse_int_expr(chunk.heap_offset, self.variables)
            size = self._chunk_size_value(chunk)
            if start is not None and size is not None:
                offsets.append(start + size)
        return max(offsets, default=-1)

    def _apply(self, operation: HeapOperation) -> tuple[list[HeapWarning], list[str]]:
        if operation.kind == HeapOperationKind.ALLOC:
            return self._alloc(operation)
        if operation.kind == HeapOperationKind.FREE:
            return self._free(operation)
        if operation.kind == HeapOperationKind.EDIT:
            return self._edit(operation)
        if operation.kind == HeapOperationKind.SHOW:
            return self._show(operation)
        if operation.kind == HeapOperationKind.DERIVE_VALUE:
            return self._derive_value(operation)
        if operation.kind == HeapOperationKind.COPY:
            return self._copy_chunk(operation)
        if operation.kind == HeapOperationKind.SAFE_LINK_FD:
            return self._safe_link_fd(operation)
        if operation.kind == HeapOperationKind.OVERFLOW_HEADER:
            return self._overflow_header(operation)
        if operation.kind == HeapOperationKind.POISON_FD:
            return self._poison_fd(operation)
        if operation.kind == HeapOperationKind.FAKE_CHUNK:
            return self._fake_chunk(operation)
        if operation.kind == HeapOperationKind.UNLINK_PREPARE:
            return self._unlink_prepare(operation)
        if operation.kind == HeapOperationKind.CONSOLIDATE:
            return self._consolidate(operation)
        if operation.kind == HeapOperationKind.MALLOC_TO_TARGET:
            return self._malloc_to_target(operation)
        if operation.kind == HeapOperationKind.LEAK_MAIN_ARENA:
            return self._leak_main_arena(operation)
        if operation.kind == HeapOperationKind.STDOUT_ENVIRON_LEAK:
            return self._stdout_environ_leak(operation)
        if operation.kind == HeapOperationKind.SETCONTEXT_ROP:
            return self._setcontext_rop(operation)
        if operation.kind == HeapOperationKind.FILL_TCACHE:
            return self._fill_tcache(operation)
        if operation.kind == HeapOperationKind.DRAIN_TCACHE:
            return self._drain_tcache(operation)
        if operation.kind == HeapOperationKind.RESIZE_PHYSICAL:
            return self._resize_physical(operation)
        return [], [operation.note or "备注步骤，不改变模拟状态。"]

    def _alloc(self, operation: HeapOperation) -> tuple[list[HeapWarning], list[str]]:
        warnings: list[HeapWarning] = []
        explanation: list[str] = []
        chunk_id = operation.chunk or f"chunk_{len(self._chunks)}"
        chunk_size = self.request2size(operation.request_size)
        if chunk_size is None:
            warnings.append(self._warning("ERROR", "bad_size", "申请大小无法解析", "request size 不是可计算的整数；保留符号表达式，但无法可靠选择 bin。", operation))
            chunk_size_text = "未知"
        else:
            chunk_size_text = hex(chunk_size)

        reused_id = ""
        heap_offset = ""
        address = ""
        returned_user_address = ""
        source = None
        reuse_source = ""
        external_target = ""
        bin_truth = None
        if chunk_size is not None:
            reused_id, reuse_source, reuse_notes, external_target, bin_truth = self._take_reusable_chunk(chunk_size, operation, warnings)
            explanation.extend(reuse_notes)
            if self._aborted:
                return warnings, [*explanation, "allocator 在读取 freelist 物理链接时触发 integrity abort。"]
            source = self._chunks.get(reused_id) if reused_id else None

        if external_target:
            # This is not a hidden "next malloc target" side channel.  The
            # external node was installed as the real freelist head when the
            # previous entry was popped and its next field was decoded from
            # PhysicalMemory.  Consuming that head is the allocator action.
            returned_user_address = external_target
            if reuse_source.startswith("fastbin"):
                returned_user_address = self._offset_address(external_target, self._word_size() * 2)
                address = external_target
            else:
                address = self._offset_address(external_target, -(self._word_size() * 2))
            heap_offset = self._heap_offset_for_address(address)
            self._physical_seq += 1
            physical_id = f"target_{self._physical_seq:04d}"
            provenance = "derived"
            explanation.append(
                f"malloc 消费了由上一 freelist 节点物理 next 字段建立的 head；"
                f"本次 user pointer={returned_user_address}。"
            )
        else:
            if source is not None:
                address = source.address
                heap_offset = source.heap_offset
                physical_id = source.physical_id or source.chunk_id
                self._mark_reused_chunk(reused_id, chunk_id)
            else:
                address_override = self._alloc_address_override(operation)
                if address_override:
                    address = address_override
                    heap_offset = self._heap_offset_for_address(address_override)
                    provenance = "assumed"
                elif not self._layout_known or chunk_size is None:
                    address = self._unknown_heap_address(chunk_id)
                    heap_offset = ""
                    provenance = "unknown"
                else:
                    heap_offset = hex(self._next_offset)
                    address = self._heap_address(self._next_offset)
                    provenance = "derived"
                if chunk_size is None:
                    self._layout_known = False
                elif self._layout_known and not address_override:
                    top_warning = self._consume_top(chunk_size, operation)
                    if top_warning is not None:
                        warnings.append(top_warning)
                        return warnings, ["malloc 从 PhysicalMemory 读取 top.size 后触发 integrity abort。"]
                self._physical_seq += 1
                physical_id = f"phys_{self._physical_seq:04d}"
                explanation.append(f"从 top chunk 切出新块 {chunk_id}，模拟 chunk header 地址 {address}。")

        aliases = (reused_id,) if reused_id and reused_id != chunk_id else ()
        provenance = "derived" if source is not None else locals().get("provenance", "derived")
        if returned_user_address:
            user_address = returned_user_address
        elif provenance == "unknown":
            user_address = self._unknown_heap_address(chunk_id, user=True)
        else:
            user_address = self._offset_address(address, self._word_size() * 2)
        bind_handle = str(operation.meta.get("bind_handle", "true")).strip().lower() not in {"0", "false", "no"}
        self._chunks[chunk_id] = ChunkState(
            chunk_id=chunk_id,
            address=address,
            user_address=user_address,
            physical_id=physical_id,
            request_size=display_expr(operation.request_size),
            chunk_size=chunk_size_text,
            lifecycle="allocated",
            menu_indexes=(display_expr(operation.index, ""),) if operation.index and bind_handle else (),
            aliases=aliases,
            data=operation.data,
            note=operation.note,
            role=operation.meta.get("role", "normal"),
            heap_offset=heap_offset,
            provenance=provenance,
            original_chunk_size=chunk_size_text,
        )
        created_chunk = self._chunks[chunk_id]
        self._initialize_chunk_memory(operation, created_chunk, reused=source is not None)
        current_size = self._chunk_size_value(created_chunk)
        if source is not None and current_size is not None:
            self._set_following_prev_inuse(created_chunk, current_size, inuse=True, note="malloc marks previous in use")
        if operation.index and bind_handle:
            self._bind_handle(operation.index, chunk_id, physical_id)
        if reused_id and reused_id != chunk_id:
            explanation.append(f"{chunk_id} 复用了 {reused_id} 的物理块（{physical_id}）；旧菜单索引会作为 dangling/alias 保留。")
        if reuse_source:
            explanation.append(f"来源：{reuse_source}。")
        explanation.append(f"{chunk_id}: request={display_expr(operation.request_size)} -> chunk size={chunk_size_text}；user ptr={user_address}。")
        self._step_alloc_events.append(AllocEvent(
            f"alloc_{operation.op_id}", operation.op_id, chunk_id, address, user_address,
            display_expr(operation.request_size), chunk_size_text, reuse_source or "top",
            allocation_source_kind=str((bin_truth or {}).get("kind") or ("top" if not source else "bin")),
            victim_physical_id=(source.physical_id if source is not None else ""),
            bin_head_before=tuple((bin_truth or {}).get("before") or ()),
            bin_head_after=tuple((bin_truth or {}).get("after") or ()),
        ))
        return warnings, explanation

    def _take_reusable_chunk(
        self,
        chunk_size: int,
        operation: HeapOperation,
        warnings: list[HeapWarning],
    ) -> tuple[str, str, list[str], str, dict[str, Any] | None]:
        """Pick the victim exactly like glibc walks its bins.

        The returned ``bin_truth`` is the audit record for this malloc:
        ``kind`` + ``victim`` + the PhysicalMemory-derived head chain before
        and after the pop.  For tcache/fastbin a victim that is not
        ``head_before[0]`` is a CACHE_DIVERGENCE allocator abort — the demo
        stops instead of drawing a state the bytes cannot justify.
        """
        notes: list[str] = []
        if self._tcache.get(chunk_size) or self._tcache_head_token_from_memory(chunk_size):
            # Allocation and snapshot consume the same memory-derived chain.
            # The Python list is only an acceleration cache and is replaced
            # before selecting the victim.
            chain = self._sync_tcache_from_memory(chunk_size)
            if not chain:
                return "", "", notes, "", None
            before = tuple(chain)
            chunk_id = chain.pop(0)
            if chunk_id != before[0]:
                warnings.append(self._abort(
                    "CACHE_DIVERGENCE", operation,
                    f"tcache victim {chunk_id} != bin_head_before[0] {before[0]}",
                    metadata={
                        "bin": f"tcache[{hex(chunk_size)}]",
                        "bin_head_before": " -> ".join(before),
                    },
                ))
                return "", "", notes, "", None
            self._record_bin_transition("malloc-pop", "tcache", hex(chunk_size), chunk_id, before, chain, (chunk_id,), (), "tcache head consumed")
            external = self._external_target_from_token(chunk_id, "tcache")
            if external:
                self._write_tcache_head(chunk_size, chain)
                notes.append(f"tcache[{hex(chunk_size)}] 当前 head 是内存解码得到的外部节点 {external}。")
                return "", f"tcache[{hex(chunk_size)}] poisoned head", notes, external, {
                    "kind": "tcache", "victim": chunk_id, "before": before, "after": tuple(chain),
                }
            self._arm_poisoned_target(chunk_id, chunk_size, notes)
            self._write_tcache_head(chunk_size, chain)
            return chunk_id, f"tcache[{hex(chunk_size)}]", notes, "", {
                "kind": "tcache", "victim": chunk_id, "before": before, "after": tuple(chain),
            }
        if self._fastbins.get(chunk_size):
            chain = self._fastbins[chunk_size]
            before = tuple(chain)
            chunk_id = chain.pop(0)
            if chunk_id != before[0]:
                warnings.append(self._abort(
                    "CACHE_DIVERGENCE", operation,
                    f"fastbin victim {chunk_id} != bin_head_before[0] {before[0]}",
                    metadata={
                        "bin": f"fastbin[{hex(chunk_size)}]",
                        "bin_head_before": " -> ".join(before),
                    },
                ))
                return "", "", notes, "", None
            self._record_bin_transition("malloc-pop", "fastbin", hex(chunk_size), chunk_id, before, chain, (chunk_id,), (), "fastbin head consumed")
            external = self._external_target_from_token(chunk_id, "fastbin")
            if external:
                notes.append(f"fastbin[{hex(chunk_size)}] 当前 head 是内存解码得到的外部节点 {external}。")
                return "", f"fastbin[{hex(chunk_size)}] poisoned head", notes, external, {
                    "kind": "fastbin", "victim": chunk_id, "before": before, "after": tuple(chain),
                }
            self._arm_poisoned_target(chunk_id, chunk_size, notes)
            moved = self._refill_tcache_from_fastbin(chunk_size, notes)
            suffix = f" + tcache refill({len(moved)})" if moved else ""
            return chunk_id, f"fastbin[{hex(chunk_size)}]{suffix}", notes, "", {
                "kind": "fastbin", "victim": chunk_id, "before": before, "after": tuple(chain),
            }
        if self._smallbins.get(chunk_size):
            chain = self._smallbins[chunk_size]
            # glibc exact-size smallbin allocation consumes the bk/tail side.
            chunk_id = chain[-1]
            if not self._validate_doubly_unlink(chain, chunk_id, f"smallbin[{hex(chunk_size)}]", operation, warnings):
                return "", "", notes, "", None
            before = tuple(chain)
            self._remove_doubly_node(chain, chunk_id, f"smallbin[{hex(chunk_size)}]", hex(chunk_size), note="smallbin exact-fit victim")
            if not chain:
                self._smallbins.pop(chunk_size, None)
            moved = self._refill_tcache_from_smallbin(chunk_size, notes, operation, warnings)
            if self._aborted:
                return "", "", notes, "", None
            suffix = f" + tcache refill({len(moved)})" if moved else ""
            return chunk_id, f"smallbin[{hex(chunk_size)}]{suffix}", notes, "", {
                "kind": "smallbin", "victim": chunk_id, "before": before, "after": tuple(chain),
            }

        # Unsorted is not a decorative holding area: malloc scans it before
        # falling back to regular bins/top.  We model the common first-fit path
        # and sort non-fitting chunks into small/large bins.
        for chunk_id in list(self._unsorted):
            chunk = self._chunks.get(chunk_id)
            candidate_size = self._chunk_size_value(chunk) if chunk else None
            if not self._validate_doubly_unlink(self._unsorted, chunk_id, "unsorted", operation, warnings):
                return "", "", notes, "", None
            self._remove_doubly_node(self._unsorted, chunk_id, "unsorted", hex(candidate_size) if candidate_size is not None else "unknown", note="unsorted malloc scan")
            if candidate_size is None:
                self._bin_regular_chunk(chunk_id, None)
                continue
            if candidate_size >= chunk_size:
                remainder = candidate_size - chunk_size
                minimum = 0x20 if self.config.bits == 64 else 0x10
                if remainder >= minimum and chunk is not None:
                    self._chunks[chunk_id] = replace(chunk, chunk_size=hex(chunk_size), note=(chunk.note + " | split from unsorted").strip(" |"))
                    self._write_chunk_size_header(chunk, chunk_size, note="unsorted split allocated part")
                    remainder_id = self._create_remainder_chunk(chunk, chunk_size, remainder)
                    self._insert_doubly_node(self._unsorted, remainder_id, "unsorted", hex(remainder), at_head=True, note="unsorted split remainder")
                    notes.append(f"unsorted 中 {chunk_id}({hex(candidate_size)}) 被切分，remainder={remainder_id}({hex(remainder)})。")
                else:
                    notes.append(f"malloc 直接复用 unsorted 中的 {chunk_id}({hex(candidate_size)})。")
                self._refresh_freelist_metadata()
                return chunk_id, "unsorted", notes, "", {"kind": "unsorted", "victim": chunk_id, "before": (), "after": ()}
            self._bin_regular_chunk(chunk_id, candidate_size)
            notes.append(f"unsorted 的 {chunk_id}({hex(candidate_size)}) 不满足本次请求，整理到 regular bin。")

        self._refresh_freelist_metadata()

        # Best-fit approximation for largebin. This intentionally stays
        # conservative; exact nextsize ordering is outside the visual model.
        best: tuple[int, str] | None = None
        for size, chain in self._largebins.items():
            if chain and size >= chunk_size and (best is None or size < best[0]):
                best = (size, chain[0])
        if best is not None:
            size, chunk_id = best
            chain = self._largebins[size]
            if not self._validate_doubly_unlink(chain, chunk_id, f"largebin[{hex(size)}]", operation, warnings):
                return "", "", notes, "", None
            self._remove_doubly_node(chain, chunk_id, f"largebin[{hex(size)}]", hex(size), note="largebin best-fit victim")
            if not chain:
                self._largebins.pop(size, None)
            self._refresh_largebin_nextsize_metadata()
            chunk = self._chunks.get(chunk_id)
            remainder = size - chunk_size
            minimum = 0x20 if self.config.bits == 64 else 0x10
            if chunk is not None and remainder >= minimum:
                self._chunks[chunk_id] = replace(chunk, chunk_size=hex(chunk_size), note=(chunk.note + " | split from largebin").strip(" |"))
                self._write_chunk_size_header(chunk, chunk_size, note="largebin split allocated part")
                remainder_id = self._create_remainder_chunk(chunk, chunk_size, remainder)
                self._insert_doubly_node(self._unsorted, remainder_id, "unsorted", hex(remainder), at_head=True, note="largebin split remainder")
                notes.append(f"largebin 中 {chunk_id}({hex(size)}) best-fit 后切分 remainder={remainder_id}({hex(remainder)})。")
                self._refresh_freelist_metadata()
            return chunk_id, f"largebin[{hex(size)}]", notes, "", {"kind": "largebin", "victim": chunk_id, "before": (), "after": ()}
        return "", "", notes, "", None

    def _arm_poisoned_target(self, chunk_id: str, size: int, notes: list[str]) -> None:
        chunk = self._chunks.get(chunk_id)
        if chunk is None:
            return
        target = self._decoded_freelist_target(chunk)
        chain = self._tcache.get(size) if chunk.bin_location.startswith("tcache") else self._fastbins.get(size)
        expected_id = chain[0] if chain else ""
        expected_chunk = self._chunks.get(expected_id) if expected_id else None
        if chunk.bin_location.startswith("tcache"):
            expected = expected_chunk.user_address if expected_chunk else "NULL"
        else:
            expected = expected_chunk.address if expected_chunk else "NULL"
        if target and not self._same_pointer(target, expected) and target not in {"NULL", "0", "0x0"}:
            kind = "tcache" if chunk.bin_location.startswith("tcache") else "fastbin"
            active_chain = self._tcache.setdefault(size, []) if kind == "tcache" else self._fastbins.setdefault(size, [])
            # The decoded pointer is now the allocator's real head.  Keep it
            # in the freelist itself rather than in an out-of-band pending map.
            active_chain.insert(0, self._external_target_token(kind, target))
            self._record_bin_transition(
                "decoded-head", kind, hex(size), chunk_id,
                tuple(active_chain[1:]), tuple(active_chain), (target,), (),
                "PhysicalMemory next became the freelist head",
            )
            notes.append(
                f"{chunk_id}.next 由 PhysicalMemory 解码为 {target}（正常链期望 {expected}）；"
                "该指针已成为 freelist head，再一次同 size malloc 将直接消费它。"
            )

    def _refill_tcache_from_fastbin(self, size: int, notes: list[str]) -> tuple[str, ...]:
        if not self.config.tcache_enabled or size > self.config.tcache_max_chunk_size:
            return ()
        source = self._fastbins.get(size, [])
        destination = self._tcache.setdefault(size, [])
        source_before = tuple(source)
        destination_before = tuple(destination)
        moved: list[str] = []
        while source and len(destination) < self.config.tcache_count_limit:
            if self._external_target_from_token(source[0], "fastbin"):
                notes.append("fastbin refill 遇到未验证的外部 head；严格模型停止继续搬运。")
                break
            chunk_id = source.pop(0)
            previous = destination[0] if destination else "NULL"
            destination.insert(0, chunk_id)
            self._initialize_singly_link(chunk_id, previous, f"tcache[{hex(size)}] refill", user_pointer=True)
            chunk = self._chunks.get(chunk_id)
            if chunk:
                self._chunks[chunk_id] = replace(chunk, lifecycle="freed", bin_location=f"tcache[{hex(size)}]")
            moved.append(chunk_id)
        if not source:
            self._fastbins.pop(size, None)
        if moved:
            self._write_tcache_head(size, destination)
            notes.append("fastbin 额外节点回填 tcache: " + " -> ".join(moved))
            self._record_bin_transition(
                "refill", "fastbin->tcache", hex(size), moved[0],
                source_before, tuple(destination), moved,
                (), f"tcache before={destination_before}; source after={tuple(source)}",
            )
        return tuple(moved)

    def _refill_tcache_from_smallbin(
        self,
        size: int,
        notes: list[str],
        operation: HeapOperation,
        warnings: list[HeapWarning],
    ) -> tuple[str, ...]:
        if not self.config.tcache_enabled or size > self.config.tcache_max_chunk_size:
            return ()
        source = self._smallbins.get(size, [])
        destination = self._tcache.setdefault(size, [])
        source_before = tuple(source)
        destination_before = tuple(destination)
        moved: list[str] = []
        while source and len(destination) < self.config.tcache_count_limit:
            chunk_id = source[-1]
            if not self._validate_doubly_unlink(
                source, chunk_id, f"smallbin[{hex(size)}]", operation, warnings,
            ):
                break
            self._remove_doubly_node(source, chunk_id, f"smallbin[{hex(size)}]", hex(size), note="smallbin tcache refill unlink")
            previous = destination[0] if destination else "NULL"
            destination.insert(0, chunk_id)
            self._initialize_singly_link(chunk_id, previous, f"tcache[{hex(size)}] refill", user_pointer=True)
            chunk = self._chunks.get(chunk_id)
            if chunk:
                self._chunks[chunk_id] = replace(chunk, lifecycle="freed", bin_location=f"tcache[{hex(size)}]")
            moved.append(chunk_id)
        if not source:
            self._smallbins.pop(size, None)
        if moved:
            self._write_tcache_head(size, destination)
            notes.append("smallbin 额外节点回填 tcache: " + " -> ".join(moved))
            self._record_bin_transition(
                "refill", "smallbin->tcache", hex(size), moved[0],
                source_before, tuple(destination), moved,
                (), f"tcache before={destination_before}; source after={tuple(source)}",
            )
        return tuple(moved)

    @staticmethod
    def _external_target_token(kind: str, target: str) -> str:
        return f"@{kind}_target:{target}"

    @staticmethod
    def _external_target_from_token(token: str, kind: str) -> str:
        prefix = f"@{kind}_target:"
        return token[len(prefix):] if str(token).startswith(prefix) else ""

    def _create_remainder_chunk(self, source: ChunkState, consumed: int, remainder: int) -> str:
        self._physical_seq += 1
        remainder_id = f"remainder_{self._physical_seq:04d}"
        address = self._offset_address(source.address, consumed)
        self._chunks[remainder_id] = ChunkState(
            chunk_id=remainder_id,
            address=address,
            user_address=self._offset_address(address, self._word_size() * 2),
            physical_id=f"phys_{self._physical_seq:04d}",
            request_size=hex(max(0, remainder - self._word_size())),
            chunk_size=hex(remainder),
            lifecycle="freed",
            bin_location="unsorted",
            note=f"split remainder from {source.chunk_id}",
            role="remainder",
            heap_offset=self._heap_offset_for_address(address),
            provenance="derived",
            original_chunk_size=hex(remainder),
        )
        remainder_chunk = self._chunks[remainder_id]
        self._memory.register_object(remainder_chunk.physical_id, address, remainder, kind="malloc_chunk", label=remainder_id)
        self._write_chunk_size_header(remainder_chunk, remainder, note="split remainder header")
        return remainder_id

    def _bin_regular_chunk(self, chunk_id: str, size: int | None) -> None:
        chunk = self._chunks.get(chunk_id)
        if chunk is None:
            return
        if size is None:
            self._insert_doubly_node(self._unsorted, chunk_id, "unsorted", "unknown", at_head=True)
            return
        min_large_size = 0x400 if self.config.bits == 64 else 0x200
        if size < min_large_size:
            chain = self._smallbins.setdefault(size, [])
            self._insert_doubly_node(chain, chunk_id, f"smallbin[{hex(size)}]", hex(size), at_head=False)
        else:
            chain = self._largebins.setdefault(size, [])
            self._insert_doubly_node(chain, chunk_id, f"largebin[{hex(size)}]", hex(size), at_head=False)
            self._refresh_largebin_nextsize_metadata()

    def _alloc_address_override(self, operation: HeapOperation) -> str:
        """Normal malloc never teleports in strict mode.

        Explicit ``meta[address]`` is treated as an observed/manual address.  The
        legacy ``target`` override remains available only in plan mode.
        """
        explicit = str(operation.meta.get("address") or "").strip()
        if explicit:
            return explicit
        if self.config.simulation_mode != "plan":
            return ""
        target = operation.target.strip()
        if target in {"__free_hook", "__malloc_hook"}:
            return ""
        return target

    def _heap_address(self, offset: int) -> str:
        base_text = (self.config.heap_base or "heap_base").strip() or "heap_base"
        base_value = parse_int_expr(base_text, self.variables)
        if base_value is not None:
            return hex(base_value + offset)
        return f"{base_text}+0x{offset:x}" if offset else base_text

    def _unknown_heap_address(self, chunk_id: str, *, user: bool = False) -> str:
        base_text = (self.config.heap_base or "heap_base").strip() or "heap_base"
        suffix = "user" if user else "chunk"
        return f"{base_text}+?<{chunk_id}:{suffix}>"

    def _heap_offset_for_address(self, address: str) -> str:
        text = (address or "").strip().replace(" ", "")
        if not text:
            return ""
        base_text = (self.config.heap_base or "heap_base").strip().replace(" ", "") or "heap_base"
        if text == base_text:
            return "0x0"
        if text.startswith(base_text + "+"):
            return text[len(base_text) + 1 :]
        base_value = parse_int_expr(base_text, self.variables)
        address_value = parse_int_expr(text, self.variables)
        if base_value is not None and address_value is not None and address_value >= base_value:
            return hex(address_value - base_value)
        return ""

    def _free(self, operation: HeapOperation) -> tuple[list[HeapWarning], list[str]]:
        warnings: list[HeapWarning] = []
        explanation: list[str] = []
        chunk = self._find_chunk(operation)
        if not chunk:
            warnings.append(self._warning("ERROR", "free_unknown", "释放未知 chunk", "没有找到对应 chunk，先检查名称或菜单索引。", operation))
            return warnings, ["free 没有改变状态。"]
        was_freed = chunk.lifecycle == "freed"
        size = self._chunk_size_value(chunk)
        if was_freed:
            # glibc first compares the entry key stored in the freed user area.
            # Only a matching key starts the (memory-following) duplicate scan;
            # Python membership is deliberately not an allocator decision.
            tcache_duplicate = False
            tcache_key_match = size is not None and self._tcache_key_matches(chunk)
            if tcache_key_match and size is not None:
                tcache_duplicate = chunk.chunk_id in self._walk_tcache_from_memory(size)
            fast_chain = self._fastbins.get(size or -1, [])
            immediate_fastbin_dup = bool(fast_chain and fast_chain[0] == chunk.chunk_id)
            if self.config.simulation_mode == "strict" and ((self.config.tcache_key_check and tcache_duplicate) or immediate_fastbin_dup):
                code = "tcache_double_free_abort" if tcache_duplicate else "fastbin_double_free_abort"
                reason = "tcache key 命中后的 PhysicalMemory 链遍历" if tcache_duplicate else "fastbin top duplicate 检测"
                warnings.append(self._abort(
                    code, operation, reason, chunk.user_address,
                    {
                        "chunk": chunk.chunk_id,
                        "size": hex(size) if size is not None else "unknown",
                        "key_match": str(tcache_key_match).lower(),
                    },
                    chunk.chunk_id,
                ))
                return warnings, [f"free({chunk.chunk_id}) 被严格模式判定为 abort；后续状态停止推进。", "如果题目先破坏/绕过了对应检查，请切到演示模式或把绕过事实作为明确利用步骤建模。"]
            warnings.append(self._warning("EXPLOIT", "double_free", "重复释放", "当前版本/模式允许继续展示 double-free 利用意图，但不代表所有完整性检查都已满足。", operation, chunk.chunk_id))

        self._chunks[chunk.chunk_id] = replace(
            chunk,
            lifecycle="freed",
            bin_location="pending",
            note=operation.note or chunk.note,
            evidence_level="confirmed" if chunk.view_kind == "fake_chunk" else chunk.evidence_level,
        )
        self._mark_physical_handles(chunk.physical_id or chunk.chunk_id, "dangling")
        if size is None:
            self._remove_from_bins(chunk.chunk_id)
            self._chunks[chunk.chunk_id] = replace(
                self._chunks[chunk.chunk_id],
                bin_location="unknown",
                fd="",
                bk="",
                provenance="unknown",
            )
            warnings.append(
                self._warning(
                    "WARNING",
                    "unknown_free_bin",
                    "free 后 bin 无法确定",
                    "chunk size 未被源码或 Pwndbg 证明，不能推测 tcache/fastbin/unsorted。",
                    operation,
                    chunk.chunk_id,
                )
            )
            return warnings, [f"{chunk.chunk_id} 已释放；size/bin/fd/bk 保持 unknown，等待真实证据校准。"]
        bin_location = self._put_free_chunk(chunk.chunk_id, size, allow_duplicate=was_freed)

        # Real glibc tcache/fastbin frees deliberately keep the following
        # chunk's PREV_INUSE bit set.  A regular free, however, publishes its
        # size in next.prev_size and clears that bit in physical memory before
        # consolidation.  Typed views then read the result from memory.
        if bin_location == "unsorted" and not was_freed:
            self._set_following_prev_inuse(chunk, size, inuse=False, note="regular free boundary tag")

        active_id = chunk.chunk_id
        if bin_location == "unsorted" and not was_freed:
            active_id, merged = self._coalesce_regular_free(chunk.chunk_id)
            if merged:
                explanation.append("立即合并相邻的普通 free chunk：" + " + ".join(merged) + f" -> {active_id}。")

        updated = self._chunks[active_id]
        if updated.bin_location.startswith("unsorted") and self._is_top_adjacent(updated):
            if self._merge_into_top(active_id, operation.op_id):
                bin_location = "top"
                explanation.append(f"{active_id} 与 top 相邻，free 后按 PhysicalMemory.top.size 并回 top。")
            else:
                warnings.append(self._abort(
                    "top_merge_invalid", operation,
                    "top merge requires readable current/top sizes",
                    updated.address,
                    {"chunk": active_id}, active_id,
                ))
                return warnings, explanation
        else:
            self._refresh_freelist_metadata()
            updated = self._chunks[active_id]
            bin_location = updated.bin_location or bin_location
            explanation.append(f"{active_id} 进入 {bin_location}。")
            if updated.fd:
                explanation.append(f"freelist link: fd/next = {updated.fd}" + (f"，bk = {updated.bk}" if updated.bk else ""))
        self._step_free_events.append(FreeEvent(
            f"free_{operation.op_id}", operation.op_id, active_id,
            self._chunks[active_id].address, bin_location,
        ))
        return warnings, explanation

    def _tcache_key_matches(self, chunk: ChunkState) -> bool:
        """Read the tcache key from PhysicalMemory (never ChunkState/list)."""
        if not self.config.tcache_key_check:
            return False
        key_address = self._offset_address(chunk.address, self._word_size() * 3)
        read = self._memory.read(key_address, self._word_size())
        if read.data is not None:
            # The model uses a symbolic per-thread key because its runtime
            # address/value is not normally known.  Concrete zero/corruption
            # is necessarily not equal to that key.
            return False
        return (read.symbolic or "").strip() == "tcache_key"

    def _walk_singly_bin_from_memory(
        self,
        size: int,
        *,
        kind: str,
        user_pointer: bool,
        limit: int = 64,
    ) -> tuple[str, ...]:
        mapping = self._tcache if kind == "tcache" else self._fastbins
        chain = mapping.get(size, [])
        memory_head = self._tcache_head_token_from_memory(size) if kind == "tcache" else None
        if memory_head is not None:
            if not memory_head:
                return ()
            current = memory_head
        else:
            if not chain:
                return ()
            current = chain[0]
        result: list[str] = []
        seen_addresses: set[str] = set()
        for _ in range(max(1, limit)):
            if not current:
                break
            external = self._external_target_from_token(current, kind)
            if external:
                result.append(current)
                break
            chunk = self._chunks.get(current)
            if chunk is None:
                break
            result.append(current)
            address = chunk.user_address if user_pointer else chunk.address
            if address in seen_addresses:
                break
            seen_addresses.add(address)
            target = self._decoded_freelist_target(chunk)
            if not target or target in {"NULL", "0", "0x0"}:
                break
            next_chunk = next(
                (
                    candidate for candidate in self._chunks.values()
                    if candidate.lifecycle != "stale"
                    and self._same_pointer(candidate.user_address if user_pointer else candidate.address, target)
                ),
                None,
            )
            if next_chunk is None:
                result.append(self._external_target_token(kind, target))
                break
            current = next_chunk.chunk_id
        return tuple(result)

    def _walk_tcache_from_memory(self, size: int, *, limit: int = 64) -> tuple[str, ...]:
        """Traverse tcache from the cached head, following current memory links."""
        return self._walk_singly_bin_from_memory(size, kind="tcache", user_pointer=True, limit=limit)

    def _walk_fastbin_from_memory(self, size: int, *, limit: int = 64) -> tuple[str, ...]:
        """Traverse fastbin from the cached head, following current memory links."""
        return self._walk_singly_bin_from_memory(size, kind="fastbin", user_pointer=False, limit=limit)

    def _coalesce_regular_free(self, chunk_id: str) -> tuple[str, list[str]]:
        """Perform glibc-style boundary-tag consolidation from PhysicalMemory."""
        current = self._chunks.get(chunk_id)
        if current is None:
            return chunk_id, []
        current_start = self._heap_offset_value(current)
        current_size = self._chunk_size_value(current)
        if current_start is None or current_size is None:
            return chunk_id, []
        members: list[ChunkState] = [current]
        start = current_start
        total = current_size
        raw_size = self._memory.read_uint(
            self._offset_address(current.address, self._word_size()), self._word_size(),
        )
        # backward: the current chunk's own PREV_INUSE and prev_size decide.
        if raw_size is not None and not (raw_size & 1):
            prev_size = self._memory.read_uint(current.address, self._word_size())
            if prev_size is not None and prev_size >= self.config.alignment and prev_size % self.config.alignment == 0:
                previous = self._chunk_at_heap_offset(start - prev_size)
                previous_size = self._chunk_size_value(previous) if previous is not None else None
                if previous is not None and previous_size == prev_size and self._is_regular_free_member(previous):
                    members.insert(0, previous)
                    start -= prev_size
                    total += prev_size
                else:
                    self._model_divergences.append(
                        f"boundary tag requests prev={hex(start - prev_size)} size={hex(prev_size)}, "
                        "but no consistent regular-bin predecessor exists"
                    )

        # forward: glibc's inuse_bit_at_offset(next, nextsize) is the
        # PREV_INUSE bit stored in the chunk after ``next``.
        next_offset = start + total
        if next_offset != self._next_offset:
            following = self._chunk_at_heap_offset(next_offset)
            following_size = self._chunk_size_value(following) if following is not None else None
            if following is not None and following_size is not None:
                after_size = self._memory.read_uint(
                    self._offset_address(following.address, following_size + self._word_size()),
                    self._word_size(),
                )
                if after_size is not None and not (after_size & 1) and self._is_regular_free_member(following):
                    members.append(following)
                    total += following_size
        if len(members) == 1:
            return chunk_id, []
        members.sort(key=lambda item: self._heap_offset_value(item) or 0)
        representative = members[0]
        representative_id = representative.chunk_id
        representative_pid = representative.physical_id or representative.chunk_id
        for item in members:
            self._remove_from_bins(item.chunk_id)
        for item in members[1:]:
            for index, handle in list(self._handles.items()):
                if handle.physical_id == (item.physical_id or item.chunk_id):
                    self._handles[index] = replace(handle, physical_id=representative_pid, status="dangling")
            self._chunks[item.chunk_id] = replace(
                item,
                lifecycle="stale",
                bin_location=f"merged into {representative_id}",
                role="coalesced-alias",
                physical_id=representative_pid,
                fd="",
                bk="",
                note=f"physical range coalesced into {representative_id}",
            )
        self._chunks[representative_id] = replace(
            representative,
            chunk_size=hex(total),
            lifecycle="freed",
            bin_location="unsorted",
            role="consolidated",
            fd="",
            bk="",
            note=(representative.note + " | coalesced").strip(" |"),
            physical_id=representative_pid,
        )
        self._memory.register_object(representative_pid, representative.address, total, kind="malloc_chunk", label=representative_id)
        self._write_chunk_size_header(representative, total, note="coalesced chunk size")
        self._set_following_prev_inuse(representative, total, inuse=False, note="coalesced boundary tag")
        self._insert_doubly_node(
            self._unsorted,
            representative_id,
            "unsorted",
            hex(total),
            at_head=True,
            note="coalesced representative inserted",
        )
        return representative_id, [item.chunk_id for item in members]

    def _chunk_at_heap_offset(self, offset: int) -> ChunkState | None:
        candidates = [
            chunk for chunk in self._chunks.values()
            if self._heap_offset_value(chunk) == offset and chunk.lifecycle != "stale"
        ]
        if not candidates:
            return None
        priority = {"freed": 3, "allocated": 2, "fake": 1}
        return max(candidates, key=lambda item: priority.get(item.lifecycle, 0))

    @staticmethod
    def _is_regular_free_member(chunk: ChunkState) -> bool:
        location = chunk.bin_location.lower()
        return chunk.lifecycle == "freed" and not (
            location.startswith("tcache") or location.startswith("fastbin") or location == "top"
        )

    def _mark_old_top_fragments(self, active_id: str) -> None:
        active = self._chunks.get(active_id)
        if active is None:
            return
        active_start = self._heap_offset_value(active)
        if active_start is None:
            return
        for chunk_id, chunk in list(self._chunks.items()):
            if chunk_id == active_id or chunk.bin_location != "top":
                continue
            start = self._heap_offset_value(chunk)
            if start is not None and start >= active_start:
                self._chunks[chunk_id] = replace(
                    chunk,
                    lifecycle="stale",
                    bin_location=f"merged into top via {active_id}",
                    role="top-fragment",
                    physical_id=active.physical_id or active.chunk_id,
                )

    def _heap_offset_value(self, chunk: ChunkState) -> int | None:
        value = parse_int_expr(chunk.heap_offset, self.variables)
        if value is not None:
            return value
        address = self._chunk_address_value(chunk)
        base = parse_int_expr(self.config.heap_base, self.variables)
        if address is not None and base is not None:
            return address - base
        return None

    def _is_top_adjacent(self, chunk: ChunkState) -> bool:
        offset = self._heap_offset_value(chunk)
        size = self._chunk_size_value(chunk)
        return offset is not None and size is not None and offset + size == self._next_offset

    def _merge_into_top(self, chunk_id: str, operation_id: str) -> bool:
        """Merge an adjacent regular chunk with the current memory-backed top."""
        chunk = self._chunks.get(chunk_id)
        if chunk is None or not self._is_top_adjacent(chunk):
            return False
        chunk_size = self._chunk_size_value(chunk)
        top_size = self._top_size_from_memory()
        start = self._heap_offset_value(chunk)
        if chunk_size is None or top_size is None or start is None:
            return False
        merged_size = chunk_size + top_size
        raw = self._memory.read_uint(
            self._offset_address(chunk.address, self._word_size()), self._word_size(),
        )
        flags = (raw if raw is not None else 1) & 0x7
        self._remove_from_bins(chunk_id)
        self._next_offset = start
        provenance = MemoryProvenance.derived(operation_id, writer="allocator", note="top merge from memory")
        self._memory.register_object("top", chunk.address, merged_size, kind="top_chunk", label="top", provenance="derived")
        self._memory.write_uint(
            self._offset_address(chunk.address, self._word_size()),
            merged_size | flags,
            self._word_size(),
            provenance,
            state="metadata",
        )
        self._chunks[chunk_id] = replace(
            chunk,
            chunk_size=hex(merged_size),
            bin_location="top",
            role="top-merged",
            fd="",
            bk="",
        )
        self._mark_old_top_fragments(chunk_id)
        return True

    def _edit(self, operation: HeapOperation) -> tuple[list[HeapWarning], list[str]]:
        warnings: list[HeapWarning] = []
        explanation: list[str] = []
        chunk = self._find_chunk(operation)
        if not chunk:
            warnings.append(self._warning("ERROR", "edit_unknown", "编辑未知 chunk", "没有找到对应 chunk。", operation))
            return warnings, ["edit 没有改变状态。"]
        if chunk.lifecycle == "freed":
            warnings.append(self._warning("EXPLOIT", "uaf_edit", "编辑已释放 chunk", "这是 UAF edit 原语，通常用于改 freelist 指针。", operation, chunk.chunk_id))
            explanation.append(f"{chunk.chunk_id} 已 free，但菜单句柄仍可写：检测到 UAF edit。")
        payload = self._write_operation_payload(operation, chunk, operation.data or operation.value)
        if payload.length is None:
            warnings.append(self._warning(
                "WARNING", "payload_unknown", "写入 payload 长度无法证明",
                "保留表达式，但不会猜测物理覆盖范围。", operation, chunk.chunk_id,
            ))
        if chunk.lifecycle == "freed" and (chunk.bin_location.startswith("tcache") or chunk.bin_location.startswith("fastbin")):
            target = self._decoded_freelist_target(chunk)
            if target and target not in {"NULL", "0", "0x0"}:
                self._chunks[chunk.chunk_id] = replace(self._chunks[chunk.chunk_id], role="poisoned", provenance="derived")
                warnings.append(self._warning(
                    "EXPLOIT", "freelist_poison_inferred", "PhysicalMemory 中的 freelist next 已变更",
                    f"{chunk.chunk_id}.next 当前解码为 {target}；malloc 仍需在取出该节点时再验证。",
                    operation, chunk.chunk_id,
                ))
                explanation.append(f"从 next 字段当前物理字节解码：{target}。")
        current_chunk = self._chunks.get(chunk.chunk_id, chunk)
        self._chunks[chunk.chunk_id] = replace(current_chunk, data=operation.data or operation.value, note=operation.note or current_chunk.note)
        explanation.append(
            f"通过 {chunk.user_address} 写入 {payload.length if payload.length is not None else 'unknown'} 字节；"
            f"物理影响由 {len(self._step_overwrite_edges)} 条 OverwriteEdge 记录。"
        )
        return warnings, explanation

    def _infer_freelist_target_from_data(self, data: str, chunk: ChunkState) -> tuple[str, str]:
        text = str(data or "").strip()
        match = re.fullmatch(r"p(?:32|64)\s*\((?P<expr>.*)\)", text)
        if not match:
            return "", ""
        expression = match.group("expr").strip()
        seen: set[str] = set()
        while re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expression) and expression in self.variables and expression not in seen:
            seen.add(expression)
            expression = str(self.variables[expression]).strip()

        try:
            tree = ast.parse(expression, mode="eval").body
        except SyntaxError:
            return "", expression

        if self.config.safe_linking:
            if isinstance(tree, ast.BinOp) and isinstance(tree.op, ast.BitXor):
                left_shift = self._is_shift12_expr(tree.left)
                right_shift = self._is_shift12_expr(tree.right)
                if left_shift ^ right_shift:
                    target_node = tree.right if left_shift else tree.left
                    try:
                        return ast.unparse(target_node).strip(), expression
                    except Exception:
                        return "", expression
            encoded = parse_int_expr(expression, self.variables)
            storage = parse_int_expr(self._fd_field_address(chunk), self.variables)
            if encoded is not None and storage is not None:
                return hex(encoded ^ (storage >> 12)), expression
            return "", expression

        value = parse_int_expr(expression, self.variables)
        if value is not None:
            return hex(value), expression
        try:
            return ast.unparse(tree).strip(), expression
        except Exception:
            return expression, expression

    @staticmethod
    def _is_shift12_expr(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.RShift)
            and isinstance(node.right, ast.Constant)
            and node.right.value == 12
        )

    def _show(self, operation: HeapOperation) -> tuple[list[HeapWarning], list[str]]:
        chunk = self._find_chunk(operation)
        result_var = operation.meta.get("result_var") or "leak"
        expression = operation.meta.get("expression") or f"{operation.meta.get('function') or 'show'}({operation.index or operation.chunk or '0'})"
        if not chunk:
            self._observations.append(
                ValueObservation(
                    name=result_var,
                    expression=expression,
                    value="<runtime bytes unknown>",
                    kind="show",
                    provenance="unknown",
                    detail="菜单索引无法关联到当前 allocator handle；没有伪造泄漏内容。",
                )
            )
            return [self._warning("WARNING", "show_unknown", "查看未知 chunk", "无法把 show 关联到已知 chunk。", operation)], [f"{result_var} 接收 show 返回值，但当前模型无法关联其来源。"]

        value, integer_value, detail = self._show_memory_value(chunk)
        self._observations.append(
            ValueObservation(
                name=result_var,
                expression=expression,
                value=value,
                source_chunk=chunk.chunk_id,
                source_address=chunk.user_address,
                kind="show",
                provenance="derived",
                integer_value=integer_value,
                detail=detail,
            )
        )
        self._step_read_events.append(ReadEvent(
            f"read_{operation.op_id}", operation.op_id, chunk.user_address,
            self._word_size(), value, "derived",
        ))
        return [], [f"{result_var} = show({operation.index or chunk.chunk_id})：读取 {chunk.chunk_id} 用户区起点 {chunk.user_address}。", detail]

    def _derive_value(self, operation: HeapOperation) -> tuple[list[HeapWarning], list[str]]:
        result_var = operation.meta.get("result_var") or operation.chunk or "value"
        expression = operation.meta.get("expression") or operation.value or operation.data or "0"
        by_name = {item.name: item for item in self._observations}
        dependency_names = tuple(
            name for name in self._expression_names(expression)
            if name in by_name
        )
        explicit_dependencies = tuple(
            item.strip() for item in operation.meta.get("dependencies", "").split(",") if item.strip()
        )
        dependencies = tuple(dict.fromkeys(explicit_dependencies + dependency_names))
        source = next((by_name[name] for name in reversed(dependencies) if name in by_name), None)

        value = expression
        integer_value = ""
        detail = "按 EXP 表达式继续派生；这是静态/allocator 推导，不是运行时采样。"
        transform = self._decode_unpack_slice_shift(expression)
        if transform:
            source_name, take, width, shift = transform
            source_observation = by_name.get(source_name)
            source_integer = parse_int_expr(source_observation.integer_value, self.variables) if source_observation else None
            mask = (1 << (take * 8)) - 1
            if source_integer is not None:
                result = (source_integer & mask) << shift
                integer_value = hex(result)
                value = integer_value
            else:
                source_word = source_observation.integer_value if source_observation and source_observation.integer_value else f"u{width * 8}({source_name})"
                integer_value = f"(({source_word}) & {hex(mask)}) << {shift}"
                value = integer_value
            detail = f"取 {source_name} 的前 {take} 字节，补零到 {width} 字节，按 little-endian 解包后左移 {shift} 位。"
            source = source_observation or source
        else:
            numeric_variables = dict(self.variables)
            for name, item in by_name.items():
                number = parse_int_expr(item.integer_value, self.variables)
                if number is not None:
                    numeric_variables[name] = number
            result = parse_int_expr(expression, numeric_variables)
            if result is not None:
                integer_value = hex(result)
                value = integer_value

        self._observations.append(
            ValueObservation(
                name=result_var,
                expression=expression,
                value=value,
                source_chunk=source.source_chunk if source else "",
                source_address=source.source_address if source else "",
                kind="derived",
                provenance="derived" if dependencies else "inferred",
                dependencies=dependencies,
                integer_value=integer_value,
                detail=detail,
            )
        )
        dependency_text = ", ".join(dependencies) or "无已知 show 依赖"
        return [], [f"{result_var} = {expression}", f"value flow: {dependency_text}；{detail}"]

    def _show_memory_value(self, chunk: ChunkState) -> tuple[str, str, str]:
        pack = "p64" if self.config.bits == 64 else "p32"
        location = (chunk.bin_location or "").lower()
        if location.startswith("tcache") or location.startswith("fastbin"):
            memory_word = self._memory.read(chunk.user_address, self._word_size())
            stored = hex(int.from_bytes(memory_word.data, "little")) if memory_word.data is not None else (memory_word.symbolic or "unknown")
            integer_value = stored if memory_word.data is not None else self._freelist_word_integer(chunk, stored)
            rendered = integer_value or stored
            decoded = self._decoded_freelist_target(chunk) or "unknown"
            detail = f"freed 单链节点：show 从 PhysicalMemory 读取 {chunk.bin_location} next/fd；stored={stored}，decoded={decoded}。"
            second_word = f" + {pack}(tcache_key)" if location.startswith("tcache") and self.config.tcache_key_check else ""
            if second_word:
                detail += " 第二个机器字是 glibc tcache double-free key。"
            return f"{pack}({rendered}){second_word} + <remaining user bytes>", integer_value, detail
        if location == "unsorted" or "smallbin" in location or "largebin" in location:
            first = self._memory.read(chunk.user_address, self._word_size())
            second = self._memory.read(self._offset_address(chunk.user_address, self._word_size()), self._word_size())
            fd = hex(int.from_bytes(first.data, "little")) if first.data is not None else (first.symbolic or chunk.fd or "unknown")
            bk = hex(int.from_bytes(second.data, "little")) if second.data is not None else (second.symbolic or chunk.bk or "unknown")
            detail = f"freed 双链节点：用户区前两个机器字分别是 fd 和 bk（{chunk.bin_location}）。"
            return f"{pack}({fd}) + {pack}({bk}) + <remaining user bytes>", "", detail

        size = self._chunk_size_value(chunk)
        capacity = max((size or self._word_size() * 2) - self._word_size() * 2, 0)
        memory = self._memory.read(chunk.user_address, capacity)
        if memory.data is not None:
            first = memory.data[: self._word_size()].ljust(self._word_size(), b"\x00")
            return repr(memory.data), hex(int.from_bytes(first, "little")), "allocated/user-controlled 区域：内容直接来自 PhysicalMemory。"
        known = [span for span in memory.spans if span.data is not None or span.symbolic]
        if known:
            rendered = " + ".join(repr(span.data) if span.data is not None else span.symbolic for span in known)
            return rendered, "", "allocated/user-controlled 区域：展示已知物理 span，未写入空洞保持 unknown。"
        return f"<{hex(capacity)} runtime user bytes>", "", "用户区没有可证明的已知字节；保持 unknown，不用 0 填充冒充真实内存。"

    def _freelist_word_integer(self, chunk: ChunkState, stored: str) -> str:
        text = str(stored or "").strip()
        match = re.fullmatch(r"PROTECT_PTR\((?P<pos>.+),\s*(?P<target>.+)\)", text)
        if match:
            pos = parse_int_expr(match.group("pos").strip(), self.variables)
            target_text = match.group("target").strip()
            target = 0 if target_text == "NULL" else self._pointer_value_from_ref(target_text)
            if pos is not None and target is not None:
                return hex((pos >> 12) ^ target)
            if target_text == "NULL":
                return f"({match.group('pos').strip()}) >> 12"
            return ""
        value = self._pointer_value_from_ref(text)
        return hex(value) if value is not None else ""

    def _pointer_value_from_ref(self, text: str) -> int | None:
        value = parse_int_expr(text, self.variables)
        if value is not None:
            return value
        address_match = re.search(r"@\s*([^\s(]+)", text)
        if address_match:
            return parse_int_expr(address_match.group(1), self.variables)
        return None

    def _literal_first_word(self, data: str) -> str:
        if not data:
            return ""
        try:
            value = ast.literal_eval(data)
        except (SyntaxError, ValueError):
            return ""
        if isinstance(value, str):
            value = value.encode()
        if not isinstance(value, bytes):
            return ""
        word = value[: self._word_size()].ljust(self._word_size(), b"\x00")
        return hex(int.from_bytes(word, "little"))

    @staticmethod
    def _expression_names(expression: str) -> tuple[str, ...]:
        try:
            tree = ast.parse(expression, mode="eval")
        except SyntaxError:
            return ()
        return tuple(dict.fromkeys(node.id for node in ast.walk(tree) if isinstance(node, ast.Name)))

    @staticmethod
    def _decode_unpack_slice_shift(expression: str) -> tuple[str, int, int, int] | None:
        """Recognize u64(data[:5].ljust(8, b'\\x00')) << 12 safely via AST."""
        try:
            node = ast.parse(expression, mode="eval").body
        except SyntaxError:
            return None
        shift = 0
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.LShift) and isinstance(node.right, ast.Constant) and isinstance(node.right.value, int):
            shift = int(node.right.value)
            node = node.left
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id not in {"u32", "u64"} or len(node.args) != 1:
            return None
        unpack_width = 4 if node.func.id == "u32" else 8
        inner = node.args[0]
        if not isinstance(inner, ast.Call) or not isinstance(inner.func, ast.Attribute) or inner.func.attr != "ljust" or not inner.args:
            return None
        width_node = inner.args[0]
        if not isinstance(width_node, ast.Constant) or not isinstance(width_node.value, int):
            return None
        sliced = inner.func.value
        if not isinstance(sliced, ast.Subscript) or not isinstance(sliced.value, ast.Name):
            return None
        slice_node = sliced.slice
        if not isinstance(slice_node, ast.Slice) or slice_node.lower is not None or not isinstance(slice_node.upper, ast.Constant) or not isinstance(slice_node.upper.value, int):
            return None
        width = int(width_node.value)
        take = int(slice_node.upper.value)
        if width != unpack_width or take < 1 or take > width:
            return None
        return sliced.value.id, take, width, shift

    def _copy_chunk(self, operation: HeapOperation) -> tuple[list[HeapWarning], list[str]]:
        source_id = operation.meta.get("src_chunk") or operation.target
        destination = self._find_chunk(operation)
        source = self._find_chunk_by_ref(source_id) if source_id else None
        if destination is None or source is None:
            return [
                self._warning(
                    "WARNING",
                    "copy_unknown",
                    "copy_chunk 关联不完整",
                    "源或目标 chunk 尚未在时间线中建立，保留原始 copy 语义。",
                    operation,
                )
            ], ["copy_chunk 未改变已知 chunk 状态。"]
        length_text = operation.request_size or operation.meta.get("length") or "unknown"
        length = parse_int_expr(length_text, self.variables)
        user_capacity = max((parse_int_expr(destination.chunk_size) or 0) - self._word_size() * 2, 0)
        overflow = length is None or length < 0 or length > user_capacity
        affected_chunks = self._copy_overlapped_chunks(destination, length)
        copied_data = f"({source.data or 'NULL'})[:{length_text}]"
        note = operation.note or f"copy_chunk({source.chunk_id} -> {destination.chunk_id}, {length_text})"
        role = "copy-overflow" if overflow else "copied"
        if length is not None and length >= 0:
            payload = self._payload_from_memory(source.user_address, length, copied_data)
            self._commit_payload(operation, destination, payload, copied_data)
        self._chunks[destination.chunk_id] = replace(destination, data=copied_data, note=note, role=role)
        self._mark_copy_overlapped_chunks(affected_chunks, operation)
        if overflow:
            return [
                self._warning(
                    "EXPLOIT",
                    "copy_overlap",
                    "copy 可能覆盖相邻 chunk",
                    f"length={length_text} 超过 {destination.chunk_id} 用户区容量 {hex(user_capacity)}。",
                    operation,
                    destination.chunk_id,
                    *affected_chunks,
                )
            ], [
                f"{source.chunk_id} -> {destination.chunk_id} 复制长度 {length_text}。",
                "长度超出目标用户区，图中以 copy-overflow 标记可能覆盖 header/相邻块。",
            ]
        return [], [f"{source.chunk_id} -> {destination.chunk_id} 复制 {length_text} 字节，目标内容保持为可追溯表达式。"]

    def _copy_overlapped_chunks(self, destination: ChunkState, length: int | None) -> list[str]:
        if length is None or length <= 0:
            return []
        dest_start = self._chunk_address_value(destination)
        dest_size = self._chunk_size_value(destination)
        if dest_start is None or dest_size is None:
            return []
        user_start = dest_start + self._word_size() * 2
        dest_end = dest_start + dest_size
        write_end = user_start + length
        if write_end <= dest_end:
            return []
        affected: list[str] = []
        for chunk in self._ordered_physical_chunks():
            if chunk.chunk_id == destination.chunk_id:
                continue
            start = self._chunk_address_value(chunk)
            size = self._chunk_size_value(chunk)
            if start is None or size is None:
                continue
            end = start + size
            if start < write_end and end > dest_end:
                affected.append(chunk.chunk_id)
        return affected

    def _mark_copy_overlapped_chunks(self, chunk_ids: list[str], operation: HeapOperation) -> None:
        for chunk_id in chunk_ids:
            chunk = self._chunks.get(chunk_id)
            if not chunk:
                continue
            note = operation.note or f"covered by copy_chunk overflow from {operation.chunk or operation.index}"
            self._chunks[chunk_id] = replace(chunk, role="copy-overlapped", note=note)

    def _safe_link_fd(self, operation: HeapOperation) -> tuple[list[HeapWarning], list[str]]:
        return self._poison_fd(operation, force_safe_link=True)

    def _overflow_header(self, operation: HeapOperation) -> tuple[list[HeapWarning], list[str]]:
        chunk = self._find_chunk(operation)
        if not chunk:
            return [self._warning("ERROR", "overflow_unknown", "溢出目标未知", "没有找到被溢出的 chunk。", operation)], ["overflow 没有改变状态。"]
        field = operation.field or operation.meta.get("field") or "size/prev_size"
        value = operation.value or operation.data or operation.meta.get("value") or "controlled"
        note = operation.note or f"overflow header: {field} = {value}"
        self._chunks[chunk.chunk_id] = replace(chunk, data=operation.data or chunk.data, note=note, role="overflow-source")
        if str(field).replace(" ", "").lower() == "top.size" and self._layout_known:
            destination = self._memory.address(chunk.user_address)
            target = self._memory.address(
                self._offset_address(self._heap_address(self._next_offset), self._word_size())
            )
            distance = destination.distance_to(target)
            if distance is not None and distance >= 0:
                expression = f"b'X' * {distance} + p{self.config.bits}({value})"
                synthetic = replace(operation, data=expression)
                self._write_operation_payload(synthetic, chunk, expression)
                return [self._warning(
                    "EXPLOIT", "header_overflow", "覆盖 top.size",
                    "写入已经 PhysicalMemory/WriteImpact 主链；下一次 malloc 会重新读取该字段。",
                    operation, chunk.chunk_id,
                )], [
                    f"{chunk.chunk_id} 通过距 user pointer +0x{distance:x} 的普通写入覆盖 top.size={value}。",
                    "House 名称不会推进 allocator；只有这次物理写入和后续 malloc 读取会改变结果。",
                ]
        return [self._warning("EXPLOIT", "header_overflow", "覆盖 chunk header", f"通过 {chunk.chunk_id} 覆盖 {field}。", operation, chunk.chunk_id)], [
            f"{chunk.chunk_id} 被标记为 header overflow 来源。",
            f"关注字段：{field} = {value}。",
        ]

    def _poison_fd(self, operation: HeapOperation, force_safe_link: bool = False) -> tuple[list[HeapWarning], list[str]]:
        warnings: list[HeapWarning] = []
        chunk = self._find_chunk(operation)
        if not chunk:
            warnings.append(self._warning("ERROR", "poison_unknown", "poison 目标未知", "没有找到要改 fd 的 chunk。", operation))
            return warnings, ["fd poisoning 没有改变状态。"]
        target = operation.target or "target"
        use_safe_link = force_safe_link or self.config.safe_linking
        if use_safe_link:
            if not self.config.safe_linking:
                warnings.append(self._warning("WARNING", "safe_linking_disabled", "当前 glibc 未默认启用 safe-linking", "glibc 2.32 之前通常不需要 fd 编码。", operation, chunk.chunk_id))
            fd_storage = operation.fd_storage or operation.meta.get("fd_storage") or self._fd_field_address(chunk)
            fd_expr = safe_link_encode_expr(target, fd_storage)
            formula = f"encoded_fd = {fd_expr}"
        else:
            fd_expr = target
            formula = f"fd = {target}"
        synthetic = replace(operation, data=f"p{self.config.bits}({fd_expr})")
        self._write_operation_payload(synthetic, chunk, synthetic.data)
        self._chunks[chunk.chunk_id] = replace(chunk, fd=fd_expr, data=synthetic.data, note=operation.note or "poisoned fd", role="poisoned", provenance="inferred")
        size = self._chunk_size_value(chunk)
        effective_freelist = size is not None and (chunk.bin_location.startswith("tcache") or chunk.bin_location.startswith("fastbin"))
        if not effective_freelist and self.config.simulation_mode == "strict":
            warnings.append(self._warning("WARNING", "poison_not_freelist", "fd 修改尚不能影响 malloc", f"{chunk.chunk_id} 当前位于 {chunk.bin_location or chunk.lifecycle}，不是模型中的 tcache/fastbin freelist 节点。", operation, chunk.chunk_id))
        target_ok, target_reason = target_compatibility(target, self.config)
        if not target_ok:
            warnings.append(self._warning("WARNING", "target_incompatible", "目标与当前 glibc 不兼容", target_reason, operation, chunk.chunk_id))
        return warnings + [self._warning("EXPLOIT", "fd_poison", "伪造 freelist fd", f"{chunk.chunk_id}.fd -> {target}", operation, chunk.chunk_id)], [
            f"把 {chunk.chunk_id}.fd 改成目标分配地址。",
            formula,
            "严格模式会在 malloc 取出该节点时重新读取 PhysicalMemory.next，不依赖攻击名称推进状态。",
            "如果开启 safe-linking，pos 应该是保存 next/fd 的字段地址，不是无条件 heap_base >> 12。",
        ]

    def _fake_chunk(self, operation: HeapOperation) -> tuple[list[HeapWarning], list[str]]:
        chunk_id = operation.chunk or f"fake_{len(self._chunks)}"
        size_expr = operation.request_size or operation.meta.get("size") or operation.value or "0x90"
        address = operation.meta.get("address") or operation.target or chunk_id
        prev_size = operation.meta.get("prev_size", "0")
        fd = operation.meta.get("fd", operation.fd_storage or "")
        bk = operation.meta.get("bk", operation.value if operation.field == "bk" else "")
        word = self._word_size()
        fields = (
            ChunkField("+0x00", "prev_size", prev_size, "fake chunk header from EXP", self._offset_address(address, 0), "prev_size"),
            ChunkField(f"+0x{word:02x}", "size", size_expr, "fake chunk size from EXP", self._offset_address(address, word), "size"),
            ChunkField(f"+0x{word * 2:02x}", "fd", fd or "NULL", "fake chunk fd from EXP", self._offset_address(address, word * 2), "fd"),
            ChunkField(f"+0x{word * 3:02x}", "bk", bk or "NULL", "fake chunk bk from EXP", self._offset_address(address, word * 3), "bk"),
        )
        self._physical_seq += 1
        self._chunks[chunk_id] = ChunkState(
            chunk_id=chunk_id,
            address=address,
            user_address=self._offset_address(address, word * 2),
            physical_id=f"fake_{self._physical_seq:04d}",
            request_size=size_expr,
            chunk_size=size_expr,
            lifecycle="fake",
            bin_location=operation.meta.get("bin", "fake"),
            fd=fd,
            bk=bk,
            data=operation.data,
            note=operation.note or "fake chunk",
            role=operation.meta.get("role", "fake"),
            fields=fields,
            heap_offset=self._heap_offset_for_address(address),
            provenance="assumed",
            original_chunk_size=size_expr,
            view_kind="fake_chunk",
            evidence_level=str(operation.meta.get("evidence_level") or "candidate"),
        )
        fake = self._chunks[chunk_id]
        size_value = parse_int_expr(size_expr, self.variables)
        self._memory.register_object(fake.physical_id, address, size_value or word * 4, kind="fake_chunk", label=chunk_id, provenance="assumed")
        self._write_metadata_value(address, prev_size, word, operation.op_id, offset=0, note="fake prev_size")
        self._write_metadata_value(address, size_expr, word, operation.op_id, offset=word, note="fake size")
        self._write_metadata_value(address, fd or "0", word, operation.op_id, offset=word * 2, note="fake fd")
        self._write_metadata_value(address, bk or "0", word, operation.op_id, offset=word * 3, note="fake bk")
        return [self._warning("EXPLOIT", "fake_chunk", "伪造 chunk", f"在 {address} 布置 fake chunk。", operation, chunk_id)], [
            f"创建 fake chunk {chunk_id} @ {address}，size={size_expr}。",
            "用于 House/unsafe unlink/smallbin/tcache 等流程中的可控内存结构。",
        ]

    def _unlink_prepare(self, operation: HeapOperation) -> tuple[list[HeapWarning], list[str]]:
        chunk = self._find_chunk(operation)
        if not chunk:
            return [self._warning("ERROR", "unlink_unknown", "unlink 目标未知", "没有找到要准备 unlink 的 chunk。", operation)], ["unlink prepare 没有改变状态。"]
        fd = operation.fd_storage or operation.meta.get("fd") or chunk.fd or f"{chunk.address}"
        bk = operation.target or operation.meta.get("bk") or chunk.bk or f"{chunk.address}"
        self._write_metadata_value(chunk.address, fd, self._word_size(), operation.op_id, offset=self._word_size() * 2, note="unlink fd")
        self._write_metadata_value(chunk.address, bk, self._word_size(), operation.op_id, offset=self._word_size() * 3, note="unlink bk")
        self._chunks[chunk.chunk_id] = replace(chunk, fd=fd, bk=bk, note=operation.note or "unlink metadata prepared", role="unlink", provenance="inferred")
        already_regular = "smallbin" in chunk.bin_location or "largebin" in chunk.bin_location or chunk.bin_location == "unsorted"
        if self.config.simulation_mode == "plan" and not already_regular:
            size = parse_int_expr(chunk.chunk_size, self.variables)
            self._remove_from_bins(chunk.chunk_id)
            if size is not None:
                self._smallbins.setdefault(size, []).insert(0, chunk.chunk_id)
                self._chunks[chunk.chunk_id] = replace(self._chunks[chunk.chunk_id], bin_location=f"smallbin[{chunk.chunk_size}]", provenance="assumed")
        status = "verified" if already_regular else "pending"
        self._step_intents.append(HeapIntent("unlink", operation.target or bk, status, "fd/bk 已布置；是否能触发 unlink 仍由真实 bin 状态/完整性检查决定。", operation.op_id))
        warnings = [self._warning("EXPLOIT", "unlink_prepare", "准备 unlink 元数据", f"{chunk.chunk_id}.fd/bk 已标注。", operation, chunk.chunk_id)]
        if not already_regular and self.config.simulation_mode == "strict":
            warnings.append(self._warning("WARNING", "unlink_not_in_bin", "当前状态无法证明会触发 unlink", "严格模式不会因为 UNLINK_PREPARE 就把 chunk 强行搬进 smallbin。", operation, chunk.chunk_id))
        return warnings, [f"{chunk.chunk_id}: fd={fd}", f"{chunk.chunk_id}: bk={bk}", "这一步只记录内存破坏事实/利用意图，不替 allocator 自动完成 bin 迁移。"]

    def _consolidate(self, operation: HeapOperation) -> tuple[list[HeapWarning], list[str]]:
        moved_ids: list[str] = []
        moved_labels: list[str] = []
        merged_groups: list[str] = []
        for size, chain in list(self._fastbins.items()):
            while chain:
                before = tuple(chain)
                chunk_id = chain.pop(0)
                self._record_bin_transition("consolidate-pop", "fastbin", hex(size), chunk_id, before, chain, (chunk_id,), (), "malloc_consolidate consumes fastbin head")
                if chunk_id not in self._unsorted:
                    self._insert_doubly_node(self._unsorted, chunk_id, "unsorted", hex(size), at_head=True, note="malloc_consolidate inserts unsorted")
                chunk = self._chunks.get(chunk_id)
                if chunk:
                    self._chunks[chunk_id] = replace(chunk, lifecycle="freed", bin_location="unsorted(consolidated)", role="consolidated")
                    # Fastbin free kept the following PREV_INUSE bit set.
                    # malloc_consolidate now converts the entry into a regular
                    # free and publishes its boundary tag before checking
                    # neighbours, exactly where the decision becomes visible.
                    self._set_following_prev_inuse(chunk, size, inuse=False, note="malloc_consolidate boundary tag")
                    representative, merged = self._coalesce_regular_free(chunk_id)
                    if merged:
                        merged_groups.append(" + ".join(merged) + f" -> {representative}")
                    representative_chunk = self._chunks.get(representative)
                    if representative_chunk and representative_chunk.lifecycle == "freed" and self._is_top_adjacent(representative_chunk):
                        self._merge_into_top(representative, operation.op_id)
                moved_ids.append(chunk_id)
                moved_labels.append(f"{chunk_id}:{hex(size)}")
        self._fastbins = {size: chain for size, chain in self._fastbins.items() if chain}
        self._refresh_freelist_metadata()
        details = [
            "模拟一次 malloc_consolidate：先把 fastbin 从 singly-linked 快速链取出，再按物理相邻关系合并。",
            "处理 fastbin: " + (", ".join(moved_labels) if moved_labels else "当前没有 fastbin chunk"),
        ]
        if merged_groups:
            details.append("物理合并: " + "；".join(merged_groups))
        return [self._warning("EXPLOIT", "malloc_consolidate", "触发 malloc_consolidate", "fastbin 块进入正常 consolidate/coalesce 视角。", operation, *moved_ids)], details

    def _malloc_to_target(self, operation: HeapOperation) -> tuple[list[HeapWarning], list[str]]:
        """Execute a malloc while treating ``target`` as an expectation.

        In strict mode this operation never teleports: allocator state decides
        the actual return address.  The expectation is then marked verified,
        pending, or invalid.  Plan mode keeps the old teaching shortcut.
        """
        chunk_id = operation.chunk or f"target_{len(self._chunks)}"
        target = operation.target or "target_address"
        size_expr = operation.request_size or "0x60"
        compatible, reason = target_compatibility(target, self.config)
        compatibility_warnings: list[HeapWarning] = []
        if not compatible:
            compatibility_warnings.append(self._warning("WARNING", "target_incompatible", "目标与当前 glibc 不兼容", reason, operation))

        if self.config.simulation_mode == "strict":
            alloc_operation = replace(operation, kind=HeapOperationKind.ALLOC, chunk=chunk_id, target="")
            warnings, explanation = self._alloc(alloc_operation)
            chunk = self._chunks.get(chunk_id)
            actual = chunk.user_address if chunk else ""
            if chunk is None:
                status = "pending"
                detail = "allocator 无法完成本次 malloc，因此目标预期也无法验证。"
            elif self._same_symbolic_target(actual, target):
                status = "verified"
                detail = f"allocator 实际返回 {actual}，与目标一致。"
            elif chunk.provenance == "derived" and actual:
                status = "invalid"
                detail = f"allocator 实际返回 {actual}，而不是预期的 {target}。"
            else:
                status = "pending"
                detail = f"allocator 当前返回 {actual or 'unknown'}；目标 {target} 尚未得到证明。"
            self._step_intents.append(HeapIntent("malloc_to_target", target, status, detail, operation.op_id))
            if status != "verified":
                warnings.append(self._warning("WARNING", "malloc_target_unverified", "目标 malloc 未命中", detail, operation, *(tuple([chunk_id]) if chunk else ())))
            else:
                warnings.append(self._warning("EXPLOIT", "malloc_to_target_verified", "目标 malloc 已验证", detail, operation, chunk_id))
            return compatibility_warnings + warnings, [f"EXP 预期：malloc({size_expr}) -> {target}", *explanation, detail]

        size = self.request2size(size_expr)
        provenance = "assumed"
        self._physical_seq += 1
        physical_id = f"target_{self._physical_seq:04d}"
        chunk_address = self._offset_address(target, -(self._word_size() * 2))
        self._chunks[chunk_id] = ChunkState(
            chunk_id=chunk_id,
            address=chunk_address,
            user_address=target,
            physical_id=physical_id,
            request_size=size_expr,
            chunk_size=hex(size) if size is not None else size_expr,
            lifecycle="allocated",
            menu_indexes=(operation.index,) if operation.index else (),
            data=operation.data,
            note=operation.note or "assumed malloc target",
            role="target-allocation",
            heap_offset=self._heap_offset_for_address(chunk_address),
            provenance=provenance,
        )
        if operation.index:
            self._bind_handle(operation.index, chunk_id, physical_id)
        self._step_intents.append(HeapIntent("malloc_to_target", target, "assumed", "演示模式按利用意图假设成立。", operation.op_id))
        return compatibility_warnings + [self._warning("EXPLOIT", "malloc_to_target", "malloc 到目标地址", f"assumed: {target}", operation, chunk_id)], [
            f"演示模式假设 {chunk_id} 的 user pointer = {target}。",
            "切到严格模式后，该地址必须由 freelist/top/regular-bin 状态实际推导出来。",
        ]

    @staticmethod
    def _same_symbolic_target(left: str, right: str) -> bool:
        def normalize(value: str) -> str:
            return re.sub(r"\s+", "", str(value or ""))

        return normalize(left) == normalize(right)

    def _leak_main_arena(self, operation: HeapOperation) -> tuple[list[HeapWarning], list[str]]:
        chunk = self._find_chunk(operation)
        if not chunk:
            return [self._warning("WARNING", "leak_unknown", "泄漏块未知", "无法关联到已有 chunk。", operation)], ["main_arena 泄漏只生成说明。"]
        valid = chunk.bin_location.startswith("unsorted")
        if self.config.simulation_mode == "strict" and not valid:
            self._step_intents.append(HeapIntent("main_arena_leak", chunk.address, "pending", f"{chunk.chunk_id} 当前不在 unsorted。", operation.op_id))
            return [self._warning("WARNING", "arena_leak_unverified", "当前状态无法证明 main_arena 泄漏", f"{chunk.chunk_id} 当前位于 {chunk.bin_location or chunk.lifecycle}，严格模式不会凭空注入 main_arena 指针。", operation, chunk.chunk_id)], ["泄漏意图已记录，但没有修改 fd/bk。"]
        self._chunks[chunk.chunk_id] = replace(chunk, fd=chunk.fd or "main_arena+offset", bk=chunk.bk or "main_arena+offset", role="leak", note=operation.note or "unsorted main_arena leak", provenance="inferred")
        self._step_intents.append(HeapIntent("main_arena_leak", chunk.address, "verified" if valid else "assumed", "unsorted chunk 元数据可作为 arena 泄漏候选。", operation.op_id))
        return [], [f"{chunk.chunk_id} 被标记为 unsorted/main_arena 泄漏点。", "真实偏移以当前 libc 和 pwndbg/gdb 结果为准。"]

    def _stdout_environ_leak(self, operation: HeapOperation) -> tuple[list[HeapWarning], list[str]]:
        chunk_id = operation.chunk or "stdout_fake"
        target = operation.target or "libc.sym['_IO_2_1_stdout_'] - 0x43"
        chunk = self._find_chunk(operation)
        status = "pending"
        if chunk is not None:
            status = "verified" if self._same_symbolic_target(chunk.user_address or chunk.address, target) else "pending"
        self._step_intents.append(
            HeapIntent(
                "stdout_environ_leak",
                target,
                status if self.config.simulation_mode == "strict" else "assumed",
                "当前模型只验证目标落点；FILE 字段/vtable 完整性仍需真实 libc 与 Pwndbg 校准。",
                operation.op_id,
            )
        )
        if self.config.simulation_mode == "strict":
            warning = self._warning(
                "EXPLOIT",
                "stdout_environ_intent",
                "stdout -> environ 利用意图",
                "严格模式不会凭这条语义指令创建一个已经成功落在 stdout 的 fake chunk。",
                operation,
                *(tuple([chunk.chunk_id]) if chunk else ()),
            )
            return [warning], [
                f"EXP 意图：把可控写/分配引向 {target}，构造 stdout 泄漏并继续取 environ/stack。",
                "需要用真实 FILE 布局、vtable 检查和运行时输出验证；这里只记录路线与当前落点证据。",
            ]

        self._physical_seq += 1
        chunk_address = self._offset_address(target, -(self._word_size() * 2))
        self._chunks[chunk_id] = ChunkState(
            chunk_id=chunk_id,
            address=chunk_address,
            user_address=target,
            physical_id=f"assumed_{self._physical_seq:04d}",
            request_size=operation.request_size or "0x60",
            chunk_size=operation.request_size or "0x60",
            lifecycle="fake",
            data=operation.data,
            note=operation.note or "stdout -> environ leak",
            role="stdout-leak",
            heap_offset=self._heap_offset_for_address(chunk_address),
            provenance="assumed",
        )
        return [self._warning("EXPLOIT", "stdout_environ", "stdout 泄漏栈地址", "演示模式假设 FILE 落点/字段条件成立。", operation, chunk_id)], [
            f"演示模式把 {chunk_id} 假设放在 stdout 目标 {target}。",
            "真实可利用性仍要以对应 glibc FILE 布局和 Pwndbg 结果为准。",
        ]

    def _setcontext_rop(self, operation: HeapOperation) -> tuple[list[HeapWarning], list[str]]:
        chunk_id = operation.chunk or "fake_ucontext"
        target = operation.target or "heap_frame"
        existing = self._find_chunk_by_ref(chunk_id) or self._find_chunk_by_ref(target)
        storage_note = "已找到可控 frame/ROP 区域；" if existing is not None else "尚未找到可控 frame/ROP 区域；"
        self._step_intents.append(
            HeapIntent(
                "setcontext_orw",
                target,
                "pending" if self.config.simulation_mode == "strict" else "assumed",
                storage_note + "控制流、setcontext gadget 偏移与寄存器布局仍必须按目标 libc 验证。",
                operation.op_id,
            )
        )
        if self.config.simulation_mode == "strict":
            return [self._warning("EXPLOIT", "setcontext_rop_intent", "setcontext / ORW 利用意图", "严格模式不凭语义标签直接制造控制流成功状态。", operation, *(tuple([existing.chunk_id]) if existing else ()))], [
                f"EXP 意图：控制流 -> setcontext gadget，frame/ROP 位于 {target}。",
                "如果前面已经建立 fake chunk/heap frame，这里只把它标记为候选，不改变 allocator。",
            ]

        self._physical_seq += 1
        self._chunks[chunk_id] = ChunkState(
            chunk_id=chunk_id,
            address=target,
            user_address=target,
            physical_id=f"assumed_{self._physical_seq:04d}",
            request_size=operation.request_size or "0x300",
            chunk_size=operation.request_size or "0x300",
            lifecycle="fake",
            data=operation.data,
            note=operation.note or "setcontext pivot frame",
            role="setcontext",
            heap_offset=self._heap_offset_for_address(target),
            provenance="assumed",
        )
        return [self._warning("EXPLOIT", "setcontext_rop", "setcontext 堆上 ROP", "演示模式假设控制流劫持条件成立。", operation, chunk_id)], [
            f"演示模式把 {chunk_id} 作为堆上的 fake ucontext / ROP 区域。",
            "具体 setcontext+偏移必须以本地 disas setcontext 为准。",
        ]

    def _fill_tcache(self, operation: HeapOperation) -> tuple[list[HeapWarning], list[str]]:
        count = max(1, min(int(operation.count or self.config.tcache_count_limit), 64))
        prefix = operation.chunk or "pad"
        start_index = parse_int_expr(operation.meta.get("start_index")) or 0
        explanations = [f"展开填满 tcache：生成 {count} 个 {display_expr(operation.request_size)} chunk 并释放。"]
        warnings: list[HeapWarning] = []
        for index in range(count):
            alloc = HeapOperation(
                op_id=f"{operation.op_id}_alloc_{index}",
                kind=HeapOperationKind.ALLOC,
                chunk=f"{prefix}{index}",
                index=str(start_index + index),
                request_size=operation.request_size,
                data=operation.data,
            )
            w, _ = self._alloc(alloc)
            warnings.extend(w)
        for index in range(count):
            free = HeapOperation(
                op_id=f"{operation.op_id}_free_{index}",
                kind=HeapOperationKind.FREE,
                chunk=f"{prefix}{index}",
            )
            w, _ = self._free(free)
            warnings.extend(w)
        return warnings, explanations

    def _drain_tcache(self, operation: HeapOperation) -> tuple[list[HeapWarning], list[str]]:
        count = max(1, min(int(operation.count or self.config.tcache_count_limit), 64))
        start_index = parse_int_expr(operation.meta.get("start_index")) or 0
        warnings: list[HeapWarning] = []
        for index in range(count):
            alloc = HeapOperation(
                op_id=f"{operation.op_id}_drain_{index}",
                kind=HeapOperationKind.ALLOC,
                chunk=f"{operation.chunk or 'take'}{index}",
                index=str(start_index + index),
                request_size=operation.request_size,
                data=operation.data,
            )
            w, _ = self._alloc(alloc)
            warnings.extend(w)
        return warnings, [f"展开清空 tcache：按相同 size malloc {count} 次。"]

    def _put_free_chunk(self, chunk_id: str, size: int | None, allow_duplicate: bool = False) -> str:
        if not allow_duplicate:
            self._remove_from_bins(chunk_id)
        if size is None:
            self._insert_doubly_node(self._unsorted, chunk_id, "unsorted", "unknown", at_head=True, note="free unknown-size regular chunk")
            return "unsorted"
        max_fast = self.config.max_fast_chunk_size
        if self.config.tcache_enabled and size <= self.config.tcache_max_chunk_size:
            chain = self._tcache.setdefault(size, [])
            if len(chain) < self.config.tcache_count_limit:
                if allow_duplicate:
                    self._remove_from_bins(chunk_id, preserve=(self._tcache, size))
                before = tuple(chain)
                previous = chain[0] if chain else "NULL"
                chain.insert(0, chunk_id)
                self._initialize_singly_link(chunk_id, previous, f"tcache[{hex(size)}]", user_pointer=True)
                self._write_tcache_head(size, chain)
                self._record_bin_transition("free-push", "tcache", hex(size), chunk_id, before, chain, (chunk_id,), (f"{chunk_id}.next={previous}",), "free inserts tcache head")
                return f"tcache[{hex(size)}]"
        if size <= max_fast:
            if allow_duplicate:
                self._remove_from_bins(chunk_id, preserve=(self._fastbins, size))
            chain = self._fastbins.setdefault(size, [])
            before = tuple(chain)
            previous = chain[0] if chain else "NULL"
            chain.insert(0, chunk_id)
            self._initialize_singly_link(chunk_id, previous, f"fastbin[{hex(size)}]", user_pointer=False)
            self._record_bin_transition("free-push", "fastbin", hex(size), chunk_id, before, chain, (chunk_id,), (f"{chunk_id}.fd={previous}",), "free inserts fastbin head")
            return f"fastbin[{hex(size)}]"
        self._insert_doubly_node(self._unsorted, chunk_id, "unsorted", hex(size), at_head=True, note="regular free inserts unsorted head")
        return "unsorted"

    def _mark_reused_chunk(self, reused_id: str, new_owner: str) -> None:
        self._remove_from_bins(reused_id)
        chunk = self._chunks.get(reused_id)
        if not chunk:
            return
        physical_id = chunk.physical_id or chunk.chunk_id
        self._chunks[reused_id] = replace(
            chunk,
            lifecycle="stale",
            bin_location=f"reused by {new_owner}",
            fd="",
            bk="",
            note=f"旧逻辑对象/菜单句柄仍可能指向物理块；当前 owner={new_owner}。",
            role="alias",
        )
        self._mark_physical_handles(physical_id, "alias")

    def _bind_handle(self, index: str, chunk_id: str, physical_id: str) -> None:
        key = str(index).strip()
        if not key:
            return
        self._handles[key] = HandleState(key, chunk_id, physical_id, "active", f"{key} -> {chunk_id}")

    def _mark_physical_handles(self, physical_id: str, status: str) -> None:
        if not physical_id:
            return
        for index, handle in list(self._handles.items()):
            if handle.physical_id == physical_id:
                self._handles[index] = replace(handle, status=status)

    def _validate_doubly_unlink(
        self,
        chain: list[str],
        chunk_id: str,
        location: str,
        operation: HeapOperation,
        warnings: list[HeapWarning],
    ) -> bool:
        """Validate fd/bk using current PhysicalMemory before unlinking."""
        if chunk_id not in chain:
            return False
        victim = self._chunks.get(chunk_id)
        if victim is None:
            return False
        index = chain.index(chunk_id)
        previous = chain[index - 1] if index else ARENA_SENTINEL
        following = chain[index + 1] if index + 1 < len(chain) else ARENA_SENTINEL
        head_address = self._bin_head_address(location)
        actual_fd = self._read_raw_pointer(victim, self._word_size() * 2)
        actual_bk = self._read_raw_pointer(victim, self._word_size() * 3)
        expected_fd = head_address if following == ARENA_SENTINEL else self._chunk_pointer(following, user=False)
        expected_bk = head_address if previous == ARENA_SENTINEL else self._chunk_pointer(previous, user=False)
        failures: list[str] = []
        if not self._same_pointer(actual_fd, expected_fd):
            failures.append(f"victim.fd={actual_fd}, expected={expected_fd}")
        if not self._same_pointer(actual_bk, expected_bk):
            failures.append(f"victim.bk={actual_bk}, expected={expected_bk}")
        if following != ARENA_SENTINEL:
            neighbour = self._chunks.get(following)
            reciprocal = self._read_raw_pointer(neighbour, self._word_size() * 3) if neighbour else "unknown"
            if not self._same_pointer(reciprocal, victim.address):
                failures.append(f"fd->bk={reciprocal}, expected={victim.address}")
        if previous != ARENA_SENTINEL:
            neighbour = self._chunks.get(previous)
            reciprocal = self._read_raw_pointer(neighbour, self._word_size() * 2) if neighbour else "unknown"
            if not self._same_pointer(reciprocal, victim.address):
                failures.append(f"bk->fd={reciprocal}, expected={victim.address}")
        if not failures:
            return True
        warnings.append(self._abort(
            "corrupted_double_linked_list",
            operation,
            "victim->fd->bk == victim && victim->bk->fd == victim",
            victim.address,
            {"bin": location, "details": "; ".join(failures)},
            chunk_id,
        ))
        return False

    def _read_raw_pointer(self, chunk: ChunkState | None, offset: int) -> str:
        if chunk is None:
            return "unknown"
        address = self._offset_address(chunk.address, offset)
        read = self._memory.read(address, self._word_size())
        if read.data is not None:
            value = int.from_bytes(read.data, "little")
            return "NULL" if value == 0 else hex(value)
        return (read.symbolic or "unknown").strip()

    def _current_chunk_for_physical(self, physical_id: str) -> ChunkState | None:
        candidates = [chunk for chunk in self._chunks.values() if (chunk.physical_id or chunk.chunk_id) == physical_id]
        if not candidates:
            return None
        priority = {"allocated": 4, "freed": 3, "fake": 2, "stale": 1}
        return max(candidates, key=lambda chunk: priority.get(chunk.lifecycle, 0))

    def _insert_doubly_node(
        self,
        chain: list[str],
        chunk_id: str,
        location: str,
        size_text: str,
        *,
        at_head: bool,
        note: str = "",
    ) -> None:
        transition = insert_doubly(chain, chunk_id, at_head=at_head)
        chain[:] = transition.after
        self._apply_doubly_transition(transition, location, size_text, note=note)

    def _remove_doubly_node(
        self,
        chain: list[str],
        chunk_id: str,
        location: str,
        size_text: str,
        *,
        note: str = "",
    ) -> bool:
        transition = remove_doubly(chain, chunk_id)
        if transition.action == "remove-missing":
            return False
        chain[:] = transition.after
        self._apply_doubly_transition(transition, location, size_text, note=note)
        return True

    def _apply_doubly_transition(
        self,
        transition: DoublyChainTransition,
        location: str,
        size_text: str,
        *,
        note: str = "",
    ) -> None:
        head_address = self._ensure_bin_head(location)
        mutation_labels: list[str] = []
        for mutation in transition.mutations:
            mutation_labels.append(f"{mutation.node}.{mutation.field}={mutation.target}")
            if mutation.node == ARENA_SENTINEL:
                offset = 0 if mutation.field == "fd" else self._word_size()
                target = head_address if mutation.target == ARENA_SENTINEL else self._chunk_pointer(mutation.target, user=False)
                self._write_metadata_value(
                    head_address,
                    target,
                    self._word_size(),
                    self._current_operation_id,
                    offset=offset,
                    note=f"{location} arena head {mutation.field}",
                )
                continue
            owner = self._chunks.get(mutation.node)
            if owner is None:
                continue
            offset = self._word_size() * (2 if mutation.field == "fd" else 3)
            self._store_pointer(
                owner,
                head_address if mutation.target == ARENA_SENTINEL else self._chunk_pointer(mutation.target, user=False),
                offset,
                protect=False,
                note=f"{location} {transition.action}: {mutation.reason}",
            )
        if transition.node in self._chunks and transition.action.startswith("insert"):
            chunk = self._chunks[transition.node]
            self._chunks[transition.node] = replace(chunk, lifecycle="freed", bin_location=location)
        self._record_bin_transition(
            transition.action,
            location.split("[", 1)[0],
            size_text,
            transition.node,
            transition.before,
            transition.after,
            (transition.node,),
            tuple(mutation_labels),
            note,
        )

    @staticmethod
    def _bin_head_address(location: str) -> str:
        normalized = re.sub(r"[^0-9A-Za-z_]+", "_", location).strip("_").lower() or "unknown"
        return f"arena_bin_{normalized}"

    def _ensure_bin_head(self, location: str) -> str:
        address = self._bin_head_address(location)
        object_id = f"bin_head:{location}"
        if not any(item.object_id == object_id for item in self._memory.objects):
            self._memory.register_object(
                object_id, address, self._word_size() * 2,
                kind="arena_bin_head", label=location, provenance="derived",
            )
            provenance = MemoryProvenance.derived(
                self._current_operation_id, writer="allocator", note=f"initialize {location} bin head",
            )
            self._memory.write_symbolic(address, address, self._word_size(), provenance, state="metadata")
            self._memory.write_symbolic(
                self._offset_address(address, self._word_size()),
                address,
                self._word_size(),
                provenance,
                state="metadata",
            )
        return address

    def _record_bin_transition(
        self,
        action: str,
        bin_kind: str,
        size_text: str,
        node: str,
        before: Iterable[str],
        after: Iterable[str],
        moved_nodes: Iterable[str] = (),
        link_mutations: Iterable[str] = (),
        note: str = "",
    ) -> None:
        self._bin_transition_sequence += 1
        self._step_bin_transition_events.append(BinTransitionEvent(
            f"bin_{self._bin_transition_sequence:04d}",
            self._current_operation_id,
            action,
            bin_kind,
            size_text,
            node,
            tuple(before),
            tuple(after),
            tuple(moved_nodes),
            tuple(link_mutations),
            "derived",
            note,
        ))

    def _remove_from_bins(self, chunk_id: str, preserve: tuple[dict[int, list[str]], int] | None = None) -> None:
        for mapping, kind in ((self._tcache, "tcache"), (self._fastbins, "fastbin")):
            for size, chain in list(mapping.items()):
                if preserve and mapping is preserve[0] and size == preserve[1]:
                    continue
                before = tuple(chain)
                mapping[size] = [item for item in chain if item != chunk_id]
                if tuple(mapping[size]) != before:
                    if kind == "tcache":
                        self._write_tcache_head(size, mapping[size])
                    self._record_bin_transition("remove", kind, hex(size), chunk_id, before, mapping[size], (chunk_id,), (), "remove membership")
                if not mapping.get(size):
                    mapping.pop(size, None)
        for mapping, kind in ((self._smallbins, "smallbin"), (self._largebins, "largebin")):
            for size, chain in list(mapping.items()):
                if preserve and mapping is preserve[0] and size == preserve[1]:
                    continue
                while chunk_id in chain:
                    self._remove_doubly_node(chain, chunk_id, f"{kind}[{hex(size)}]", hex(size), note="remove membership")
                if not chain:
                    mapping.pop(size, None)
        while chunk_id in self._unsorted:
            self._remove_doubly_node(self._unsorted, chunk_id, "unsorted", "unknown", note="remove membership")
        self._refresh_largebin_nextsize_metadata()

    def _refresh_freelist_metadata(self) -> None:
        for size, chain in self._tcache.items():
            self._refresh_singly_chain(chain, size, f"tcache[{hex(size)}]")
        for size, chain in self._fastbins.items():
            self._refresh_singly_chain(chain, size, f"fastbin[{hex(size)}]")
        for size, chain in self._smallbins.items():
            self._refresh_doubly_chain(chain, f"smallbin[{hex(size)}]")
        for size, chain in self._largebins.items():
            self._refresh_doubly_chain(chain, f"largebin[{hex(size)}]")
        self._refresh_doubly_chain(self._unsorted, "unsorted")

    def _refresh_singly_chain(self, chain: list[str], size: int, location: str) -> None:
        seen: set[str] = set()
        for index, chunk_id in enumerate(chain):
            if chunk_id in seen:
                continue
            seen.add(chunk_id)
            chunk = self._chunks.get(chunk_id)
            if not chunk:
                continue
            # The list order is an allocator head view, but the entry link is
            # always read from PhysicalMemory.  Rebuilding a list must never
            # overwrite a UAF/overflow corruption that the EXP already made.
            decoded = self._decoded_freelist_target(chunk) or "unknown"
            target = decoded
            fd = f"PROTECT_PTR({self._fd_field_address(chunk)}, {target})" if self.config.safe_linking else target
            self._chunks[chunk_id] = replace(
                chunk,
                lifecycle="freed",
                bin_location=location,
                fd=fd,
                bk="",
            )

    def _initialize_singly_link(self, chunk_id: str, next_id: str, location: str, *, user_pointer: bool) -> None:
        chunk = self._chunks.get(chunk_id)
        if chunk is None:
            return
        pointer = self._chunk_pointer(next_id, user=user_pointer)
        self._store_pointer(
            chunk, pointer, self._word_size() * 2,
            protect=self.config.safe_linking, note=f"{location} next insertion",
        )
        if location.startswith("tcache") and self.config.tcache_key_check:
            self._memory.write_symbolic(
                self._offset_address(chunk.address, self._word_size() * 3),
                "tcache_key",
                self._word_size(),
                MemoryProvenance.derived(self._current_operation_id, writer="allocator", note="tcache key insertion"),
                state="metadata",
            )

    def _refresh_doubly_chain(self, chain: list[str], location: str) -> None:
        for chunk_id in chain:
            chunk = self._chunks.get(chunk_id)
            if not chunk:
                continue
            fd = self._pointer_field_display(chunk, self._word_size() * 2)
            bk = self._pointer_field_display(chunk, self._word_size() * 3)
            self._chunks[chunk_id] = replace(
                chunk,
                lifecycle="freed",
                bin_location=location,
                fd=fd,
                bk=bk,
            )

    def _pointer_field_display(self, chunk: ChunkState, offset: int) -> str:
        address = self._offset_address(chunk.address, offset)
        read = self._memory.read(address, self._word_size())
        value = self._memory.read_uint(address, self._word_size())
        target = hex(value) if value is not None else (read.symbolic or "unknown")
        if target in {"0", "0x0", "NULL"}:
            return "NULL"
        if target == "main_arena":
            return target
        for candidate in self._chunks.values():
            if self._same_pointer(target, candidate.address):
                return self._chunk_ref(candidate.chunk_id)
        return target

    def _refresh_largebin_nextsize_metadata(self) -> None:
        """Publish a conservative size-representative ring in physical memory.

        The regular fd/bk chains remain per exact-size class.  The first node
        of every non-empty class participates in a circular nextsize ring,
        matching the allocator field roles without pretending to model every
        largebin bucket boundary.
        """
        representatives = [
            chain[0]
            for _size, chain in sorted(self._largebins.items())
            if chain and chain[0] in self._chunks
        ]
        if not representatives:
            self._largebin_nextsize_order = []
            return
        previous_order = tuple(self._largebin_nextsize_order)
        old_neighbours: dict[str, tuple[str, str]] = {}
        for index, old_id in enumerate(previous_order):
            if previous_order:
                old_neighbours[old_id] = (
                    previous_order[(index + 1) % len(previous_order)],
                    previous_order[(index - 1) % len(previous_order)],
                )
        for index, chunk_id in enumerate(representatives):
            chunk = self._chunks[chunk_id]
            following = representatives[(index + 1) % len(representatives)]
            previous = representatives[(index - 1) % len(representatives)]
            old_following, old_previous = old_neighbours.get(chunk_id, ("", ""))
            if following != old_following:
                self._store_pointer(chunk, self._chunk_pointer(following, user=False), self._word_size() * 4, protect=False, note="largebin fd_nextsize representative ring")
            if previous != old_previous:
                self._store_pointer(chunk, self._chunk_pointer(previous, user=False), self._word_size() * 5, protect=False, note="largebin bk_nextsize representative ring")
        self._largebin_nextsize_order = list(representatives)

    def _chunk_pointer(self, chunk_id: str, *, user: bool) -> str:
        for kind in ("tcache", "fastbin"):
            external = self._external_target_from_token(chunk_id, kind)
            if external:
                return external
        if chunk_id == "NULL":
            return "0"
        if chunk_id == "main_arena":
            return "main_arena"
        chunk = self._chunks.get(chunk_id)
        if chunk is None:
            return chunk_id
        return chunk.user_address if user else chunk.address

    def _store_pointer(self, chunk: ChunkState, target: str, offset: int, *, protect: bool, note: str) -> None:
        field = self._offset_address(chunk.address, offset)
        target_value = parse_int_expr(target, self.variables)
        field_value = parse_int_expr(field, self.variables)
        provenance = MemoryProvenance.derived(self._current_operation_id, writer="allocator", note=note)
        if target_value is not None and (not protect or field_value is not None):
            stored = target_value ^ (field_value >> 12) if protect and field_value is not None else target_value
            self._memory.write_uint(field, stored, self._word_size(), provenance, state="metadata")
            return
        expression = f"PROTECT_PTR({field}, {target if target not in {'0', 'NULL'} else 'NULL'})" if protect else target
        self._memory.write_symbolic(field, expression, self._word_size(), provenance, state="metadata")

    def _chunk_ref(self, chunk_id: str) -> str:
        for kind in ("tcache", "fastbin"):
            external = self._external_target_from_token(chunk_id, kind)
            if external:
                return f"external @ {external}"
        if chunk_id in {"NULL", "main_arena"}:
            return chunk_id
        chunk = self._chunks.get(chunk_id)
        if not chunk:
            return chunk_id
        offset = f" (+{chunk.heap_offset.lstrip('+')})" if chunk.heap_offset else ""
        return f"{chunk_id} @ {chunk.address}{offset}"

    def _display_bin_node(self, node: str) -> str:
        for kind in ("tcache", "fastbin"):
            external = self._external_target_from_token(node, kind)
            if external:
                return f"external @ {external}"
        return node

    def _freelist_links(self, chunk: ChunkState, size: int | None, bin_location: str) -> tuple[str, str]:
        """Describe allocator metadata stored in a newly-freed chunk."""
        if bin_location.startswith("tcache") and size is not None:
            chain = self._tcache.get(size, [])
            next_id = chain[1] if len(chain) > 1 else "NULL"
            next_chunk = self._chunks.get(next_id)
            target = f"{next_id} @ {next_chunk.address}" if next_chunk else next_id
            if self.config.safe_linking:
                return f"PROTECT_PTR({self._fd_field_address(chunk)}, {target})", ""
            return target, ""
        if bin_location.startswith("fastbin") and size is not None:
            chain = self._fastbins.get(size, [])
            next_id = chain[1] if len(chain) > 1 else "NULL"
            next_chunk = self._chunks.get(next_id)
            target = f"{next_id} @ {next_chunk.address}" if next_chunk else next_id
            if self.config.safe_linking:
                return f"PROTECT_PTR({self._fd_field_address(chunk)}, {target})", ""
            return target, ""
        if bin_location.startswith("unsorted"):
            return "main_arena bins (fd)", "main_arena bins (bk)"
        return chunk.fd, chunk.bk

    def _find_chunk(self, operation: HeapOperation) -> ChunkState | None:
        # Menu indexes are handles, not physical chunks. Resolve the handle to
        # the current owner of the same physical allocation first, which makes
        # UAF-after-reuse behave like the real program pointer.
        if operation.index:
            handle = self._handles.get(str(operation.index).strip())
            if handle:
                current = self._current_chunk_for_physical(handle.physical_id)
                if current:
                    return current
        if operation.chunk and operation.chunk in self._chunks:
            chunk = self._chunks[operation.chunk]
            if chunk.lifecycle == "stale" and chunk.physical_id:
                return self._current_chunk_for_physical(chunk.physical_id) or chunk
            return chunk
        if operation.chunk:
            for chunk in self._chunks.values():
                if operation.chunk in chunk.aliases:
                    return self._current_chunk_for_physical(chunk.physical_id or chunk.chunk_id) or chunk
        return None

    def _find_chunk_by_ref(self, ref: str) -> ChunkState | None:
        text = str(ref or "").strip()
        if not text:
            return None
        handle = self._handles.get(text)
        if handle:
            current = self._current_chunk_for_physical(handle.physical_id)
            if current:
                return current
        if text in self._chunks:
            chunk = self._chunks[text]
            return self._current_chunk_for_physical(chunk.physical_id) if chunk.lifecycle == "stale" and chunk.physical_id else chunk
        for chunk in self._chunks.values():
            if text in chunk.menu_indexes or text in chunk.aliases:
                return self._current_chunk_for_physical(chunk.physical_id or chunk.chunk_id) or chunk
        return None

    def _focus_chunks(self, operation: HeapOperation) -> tuple[str, ...]:
        names: list[str] = []
        if operation.chunk:
            names.append(operation.chunk)
        source_id = operation.meta.get("src_chunk")
        if source_id:
            names.append(source_id)
        chunk = self._find_chunk(operation)
        if chunk and chunk.chunk_id not in names:
            names.append(chunk.chunk_id)
        names.extend(
            edge.target_chunk for edge in self._step_overwrite_edges
            if edge.target_chunk and edge.target_chunk not in names
        )
        if operation.kind in {HeapOperationKind.FILL_TCACHE, HeapOperationKind.DRAIN_TCACHE}:
            prefix = operation.chunk or ("pad" if operation.kind == HeapOperationKind.FILL_TCACHE else "take")
            names.extend(name for name in self._chunks if name.startswith(prefix))
        return tuple(name for name in names if name in self._chunks)

    def _snapshot(
        self,
        step: int,
        operation_id: str,
        warnings: tuple[HeapWarning, ...],
        explanation: tuple[str, ...],
        focus_chunks: tuple[str, ...],
        event_title: str,
    ) -> HeapSnapshot:
        for detail in self._detect_cache_divergences():
            if detail not in self._model_divergences:
                self._model_divergences.append(detail)
        # BinState exposed to Canvas is derived from the same tcache head and
        # next pointers that the next malloc will consume.
        for size in tuple(self._tcache):
            self._sync_tcache_from_memory(size)
        ordered_chunks = self._ordered_physical_chunks()
        previous_chunks = self._previous_physical_chunks(ordered_chunks)
        memory_snapshot = self._memory.snapshot()
        enriched_chunks: dict[str, ChunkState] = {}
        for chunk_id, chunk in self._chunks.items():
            previous = previous_chunks.get(chunk_id)
            physical_id = chunk.physical_id or chunk.chunk_id
            previous_key = (
                previous.chunk_id,
                previous.lifecycle,
                previous.bin_location,
                previous.chunk_size,
                self._memory.object_revision(previous.physical_id or previous.chunk_id),
            ) if previous is not None else None
            key = (chunk, self._memory.object_revision(physical_id), previous_key)
            cached = self._enriched_cache.get(chunk_id)
            if cached is not None and cached[0] == key:
                enriched = cached[1]
            else:
                enriched = self._enrich_chunk(chunk, previous, memory_snapshot)
                self._enriched_cache[chunk_id] = (key, enriched)
            enriched_chunks[chunk_id] = enriched
        return HeapSnapshot(
            step=step,
            operation_id=operation_id,
            chunks=enriched_chunks,
            bins=BinState(
                tcache={hex(size): tuple(self._display_bin_node(item) for item in chain) for size, chain in sorted(self._tcache.items()) if chain},
                fastbins={hex(size): tuple(self._display_bin_node(item) for item in chain) for size, chain in sorted(self._fastbins.items()) if chain},
                smallbins={hex(size): tuple(chain) for size, chain in sorted(self._smallbins.items()) if chain},
                largebins={hex(size): tuple(chain) for size, chain in sorted(self._largebins.items()) if chain},
                unsorted=tuple(self._unsorted),
            ),
            warnings=warnings,
            explanation=explanation,
            focus_chunks=focus_chunks,
            event_title=event_title,
            heap_base=self.config.heap_base or "heap_base",
            handles=dict(self._handles),
            intents=tuple(self._step_intents),
            observations=tuple(self._observations),
            aborted=self._aborted,
            memory=memory_snapshot,
            write_events=tuple(self._step_write_events),
            overwrite_edges=tuple(self._step_overwrite_edges),
            write_history=tuple(self._write_history),
            overwrite_history=tuple(self._overwrite_history),
            read_events=tuple(self._step_read_events),
            alloc_events=tuple(self._step_alloc_events),
            free_events=tuple(self._step_free_events),
            bin_transition_events=tuple(self._step_bin_transition_events),
            top_address=self._heap_address(self._next_offset) if self._layout_known else "heap_base+?<top>",
            top_size=(hex(self._top_size_from_memory()) if self._top_size_from_memory() is not None else "unknown"),
            top_provenance="memory" if self._layout_known else "unknown",
            allocator_abort=self._allocator_abort,
            model_divergences=tuple(self._model_divergences),
        )

    def _word_size(self) -> int:
        return 8 if self.config.bits == 64 else 4

    def _offset_address(self, base: str, offset: int) -> str:
        text = str(base or "").strip()
        if not text:
            return ""
        try:
            return str(self._memory.address(text).add(offset))
        except ValueError:
            if offset == 0:
                return text

        compact = re.sub(r"\s+", "", text)
        # Keep common symbolic heap expressions readable: heap_base+0x290+0x10
        # becomes heap_base+0x2a0 instead of growing an arithmetic tail forever.
        match = re.fullmatch(r"(?P<root>[A-Za-z_][A-Za-z0-9_]*)(?P<sign>[+-])(?P<num>0x[0-9a-fA-F]+|\d+)", compact)
        if match:
            current = int(match.group("num"), 0)
            if match.group("sign") == "-":
                current = -current
            total = current + offset
            if total == 0:
                return match.group("root")
            sign = "+" if total > 0 else "-"
            return f"{match.group('root')}{sign}0x{abs(total):x}"
        sign = "+" if offset > 0 else "-"
        return f"{text}{sign}0x{abs(offset):x}"

    def _fd_field_address(self, chunk: ChunkState) -> str:
        return self._offset_address(chunk.address, self._word_size() * 2)

    @property
    def physical_memory(self):
        """Current sparse memory snapshot for deterministic tooling/tests."""
        return self._memory.snapshot()

    # ------------------------------------------------------------------
    # Canvas structural edit: RESIZE_PHYSICAL

    def _canvas_provenance(self, operation_id: str, address: str, size: int,
                           physical_id: str, note: str) -> MemoryProvenance:
        """画布编辑写入的 provenance：落到其他对象注册范围内 → CROSS；
        否则 USER_CONFIRMED 校准写。红色 overlap/cross 绘制都由它驱动。"""
        write_kind = WriteKind.CALIBRATED
        owner = ""
        try:
            start = self._memory.address(address)
            end = self._memory.address(self._offset_address(str(address), size - 1))
            intruders = [
                obj.object_id
                for obj in self._memory.overlaps(start, end)
                if obj.object_id != physical_id
            ]
            if intruders:
                write_kind = WriteKind.CROSS_CHUNK_OVERWRITE
                owner = ",".join(intruders)
        except (ValueError, KeyError, TypeError):
            pass
        return MemoryProvenance(
            ProvenanceKind.USER_CONFIRMED,
            operation_id,
            0,
            "",
            None,
            "canvas-resize",
            note,
            physical_id,
            write_kind,
            owner,
            "size",
            0,
        )

    def _chunk_offset_of(self, state: ChunkState) -> int | None:
        return parse_int_expr(state.heap_offset, self.variables)

    def _resize_physical(self, operation: HeapOperation) -> tuple[list[HeapWarning], list[str]]:
        """画布拖动 chunk 上/下边界：直接调整物理注册范围 + allocator 真值。

        结构固定为三个阶段，任何分支都不依赖条件赋值的中间变量：
          ① 无条件解析：physical_id → PhysicalMemory 注册对象（物理真相）
             + ChunkState（typed view 元数据）。任一解析不出 → 结构编辑拒绝。
          ② 统一几何：old_start/old_end 来自注册对象；new_start/new_end 按
             edge 直接计算（bottom: end 平移；top: start 平移）。
          ③ 统一 overlap 判定：遍历其他全部 PhysicalChunk，取
             [new_start,new_end) ∩ [other_start,other_end)；不挑"最近邻居"，
             连续覆盖多个 chunk 也能逐一标红。top 的侵入单独记账。

        语义：边界侵入相邻 chunk → 真实 overlap（对方视图原地不动，重叠
        字节经 provenance 标红）；bottom 侵入 top → top 账本同步切分；
        收缩 → 尾部脱离注册范围（诚实 untouched 字节）。首个 chunk 的上
        边界锁定；结果 extent 必须 >= MINSIZE 且按 word 对齐（允许半行）。
        """
        warnings: list[HeapWarning] = []
        explanation: list[str] = []
        physical_id = str(operation.meta.get("physical_id") or "")

        # ── ① 无条件解析目标（绝不把解析埋进分支）────────────────────
        chunk = next((
            item for item in self._chunks.values()
            if physical_id and item.physical_id == physical_id
        ), None)
        if chunk is None:
            chunk = self._find_chunk(operation)
        if chunk is None:
            return [self._abort(
                "resize_target_unknown", operation, "resize 目标必须可解析",
                "", {"chunk": operation.chunk, "physical_id": physical_id},
            )
            ], []
        if chunk.view_kind in {"top_chunk", "fake_chunk"} or chunk.chunk_id == "TOP":
            return [self._abort(
                "resize_invalid_target", operation, "只能 resize 普通 malloc chunk",
                chunk.address, {"view_kind": chunk.view_kind},
            )
            ], []
        pid = chunk.physical_id or chunk.chunk_id
        physical = next((
            item for item in self._memory.objects
            if item.object_id == pid
        ), None)
        if physical is None or physical.size <= 0:
            return [self._abort(
                "resize_extent_unknown", operation,
                "physical_id 无法在 PhysicalMemory 唯一解析出物理范围，拒绝结构编辑",
                chunk.address, {"physical_id": pid},
            )
            ], []
        old_start = physical.start.offset
        old_end = old_start + physical.size
        old_extent = physical.size

        edge = str(operation.meta.get("edge") or "bottom").lower()
        if edge not in {"top", "bottom"}:
            return [self._abort(
                "resize_bad_edge", operation, "edge 必须是 top 或 bottom",
                chunk.address, {"edge": edge},
            )
            ], []
        delta = parse_int_expr(str(operation.meta.get("delta") or ""), self.variables)
        word = self._word_size()
        if delta is None or delta == 0 or delta % word:
            return [self._abort(
                "resize_bad_delta", operation, f"delta 必须是 {word} 字节的非零倍数",
                chunk.address, {"delta": str(operation.meta.get("delta"))},
            )
            ], []

        # ── ② 统一几何：先算 new_start/new_end，不做分支内赋值 ────────
        new_start = old_start if edge == "bottom" else old_start + delta
        new_end = old_end + delta if edge == "bottom" else old_end
        new_extent = new_end - new_start

        # 首个 chunk 上边界锁定：注册表里不存在起点更靠前的普通 chunk
        if edge == "top" and not any(
            item.object_id != pid and item.kind == "malloc_chunk"
            and item.start.offset < old_start
            for item in self._memory.objects
        ):
            return [self._abort(
                "resize_first_chunk_locked", operation,
                "第一个 chunk 的上边界锁定（堆起始边界不可拖）",
                chunk.address, {},
            )
            ], []

        alignment_minimum = 0x20 if self.config.bits == 64 else 0x10
        if new_extent < alignment_minimum or new_extent % word:
            return [self._abort(
                "resize_invalid_size", operation,
                f"chunksize 必须 >= {hex(alignment_minimum)} 且按 {hex(word)} 字节对齐（允许半行）",
                chunk.address,
                {"new_extent": hex(new_extent)},
            )
            ], []

        # ── ③ 统一 overlap 判定：区间相交，一次遍历全部物理对象 ───────
        chunk_overlaps: list[tuple[MemoryObject, int, int]] = []
        top_intrusion = 0
        for other in self._memory.objects:
            if other.object_id == pid:
                continue
            other_start = other.start.offset
            other_end = other_start + other.size
            inter_start = max(new_start, other_start)
            inter_end = min(new_end, other_end)
            if inter_end <= inter_start:
                continue
            if other.object_id == "top":
                top_intrusion = inter_end - inter_start
            elif other.kind == "malloc_chunk":
                chunk_overlaps.append((other, inter_start, inter_end))

        if top_intrusion > 0:
            top_size = self._top_size_from_memory()
            if top_size is None or top_size < top_intrusion + alignment_minimum:
                return [self._abort(
                    "resize_top_exhausted", operation,
                    "chunksize(top) >= 侵入量 + MINSIZE",
                    chunk.address,
                    {"top_size": hex(top_size or 0), "intrusion": hex(top_intrusion)},
                )
                ], []

        provenance_note = f"canvas resize {edge} {delta:+#x}"
        new_off = new_start
        shift = new_start - old_start
        new_address = self._offset_address(chunk.address, shift)
        raw = self._memory.read_uint(
            self._offset_address(chunk.address, self._word_size()), self._word_size(),
        )
        flags = (raw or 1) & 0x7
        new_decoded = new_extent

        if edge == "top":
            # 头部搬迁：先在（可能的）他人范围内写入新 header —— 写入的
            # provenance 会按真实归属标 CROSS。
            self._memory.write_uint(
                self._offset_address(new_address, self._word_size()),
                new_decoded | flags, self._word_size(),
                self._canvas_provenance(operation.op_id, self._offset_address(new_address, self._word_size()),
                                        self._word_size(), pid, provenance_note),
                state="metadata",
            )

        self._memory.register_object(
            pid,
            new_address, new_decoded,
            kind="malloc_chunk", label=chunk.chunk_id, provenance="user_confirmed",
        )
        if edge == "bottom":
            self._memory.write_uint(
                self._offset_address(chunk.address, self._word_size()),
                new_decoded | flags, self._word_size(),
                self._canvas_provenance(operation.op_id, self._offset_address(chunk.address, self._word_size()),
                                        self._word_size(), pid, provenance_note),
                state="metadata",
            )

        if top_intrusion > 0:
            # 顶层账本随 resize 同步：top 起点按侵入量上移、header 重写（对齐
            # _consume_top 的切分语义：prev_size=本 chunk 新尺寸、size|1）。
            new_top_size = (self._top_size_from_memory() or 0) - top_intrusion
            self._next_offset = self._next_offset + top_intrusion
            top_address = self._heap_address(self._next_offset)
            top_provenance = MemoryProvenance.derived(
                operation.op_id, writer="canvas-resize", note="top split by canvas resize",
            )
            self._memory.register_object(
                "top", top_address, new_top_size,
                kind="top_chunk", label="top", provenance="derived",
            )
            self._memory.write_uint(top_address, new_decoded, self._word_size(), top_provenance, state="metadata")
            self._memory.write_uint(
                self._offset_address(top_address, self._word_size()),
                new_top_size | 1, self._word_size(), top_provenance, state="metadata",
            )
            explanation.append(
                f"{chunk.chunk_id} 物理范围向下侵入 top {hex(top_intrusion)}，从 top 切分；top 账本与 boundary tag 已重算。"
            )
        if chunk_overlaps:
            overlap_names = "、".join(item.object_id for item, _s, _e in chunk_overlaps)
            explanation.append(
                f"{chunk.chunk_id} 物理范围 [{hex(new_start)},{hex(new_end)}) 侵入 {overlap_names} → 真实 overlap；"
                "重叠区保持对方视图并按字节标红，后续 free/malloc 按新物理视图校验。"
            )
            warnings.append(self._warning(
                "WARNING", "resize_overlap",
                "物理范围侵入相邻 chunk",
                f"{chunk.chunk_id} 的视图覆盖了 {overlap_names} 的头部/数据区；这是 overlap 状态，"
                "相邻 chunk 的 boundary tag 保持原值（stale）。",
                operation, chunk.chunk_id,
            ))
        else:
            explanation.append(
                f"{chunk.chunk_id} 物理范围调整为 [{hex(new_start)},{hex(new_end)})（{edge} 边界 {delta:+#x}）。"
            )

        if chunk.bin_location:
            warnings.append(self._warning(
                "WARNING", "resize_bin_stale",
                "free chunk 的 bin 视图未重算",
                f"{chunk.chunk_id} 当前位于 {chunk.bin_location}；resize 不改变 bin 归属，"
                "后续 free/malloc 会按新的 size header 校验并可能触发 integrity abort。",
                operation, chunk.chunk_id,
            ))

        raw_after = (self._memory.read_uint(
            self._offset_address(new_address, self._word_size()), self._word_size(),
        ) or (new_decoded | flags))
        updated = replace(
            chunk,
            address=new_address,
            chunk_size=hex(new_decoded),
            physical_extent_size=hex(new_decoded),
            decoded_chunksize=hex(new_decoded),
            header_raw_size=hex(raw_after),
            heap_offset=hex(new_off),
            note=(chunk.note + " | canvas resize").strip(" |"),
        )
        self._chunks[chunk.chunk_id] = updated
        return warnings, explanation
    def _initialize_chunk_memory(self, operation: HeapOperation, chunk: ChunkState, *, reused: bool) -> None:
        size = parse_int_expr(chunk.chunk_size, self.variables)
        if size is not None:
            self._memory.register_object(
                chunk.physical_id or chunk.chunk_id,
                chunk.address,
                size,
                kind="malloc_chunk",
                label=chunk.chunk_id,
                provenance=chunk.provenance,
            )
            if not reused:
                flagged_size = size | 1
                self._memory.write_uint(
                    self._offset_address(chunk.address, self._word_size()),
                    flagged_size,
                    self._word_size(),
                    MemoryProvenance.derived(
                        operation.op_id,
                        writer="allocator",
                        note="malloc chunk size header",
                    ),
                    state="metadata",
                )
        if operation.data:
            self._write_operation_payload(operation, chunk, operation.data)
        self._sync_top_memory(operation.op_id)

    def _sync_top_memory(self, operation_id: str) -> None:
        if not self._layout_known:
            return
        address = self._heap_address(self._next_offset)
        # Register the view span without rewriting either header word.  In
        # particular an overflow-modified top.size must survive all UI/cache
        # refreshes and drive the next malloc.
        top_size = self._top_size_from_memory()
        self._memory.register_object(
            "top", address, top_size or self._word_size() * 2,
            kind="top_chunk", label="top", provenance="derived",
        )

    def _initialize_top_memory(self, operation_id: str) -> None:
        if not self._layout_known:
            return
        address = self._heap_address(self._next_offset)
        provenance = MemoryProvenance.derived(operation_id, writer="allocator", note="initial top header")
        self._memory.register_object("top", address, self._initial_top_size, kind="top_chunk", label="top", provenance="derived")
        self._memory.write_uint(address, 0, self._word_size(), provenance, state="metadata")
        self._memory.write_uint(
            self._offset_address(address, self._word_size()),
            self._initial_top_size | 1,
            self._word_size(),
            provenance,
            state="metadata",
        )

    def _top_size_from_memory(self) -> int | None:
        if not self._layout_known:
            return None
        raw = self._memory.read_uint(
            self._offset_address(self._heap_address(self._next_offset), self._word_size()),
            self._word_size(),
        )
        return (raw & ~0x7) if raw is not None else None

    def _consume_top(self, chunk_size: int, operation: HeapOperation) -> HeapWarning | None:
        """Split top using its current PhysicalMemory header as allocator truth."""

        old_offset = self._next_offset
        old_address = self._heap_address(old_offset)
        raw_top_size = self._memory.read_uint(
            self._offset_address(old_address, self._word_size()), self._word_size(),
        )
        top_size = (raw_top_size & ~0x7) if raw_top_size is not None else None
        minimum = 0x20 if self.config.bits == 64 else 0x10
        if top_size is None:
            return self._abort(
                "top_size_unknown", operation, "top.size must be readable", old_address,
                {"requested_chunk_size": hex(chunk_size)},
            )
        if top_size < minimum or top_size % self.config.alignment:
            return self._abort(
                "invalid_top_size", operation, "chunksize(top) is aligned and >= MINSIZE", old_address,
                {"raw_top_size": hex(raw_top_size or 0), "top_size": hex(top_size)},
            )
        if self.config.top_size_check and raw_top_size is not None and not (raw_top_size & 1):
            return self._abort(
                "invalid_top_prev_inuse", operation, "top PREV_INUSE must be set", old_address,
                {"raw_top_size": hex(raw_top_size)},
            )
        if top_size < chunk_size + minimum:
            return self._abort(
                "top_size_too_small", operation, "chunksize(top) >= nb + MINSIZE", old_address,
                {"top_size": hex(top_size), "requested_chunk_size": hex(chunk_size)},
            )
        new_size = top_size - chunk_size
        self._next_offset = old_offset + chunk_size
        new_address = self._heap_address(self._next_offset)
        provenance = MemoryProvenance.derived(operation.op_id, writer="allocator", note="top split from memory")
        self._memory.register_object("top", new_address, new_size, kind="top_chunk", label="top", provenance="derived")
        self._memory.write_uint(new_address, chunk_size, self._word_size(), provenance, state="metadata")
        self._memory.write_uint(
            self._offset_address(new_address, self._word_size()),
            new_size | 1,
            self._word_size(),
            provenance,
            state="metadata",
        )
        return None

    def _write_metadata_value(
        self,
        base: str,
        expression: str,
        size: int,
        operation_id: str,
        *,
        offset: int = 0,
        note: str = "allocator metadata",
    ) -> None:
        address = self._offset_address(base, offset)
        text = str(expression or "0").strip()
        value = 0 if text in {"NULL", "null", ""} else parse_int_expr(text, self.variables)
        provenance = MemoryProvenance.derived(operation_id, source_expression=text, writer="allocator", note=note)
        if value is not None:
            self._memory.write_uint(address, value, size, provenance, state="metadata")
        else:
            self._memory.write_symbolic(address, text, size, provenance, state="metadata")

    def _write_chunk_size_header(self, chunk: ChunkState, size: int, *, note: str) -> None:
        try:
            current = self._memory.read_uint(self._offset_address(chunk.address, self._word_size()), self._word_size())
        except ValueError:
            current = None
        flags = (current or 1) & 0x7
        self._memory.write_uint(
            self._offset_address(chunk.address, self._word_size()),
            size | flags,
            self._word_size(),
            MemoryProvenance.derived(self._current_operation_id, writer="allocator", note=note),
            state="metadata",
        )

    def _set_following_prev_inuse(self, chunk: ChunkState, size: int, *, inuse: bool, note: str) -> None:
        """Update the boundary tag at ``chunk + size`` in PhysicalMemory."""
        next_header = self._offset_address(chunk.address, size)
        provenance = MemoryProvenance.derived(
            self._current_operation_id, writer="allocator", note=note,
        )
        if not inuse:
            self._memory.write_uint(next_header, size, self._word_size(), provenance, state="metadata")
        size_field = self._offset_address(next_header, self._word_size())
        current = self._memory.read_uint(size_field, self._word_size())
        if current is not None:
            updated = current | 1 if inuse else current & ~1
            self._memory.write_uint(size_field, updated, self._word_size(), provenance, state="metadata")

    def _write_operation_payload(self, operation: HeapOperation, chunk: ChunkState, expression: str) -> PayloadIR:
        payload = PayloadEvaluator(bits=self.config.bits, variables=self.variables).evaluate(expression)
        return self._commit_payload(operation, chunk, payload, expression)

    def _commit_payload(self, operation: HeapOperation, chunk: ChunkState, payload: PayloadIR, expression: str) -> PayloadIR:
        if payload.length is None:
            return payload
        base_destination = chunk.user_address or self._offset_address(chunk.address, self._word_size() * 2)
        edit_offset = parse_int_expr(str(operation.meta.get("offset") or "0"), self.variables)
        if edit_offset is None:
            # An unresolved offset must never be silently treated as zero.
            return PayloadIR.unknown(expression, "edit offset is symbolic/unknown")
        destination = self._offset_address(base_destination, edit_offset)
        source_line = parse_int_expr(str(operation.meta.get("source_line") or "0"), self.variables) or 0
        impacts: list[WriteImpact] = []
        for segment in payload.segments:
            provenance_kind = ProvenanceKind.DERIVED if segment.raw_bytes is not None else ProvenanceKind.INFERRED
            provenance = MemoryProvenance(
                provenance_kind,
                operation.op_id,
                source_line,
                expression,
                segment.offset,
                chunk.chunk_id,
                "program payload write",
            )
            target = self._offset_address(destination, segment.offset)
            if segment.raw_bytes is not None:
                changes = self._memory.write(target, segment.raw_bytes, provenance, state="known")
            else:
                changes = self._memory.write_symbolic(
                    target,
                    segment.symbolic_value or segment.expression or "unknown",
                    segment.length,
                    provenance,
                    state="known",
                )
            for change in changes:
                impacts.extend(self._write_impacts(change, chunk, segment.offset))

        self._stamp_current_cross_write_provenance(impacts, chunk)

        self._write_sequence += 1
        event_id = f"write_{self._write_sequence:04d}"
        overwritten = tuple(dict.fromkeys(
            f"{item.target_chunk}.{item.target_field}" for item in impacts if item.target_field
        ))
        event = WriteEvent(
            event_id,
            operation.op_id,
            source_line,
            expression,
            chunk.user_address,
            destination,
            payload,
            payload.length,
            payload.confidence,
            chunk.chunk_id,
            tuple(impacts),
            overwritten,
            "program",
        )
        self._step_write_events.append(event)
        self._write_history.append(event)
        resized_chunks: set[str] = set()
        for impact in impacts:
            if impact.kind == WriteImpactKind.SELF_USER_WRITE.value:
                continue
            edge = OverwriteEdge(
                operation.op_id,
                chunk.chunk_id,
                chunk.user_address,
                impact.target_physical_object,
                impact.target_chunk,
                impact.target_field,
                str(impact.physical_start),
                str(impact.physical_end),
                impact.source_payload_offset,
                impact.before,
                impact.after,
                impact.confidence,
                impact.kind,
                impact.target_field_offset,
                impact.target_field_length,
                impact.source_payload_length,
                impact.changed_byte_mask,
            )
            self._step_overwrite_edges.append(edge)
            self._overwrite_history.append(edge)
            if impact.target_field == "size" and impact.target_chunk:
                resized_chunks.add(impact.target_chunk)
        for chunk_id in resized_chunks:
            target_chunk = self._chunks.get(chunk_id)
            if target_chunk is None:
                continue
            current_size = self._chunk_size_value(target_chunk)
            if current_size is not None:
                self._memory.register_object(
                    target_chunk.physical_id or target_chunk.chunk_id,
                    target_chunk.address,
                    current_size,
                    kind="malloc_chunk",
                    label=target_chunk.chunk_id,
                    provenance=target_chunk.provenance,
                )
        self._promote_fake_evidence_from_payload(expression, chunk)
        return payload

    def _stamp_current_cross_write_provenance(
        self,
        impacts: Iterable[WriteImpact],
        source_chunk: ChunkState,
    ) -> None:
        """Persist CURRENT cross-object ownership into PhysicalMemory.

        OverwriteEdge is an event/log artifact.  Canvas colour must survive
        later operations that do not touch the bytes, so the final bytes carry
        their current owner/writer relationship directly.  Rewriting the same
        bytes later replaces this provenance automatically.
        """
        source_physical = source_chunk.physical_id or source_chunk.chunk_id
        for impact in impacts:
            target_physical = impact.target_physical_object or impact.target_chunk
            if not target_physical or target_physical == source_physical:
                continue
            length = max(0, impact.physical_end.offset - impact.physical_start.offset)
            if length <= 0:
                continue
            current = self._memory.read(impact.physical_start, length)
            for span in current.spans:
                # Unknown holes cannot have been written by this payload.
                if span.state == "unknown" and span.data is None and not span.symbolic:
                    continue
                field_delta = max(0, span.start.offset - impact.physical_start.offset)
                provenance = MemoryProvenance(
                    kind=span.provenance.kind,
                    operation_id=self._current_operation_id,
                    source_line=span.provenance.source_line,
                    source_expression=span.provenance.source_expression,
                    payload_offset=span.provenance.payload_offset,
                    writer=source_chunk.chunk_id,
                    note="current cross-object payload write",
                    writer_object_id=source_physical,
                    write_kind=WriteKind.CROSS_CHUNK_OVERWRITE,
                    owner_at_write=target_physical,
                    target_field=impact.target_field,
                    target_field_offset=max(0, impact.target_field_offset + field_delta),
                )
                if span.data is not None:
                    self._memory.write(span.start, span.data, provenance, state=span.state)
                else:
                    self._memory.write_symbolic(
                        span.start,
                        span.symbolic or "unknown",
                        span.length,
                        provenance,
                        state=span.state,
                    )

    def _promote_fake_evidence_from_payload(self, expression: str, source: ChunkState) -> None:
        """A stored pointer to a candidate upgrades evidence, never confirms it."""
        text = str(expression or "")
        for chunk_id, candidate in list(self._chunks.items()):
            if candidate.view_kind != "fake_chunk" or candidate.evidence_level != "candidate":
                continue
            if (candidate.physical_id or candidate.chunk_id) == (source.physical_id or source.chunk_id):
                continue
            address = str(candidate.address or "")
            if chunk_id in text or (address and address in text):
                self._chunks[chunk_id] = replace(candidate, evidence_level="likely")

    def _payload_from_memory(self, address: str, length: int, expression: str) -> PayloadIR:
        read = self._memory.read(address, length)
        base = self._memory.address(address)
        segments: list[PayloadSegment] = []
        confidence = "derived"
        for span in read.spans:
            offset = span.start.offset - base.offset
            if span.state == "unknown" and span.data is None and not span.symbolic:
                confidence = "unknown"
                continue
            segments.append(PayloadSegment(
                offset,
                span.length,
                span.data,
                span.symbolic,
                expression,
                "little",
                "",
                span.provenance.kind.value,
            ))
            if span.data is None:
                confidence = "inferred"
        return PayloadIR(expression, tuple(segments), length, confidence)

    def _write_impacts(self, change, source_chunk: ChunkState, payload_offset: int) -> list[WriteImpact]:
        result: list[WriteImpact] = []
        change_start = change.start
        change_end = change.start.add(change.length)
        seen: set[tuple[str, str, int, int]] = set()
        candidates: list[ChunkState] = []
        for memory_object in self._memory.overlaps(change_start, change_end):
            chunk = self._chunks.get(memory_object.label) or self._chunks.get(memory_object.object_id)
            if chunk is None:
                chunk = self._current_chunk_for_physical(memory_object.object_id)
            if chunk is not None and chunk not in candidates:
                candidates.append(chunk)
        for chunk in candidates:
            try:
                chunk_start = self._memory.address(chunk.address)
            except ValueError:
                continue
            if chunk_start.space != change_start.space:
                continue
            size = self._chunk_size_value(chunk) or parse_int_expr(chunk.original_chunk_size or chunk.chunk_size, self.variables)
            if size is None or size <= 0:
                continue
            chunk_end = chunk_start.add(size)
            left = max(change_start.offset, chunk_start.offset)
            right = min(change_end.offset, chunk_end.offset)
            if right <= left:
                continue
            field_ranges = self._typed_field_ranges(chunk, size)
            for field_start, field_end, field_name in field_ranges:
                absolute_start = chunk_start.offset + field_start
                absolute_end = chunk_start.offset + field_end
                hit_start = max(left, absolute_start)
                hit_end = min(right, absolute_end)
                if hit_end <= hit_start:
                    continue
                physical_id = chunk.physical_id or chunk.chunk_id
                key = (physical_id, field_name, hit_start, hit_end)
                if key in seen:
                    continue
                seen.add(key)
                local_change = hit_start - change_start.offset
                length = hit_end - hit_start
                numeric = field_name in {"prev_size", "size", "next", "fd", "bk", "key", "fd_nextsize", "bk_nextsize"}
                before = self._display_read_fragment(change.before, local_change, length, numeric=numeric)
                after = self._display_read_fragment(change.after, local_change, length, numeric=numeric)
                result.append(WriteImpact(
                    physical_id,
                    chunk.chunk_id,
                    field_name,
                    MemoryAddress(change_start.root, hit_start, change_start.expression),
                    MemoryAddress(change_start.root, hit_end, change_start.expression),
                    payload_offset + local_change,
                    before,
                    after,
                    "derived",
                    self._write_impact_kind(source_chunk, chunk, field_name, length, field_end - field_start),
                    hit_start - absolute_start,
                    length,
                    length,
                    self._changed_byte_mask(
                        change.before, change.after, local_change, length,
                        hit_start - absolute_start, field_end - field_start,
                    ),
                ))
        for memory_object in self._memory.overlaps(change_start, change_end):
            if memory_object.kind != "top_chunk":
                continue
            top_start = memory_object.start
            for field_offset, field_name in ((0, "prev_size"), (self._word_size(), "size")):
                absolute_start = top_start.offset + field_offset
                absolute_end = absolute_start + self._word_size()
                hit_start = max(change_start.offset, absolute_start)
                hit_end = min(change_end.offset, absolute_end)
                if hit_end <= hit_start:
                    continue
                key = ("top", field_name, hit_start, hit_end)
                if key in seen:
                    continue
                seen.add(key)
                local_change = hit_start - change_start.offset
                length = hit_end - hit_start
                result.append(WriteImpact(
                    "top",
                    "top",
                    field_name,
                    MemoryAddress(change_start.root, hit_start, change_start.expression),
                    MemoryAddress(change_start.root, hit_end, change_start.expression),
                    payload_offset + local_change,
                    self._display_read_fragment(change.before, local_change, length, numeric=True),
                    self._display_read_fragment(change.after, local_change, length, numeric=True),
                    "derived",
                    WriteImpactKind.TOP_METADATA_CORRUPTION.value,
                    hit_start - absolute_start,
                    length,
                    length,
                    self._changed_byte_mask(
                        change.before, change.after, local_change, length,
                        hit_start - absolute_start, self._word_size(),
                    ),
                ))
        return result

    def _write_impact_kind(
        self,
        source: ChunkState,
        target: ChunkState,
        field: str,
        hit_length: int,
        field_length: int,
    ) -> str:
        same_object = (source.physical_id or source.chunk_id) == (target.physical_id or target.chunk_id)
        if field.startswith("user"):
            return (
                WriteImpactKind.SELF_USER_WRITE.value
                if same_object
                else WriteImpactKind.CROSS_OBJECT_WRITE.value
            )
        if field in {"next", "fd", "bk", "key", "fd_nextsize", "bk_nextsize"}:
            return WriteImpactKind.FREELIST_METADATA_CORRUPTION.value
        if hit_length < field_length:
            return WriteImpactKind.PARTIAL_FIELD_OVERWRITE.value
        return (
            WriteImpactKind.SELF_METADATA_WRITE.value
            if same_object
            else WriteImpactKind.CROSS_CHUNK_OVERWRITE.value
        )

    @staticmethod
    def _changed_byte_mask(
        before, after, offset: int, length: int,
        field_offset: int = 0, field_length: int | None = None,
    ) -> str:
        left = before.data
        right = after.data
        if left is None or right is None or offset + length > len(left) or offset + length > len(right):
            return "unknown"
        touched = ["ff" if a != b else "00" for a, b in zip(left[offset:offset + length], right[offset:offset + length])]
        total = max(length, field_length or length)
        mask = ["00"] * total
        mask[field_offset:field_offset + length] = touched
        return " ".join(mask)

    def _typed_field_ranges(self, chunk: ChunkState, size: int) -> list[tuple[int, int, str]]:
        word = self._word_size()
        ranges: list[tuple[int, int, str]] = [(0, min(word, size), "prev_size")]
        if size > word:
            ranges.append((word, min(word * 2, size), "size"))
        if size <= word * 2:
            return ranges
        location = chunk.bin_location.lower()
        cursor = word * 2
        if location.startswith("tcache"):
            ranges.append((cursor, min(cursor + word, size), "next"))
            cursor += word
            if cursor < size:
                ranges.append((cursor, min(cursor + word, size), "key"))
                cursor += word
        elif location.startswith("fastbin"):
            ranges.append((cursor, min(cursor + word, size), "fd"))
            cursor += word
        elif location == "unsorted" or "smallbin" in location or "largebin" in location or chunk.lifecycle == "fake":
            ranges.append((cursor, min(cursor + word, size), "fd"))
            cursor += word
            if cursor < size:
                ranges.append((cursor, min(cursor + word, size), "bk"))
                cursor += word
            if "largebin" in location:
                if cursor < size:
                    ranges.append((cursor, min(cursor + word, size), "fd_nextsize"))
                    cursor += word
                if cursor < size:
                    ranges.append((cursor, min(cursor + word, size), "bk_nextsize"))
                    cursor += word
        if cursor < size:
            ranges.append((cursor, size, f"user[0x{max(0, cursor - word * 2):x}]") )
        return ranges

    @staticmethod
    def _display_read_fragment(read, offset: int, length: int, *, numeric: bool) -> str:
        end = offset + length
        raw = bytearray()
        symbolic: list[str] = []
        covered = 0
        absolute_start = read.start.offset + offset
        absolute_end = read.start.offset + end
        for span in read.spans:
            left = max(span.start.offset, absolute_start)
            right = min(span.end.offset, absolute_end)
            if right <= left:
                continue
            local_left = left - span.start.offset
            local_right = right - span.start.offset
            covered += right - left
            if span.data is not None:
                raw.extend(span.data[local_left:local_right])
            else:
                symbolic.append(span.symbolic or "unknown")
        if symbolic:
            return " | ".join(dict.fromkeys(symbolic))
        if covered != length:
            return "unknown"
        if numeric and length <= 8:
            return hex(int.from_bytes(bytes(raw), "little"))
        return repr(bytes(raw))

    def _decoded_freelist_target(self, chunk: ChunkState) -> str:
        field_text = self._fd_field_address(chunk)
        try:
            field = self._memory.address(field_text)
        except ValueError:
            return ""
        read = self._memory.read(field, self._word_size())
        if read.data is not None:
            stored = int.from_bytes(read.data, "little")
            if self.config.safe_linking:
                if not field.concrete:
                    return ""
                stored ^= field.offset >> 12
            return "NULL" if stored == 0 else hex(stored)
        expression = (read.symbolic or "").strip()
        if not expression:
            return ""
        packed = re.fullmatch(r"p(?:8|16|32|64)\s*\((.*)\)", expression)
        if packed:
            expression = packed.group(1).strip()
        protected = re.fullmatch(r"PROTECT_PTR\s*\(.*?,\s*(.*?)\s*\)", expression)
        if protected:
            target = protected.group(1).strip()
            return "NULL" if target in {"0", "0x0", "NULL"} else target
        if self.config.safe_linking:
            try:
                node = ast.parse(expression, mode="eval").body
            except SyntaxError:
                return ""
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitXor):
                left_shift = self._is_shift12_expr(node.left)
                right_shift = self._is_shift12_expr(node.right)
                if left_shift ^ right_shift:
                    target_node = node.right if left_shift else node.left
                    return ast.unparse(target_node).strip()
            return ""
        return expression

    def _same_pointer(self, left: str, right: str) -> bool:
        if left in {"NULL", "0", "0x0"} and right in {"NULL", "0", "0x0"}:
            return True
        try:
            return self._memory.address(left) == self._memory.address(right)
        except ValueError:
            return re.sub(r"\s+", "", left) == re.sub(r"\s+", "", right)

    def _ordered_physical_chunks(self) -> list[ChunkState]:
        def sort_key(item: tuple[int, ChunkState]) -> tuple[int, int, int]:
            fallback, chunk = item
            start = self._chunk_address_value(chunk)
            return (1, fallback, fallback) if start is None else (0, start, fallback)

        return [chunk for _fallback, chunk in sorted(enumerate(self._chunks.values()), key=sort_key)]

    def _previous_physical_chunks(self, ordered_chunks: list[ChunkState]) -> dict[str, ChunkState]:
        previous: dict[str, ChunkState] = {}
        pending_by_end: list[tuple[int, int, ChunkState]] = []
        nearest_closed: ChunkState | None = None
        nearest_end = -1
        for sequence, chunk in enumerate(ordered_chunks):
            start = self._chunk_address_value(chunk)
            if start is None:
                continue
            while pending_by_end and pending_by_end[0][0] <= start:
                range_end, _order, prior = heapq.heappop(pending_by_end)
                if range_end >= nearest_end:
                    nearest_closed = prior
                    nearest_end = range_end
            if nearest_closed is not None:
                previous[chunk.chunk_id] = nearest_closed
            size = self._chunk_size_value(chunk)
            heapq.heappush(pending_by_end, (start + max(size or 1, 1), sequence, chunk))
        return previous

    def _chunk_address_value(self, chunk: ChunkState) -> int | None:
        try:
            address = self._memory.address(chunk.address)
            if address.concrete:
                return address.offset
            heap_root = self._memory.address(self.config.heap_base)
            if address.root == heap_root.root:
                return (heap_root.offset if heap_root.concrete else 0) + address.offset
        except ValueError:
            pass
        offset = parse_int_expr(chunk.heap_offset, self.variables)
        if offset is not None:
            base = parse_int_expr(self.config.heap_base, self.variables)
            return (base or 0) + offset
        text = (chunk.address or "").strip().replace(" ", "")
        if "+" in text:
            offset = parse_int_expr(text.rsplit("+", 1)[-1])
            if offset is not None:
                base = parse_int_expr(text.split("+", 1)[0])
                return (base or 0) + offset
        return None

    def _chunk_size_value(self, chunk: ChunkState) -> int | None:
        """Read the allocator size word from PhysicalMemory first."""
        try:
            raw = self._memory.read_uint(
                self._offset_address(chunk.address, self._word_size()),
                self._word_size(),
            )
        except ValueError:
            raw = None
        if raw is not None:
            return raw & ~0x7
        return parse_int_expr(chunk.chunk_size, self.variables)

    @staticmethod
    def _is_prev_size_visible(previous: ChunkState | None) -> bool:
        if previous is None:
            return False
        if previous.role == "consolidated" or "consolidated" in previous.bin_location:
            return True
        return previous.lifecycle == "freed"

    def _prev_size_field_value(self, chunk: ChunkState, previous: ChunkState | None) -> str:
        flagged = self._memory.read_uint(
            self._offset_address(chunk.address, self._word_size()), self._word_size(),
        )
        if flagged is not None:
            if flagged & 1:
                return "inactive / unknown"
            raw = self._memory.read_uint(chunk.address, self._word_size())
            return hex(raw) if raw is not None else "unknown / not observed"
        # Compatibility fallback for an imported old scene that predates the
        # PhysicalMemory snapshot.  New replay paths never derive a boundary
        # tag solely from a neighbouring ChunkState lifecycle.
        if previous is not None:
            size = self._chunk_size_value(previous)
            if self._is_prev_size_visible(previous) and size is not None:
                return hex(size)
        return "inactive / unknown"

    def _size_truth_triple(self, chunk: ChunkState) -> tuple[str, str, str]:
        """尺寸三拆的物理真值，全部读自 PhysicalMemory，绝不用历史 header size 冒充。

        返回 (physical_extent_size, header_raw_size, decoded_chunksize)。
        extent 取注册对象（malloc/top/fake chunk 事务登记）的真实范围；
        对象未登记（布局未知）时退回创建期 chunk size，并保持为诚实降级而非观测值。
        """
        word = self._word_size()
        try:
            raw = self._memory.read_uint(
                self._offset_address(chunk.address, word), word,
            )
        except ValueError:
            raw = None
        object_id = chunk.physical_id or chunk.chunk_id
        extent = next(
            (item.size for item in self._memory.objects if item.object_id == object_id),
            None,
        )
        if extent is None:
            extent = parse_int_expr(chunk.original_chunk_size or chunk.chunk_size, self.variables)
        header_raw = hex(raw) if raw is not None else ""
        decoded = hex(raw & ~0x7) if raw is not None else ""
        extent_text = hex(extent) if extent is not None and extent > 0 else ""
        return extent_text, header_raw, decoded

    def _size_field_value(self, chunk: ChunkState, previous: ChunkState | None) -> str:
        try:
            flagged = self._memory.read_uint(self._offset_address(chunk.address, self._word_size()), self._word_size())
        except ValueError:
            flagged = None
        if flagged is None:
            size = self._chunk_size_value(chunk)
            prev_inuse = not self._is_prev_size_visible(previous)
            if size is None:
                return f"{chunk.chunk_size} | PREV_INUSE={int(prev_inuse)}"
            flagged = size | (1 if prev_inuse else 0)
        return f"{hex(flagged)} ({hex(flagged & ~0x7)} | PREV_INUSE={flagged & 1})"

    def _enrich_chunk(
        self,
        chunk: ChunkState,
        previous: ChunkState | None = None,
        memory_snapshot=None,
    ) -> ChunkState:
        memory_snapshot = memory_snapshot or self._memory.snapshot()
        view = ChunkMemoryView(
            memory_snapshot,
            chunk.address,
            bits=self.config.bits,
            lifecycle=chunk.lifecycle,
            bin_location=chunk.bin_location,
            chunk_size_hint=parse_int_expr(chunk.original_chunk_size or chunk.chunk_size, self.variables),
            safe_linking=self.config.safe_linking,
        )
        typed = list(view.fields())
        fields: list[ChunkField] = []
        for item in typed:
            value = item.value
            meaning = item.meaning
            if item.name == "prev_size" and value == "unknown":
                value = self._prev_size_field_value(chunk, previous)
            elif item.name == "size":
                value = self._size_field_value(chunk, previous)
            if chunk.lifecycle == "fake":
                if item.name == "prev_size" and value == "0x0":
                    value = "0"
                elif item.name == "size":
                    raw_size = self._memory.read_uint(
                        self._offset_address(chunk.address, self._word_size()),
                        self._word_size(),
                    )
                    if raw_size is not None:
                        value = hex(raw_size)
            if item.stored_value:
                meaning += f"; stored={item.stored_value}; decoded={item.decoded_value or 'unknown'}; formula=stored ^ (field_address >> 12)"
            fields.append(ChunkField(
                f"+0x{item.offset:02x}",
                item.name,
                value,
                meaning,
                item.address,
                item.role,
                item.provenance,
            ))
        current_size = view.chunk_size()
        fd_field = next((item for item in fields if item.role == "fd"), None)
        bk_field = next((item for item in fields if item.role == "bk"), None)
        extent_text, header_raw_text, decoded_text = self._size_truth_triple(chunk)
        enriched = replace(
            chunk,
            chunk_size=hex(current_size) if current_size is not None else chunk.chunk_size,
            original_chunk_size=chunk.original_chunk_size or chunk.chunk_size,
            physical_extent_size=extent_text,
            header_raw_size=header_raw_text,
            decoded_chunksize=decoded_text,
            fields=tuple(fields),
            fd=fd_field.value if fd_field and fd_field.value != "unknown" else chunk.fd,
            bk=bk_field.value if bk_field and bk_field.value != "unknown" else chunk.bk,
            view_kind=view.view_kind,
        )
        return replace(enriched, memory_regions=self._memory_regions_from_physical(enriched, view))

    def _memory_regions_from_physical(self, chunk: ChunkState, view: ChunkMemoryView) -> tuple[MemoryRegion, ...]:
        size = view.chunk_size() or parse_int_expr(chunk.original_chunk_size or chunk.chunk_size, self.variables)
        if size is None:
            return self._memory_regions(chunk, chunk.fields)
        read = view.memory.read(chunk.address, size)
        result: list[MemoryRegion] = []
        field_by_offset = {item.offset: item for item in view.fields()}
        rendered_field_by_offset = {
            parse_int_expr(item.offset, self.variables): item
            for item in chunk.fields
            if parse_int_expr(item.offset, self.variables) is not None
        }
        base = self._memory.address(chunk.address)
        word = self._word_size()
        for span in read.spans:
            span_start = span.start.offset - base.offset
            span_end = span_start + span.length
            cuts = {span_start, span_end}
            if span.data is not None:
                # Word-boundary cuts only make sense where real bytes exist.
                # A corrupted size can make the read sweep a gigantic implicit
                # unknown hole; cutting that per word would never terminate.
                first_word = max(0, (span_start // word) * word)
                for boundary in range(first_word, span_end + word, word):
                    if span_start < boundary < span_end:
                        cuts.add(boundary)
            for field_offset, typed_field in field_by_offset.items():
                for boundary in (field_offset, field_offset + typed_field.size):
                    if span_start < boundary < span_end:
                        cuts.add(boundary)
            ordered_cuts = sorted(cuts)
            for start, end in zip(ordered_cuts, ordered_cuts[1:]):
                piece = span.slice(start - span_start, end - span_start)
                field = next((item for offset, item in field_by_offset.items() if offset <= start < offset + item.size), None)
                if piece.data is not None:
                    value = repr(piece.data)
                    state = "zero" if piece.data and not any(piece.data) else piece.state
                else:
                    value = piece.symbolic
                    state = piece.state
                if field and field.role != "user" and start == field.offset and piece.length == field.size:
                    rendered = rendered_field_by_offset.get(field.offset)
                    value = rendered.value if rendered is not None else field.value
                    state = "metadata" if value != "unknown" else "unknown"
                provenance = piece.provenance.kind.value
                if field and field.role == "user":
                    # A physical span may start in the middle of the broad
                    # allocated-user typed field (for example one known byte
                    # followed by an unobserved tail).  Label the exact byte
                    # offset rather than inheriting the field's `user[0]`
                    # name, which would make the memory table misleading.
                    user_offset = max(0, start - word * 2)
                    offset_text = str(user_offset) if user_offset < 0x10 else f"0x{user_offset:x}"
                    region_name = f"user[{offset_text}]"
                else:
                    region_name = field.name if field else f"user[0x{max(0, start - word * 2):x}]"
                region_meaning = field.meaning if field else "user bytes backed by PhysicalMemory"
                if field is None and piece.provenance.writer == "allocator":
                    note = piece.provenance.note or "allocator metadata"
                    if piece.symbolic == "top_size" or "top header" in note:
                        region_name = "top.size"
                    elif "tcache key" in note:
                        region_name = "tcache.key"
                    else:
                        region_name = "allocator.metadata"
                    region_meaning = f"allocator 写入：{note}；该地址与当前 chunk 视图发生物理重叠"
                result.append(MemoryRegion(
                    start,
                    end,
                    value,
                    state,
                    region_name,
                    provenance,
                    region_meaning,
                ))
        return self._merge_memory_regions(result)

    @staticmethod
    def _split_user_words(data: str, word: int) -> tuple[str, str]:
        text = (data or "").strip()
        if not text:
            return ("unknown", "unknown")
        try:
            value = ast.literal_eval(text)
        except (SyntaxError, ValueError):
            return (text, "unknown")
        if isinstance(value, bytes):
            first = repr(value[:word]) if value[:word] else "unknown"
            second = repr(value[word : word * 2]) if value[word : word * 2] else "unknown"
            return (first, second)
        if isinstance(value, str):
            first_text = value[:word]
            second_text = value[word : word * 2]
            return (repr(first_text) if first_text else "unknown", repr(second_text) if second_text else "unknown")
        return (text, "unknown")

    def _memory_regions(self, chunk: ChunkState, fields: tuple[ChunkField, ...]) -> tuple[MemoryRegion, ...]:
        """Build a conservative physical-memory view for the renderer.

        Missing malloc data is deliberately unknown.  Only an explicit byte
        value or an allocator metadata write may become zero/known.
        """
        word = self._word_size()
        size = self._chunk_size_value(chunk)
        end = max(word * 2, size or word * 4)
        regions: list[MemoryRegion] = []
        for index, field in enumerate(fields[:2]):
            start = index * word
            regions.append(MemoryRegion(
                start,
                min(end, start + word),
                field.value,
                "metadata",
                field.name,
                field.provenance,
                field.meaning,
            ))

        user_start = word * 2
        if end <= user_start:
            return self._merge_memory_regions(regions)

        metadata_view = chunk.lifecycle in {"freed", "fake", "stale"} or bool(chunk.fd or chunk.bk)
        if metadata_view:
            for index, field in enumerate(fields[2:4], 2):
                start = index * word
                if start >= end:
                    break
                value = field.value or "unknown"
                state = "zero" if value in {"NULL", "0", "0x0", "b'\\x00'"} else "metadata"
                provenance = "derived" if value != "unknown" else "unknown"
                regions.append(MemoryRegion(start, min(end, start + word), value, state, field.name, provenance, field.meaning))
            covered = min(end, word * 4)
            if covered < end:
                previous_bytes = self._safe_bytes_value(chunk.data)
                preserved = previous_bytes[word * 2 :] if previous_bytes is not None else b""
                cursor = covered
                for index in range(0, min(len(preserved), end - covered), word):
                    piece = preserved[index : min(index + word, end - covered)]
                    if not piece:
                        break
                    state = "zero" if all(value == 0 for value in piece) else "known"
                    regions.append(MemoryRegion(cursor, cursor + len(piece), repr(piece), state, f"user[{cursor - user_start}]", "derived", "EXP payload bytes preserved across free"))
                    cursor += len(piece)
                if cursor < end:
                    regions.append(MemoryRegion(cursor, end, "", "unknown", "user", "unknown", "not observed after allocator metadata"))
            return self._merge_memory_regions(regions)

        byte_value = self._safe_bytes_value(chunk.data)
        if byte_value is not None:
            cursor = user_start
            for index in range(0, min(len(byte_value), end - user_start), word):
                piece = byte_value[index : min(index + word, end - user_start)]
                if not piece:
                    break
                state = "zero" if all(value == 0 for value in piece) else "known"
                regions.append(MemoryRegion(cursor, cursor + len(piece), repr(piece), state, f"user[{cursor - user_start}]", "derived", "explicit EXP payload bytes"))
                cursor += len(piece)
            if cursor < end:
                regions.append(MemoryRegion(cursor, end, "", "unknown", "user", "unknown", "not written or observed"))
            return self._merge_memory_regions(regions)

        text = (chunk.data or "").strip()
        if text:
            regions.append(MemoryRegion(user_start, min(end, user_start + word), text, "known", "user[0]", "inferred", "symbolic payload expression"))
            if user_start + word < end:
                regions.append(MemoryRegion(user_start + word, end, "", "unknown", "user", "unknown", "not written or observed"))
        else:
            regions.append(MemoryRegion(user_start, end, "", "unknown", "user", "unknown", "malloc returned uninitialised storage"))
        return self._merge_memory_regions(regions)

    @staticmethod
    def _merge_memory_regions(regions: list[MemoryRegion]) -> tuple[MemoryRegion, ...]:
        merged: list[MemoryRegion] = []
        for region in regions:
            if (
                merged
                and region.state in {"zero", "unknown"}
                and merged[-1].state == region.state
                and merged[-1].end == region.start
                and merged[-1].provenance == region.provenance
            ):
                previous = merged[-1]
                merged[-1] = MemoryRegion(
                    previous.start,
                    region.end,
                    "NULL" if region.state == "zero" else "",
                    region.state,
                    previous.name or region.name,
                    region.provenance,
                    previous.meaning or region.meaning,
                )
            else:
                merged.append(region)
        return tuple(merged)

    @classmethod
    def _safe_bytes_value(cls, expression: str) -> bytes | None:
        text = (expression or "").strip()
        if not text:
            return None
        try:
            node = ast.parse(text, mode="eval").body
        except SyntaxError:
            return None

        def evaluate(item: ast.AST):
            if isinstance(item, ast.Constant):
                if isinstance(item.value, bytes):
                    return item.value
                if isinstance(item.value, str):
                    return item.value.encode()
                if isinstance(item.value, int):
                    return item.value
            if isinstance(item, (ast.List, ast.Tuple)):
                values = [evaluate(child) for child in item.elts]
                if all(isinstance(value, int) and 0 <= value <= 255 for value in values):
                    return values
            if isinstance(item, ast.BinOp):
                left, right = evaluate(item.left), evaluate(item.right)
                if isinstance(left, int) and isinstance(right, int):
                    if isinstance(item.op, ast.Add):
                        return left + right
                    if isinstance(item.op, ast.Sub):
                        return left - right
                    if isinstance(item.op, ast.Mult):
                        return left * right
                if isinstance(item.op, ast.Add) and isinstance(left, bytes) and isinstance(right, bytes):
                    return left + right
                if isinstance(item.op, ast.Mult):
                    if isinstance(left, bytes) and isinstance(right, int) and 0 <= right <= 0x10000:
                        return left * right
                    if isinstance(right, bytes) and isinstance(left, int) and 0 <= left <= 0x10000:
                        return right * left
            if isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute) and item.func.attr in {"ljust", "rjust"}:
                base = evaluate(item.func.value)
                width = evaluate(item.args[0]) if item.args else None
                fill = evaluate(item.args[1]) if len(item.args) > 1 else b" "
                if isinstance(base, bytes) and isinstance(width, int) and isinstance(fill, bytes) and len(fill) == 1 and 0 <= width <= 0x10000:
                    return base.ljust(width, fill) if item.func.attr == "ljust" else base.rjust(width, fill)
            if isinstance(item, ast.Call) and isinstance(item.func, ast.Name) and item.func.id == "bytes" and len(item.args) <= 1:
                value = evaluate(item.args[0]) if item.args else []
                if isinstance(value, (list, tuple)):
                    try:
                        return bytes(value)
                    except ValueError:
                        return None
            return None

        value = evaluate(node)
        return value if isinstance(value, bytes) else None

    def _warning(
        self,
        severity: str,
        code: str,
        title: str,
        message: str,
        operation: HeapOperation,
        *chunks: str,
    ) -> HeapWarning:
        return HeapWarning(
            severity=severity,
            code=code,
            title=title,
            message=message,
            operation_id=operation.op_id,
            related_chunks=tuple(chunks),
        )

    def _abort(
        self,
        reason: str,
        operation: HeapOperation,
        check: str,
        address: str = "",
        metadata: Mapping[str, str] | None = None,
        *chunks: str,
    ) -> HeapWarning:
        self._aborted = True
        self._allocator_abort = AllocatorAbort(
            reason,
            operation.op_id,
            check,
            address,
            dict(metadata or {}),
            self.config.label,
        )
        return self._warning(
            "FATAL",
            reason,
            "allocator integrity abort",
            f"{check}; address={address or 'unknown'}; metadata={dict(metadata or {})}",
            operation,
            *chunks,
        )
