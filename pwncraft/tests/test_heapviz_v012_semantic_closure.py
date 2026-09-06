from __future__ import annotations

import json
from dataclasses import replace

from pwncraft.features.heapviz import GlibcHeapEngine, analyze_heap_source, build_allocator_config
from pwncraft.features.heapviz.constraints import ConstraintEngine, EditRequest, ValidationStatus, protect_ptr
from pwncraft.features.heapviz.contracts import (
    ArgumentBinding,
    ContractConfidence,
    ContractEvidence,
    ContractEvidenceSource,
    HelperContractResolver,
    lower_source_calls,
)
from pwncraft.features.heapviz.corrections import (
    CorrectionEngine,
    CorrectionHistory,
    HelperContractPatch,
    LayoutPatch,
    ObservedMemoryPatch,
    ReplayDependencyIndex,
)
from pwncraft.features.heapviz.memory import MemoryProvenance, PhysicalMemory
from pwncraft.features.heapviz.models import BinState, ChunkField, ChunkState, HeapSnapshot
from pwncraft.features.heapviz.presentation import (
    CanvasLayoutModel,
    CanvasObjectLayout,
    HeapVisualModelBuilder,
    PhysicalViewRelationKind,
    VisualKind,
)
from pwncraft.features.heapviz.semantics import (
    CanonicalHeapOperation,
    CanonicalOperationKind,
    ConcreteBytes,
    ConcreteInt,
    LengthExpr,
    SymbolicBytes,
    UnknownValue,
    evaluate_value,
)


def test_len_and_symbolic_byte_algebra_are_first_class() -> None:
    concrete = evaluate_value("len(b'A' * 0x18 + p64(x) + p64(0x91))")
    symbolic = evaluate_value("len(b'A' * n + p64(x))")
    sparse = evaluate_value("flat({0x20: p64(x), 0x38: p64(y)})")
    assert concrete == ConcreteInt(0x28, "len(b'A' * 0x18 + p64(x) + p64(0x91))")
    assert isinstance(symbolic, LengthExpr) and "n" in symbolic.expression and "+(8)" in symbolic.expression
    assert isinstance(sparse, SymbolicBytes)
    assert sparse.byte_length.value == 0x40
    assert sparse.spans == ((0x20, 0x28, "p64(x)"), (0x38, 0x40, "p64(y)"))


def test_addchunk_data_len_static_size_lower(  # requirement 211 / 5.1
) -> None:
    """addchunk(data) with send_size(len(data)) + send_data(data) proves ALLOC.

    Input: ``addchunk(b"A" * 0x80)`` where the helper body sends ``len(data)``
    as the size line.  Expected: ALLOC with menu_request == ConcreteInt(0x80).
    The same helper must keep working when the payload is a module-level
    builder (``payload = b"A" * 0x40 + p64(0)`` -> 0x48) and when the builder
    contains a free variable (``b"A" * n + p64(0)`` -> LengthExpr n+8).
    """
    source = '''
def addchunk(data):
    send_size(len(data))
    send_data(data)

addchunk(b"A" * 0x80)
'''
    operations = lower_source_calls(source)
    assert len(operations) == 1
    operation = operations[0]
    assert operation.kind is CanonicalOperationKind.ALLOC
    assert operation.menu_request == ConcreteInt(0x80, "len(b'A' * 128)")
    assert operation.payload == ConcreteBytes(b"A" * 0x80, "b'A' * 128")

    constant_payload = '''
def addchunk(data):
    send_size(len(data))
    send_data(data)

payload = b"A" * 0x40 + p64(0)
addchunk(payload)
'''
    operations = lower_source_calls(constant_payload)
    assert operations[0].kind is CanonicalOperationKind.ALLOC
    assert operations[0].menu_request == ConcreteInt(0x48, "len(b'A' * 64 + p64(0))")

    symbolic_payload = '''
def addchunk(data):
    send_size(len(data))
    send_data(data)

n = 0x30
payload = b"A" * n + p64(0)
addchunk(payload)
'''
    operations = lower_source_calls(symbolic_payload)
    assert operations[0].kind is CanonicalOperationKind.ALLOC
    assert isinstance(operations[0].menu_request, LengthExpr)
    assert "n" in operations[0].menu_request.expression


def test_contract_resolver_reorders_edit_and_lower_offset() -> None:
    source = """
def modify(slot, payload, where):
    io.sendline(b"2")
    io.sendlineafter(b"index", str(slot))
    io.sendlineafter(b"offset", str(where))
    io.sendafter(b"data", payload)

def pwn():
    modify(3, b"Z", 7)
pwn()
"""
    resolution = HelperContractResolver().resolve(source)
    contract = resolution.contract_for("modify")
    assert contract is not None and contract.operation is CanonicalOperationKind.EDIT
    assert contract.roles["offset"].parameter == "where"
    operation = lower_source_calls(source, resolution)[0]
    assert operation.kind is CanonicalOperationKind.EDIT
    assert operation.handle == ConcreteInt(3, "3")
    assert operation.offset == ConcreteInt(7, "7")
    assert isinstance(operation.length, ConcreteInt) and operation.length.value == 1


def test_mixed_profile_and_contract_calls_form_one_complete_canonical_stream() -> None:
    source = """
def modify(slot, where, payload):
    io.sendlineafter(b"index", str(slot))
    io.sendlineafter(b"offset", str(where))
    io.sendafter(b"data", payload)

add(0x20, b"A")
add(0x20, b"B")
modify(0, 0x28, b"\\x51")
"""
    result = analyze_heap_source(source)
    assert [item.kind for item in result.canonical_operations] == [
        CanonicalOperationKind.ALLOC,
        CanonicalOperationKind.ALLOC,
        CanonicalOperationKind.EDIT,
    ]
    assert [item.operation_id for item in result.canonical_operations] == ["op_001", "op_002", "op_003"]
    edit = result.canonical_operations[-1]
    assert edit.offset == ConcreteInt(0x28, "40")
    assert edit.length == ConcreteInt(1, "len(b'Q')")
    final = GlibcHeapEngine(build_allocator_config()).replay(result.canonical_operations)[-1]
    assert len(final.overwrite_edges) == 1
    assert final.overwrite_edges[0].target_field == "size"
    assert final.overwrite_edges[0].target_field_length == 1


def test_name_is_candidate_not_proof() -> None:
    source = "def addchunk(x):\n    return x + 1\n\naddchunk(3)\n"
    contract = HelperContractResolver().resolve(source).contract_for("addchunk")
    assert contract is not None
    assert contract.operation is CanonicalOperationKind.UNKNOWN
    assert contract.candidate_operation is CanonicalOperationKind.ALLOC
    assert not lower_source_calls(source)


def test_alias_partial_wrapper_method_and_cycle_are_bounded() -> None:
    source = """
from functools import partial
# pwncraft: op=alloc index=idx size=size data=data
def create(idx, size, data):
    io.sendline(b"1")
alias = create
add0 = partial(create, 0)
def take(size, data):
    return add0(size + 0x10, data)
class Menu:
    # pwncraft: op=delete index=idx
    def remove(self, idx):
        self.io.sendlineafter(b"index", str(idx))
def loop_a(x): return loop_b(x)
def loop_b(x): return loop_a(x)
menu = Menu()
alias(1, 0x20, b"A")
add0(0x30, b"B")
take(0x40, b"C")
menu.remove(2)
"""
    resolution = HelperContractResolver(max_wrapper_depth=4).resolve(source)
    assert resolution.contract_for("alias").operation is CanonicalOperationKind.ALLOC
    assert resolution.contract_for("add0").operation is CanonicalOperationKind.ALLOC
    assert resolution.contract_for("take").operation is CanonicalOperationKind.ALLOC
    assert resolution.contract_for("remove", "Menu").operation is CanonicalOperationKind.DELETE
    assert any(item.startswith("wrapper_cycle:") for item in resolution.diagnostics)
    operations = lower_source_calls(source, resolution)
    assert [item.kind for item in operations] == [
        CanonicalOperationKind.ALLOC,
        CanonicalOperationKind.ALLOC,
        CanonicalOperationKind.ALLOC,
        CanonicalOperationKind.DELETE,
    ]


def test_user_contract_fingerprint_stale_and_all_calls_relower() -> None:
    source = "def mystery(a, b):\n    return io.sendline(b)\n\nmystery(1, b'A')\nmystery(2, b'B')\n"
    base = HelperContractResolver().resolve(source).contract_for("mystery")
    assert base is not None
    confirmed = replace(
        base,
        operation=CanonicalOperationKind.EDIT,
        roles={
            "index": ArgumentBinding("index", "a", "a", 0),
            "data": ArgumentBinding("data", "b", "b", 1),
            "offset": ArgumentBinding("offset", expression="0", fixed=True),
        },
        evidence=(ContractEvidence(ContractEvidenceSource.USER_CONFIRMED, "user mapping", score=1.0),),
        confidence=ContractConfidence.CONFIRMED,
    )
    memory = PhysicalMemory()
    outcome = CorrectionEngine().apply(
        HelperContractPatch("contract-fix", contract=confirmed),
        memory=memory,
        source=source,
    )
    assert outcome.result.accepted
    assert outcome.result.normalized["affected_calls"] == 2
    changed = source.replace("def mystery(a, b):", "def mystery(b, a):")
    stale = HelperContractResolver(user_contracts=(confirmed,)).resolve(changed).contract_for("mystery")
    assert stale is not None and stale.status.value == "stale" and not stale.proven


def test_confirmed_contract_replaces_every_matching_legacy_call() -> None:
    source = "def mystery(slot, payload):\n    io.send(payload)\n\nmystery(1, b'A')\nmystery(2, b'B')\n"
    base = HelperContractResolver().resolve(source).contract_for("mystery")
    assert base is not None
    confirmed = replace(
        base,
        operation=CanonicalOperationKind.EDIT,
        roles={
            "index": ArgumentBinding("index", "slot", "slot", 0),
            "offset": ArgumentBinding("offset", expression="0", fixed=True),
            "data": ArgumentBinding("data", "payload", "payload", 1),
        },
        evidence=(ContractEvidence(ContractEvidenceSource.USER_CONFIRMED, "user", score=1.0),),
        confidence=ContractConfidence.CONFIRMED,
    )
    result = analyze_heap_source(source, helper_contracts=(confirmed,))
    assert len(result.operations) == 2
    assert [item.kind.value for item in result.operations] == ["edit", "edit"]
    assert [item.index for item in result.operations] == ["1", "2"]
    assert all(item.meta["offset"] == "0" for item in result.operations)


def test_edit_offset_reaches_physical_memory_address() -> None:
    operations = (
        CanonicalHeapOperation(
            "alloc-a", CanonicalOperationKind.ALLOC,
            handle=ConcreteInt(0), menu_request=ConcreteInt(0x20), payload=ConcreteBytes(b"A"),
        ),
        CanonicalHeapOperation(
            "edit-a", CanonicalOperationKind.EDIT,
            handle=ConcreteInt(0), offset=ConcreteInt(8), length=ConcreteInt(1), payload=ConcreteBytes(b"Z"),
        ),
    )
    config = replace(build_allocator_config(), heap_base="0x100000")
    final = GlibcHeapEngine(config).replay(operations)[-1]
    chunk = final.chunks["chunk_0"]
    base = int(chunk.user_address, 0)
    assert final.memory.read(base + 8, 1).data == b"Z"
    assert final.write_events[0].destination_address == hex(base + 8)


def test_incremental_replay_resumes_after_corrected_checkpoint() -> None:
    operations = (
        CanonicalHeapOperation(
            "alloc-a", CanonicalOperationKind.ALLOC,
            handle=ConcreteInt(0), menu_request=ConcreteInt(0x20), payload=ConcreteBytes(b"A"),
        ),
        CanonicalHeapOperation(
            "alloc-b", CanonicalOperationKind.ALLOC,
            handle=ConcreteInt(1), menu_request=ConcreteInt(0x20), payload=ConcreteBytes(b"B"),
        ),
        CanonicalHeapOperation("free-b", CanonicalOperationKind.DELETE, handle=ConcreteInt(1)),
    )
    config = replace(build_allocator_config(), heap_base="0x100000")
    prefix = GlibcHeapEngine(config).replay(operations[:2])
    checkpoint = prefix[-1]
    memory = PhysicalMemory.from_snapshot(checkpoint.memory)
    b_chunk = checkpoint.chunks["chunk_1"]
    memory.write(
        int(b_chunk.address, 0) + 8,
        (0x51).to_bytes(8, "little"),
        MemoryProvenance.user_observed("resize-b"),
    )
    corrected = replace(checkpoint, memory=memory.snapshot())
    resumed = GlibcHeapEngine(config).replay_from_snapshot(corrected, operations[2:])
    assert len(resumed) == 2
    assert resumed[0] is corrected
    assert resumed[-1].step == 3
    assert resumed[-1].bins.tcache["0x50"] == ("chunk_1",)


def test_replay_dependency_index_selects_earliest_affected_call() -> None:
    source = """
# pwncraft: op=alloc index=idx size=size data=data
def create(idx, size, data):
    io.sendline(b"1")
create(0, 0x20, b"A")
create(1, 0x30, b"B")
"""
    operations = analyze_heap_source(source).canonical_operations
    index = ReplayDependencyIndex.from_operations(operations)
    contract_id = operations[0].contract_id
    assert index.earliest_checkpoint(contract_ids=(contract_id,)) == 1
    assert index.suffix_operation_ids(1) == ("op_001", "op_002")


def test_constraint_statuses_and_field_address_safe_link() -> None:
    config = replace(build_allocator_config(), safe_linking=True)
    memory = PhysicalMemory()
    memory.register_object("A", 0x1000, 0x100)
    engine = ConstraintEngine(config)
    valid = engine.validate(EditRequest("size", 0x1008, 0x91, 8), memory)
    invalid = engine.validate(EditRequest("size", 0x1008, -1, 8), memory)
    corruption = engine.validate(EditRequest("next", 0x1010, 0x123, 8, decoded_pointer=True), memory)
    assert valid.status is ValidationStatus.VALID
    assert invalid.status is ValidationStatus.INVALID
    assert corruption.status is ValidationStatus.REPRESENTABLE_CORRUPTION
    assert protect_ptr(0x1010, 0x404040) == 0x404040 ^ (0x1010 >> 12)
    derived = engine.validate(EditRequest("bin_location", 0x1010, "unsorted", 8), memory)
    assert derived.status is ValidationStatus.INVALID
    structural = engine.validate_prev_size(0x1100, 0x80, previous_address=0x1000, previous_size=0x100)
    observed = engine.validate_prev_size(0x1100, 0x80, previous_address=0x1000, previous_size=0x100, observed=True)
    assert structural.status is ValidationStatus.INVALID
    assert observed.status is ValidationStatus.REPRESENTABLE_CORRUPTION


def test_decoded_safe_link_correction_writes_encoded_stored_value() -> None:
    memory = PhysicalMemory()
    memory.register_object("A", 0x5000, 0x40)
    memory.write(0x5000, b"\0" * 0x40, MemoryProvenance.derived("initial"))
    config = replace(build_allocator_config(), safe_linking=True)
    target = 0x6010
    outcome = CorrectionEngine(config).apply(
        ObservedMemoryPatch(
            "safe-link",
            address="0x5010",
            data=target.to_bytes(8, "little"),
            length=8,
            field="fd",
            decoded_pointer=True,
        ),
        memory=memory,
    )
    assert outcome.result.accepted
    assert memory.read_uint(0x5010, 8) == protect_ptr(0x5010, target)


def test_observed_patch_writes_memory_and_layout_patch_does_not() -> None:
    memory = PhysicalMemory()
    memory.register_object("A", 0x2000, 0x40)
    memory.write(0x2000, b"A" * 0x40, MemoryProvenance.derived("initial"))
    engine = CorrectionEngine()
    before = memory.snapshot()
    layout = engine.apply(LayoutPatch("layout", object_id="A", after={"x": 88}), memory=memory)
    assert layout.replay is None and memory.snapshot() == before
    patched = engine.apply(
        ObservedMemoryPatch("mem", checkpoint=2, address="0x2008", data=b"Z", length=1, object_id="A"),
        memory=memory,
    )
    assert patched.result.accepted
    assert memory.read(0x2008, 1).data == b"Z"
    assert patched.replay.start_checkpoint == 3


def test_canvas_layout_drag_resize_undo_and_persistence(tmp_path) -> None:
    model = CanvasLayoutModel((
        CanvasObjectLayout("A", 10, 20, 200, 100),
        CanvasObjectLayout("B", 300, 20, 200, 100),
        CanvasObjectLayout("C", 700, 80, 200, 100),
    ))
    model.move(("A",), 17, 9)
    model.resize("A", 260, 140)
    model.select(("A", "B", "C"))
    model.align(model.selected_ids, "top")
    model.distribute(model.selected_ids, "horizontal")
    assert model.get("A").x == 27 and model.get("A").width == 260
    model.undo()
    model.redo()
    path = tmp_path / "layout.json"
    model.save(path)
    loaded = CanvasLayoutModel.load(path)
    assert loaded.to_dict() == model.to_dict()
    # Layout contains no address or memory field by construction.
    assert "address" not in json.dumps(loaded.to_dict())


def _snapshot_with_chunks(chunks: dict[str, ChunkState], edges=()) -> HeapSnapshot:
    return HeapSnapshot(1, "op", chunks, BinState(), overwrite_edges=tuple(edges))


def test_visual_normal_reuse_and_attack_name_false_positive_have_no_overlap_span() -> None:
    old = ChunkState("old", "0x1000", "0x20", "0x30", "stale", physical_id="p", role="house-of-anything")
    new = ChunkState("new", "0x1000", "0x20", "0x30", "allocated", physical_id="p")
    model = HeapVisualModelBuilder().build(_snapshot_with_chunks({"old": old, "new": new}))
    assert model.relations[0].kind is PhysicalViewRelationKind.NORMAL_REUSE
    assert not any(span.visual_kind is VisualKind.PHYSICAL_OVERLAP for span in model.spans)


def test_visual_partial_one_byte_cross_write_span() -> None:
    from pwncraft.features.heapviz.events import OverwriteEdge

    fields = (ChunkField("+0x8", "size", "0x91", address="0x1008", role="size"),)
    chunk = ChunkState("B", "0x1000", "0x20", "0x30", "allocated", physical_id="pB", fields=fields)
    edge = OverwriteEdge(
        "edit-a", "A", "0xff0", "pB", "B", "size", "0x1008", "0x1009", 0x18,
        "0x91", "0x00", target_field_offset=0, target_field_length=1, source_payload_length=1,
    )
    model = HeapVisualModelBuilder().build(_snapshot_with_chunks({"B": chunk}, (edge,)))
    spans = [span for span in model.spans if span.visual_kind is VisualKind.CROSS_WRITE]
    assert len(spans) == 1
    assert spans[0].physical_start == "0x1008"
    assert spans[0].physical_end == "0x1009"
    assert spans[0].byte_length == 1


def test_helper_variant_benchmark_120_contracts() -> None:
    blocks: list[str] = []
    calls: list[str] = []
    for index in range(30):
        for kind, parameters, annotation, call in (
            ("alloc", "idx, content, size", "index=idx data=content size=size", f"h_alloc_{index}(1, b'A', 0x40)"),
            ("edit", "payload, slot, off", "data=payload index=slot offset=off", f"h_edit_{index}(b'B', 1, 3)"),
            ("show", "length, slot", "length=length index=slot", f"h_show_{index}(8, 1)"),
            ("delete", "slot", "index=slot", f"h_delete_{index}(1)"),
        ):
            name = f"h_{kind}_{index}"
            blocks.append(f"# pwncraft: op={kind} {annotation}\ndef {name}({parameters}):\n    io.sendline(b'1')")
            calls.append(call)
    source = "\n\n".join(blocks) + "\n\n" + "\n".join(calls)
    resolution = HelperContractResolver().resolve(source)
    assert len(resolution.proven) == 120
    operations = lower_source_calls(source, resolution)
    assert len(operations) == 120
    assert sum(item.kind is CanonicalOperationKind.EDIT for item in operations) == 30


def test_correction_history_undo_redo() -> None:
    history = CorrectionHistory()
    patch = LayoutPatch("layout", object_id="A", after={"x": 7})
    history.push(patch)
    assert history.undo().status.value == "undone"
    assert history.redo().status.value == "active"


def test_semantic_undo_redo_restores_physical_memory() -> None:
    memory = PhysicalMemory()
    memory.register_object("A", 0x3000, 0x20)
    memory.write(0x3000, b"A" * 0x20, MemoryProvenance.derived("initial"))
    engine = CorrectionEngine()
    outcome = engine.apply(
        ObservedMemoryPatch("semantic", address="0x3008", data=b"Z", length=1, object_id="A"),
        memory=memory,
    )
    assert outcome.result.accepted and memory.read(0x3008, 1).data == b"Z"
    undone = engine.undo_memory(memory)
    assert undone is not None and memory.read(0x3008, 1).data == b"A"
    redone = engine.redo_memory(memory)
    assert redone is not None and memory.read(0x3008, 1).data == b"Z"


def test_unknown_stays_unknown() -> None:
    value = evaluate_value("runtime_only(socket.recv())")
    assert isinstance(value, UnknownValue)
