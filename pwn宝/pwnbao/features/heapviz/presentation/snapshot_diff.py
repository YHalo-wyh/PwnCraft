from __future__ import annotations

from dataclasses import dataclass

from pwnbao.features.heapviz.models import ChunkState, HeapSnapshot


@dataclass(frozen=True)
class SceneChange:
    action: str  # create | update | move | delete
    node_id: str
    kind: str
    before: str = ""
    after: str = ""


def diff_heap_snapshots(before: HeapSnapshot | None, after: HeapSnapshot) -> tuple[SceneChange, ...]:
    old_chunks = _physical_chunks(before)
    new_chunks = _physical_chunks(after)
    changes: list[SceneChange] = []
    for node_id in sorted(old_chunks.keys() - new_chunks.keys()):
        changes.append(SceneChange("delete", node_id, "chunk", _chunk_signature(old_chunks[node_id]), ""))
    for node_id in sorted(new_chunks.keys() - old_chunks.keys()):
        changes.append(SceneChange("create", node_id, "chunk", "", _chunk_signature(new_chunks[node_id])))
    for node_id in sorted(old_chunks.keys() & new_chunks.keys()):
        old = old_chunks[node_id]
        new = new_chunks[node_id]
        if old.address != new.address:
            changes.append(SceneChange("move", node_id, "chunk", old.address, new.address))
        elif _chunk_signature(old) != _chunk_signature(new):
            changes.append(SceneChange("update", node_id, "chunk", _chunk_signature(old), _chunk_signature(new)))

    old_edges = _bin_edges(before)
    new_edges = _bin_edges(after)
    for edge in sorted(old_edges - new_edges):
        changes.append(SceneChange("delete", edge, "bin_edge"))
    for edge in sorted(new_edges - old_edges):
        changes.append(SceneChange("create", edge, "bin_edge"))
    return tuple(changes)


def _physical_chunks(snapshot: HeapSnapshot | None) -> dict[str, ChunkState]:
    if snapshot is None:
        return {}
    result: dict[str, ChunkState] = {}
    for chunk in snapshot.chunks.values():
        key = chunk.physical_id or chunk.chunk_id
        current = result.get(key)
        if current is None or (current.lifecycle == "stale" and chunk.lifecycle != "stale"):
            result[key] = chunk
    return result


def _chunk_signature(chunk: ChunkState) -> str:
    return "|".join((
        chunk.chunk_id,
        chunk.address,
        chunk.chunk_size,
        chunk.lifecycle,
        chunk.bin_location,
        chunk.fd,
        chunk.bk,
        chunk.data,
        chunk.role,
    ))


def _bin_edges(snapshot: HeapSnapshot | None) -> set[str]:
    if snapshot is None:
        return set()
    result: set[str] = set()
    mappings = {
        "tcache": snapshot.bins.tcache,
        "fastbins": snapshot.bins.fastbins,
        "smallbins": snapshot.bins.smallbins,
        "largebins": snapshot.bins.largebins,
    }
    for title, mapping in mappings.items():
        for size, chain in mapping.items():
            nodes = list(chain) + (["NULL"] if title in {"tcache", "fastbins"} else [])
            for left, right in zip(nodes, nodes[1:]):
                result.add(f"bin:{title}:{size}:{left}->{right}")
    if snapshot.bins.unsorted:
        nodes = ["arena", *snapshot.bins.unsorted, "arena"]
        for left, right in zip(nodes, nodes[1:]):
            result.add(f"bin:unsorted:arena:{left}<->{right}")
    return result
