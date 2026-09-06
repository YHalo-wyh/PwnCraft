"""CanvasTruthModel export (renamed by INFRA-CLOSURE-1 P0-5).

Represents the BACKEND TRUTH of what should be presented — it is NOT a claim
about the actual JS renderer's plan (heap.js builds its own geometry; compare
via exportRendererPlan). Previously "Canvas Semantic Model" (v1.2 §J).
Original docstring follows:
------------------------------------------------------------------------------
Canvas Semantic Model export (v1.2 visual-review protocol).

A first-class, pre-render truth layer: for every heap state-change step we
serialize the *semantic and geometric inputs the renderer consumes* — the
bridge step payload plus the canonical PhysicalGrid row model — so AI review
can compare structured data instead of screenshots.

Rules:
  * every field comes from renderer inputs (bridge step dict, grid functions,
    HeapSceneLayout constants) — nothing is ever inferred from pixels/OCR;
  * pixel scales are the TS renderer's concern: layout x/y/width/height are
    exported in documented semantic units (bytes for x-offset/width, rows for
    y/height) plus the scene-layout constants, which is exactly what the
    invariants need;
  * pure serialization: never mutates snapshots, never affects recognition.
"""
from __future__ import annotations

import re
from typing import Any, Mapping

from pwnbao.features.heapviz.grid.physical_grid import (
    build_chunk_rows,
    intersect_coverage,
    virtualize,
)
from pwnbao.features.heapviz.presentation.scene_model import HeapSceneLayout

_OFFSET_RE = re.compile(r"^heap_base\s*\+\s*(0x[0-9a-fA-F]+|\d+)$")
_ABS_RE = re.compile(r"^(0x[0-9a-fA-F]+|\d+)$")

VIRTUALIZE_THRESHOLD_ROWS = 64  # beyond this, export uses virtualize() + flags


def _offset_of(address: Any) -> int | None:
    """heap_base+0xNNN -> int offset; plain ints pass; anything else -> None."""
    if address is None:
        return None
    text = str(address).strip()
    m = _OFFSET_RE.match(text)
    if m:
        return int(m.group(1), 0)
    if _ABS_RE.match(text):
        return int(text, 0)
    return None


def _int_of(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if _ABS_RE.match(text):
        return int(text, 0)
    return None


def build_canvas_semantic_model(step: Mapping[str, Any], word_size: int = 8,
                                layout: HeapSceneLayout | None = None) -> dict:
    """Build the canvas semantic model for ONE bridge step dict.

    Sources: step['physical_chunks' | 'chunks' | 'groups' | 'paint_spans' |
    'top' | 'bins' | 'bin_rows' | 'typed_views' | 'handles'] + grid row model.
    """
    layout = layout or HeapSceneLayout()
    physical_chunks = list(step.get("physical_chunks") or [])
    logical_chunks = list(step.get("chunks") or [])
    groups = list(step.get("groups") or [])
    typed_views = list(step.get("typed_views") or [])
    spans = list(step.get("paint_spans") or [])

    logical_by_physical: dict[str, list[str]] = {}
    for c in logical_chunks:
        pid = c.get("physical_id") or ""
        logical_by_physical.setdefault(pid, []).append(c.get("chunk_id") or "")

    group_of_physical: dict[str, str] = {}
    for g in groups:
        for pid in g.get("physical_ids") or []:
            group_of_physical[pid] = g.get("group_id") or ""

    cross_write_spans = [s for s in spans if s.get("visual_kind") == "cross_write"]
    overlap_spans = [s for s in spans if s.get("visual_kind") == "physical_overlap"]

    # heap-resident physical chunks ordered by address; externals flagged
    resident = [c for c in physical_chunks if _offset_of(c.get("address")) is not None]
    external = [c for c in physical_chunks if _offset_of(c.get("address")) is None]
    resident.sort(key=lambda c: (_offset_of(c.get("address")) or 0))

    chunks_out = []
    rows_out = []
    y_rows = 0  # stacking cursor in row units (semantic height)
    for order, pc in enumerate(resident):
        pid = pc.get("physical_id") or pc.get("chunk_id") or f"phys_{order}"
        chunk_id = pc.get("chunk_id") or pid
        heap_offset = _offset_of(pc.get("address"))
        extent = _int_of(pc.get("physical_extent_size"))
        # Row geometry basis MUST be the physical extent — the same rule the
        # JS renderer applies (buildChunkGrid uses triple.physicalExtentSize).
        # A forged/huge decoded_chunksize (e.g. unlink-forged headers) is
        # carried by the size data, never by row geometry.
        chunk_size = extent or _int_of(pc.get("decoded_chunksize")) or _int_of(pc.get("chunk_size"))
        rows = build_chunk_rows(chunk_size or 0, word_size, chunk_id=chunk_id) \
            if (chunk_size or 0) > 0 else ()
        virtualized = len(rows) > VIRTUALIZE_THRESHOLD_ROWS
        collapsed_bytes = 0
        if virtualized:
            rows, collapsed_bytes = virtualize(rows, chunk_size or 0)
        # coverage/partial flags from cross-write spans intersecting this chunk
        base = heap_offset or 0
        coverage_by_row: dict[str, list[tuple[int, int]]] = {}
        for span in cross_write_spans:
            s0 = _offset_of(span.get("physical_start"))
            s1 = _offset_of(span.get("physical_end"))
            if s0 is None or s1 is None:
                continue
            for row, cs, ce in intersect_coverage(rows, s0 - base, s1 - base):
                coverage_by_row.setdefault(row.row_id, []).append((base + cs, base + ce))
        for row in rows:
            intervals = coverage_by_row.get(row.row_id)
            covered = None
            partial = False
            if intervals:
                cs = min(a for a, _ in intervals)
                ce = max(b for _, b in intervals)
                covered = [cs, ce]
                # partial = a strict sub-range of the row (some byte uncovered)
                partial = cs > base + row.start or ce < base + row.end
            rows_out.append({
                "chunk_id": chunk_id, "physical_id": pid, "kind": row.role,
                "physical_start": base + row.start, "physical_end": base + row.end,
                "partial": partial,
                "covered_start": covered[0] if covered else None,
                "covered_end": covered[1] if covered else None,
            })
        height_rows = len(rows)
        chunks_out.append({
            "physical_id": pid,
            "chunk_id": chunk_id,
            "heap_offset": heap_offset,
            "physical_extent_size": extent,
            "original_extent_size": _int_of(pc.get("original_chunk_size")),
            "lifecycle": pc.get("lifecycle"),
            "bin_location": pc.get("bin_location") or "",
            "group_id": group_of_physical.get(pid, ""),
            "logical_chunk_ids": logical_by_physical.get(pid, []),
            "external": False,
            "layout": {
                # semantic units: x/width in bytes from heap origin, y/height in rows
                "x": heap_offset, "y": y_rows,
                "width": extent, "height": height_rows,
                "column": "heap",
                "collapsed_bytes": collapsed_bytes,
            },
        })
        y_rows += height_rows
    for order, pc in enumerate(external):
        pid = pc.get("physical_id") or f"ext_{order}"
        chunks_out.append({
            "physical_id": pid, "chunk_id": pc.get("chunk_id") or pid,
            "heap_offset": None,
            "physical_extent_size": _int_of(pc.get("physical_extent_size")),
            "lifecycle": pc.get("lifecycle"),
            "bin_location": pc.get("bin_location") or "",
            "group_id": group_of_physical.get(pid, ""),
            "logical_chunk_ids": logical_by_physical.get(pid, []),
            "external": True,
            "layout": {"x": None, "y": None, "width": _int_of(pc.get("physical_extent_size")),
                       "height": 0, "column": "external", "collapsed_bytes": 0},
        })

    top = step.get("top") or {}
    bins = step.get("bins") or {}
    return {
        "step": step.get("step"),
        "snapshot_id": step.get("op_id") or step.get("operation_id"),
        "word_size": word_size,
        "scene_layout": {"heap_x": layout.heap_x, "heap_y": layout.heap_y,
                         "heap_width": layout.heap_width, "bin_x": layout.bin_x,
                         "units": "x/width=bytes from heap origin; y/height=rows"},
        "chunks": chunks_out,
        "rows": rows_out,
        "paint_spans": {
            "cross_write": [
                {"owner": s.get("owner"), "writer": s.get("writer"),
                 "start": _offset_of(s.get("physical_start")),
                 "end": _offset_of(s.get("physical_end")),
                 "byte_start": s.get("byte_start"), "byte_end": s.get("byte_end")}
                for s in cross_write_spans],
            "physical_overlap": [
                {"owner": s.get("owner"), "writer": s.get("writer"),
                 "start": _offset_of(s.get("physical_start")),
                 "end": _offset_of(s.get("physical_end")),
                 "byte_start": s.get("byte_start"), "byte_end": s.get("byte_end")}
                for s in overlap_spans],
            "raw_count": len(spans),
        },
        "top_chunk": {"offset": _offset_of(top.get("address")),
                      "size": _int_of(top.get("size"))},
        "bins": bins,
        "bin_rows": list(step.get("bin_rows") or []),
        "selected_physical_id": step.get("selected_physical_id"),
        "groups": [{"group_id": g.get("group_id"), "start": g.get("start"),
                    "end": g.get("end"), "overlap": bool(g.get("overlap")),
                    "shared_memory": bool(g.get("shared_memory")),
                    "physical_ids": list(g.get("physical_ids") or [])}
                   for g in groups],
    }


# ---------------------------------------------------------------- invariants

def check_canvas_invariants(model: dict, step: Mapping[str, Any]) -> list[dict]:
    """Check the 14 protocol invariants of a canvas model against its source
    step payload. Returns a list of violation records (empty = all hold)."""
    v: list[dict] = []

    def bad(inv: int, what: str, detail: Any = None):
        v.append({"invariant": inv, "what": what, "detail": detail})

    physical_chunks = list(step.get("physical_chunks") or [])
    m_chunks = model["chunks"]

    # 1/2: count + physical_id identity
    pids_step = [c.get("physical_id") for c in physical_chunks]
    pids_model = [c["physical_id"] for c in m_chunks]
    if len(pids_step) != len(pids_model):
        bad(1, "physical chunk count mismatch",
            {"step": len(pids_step), "model": len(pids_model)})
    if set(pids_step) != set(pids_model):
        bad(2, "physical_id set mismatch",
            {"missing": sorted(set(pids_step) - set(pids_model)),
             "extra": sorted(set(pids_model) - set(pids_step))})

    # 3: address order preserved
    offs = [(c["physical_id"], c["heap_offset"]) for c in m_chunks if not c["external"]]
    if any(o1 is not None and o2 is not None and o1 > o2
           for (_, o1), (_, o2) in zip(offs, offs[1:])):
        bad(3, "address order not monotonic", offs)

    # 4: physical extent identity
    step_extent = {c.get("physical_id"): _int_of(c.get("physical_extent_size"))
                   for c in physical_chunks}
    for c in m_chunks:
        if step_extent.get(c["physical_id"]) != c["physical_extent_size"]:
            bad(4, "physical extent mismatch",
                {"physical_id": c["physical_id"],
                 "step": step_extent.get(c["physical_id"]),
                 "model": c["physical_extent_size"]})

    # 5: card height == row-model row count (virtualized chunks flagged)
    rows_by_pid: dict[str, int] = {}
    for r in model["rows"]:
        rows_by_pid[r["physical_id"]] = rows_by_pid.get(r["physical_id"], 0) + 1
    for c in m_chunks:
        if c["external"]:
            continue
        expected = c["layout"]["height"]
        actual = rows_by_pid.get(c["physical_id"], 0)
        if c["layout"]["collapsed_bytes"]:
            continue  # virtualized: row export is a projection, height carries truth
        if expected != actual:
            bad(5, "card height != row count",
                {"physical_id": c["physical_id"], "layout_height": expected,
                 "row_count": actual})

    # 6: partial rows are non-full coverages inside a cross-write span
    cw = [(s["start"], s["end"]) for s in model["paint_spans"]["cross_write"]
          if s["start"] is not None and s["end"] is not None]
    for r in model["rows"]:
        if r["partial"]:
            cs, ce = r["covered_start"], r["covered_end"]
            if cs is None or ce is None:
                bad(6, "partial row without coverage interval", r)
                break
            if not (r["physical_start"] <= cs <= ce <= r["physical_end"]):
                bad(6, "partial row coverage outside its own row extent", r)
                break
            if not (cs > r["physical_start"] or ce < r["physical_end"]):
                bad(6, "row marked partial but coverage is full-row", r)
                break
            if not any(s0 <= cs and ce <= s1 for s0, s1 in cw):
                bad(6, "partial row not inside any cross_write span", r)
                break

    # 7: top chunk position (matches snapshot top; not covered by resident cards)
    top = model["top_chunk"]
    step_top = step.get("top") or {}
    if top["offset"] != _offset_of(step_top.get("address")) or \
            top["size"] != _int_of(step_top.get("size")):
        bad(7, "top chunk mismatch vs snapshot",
            {"model": top, "step": {"address": step_top.get("address"),
                                    "size": step_top.get("size")}})
    if top["offset"] is not None:
        for c in m_chunks:
            if c["external"] or c["heap_offset"] is None or c["physical_extent_size"] is None:
                continue
            end = c["heap_offset"] + c["physical_extent_size"]
            if c["heap_offset"] < top["offset"] < end:
                # A card may legitimately reach into the top region when its
                # size was rewritten (forged size / chunk extend): overlap is
                # then the *semantic truth* the canvas must show. Only an
                # overlap with no resize evidence is a layout violation.
                resized = c.get("original_extent_size") not in (None, c["physical_extent_size"])
                if not resized:
                    bad(7, "top chunk address covered by a chunk card without resize evidence",
                        {"physical_id": c["physical_id"], "top": top["offset"],
                         "extent": c["physical_extent_size"],
                         "original": c.get("original_extent_size")})
                break

    # 8: lifecycle passthrough (freed/reused states unchanged)
    step_life = {c.get("physical_id"): c.get("lifecycle") for c in physical_chunks}
    for c in m_chunks:
        if step_life.get(c["physical_id"]) != c["lifecycle"]:
            bad(8, "lifecycle mismatch", {"physical_id": c["physical_id"],
                                          "step": step_life.get(c["physical_id"]),
                                          "model": c["lifecycle"]})

    # 9: bin membership consistency
    _BIN_FAMILY = re.compile(r"fastbin|unsorted|tcache|smallbin|largebin", re.I)
    bin_locs = {c["physical_id"]: c["bin_location"] for c in m_chunks
                if c["bin_location"] and _BIN_FAMILY.search(str(c["bin_location"]))}
    bins = model["bins"] or {}
    bin_members: set[str] = set()
    for family in ("fastbins", "tcache", "smallbins", "largebins"):
        for coll in (bins.get(family) or {}).values():
            if isinstance(coll, list):
                bin_members |= {str(x) for x in coll}
    unsorted = bins.get("unsorted") or []
    if isinstance(unsorted, list):
        bin_members |= {str(x) for x in unsorted}
    for pid, loc in bin_locs.items():
        cid = next((c["chunk_id"] for c in m_chunks if c["physical_id"] == pid), pid)
        if cid not in bin_members and pid not in bin_members:
            bad(9, "bin_location set but chunk absent from bins",
                {"physical_id": pid, "bin_location": loc})
            break

    # 10/11: cross_write & physical_overlap span passthrough fidelity
    raw_cw = [s for s in (step.get("paint_spans") or [])
              if s.get("visual_kind") == "cross_write"]
    if len(raw_cw) != len(model["paint_spans"]["cross_write"]):
        bad(10, "cross_write span count differs from renderer input",
            {"input": len(raw_cw), "model": len(model["paint_spans"]["cross_write"])})
    raw_ov = [s for s in (step.get("paint_spans") or [])
              if s.get("visual_kind") == "physical_overlap"]
    if len(raw_ov) != len(model["paint_spans"]["physical_overlap"]):
        bad(11, "physical_overlap span count differs from renderer input",
            {"input": len(raw_ov), "model": len(model["paint_spans"]["physical_overlap"])})

    # 12: no spurious semantic overlap when no group claims overlap/shared memory
    claims_overlap = any(g["overlap"] or g["shared_memory"] for g in model["groups"])
    if not claims_overlap and not model["paint_spans"]["physical_overlap"]:
        cards = [(c["heap_offset"], c["heap_offset"] + (c["physical_extent_size"] or 0),
                  c["physical_id"]) for c in m_chunks
                 if not c["external"] and c["heap_offset"] is not None
                 and c["physical_extent_size"]]
        cards.sort()
        for (a0, a1, pa), (b0, b1, pb) in zip(cards, cards[1:]):
            if b0 < a1:
                bad(12, "semantic overlap without overlap evidence",
                    {"a": pa, "b": pb, "range": [a0, a1, b0, b1]})
                break

    # 13: stale typed view must not become a physical card (and vice versa)
    typed_pids = {t.get("physical_id") for t in (step.get("typed_views") or [])}
    model_pids = {c["physical_id"] for c in m_chunks}
    stale = typed_pids - model_pids - {None}
    if stale:
        bad(13, "typed views referencing non-existent physical chunks",
            sorted(x for x in stale if x))

    # 14: step/snapshot identity
    if model["step"] != step.get("step"):
        bad(14, "step mismatch", {"model": model["step"], "step": step.get("step")})
    if model["snapshot_id"] != (step.get("op_id") or step.get("operation_id")):
        bad(14, "snapshot_id mismatch", {"model": model["snapshot_id"]})

    return v
