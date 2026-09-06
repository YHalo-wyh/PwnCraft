"""VNext.3.1B: Canvas 编辑意图分裂验收。"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pwnbao.features.heapviz.bridge_session import HeapSession


EXP = """
from pwn import *

def create(size, content):
    io.recvuntil(b"Choice:")
    io.sendline(b"1")
    io.recvuntil(b"Size:")
    io.sendline(str(size).encode())
    io.send(content)

def pwn():
    create(0x18, b"dada")
    create(0x10, b"ddaa")
"""

PATCH = {"address": "heap_base+0x2a0", "field": "user_area",
         "value_int": 0x71, "length": 2, "object_id": "A"}


def _fresh():
    s = HeapSession()
    s.load(source=EXP, allocator={"version": "2.23"})
    return s


def test_correction_default_unchanged():
    s = _fresh()
    r = s.correct(1, PATCH)
    assert r["accepted"] and "intent" not in r
    assert "learning" in r


def test_assumption_tags_and_skips_learning():
    s = _fresh()
    r = s.correct(1, PATCH, intent="assumption")
    assert r["accepted"] and r["intent"] == "assumption"
    learning = r["learning"]
    assert learning.get("skipped_reason"), "assumption 必须显式声明跳过学习"
    ep = learning.get("episode") or {}
    assert ep.get("provenance") == "MANUAL_ASSUMPTION"
    assert ep.get("trainable") is False
    assert s.corrections[-1]["intent"] == "assumption"
    assert s.corrections[-1]["provenance"] == "MANUAL_ASSUMPTION"
    assert len(s.snapshots) >= 3


def test_a_completion_memory_provenance_stamped() -> None:
    """A-completion: MANUAL_ASSUMPTION 真正贯穿到 PhysicalMemory 字节级。"""
    s = _fresh()
    r = s.correct(1, PATCH, intent="assumption")
    assert r["accepted"]
    # 补丁地址的字节 provenance 必须是 manual_assumption (非 user_observed)
    snap = s.snapshots[1]
    from pwnbao.features.heapviz.memory.address import MemoryAddress
    address = MemoryAddress("heap_base", 0x2a0)
    provenance = snap.memory.get_provenance(address, 2)
    kinds = {p.kind.value for p in provenance}
    assert "manual_assumption" in kinds, kinds
    # correction 对照组: user_confirmed_correction
    s2 = _fresh()
    s2.correct(1, PATCH)  # correction 默认
    r2 = s2.correct(1, PATCH, intent="correction")
    assert r2["accepted"]
    snap2 = s2.snapshots[1]
    kinds2 = {p.kind.value for p in
              snap2.memory.get_provenance(
                  MemoryAddress("heap_base", 0x2a0), 2)}
    assert "user_confirmed_correction" in kinds2, kinds2


def test_a_completion_lineage_and_branch_identity() -> None:
    s = _fresh()
    r = s.correct(1, PATCH, intent="assumption")
    assert r["intent"] == "assumption"
    ep = r["learning"]["episode"]
    assert ep["branch_kind"] == "MANUAL_ASSUMPTION"
    assert ep["parent_snapshot_id"] == "step-1"
    assert ep["assumption_id"]
    assert ep["trainable"] is False
    # session 层假设登记 + Canvas 世界标识
    assert len(s.assumptions) == 1
    assert s.assumptions[0]["assumption_id"] == ep["assumption_id"]
    assert s.assumptions[0]["trainable"] is False


def test_unknown_intent_rejected():
    s = _fresh()
    try:
        s.correct(1, PATCH, intent="magic")
        raise SystemExit("should reject")
    except ValueError:
        pass


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"PASS {name}")
    print("all intent-split tests passed")
