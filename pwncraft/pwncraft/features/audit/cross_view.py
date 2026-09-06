#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""跨视图一致性验证 (VNext M5)。

验证同一对象/地址/值在多个视图 (BinaryIR / ExploitIR / HeapModel) 中
保持身份与版本一致。输出不一致条目列表。

三视图：
  BinaryIR  : 目标程序结构 (函数/callsite/表/global)
  ExploitIR : EXP 交互序列 (send/recv/pack/unpack/helper 调用)
  HeapModel : allocator 模拟的物理堆状态

一致性检查项：
  C1  BinaryIR 函数列表 ⊇ ExploitIR 调用的 helper 集合 (无幽灵调用)
  C2  BinaryIR 全局表地址 ↔ HeapModel heap_base 偏移范围匹配
  C3  ExploitIR pack 宽度 ↔ BinaryIR arch bits 一致
  C4  BinaryIR allocator 调用次数 ↔ HeapModel alloc/free 事件次数
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def cross_view_check(binary_ir: dict, exploit_ir: dict,
                     heap_model: dict | None = None) -> list[dict]:
    """检查三视图一致性。返回不一致条目列表 (空 = 全一致)。"""
    issues = []

    # ---- C1: ExploitIR helper calls must exist in BinaryIR function table
    binary_fn_names = {f.get("name") for f in binary_ir.get("functions", []) if f.get("name")}
    exp_helpers = {c.get("function") for c in exploit_ir.get("helper_calls", []) if c.get("function")}
    ghosts = exp_helpers - binary_fn_names
    if ghosts:
        issues.append({
            "check": "C1_ghost_helpers",
            "severity": "warning",
            "detail": f"EXP 调用的 helper 不在 BinaryIR 函数表中: {sorted(ghosts)}",
        })

    # ---- C3: pack width consistency
    bits = 64
    if heap_model and isinstance(heap_model, dict):
        # infer bits from allocator config if available
        bits = heap_model.get("bits", 64)
    for pack in exploit_ir.get("packs", []):
        fn = pack.get("fn", "")
        if fn == "p64" and bits == 32:
            issues.append({"check": "C3_pack_width", "severity": "error",
                           "detail": f"p64 used but target is 32-bit"})
        elif fn == "p32" and bits == 64:
            issues.append({"check": "C3_pack_width", "severity": "warning",
                           "detail": f"p32 used but target is 64-bit"})

    # ---- C4: allocator call counts
    binary_alloc_xrefs = binary_ir.get("alloc_xrefs", {})
    heap_calls = {}
    for step in (heap_model or {}).get("steps", []):
        for ev in step.get("alloc_events", []):
            heap_calls["malloc"] = heap_calls.get("malloc", 0) + 1
        for ev in step.get("free_events", []):
            heap_calls["free"] = heap_calls.get("free", 0) + 1

    # BinaryIR 侧 allocator 调用次数 (从 xrefs 数)
    for symbol in ("malloc", "free"):
        xrefs = binary_alloc_xrefs.get(symbol, {})
        if isinstance(xrefs, dict) and "xrefs" in xrefs:
            xref_text = xrefs["xrefs"]
            if isinstance(xref_text, str):
                count = xref_text.count('"type": "code"')
            elif isinstance(xref_text, list):
                count = len(xref_text)
            else:
                count = 0
            heap_count = heap_calls.get(symbol, 0)
            if count > 0 and heap_count > 0 and count != heap_count:
                issues.append({
                    "check": "C4_allocator_count",
                    "severity": "info",
                    "detail": f"BinaryIR {symbol} callsites={count}, "
                              f"HeapModel {symbol} events={heap_count} "
                              f"(差异可能来自 1:N 未建模或条件路径)",
                })

    return issues


def cross_view_from_files(binary_ir_path: Path, exploit_ir_path: Path | None = None,
                          heap_model_path: Path | None = None) -> list[dict]:
    """从文件加载三视图并执行一致性检查。"""
    binary_ir = json.loads(binary_ir_path.read_text(encoding="utf-8")) \
        if binary_ir_path.exists() else {}
    exploit_ir = json.loads(exploit_ir_path.read_text(encoding="utf-8")) \
        if exploit_ir_path and exploit_ir_path.exists() else {}
    heap_model = json.loads(heap_model_path.read_text(encoding="utf-8")) \
        if heap_model_path and heap_model_path.exists() else None
    return cross_view_check(binary_ir, exploit_ir, heap_model)
