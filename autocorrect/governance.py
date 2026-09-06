#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""阶段 2 课程 1-8 + 阶段 3 金标准治理 + 阶段 4 指标 (确定性, 数据驱动)。"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# ---- 阶段 2: 八领域课程 ----
COURSES = {
    1: {"name": "公共 EXP 语义", "status": "PARTIAL",
        "done": ["PROMPT_SYNC vs OUTPUT_DATA_FLOW", "调用点接收结果使用 (EXP_LEAK_004)",
                 "参数绑定 (CALLSITE_ARGUMENT_BINDING)"],
        "todo": ["长度派生 (len(payload) → size)", "常量循环 (for i in range(n))",
                 "状态重置后过期值"]},
    2: {"name": "栈基础", "status": "PARTIAL",
        "done": ["栈布局收集 (canary/帧/槽位)", "字节范围 (ExploitIR recv/send)"],
        "todo": ["源码 decl ↔ binary slot 交叉验证", "保存状态 (push/pop) 语义"]},
    3: {"name": "栈状态", "status": "NOT_STARTED",
        "done": [], "todo": ["栈指针变化追踪", "控制数据与普通数据区分"]},
    4: {"name": "堆现有缺口", "status": "PARTIAL",
        "done": ["1:N allocator events (BinaryIR→profile)", "CLEAR_POINTER 证据链",
                 "调用点 OUTPUT_DATA_FLOW (show/shownote)"],
        "todo": ["size-only alloc 契约", "delete second-free 引擎建模",
                 "edit size+1 off-by-one"]},
    5: {"name": "格式化字符串", "status": "PARTIAL",
        "done": ["%n 写检测", "位置参数引用", "转换计数"],
        "todo": ["fmtstr_payload 构造", "GOT/返回地址写目标分析"]},
    6: {"name": "值与地址", "status": "NOT_STARTED",
        "done": [], "todo": ["截断/符号扩展/端序验证", "地址归属/派生依赖"]},
    7: {"name": "结构与环境", "status": "NOT_STARTED",
        "done": [], "todo": ["FILE 类型化视图", "ABI/内存权限/调用约束"]},
    8: {"name": "跨区域解释", "status": "NOT_STARTED",
        "done": [], "todo": ["同一对象在多视图中身份一致", "别名/时间序/跨视图断言"]},
}


def course_status() -> dict:
    return {"courses": {str(k): v for k, v in sorted(COURSES.items())},
            "partial": sum(1 for v in COURSES.values() if v["status"] == "PARTIAL"),
            "not_started": sum(1 for v in COURSES.values() if v["status"] == "NOT_STARTED")}


# ---- 阶段 3: 金标准治理 ----

def material_governance(inventory: dict) -> dict:
    """对清点结果做材料治理分类 (阶段 3)。"""
    cases = inventory.get("cases", [])
    governed = []
    for c in cases:
        governed.append({
            "case_id": c["case_id"],
            "domain": c["domain"],
            "material_readiness": c["material_readiness"],
            "annotation_status": "LOCKED" if c["entry_status"] == "ok" else "GAP",
            "oracle_scope": _oracle_scope(c["domain"]),
            "evaluation_status": "NOT_EVALUATED",
            "gaps": c.get("gaps", []),
        })
    by_status = {}
    for g in governed:
        by_status[g["annotation_status"]] = by_status.get(g["annotation_status"], 0) + 1
    return {"total": len(governed), "by_annotation_status": by_status,
            "cases": governed}


def _oracle_scope(domain: str) -> str:
    scopes = {
        "heap": "解析+值流+对象同一性 (TARGET_BEHAVIOR defer: 引擎 1:N 建模缺口)",
        "stack": "解析+交互 (栈布局断言已有, 语义规则属课程 3/6)",
        "fmt": "解析+交互 (FMT_SEMANTIC_CHECKS 已实现, 深度分析待后续)",
    }
    return scopes.get(domain, "UNKNOWN")


# ---- 阶段 4: 指标实测 ----

def compute_metrics(truth_results: list[dict]) -> dict:
    """从 truthregress 结果计算指标 (确定性)。"""
    total = len(truth_results)
    match = sum(1 for r in truth_results if r.get("verdict") == "MATCH")
    diverged = sum(1 for r in truth_results if r.get("verdict") == "DIVERGED")
    inconclusive = sum(1 for r in truth_results if r.get("verdict") == "INCONCLUSIVE")
    blocked = sum(1 for r in truth_results if r.get("verdict") == "BLOCKED")

    # UNKNOWN 率: 契约 not_applicable 的层不计入分母
    deferred_total = 0
    for r in truth_results:
        ac = r.get("assertions") or {}
        deferred_total += 1 if "gate" in ac else 0

    return {
        "total_cases": total,
        "match": match,
        "diverged": diverged,
        "inconclusive": inconclusive,
        "blocked": blocked,
        "pass_rate": f"{match}/{total}" if total else "0/0",
        "note": "整题通过 = 契约全部必需层 MATCH; DEFERRED 层不算失败也不算通过",
    }
