#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""M3 真实失败记录持久化 + 分领域边界清单生成 (一次性脚本)。"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pwn宝"))

from pwnbao.features.audit.audit import audit_exp

case = ROOT / "heap-corpus" / "corpus" / "heap-ctf-wiki-hitcontraning-lab13-bae716d5"
exp = next((case / "original" / "solution").glob("*.py")).read_text(encoding="utf-8")

profile = {"version": 1, "name": "lab13-real", "helpers": [
    {"function": "create", "parameters": ["size", "content"],
     "effects": [{"kind": "alloc", "chunk": "C", "request_size": "size"}]},
    {"function": "delete", "parameters": ["idx"],
     "effects": [{"kind": "free", "index": "idx"}]},
    {"function": "edit", "parameters": ["idx", "content"],
     "effects": [{"kind": "edit", "index": "idx", "data": "content"}]},
    {"function": "show", "parameters": ["idx"],
     "effects": [{"kind": "show", "index": "idx"}]},
], "behavior_facts": [
    {"kind": "CLEAR_POINTER", "subject": "chunks[idx]", "confidence": 0.99,
     "scope": "delete@0x400c3a", "backend": "source-ast",
     "evidence": [{"kind": "POST_FREE_NULL_STORE", "detail": "heaparray[idx]=NULL"}]},
]}
diags = audit_exp(exp, bits=64, pie=False, profile=profile)
hits = [d for d in diags if d["code"] == "EXP_HEAP_014"]
assert hits, "EXP_HEAP_014 should fire on lab13"

record = {
    "record_type": "M3_real_failure",
    "case_id": "heap-ctf-wiki-hitcontraning-lab13-bae716d5",
    "exp_source": "heapcreator EXP (real, edit-after-delete UAF pattern)",
    "diagnostic": hits[0],
    "assertion": "EXP_HEAP_014 must fire when target has CLEAR_POINTER and EXP has edit-after-delete",
    "provenance": "OBSERVED (audit_exp on real EXP + real behavior profile)",
    "significance": "Auditor 检测到真实 EXP 中与目标行为冲突的利用假设——非平凡通过",
}
out = ROOT / "autocorrect" / "m3_real_failure_records.json"
out.write_text(json.dumps({"records": [record]}, ensure_ascii=False, indent=2),
               encoding="utf-8")
print(f"real failure record saved: EXP_HEAP_014 fired={bool(hits)}")
