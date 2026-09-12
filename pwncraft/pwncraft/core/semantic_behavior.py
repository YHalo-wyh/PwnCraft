"""Name independent behavior extraction for CTF Pwn triage.

This layer emits observations from instruction shape. It deliberately does not
claim a vulnerability; downstream rules combine these labels with sources,
objects and runtime evidence.
"""
from __future__ import annotations

import re
from typing import Iterable

from pwncraft.features.patch.patch_core import parse_instruction_lines

_CALL = re.compile(r"^(?:callq?|jmpq?)\s+[^<]*<([^>]+)>")
_CMP = re.compile(r"^(?:cmp|test)[a-z]*\s+")
_BRANCH = re.compile(r"^j[a-z]+\s+([0-9a-fA-F]+)")
_STORE = re.compile(r"^(?:mov|stos|xchg)[a-z]*\s+.*\([^)]*\)")
_INDIRECT = re.compile(r"^(?:callq?|jmpq?)\s+\*|^(?:callq?|jmpq?)\s+\w+")
_MEMORY_READ = re.compile(r"^(?:mov|movzx|movsx)[a-z]*\s+[^,]*\([^)]*\),")
_NARROW = re.compile(r"^(?:movz|movs|movb|movw|movl)\w*\s+")
_SIGNED_BRANCH = re.compile(r"^j(?:g|ge|l|le|s|ns)\s+")
# AT&T / Intel 两种反汇编均纳入；这里仍只描述指令形态，不判断该地址是否可控。
_CONST_POINTER_STORE = re.compile(
    r"^(?:mov|stos)[a-z]*\s+\$?(0x[0-9a-f]+|[0-9]+),\s*([^,]*\([^)]*%r[a-z0-9]+[^)]*\))", re.I)
_INTEL_CONST_POINTER_STORE = re.compile(
    r"^(?:mov|stos)\w*\s+(?:BYTE|WORD|DWORD|QWORD)?\s*PTR\s*\[([^]]+)\],\s*(0x[0-9a-f]+|[0-9]+)", re.I)
_SCALED_INDEX = re.compile(r"\([^)]*,%[re]?[a-z0-9]+,(?:2|4|8)\)|\[[^]]*\*\s*(?:2|4|8)[^]]*\]", re.I)
_INPUT_CALLS = {"read", "recv", "recvfrom", "fgets", "gets", "scanf", "__isoc99_scanf", "sscanf", "fread", "getchar"}
_OUTPUT_CALLS = {"puts", "printf", "fprintf", "write", "send", "sendto"}
_EXEC_CALLS = {"system", "popen", "execve", "execvp", "execl", "execle"}
_DIVISION = re.compile(r"^(?:idiv|div)[a-z]*\s+")
# 常见 CTF 自定义 allocator 导出名。它们只补充“对象生命周期”事实，
# 不单独构成堆漏洞结论；真正的 UAF/double-free 仍由数据流层证明。
_CUSTOM_ALLOC_CALLS = {"pmalloc", "p_malloc", "safe_malloc", "safemalloc",
                       "pool_alloc", "pool_malloc"}
_CUSTOM_FREE_CALLS = {"pfree", "p_free", "safe_free", "safefree",
                      "pool_free"}


def classify_function(function: dict) -> dict:
    """Return deterministic, name-independent semantic observations."""
    lines = parse_instruction_lines(function.get("assembly") or "")
    texts = [str(item.get("text") or "").strip() for item in lines]
    calls = []
    labels: set[str] = set()
    evidence = []
    input_calls: list[str] = []
    for item, text in zip(lines, texts):
        call = _CALL.match(text)
        if call:
            symbol = call.group(1).split("@", 1)[0]
            calls.append(symbol)
            low = symbol.lower()
            if low in {"malloc", "calloc", "realloc", "operator new"}:
                labels.add("ALLOCATE_OBJECT")
            if low in _CUSTOM_ALLOC_CALLS:
                labels.update({"ALLOCATE_OBJECT", "CUSTOM_ALLOCATOR_API"})
                evidence.append({"kind": "CUSTOM_ALLOCATOR_API",
                                 "address": f"0x{int(item['address']):x}",
                                 "symbol": symbol, "operation": "allocate"})
            if low in {"free", "realloc", "operator delete"}:
                labels.add("FREE_OBJECT")
            if low in _CUSTOM_FREE_CALLS:
                labels.update({"FREE_OBJECT", "CUSTOM_ALLOCATOR_API"})
                evidence.append({"kind": "CUSTOM_ALLOCATOR_API",
                                 "address": f"0x{int(item['address']):x}",
                                 "symbol": symbol, "operation": "free"})
            if low in _INPUT_CALLS:
                labels.add("READ_EXTERNAL_INPUT")
                input_calls.append(symbol)
            if low in _OUTPUT_CALLS:
                labels.add("WRITE_EXTERNAL_OUTPUT")
            if low in _EXEC_CALLS:
                labels.add("EXECUTION_SINK")
            evidence.append({"kind": "CALL", "address": f"0x{int(item['address']):x}", "symbol": symbol})
        if _CMP.match(text):
            labels.add("CHECK_SIZE")
            evidence.append({"kind": "CMP", "address": f"0x{int(item['address']):x}", "statement": text})
        if _SIGNED_BRANCH.match(text):
            labels.add("SIGNED_BOUNDS_CHECK")
            evidence.append({"kind": "SIGNED_BRANCH", "address": f"0x{int(item['address']):x}", "statement": text})
        if _NARROW.match(text) and any(width in text.split(None, 1)[0] for width in ("b", "w", "l")):
            labels.add("NARROWING_CONVERSION")
            evidence.append({"kind": "NARROWING", "address": f"0x{int(item['address']):x}", "statement": text})
        if _STORE.match(text):
            labels.add("WRITE_OBJECT")
        att_store = _CONST_POINTER_STORE.match(text)
        intel_store = _INTEL_CONST_POINTER_STORE.match(text)
        # 清零（free 后置空）和 RIP 相对的全局初始化是正常防御/运行时样板，
        # 不作为“可影响目标选择”的固定写候选。仍可由 WRITE_OBJECT 保留事实。
        immediate = (att_store.group(1) if att_store else (intel_store.group(2) if intel_store else "0"))
        destination = (att_store.group(2) if att_store else (intel_store.group(1) if intel_store else ""))
        if (att_store or intel_store) and int(immediate, 0) != 0 and "%rip" not in destination.lower():
            labels.add("FIXED_VALUE_POINTER_WRITE")
            evidence.append({"kind": "FIXED_VALUE_POINTER_WRITE",
                         "address": f"0x{int(item['address']):x}", "statement": text})
        if _DIVISION.match(text):
            labels.add("DIVISION_OPERATION")
            evidence.append({"kind": "DIVISION_OPERATION",
                             "address": f"0x{int(item['address']):x}",
                             "statement": text})
        if _MEMORY_READ.match(text):
            labels.add("READ_OBJECT")
        if _SCALED_INDEX.search(text):
            labels.add("INDEXED_OBJECT_ACCESS")
            evidence.append({"kind": "INDEXED_OBJECT_ACCESS",
                             "address": f"0x{int(item['address']):x}", "statement": text})
        if _INDIRECT.match(text) and ("*" in text or "(" in text):
            labels.add("CALL_INDIRECT")
            evidence.append({"kind": "CALL_INDIRECT", "address": f"0x{int(item['address']):x}", "statement": text})
    if any(_BRANCH.match(text) and int(_BRANCH.match(text).group(1), 16) < int(lines[i]["address"])
           for i, text in enumerate(texts) if _BRANCH.match(text)):
        labels.add("LOOP_PRESENT")
    if "CHECK_SIZE" not in labels and "LOOP_PRESENT" in labels:
        labels.add("INDEX_CHECK_NOT_OBSERVED")
    if "FIXED_VALUE_POINTER_WRITE" in labels and input_calls:
        # 仅表示同一函数内同时观测到外部输入与“常量→指针目标”写；
        # 指针值是否来自输入必须由数据流或运行时验证，故特意带 CANDIDATE 后缀。
        labels.add("INPUT_TO_POINTER_WRITE_CANDIDATE")
    if "INDEXED_OBJECT_ACCESS" in labels and input_calls:
        labels.add("INPUT_INDEXED_OBJECT_ACCESS_CANDIDATE")
    if "DIVISION_OPERATION" in labels and input_calls:
        # 只报告候选：是否确有零值可达，需跨块数据流或运行时探针确认。
        labels.add("INPUT_DIVISION_BY_ZERO_CANDIDATE")
    if "CUSTOM_ALLOCATOR_API" in labels and "NARROWING_CONVERSION" in labels:
        labels.add("CUSTOM_ALLOCATOR_SIZE_TRUNCATION_CANDIDATE")
    # 全局/表项指针传给 free，但函数内未观察到对应清零写：这是跨函数
    # UAF 的重要候选；仅标记候选，不宣称已可利用。
    if "FREE_OBJECT" in labels and any("(%rip)" in t for t in texts):
        has_zero_store = any(re.search(r"mov[a-z]*\s+\$?0x0,.*\(%rip\)", t, re.I)
                             for t in texts)
        if not has_zero_store:
            labels.add("GLOBAL_POINTER_FREE_NO_CLEAR_CANDIDATE")
    # A GOT/PLT call is also indirect on x86, but it is not evidence of a
    # function-pointer overwrite. Require an explicit memory store somewhere
    # before the indirect call; alias matching is deferred to the deeper pass.
    if "CALL_INDIRECT" in labels:
        indirect_positions = [i for i, text in enumerate(texts)
                              if (text.startswith(("call ", "callq ", "jmp ", "jmpq ")) and "*" in text)]
        if any(_STORE.match(texts[position]) and "%rip" not in texts[position]
               and "@got" not in texts[position].lower()
               for indirect in indirect_positions
               for position in range(max(0, indirect - 12), indirect)):
            labels.add("WRITE_FUNCTION_POINTER")
    return {
        "function": str(function.get("name") or ""),
        "address": str(function.get("address") or "0x0"),
        "labels": sorted(labels), "calls": calls,
        "evidence": evidence[:80],
        "coverage": {"instructions": len(lines), "complete": not bool(function.get("truncated"))},
    }


def classify_functions(functions: Iterable[dict]) -> list[dict]:
    return [classify_function(function) for function in functions]


def summarize_labels(functions: Iterable[dict]) -> dict[str, int]:
    """Count observed labels for UI, training manifests and regression gates."""
    summary: dict[str, int] = {}
    for function in functions:
        for label in function.get("labels") or ():
            key = str(label)
            summary[key] = summary.get(key, 0) + 1
    return dict(sorted(summary.items()))
