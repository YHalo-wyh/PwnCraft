"""把动态验证结果适配为 semantic_vuln 的 runtime observations。"""
from __future__ import annotations

from typing import Mapping


def observations_from_synth(result: Mapping[str, object]) -> list[dict]:
    observations: list[dict] = []
    runtime = result.get("runtime") or {}
    if isinstance(runtime, Mapping) and runtime.get("offset") is not None:
        observations.append({
            "vuln_type": "stack_overflow",
            "verdict": "stack_offset_observed",
            "severity": "high",
            "primitives": ["RIP_control"],
            "controllables": [{"kind": "saved_return_address_offset",
                                  "value": runtime.get("offset")}],
            "trigger": {"method": runtime.get("method")},
            "evidence": list(runtime.get("evidence") or []),
            "next_steps": ["根据保护配置选择 ret2win、ROP 或 ret2libc"],
        })
    verification = result.get("verification") or {}
    if isinstance(verification, Mapping):
        status = str(verification.get("status") or "")
        if status == "VERIFIED_SHELL":
            observations.append({
                "vuln_type": "runtime_exploit",
                "verdict": "exploit_verified",
                "severity": "critical",
                "confidence": "runtime_observed",
                "primitives": ["code_execution"],
                "evidence": list(verification.get("evidence") or []) + [str(verification.get("summary") or "")],
                "next_steps": ["保存已验证 EXP，并记录目标 libc/保护配置"],
            })
    return observations


def observations_from_fmt(probe: Mapping[str, object]) -> list[dict]:
    if not probe.get("controlled"):
        return []
    return [{
        "vuln_type": "format_string",
        "verdict": "format_control_observed",
        "severity": "high",
        "confidence": "runtime_observed",
        "primitives": ["info_leak", "arbitrary_write_candidate"],
        "trigger": {"probe": probe.get("probe")},
        "evidence": list(probe.get("evidence") or []),
        "missing_conditions": ["确认栈参数 offset 和 %n 写入目标"],
        "next_steps": ["自动枚举 offset，测试 GOT/返回地址可写性"],
    }]


def observations_from_heap_trace(trace: Mapping[str, object]) -> list[dict]:
    """把菜单题生命周期回放压缩成可解释的堆 primitive 证据。

    trace 由 UI/脚本提供结构化事件，不执行其中命令：
    ``events=[{op,index,size,handle}]``，可附 ``stale_read``、``alias``、
    ``double_free``、``overlap`` 和 ``write_target``。
    """
    events = list(trace.get("events") or [])
    observations: list[dict] = []
    if trace.get("double_free"):
        observations.append({
            "vuln_type": "double_free", "verdict": "double_free_observed",
            "severity": "high", "confidence": "runtime_observed",
            "primitives": ["tcache_poisoning_candidate"],
            "trigger": {"events": events},
            "evidence": list(trace.get("evidence") or []),
            "missing_conditions": ["确认 allocator 版本和 freelist 校验"],
            "next_steps": ["计算 safe-linking 编码并验证重分配目标"],
        })
    if trace.get("stale_read") or trace.get("alias"):
        observations.append({
            "vuln_type": "uaf", "verdict": "uaf_alias_observed",
            "severity": "high", "confidence": "runtime_observed",
            "primitives": ["UAF_read"] + (["UAF_write"] if trace.get("write_target") else []),
            "trigger": {"events": events},
            "controllables": ([{"kind": "write_target", "value": trace.get("write_target")} ]
                            if trace.get("write_target") else []),
            "evidence": list(trace.get("evidence") or []),
            "missing_conditions": ["确认悬挂句柄可稳定复用目标 chunk"],
            "next_steps": ["在 heap canvas 标记旧句柄与新 chunk 的别名关系"],
        })
    if trace.get("overlap"):
        observations.append({
            "vuln_type": "heap_overlap", "verdict": "heap_overlap_observed",
            "severity": "critical", "confidence": "runtime_observed",
            "primitives": ["arbitrary_write_candidate", "overlapping_chunks"],
            "trigger": {"events": events},
            "evidence": list(trace.get("evidence") or []),
            "missing_conditions": ["确认重叠 chunk 对目标函数指针/GOT 的影响"],
            "next_steps": ["导出 heap canvas 快照并规划写目标"],
        })
    return observations
