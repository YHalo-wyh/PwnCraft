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
