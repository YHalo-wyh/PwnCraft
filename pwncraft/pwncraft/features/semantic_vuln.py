"""CTF Pwn 漏洞语义层 MVP。

把已有的 objdump/data-flow/lifecycle 证据提升为面向利用的语义对象：
漏洞类型、触发点、可控实体、当前 primitive、缺失条件、下一步和置信度。
本模块不猜地址，也不把危险 API 直接当漏洞；动态观测可作为额外证据回灌。
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Mapping, Sequence


@dataclass
class SemanticFinding:
    vuln_type: str
    verdict: str
    severity: str
    confidence: str
    trigger: dict = field(default_factory=dict)
    controllables: list[dict] = field(default_factory=list)
    primitives: list[str] = field(default_factory=list)
    missing_conditions: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    source: str = "static_dataflow"

    def to_dict(self) -> dict:
        return asdict(self)


_TYPE_MAP = {
    "memory_corruption": "stack_overflow",
    "stack_overflow": "stack_overflow",
    "heap_overflow": "heap_overflow",
    "format_string": "format_string",
    "heap_lifetime": "uaf_or_double_free",
    "out_of_bounds": "oob",
    "integer": "integer_vulnerability",
}


def _primitive(point: Mapping[str, object], vuln_type: str) -> tuple[list[str], list[str], list[str]]:
    verdict = str(point.get("verdict") or "")
    text = " ".join(str(point.get(key) or "") for key in ("reason", "detail", "title")).lower()
    primitives: list[str] = []
    missing: list[str] = []
    next_steps: list[str] = []
    if vuln_type == "stack_overflow":
        if any(token in verdict for token in ("overflow_confirmed", "stack")):
            primitives.append("RIP_control")
        else:
            missing.append("需要确认输入长度可达保存返回地址")
        if "canary" in text:
            missing.append("canary 泄漏或绕过")
        if not primitives:
            next_steps.append("使用 cyclic + gdb 测量偏移")
        else:
            next_steps.extend(["使用 cyclic + gdb 复核偏移", "检查 PIE/NX/Canary 并选择 ROP 或 ret2win"])
    elif vuln_type == "format_string":
        if "controlled" in verdict or "format_write" in verdict:
            primitives.extend(["info_leak", "arbitrary_write"])
        else:
            missing.append("需要证明格式串参数由攻击者控制")
        next_steps.append("运行格式串 offset 探针并确认 %n 可写目标")
    elif vuln_type == "uaf_or_double_free":
        if "double" in verdict:
            primitives.append("tcache_poisoning_candidate")
        else:
            primitives.append("UAF_write_candidate")
        missing.extend(["确认释放后对象是否可重分配别名", "确认可控写入字段或函数指针"])
        next_steps.append("按菜单序列做 malloc/free/show/edit 动态生命周期回放")
    elif vuln_type == "heap_overflow":
        primitives.append("heap_metadata_corruption_candidate")
        missing.extend(["相邻 chunk 布局", "allocator 版本与校验约束"])
        next_steps.append("记录 chunk size/prev_size 并用 gdb/heap 画布验证覆盖范围")
    elif vuln_type == "oob":
        primitives.append("arbitrary_read_or_write_candidate")
        missing.append("索引可控范围与目标对象布局")
        next_steps.append("动态 fuzz 边界索引，区分读越界和写越界")
    elif vuln_type == "integer_vulnerability":
        primitives.append("size_or_index_control_candidate")
        missing.append("确认溢出/截断结果能到达内存操作")
        next_steps.append("对符号扩展、乘法和长度检查做边界值验证")
    else:
        next_steps.append("补充反汇编调用链和运行时输入证据")
    return primitives, missing, next_steps


def from_vuln_report(report: Mapping[str, object], *, runtime_observations: Sequence[Mapping[str, object]] = ()) -> dict:
    """把现有 vuln_points 报告转换为稳定的语义 JSON。"""
    findings: list[SemanticFinding] = []
    for point in report.get("points") or ():
        if not isinstance(point, Mapping):
            continue
        category = str(point.get("category") or "unknown")
        verdict = str(point.get("verdict") or "candidate")
        vuln_type = _TYPE_MAP.get(category, category if category != "unknown" else "unknown")
        primitives, missing, next_steps = _primitive(point, vuln_type)
        evidence = [str(item) for item in (point.get("evidence") or [])]
        if point.get("reason"):
            evidence.append(str(point["reason"]))
        trigger = {key: point.get(key) for key in ("function", "callee", "vaddr", "line") if point.get(key) is not None}
        controllables = []
        for key in ("input", "length", "size", "index", "address", "object"):
            if point.get(key) is not None:
                controllables.append({"kind": key, "value": point[key], "source": "dataflow"})
        findings.append(SemanticFinding(vuln_type, verdict, str(point.get("severity") or "info"),
                                        str(point.get("confidence") or "unknown"), trigger, controllables,
                                        primitives, missing, next_steps, evidence))
    for observation in runtime_observations:
        if not isinstance(observation, Mapping):
            continue
        vuln_type = str(observation.get("vuln_type") or observation.get("category") or "runtime_observation")
        findings.append(SemanticFinding(vuln_type, str(observation.get("verdict") or "observed"),
                                        str(observation.get("severity") or "high"), "runtime_observed",
                                        dict(observation.get("trigger") or {}), list(observation.get("controllables") or []),
                                        list(observation.get("primitives") or []), list(observation.get("missing_conditions") or []),
                                        list(observation.get("next_steps") or []), list(observation.get("evidence") or []), "dynamic"))
    primitive_set = sorted({primitive for item in findings for primitive in item.primitives})
    return {"findings": [item.to_dict() for item in findings],
            "primitives": primitive_set,
            "summary": {"total": len(findings), "high_confidence": sum(item.confidence in {"proven", "dataflow", "lifecycle", "runtime_observed"} for item in findings),
                         "types": sorted({item.vuln_type for item in findings})},
            "method": "static_dataflow+lifecycle+optional_runtime",
            "limitations": ["间接调用、深层跨函数数据流和自修改代码仍需 angr/IDA/GDB 动态补证","candidate 不等于可利用，primitive 仍需运行时确认"]}
