"""Fast AWDP risk audit that turns disassembly evidence into patch previews.

The audit does not claim a vulnerability from imports alone.  It highlights
high-risk primitives and only emits requests that still pass the normal patch
preview verification before the user can apply them.
"""
from __future__ import annotations

import re

from .patch_core import PatchLab, parse_instruction_lines
from .recipes import LENGTH_ARG_INDEX, LENGTH_REGISTERS, extract_plt_stubs, find_call_sites


_RISK_IMPORTS: dict[str, tuple[str, str]] = {
    "gets": ("critical", "无长度限制输入"),
    "system": ("critical", "命令执行入口"),
    "popen": ("critical", "命令执行入口"),
    "execve": ("critical", "进程执行入口"),
    "execveat": ("critical", "进程执行入口"),
    "strcpy": ("high", "无长度限制复制"),
    "strcat": ("high", "无长度限制拼接"),
    "sprintf": ("high", "无长度限制格式化写入"),
    "scanf": ("high", "格式化输入入口"),
    "__isoc99_scanf": ("high", "格式化输入入口"),
    "memcpy": ("medium", "长度敏感内存复制"),
    "memmove": ("medium", "长度敏感内存移动"),
    "recv": ("medium", "长度敏感网络读取"),
    "recvfrom": ("medium", "长度敏感网络读取"),
    "strncpy": ("medium", "需复核长度与终止符的复制"),
    "strncat": ("medium", "需复核剩余容量的拼接"),
    "vsprintf": ("high", "无目标容量参数的格式化写入"),
    "vscanf": ("high", "需复核字段宽度的格式化输入"),
    "sscanf": ("medium", "需复核字段宽度的格式化输入"),
    "fscanf": ("medium", "需复核字段宽度的格式化输入"),
    "__isoc99_sscanf": ("medium", "需复核字段宽度的格式化输入"),
    "__isoc99_fscanf": ("medium", "需复核字段宽度的格式化输入"),
}

_EXEC_IMPORTS = {"system", "popen", "execve", "execveat"}
_SAFE_STOP_TARGETS = ("_exit", "exit", "abort")
_MOV_LENGTH_RE = re.compile(r"^\s*mov[q]?\s+\$0x([0-9a-fA-F]+),%(edx|esi)\b")
_PUSH_LENGTH_RE = re.compile(r"^\s*push[l]?\s+\$0x([0-9a-fA-F]+)\b")
_CALL_RE = re.compile(r"^\s*call[qw]?\s+[0-9a-fA-F]+\s+<([^>]+)>")
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}


def _locations(sites: list[dict]) -> list[dict]:
    return [{"function": site["function"], "address": hex(site["insn"]["address"]),
             "instruction": site["insn"]["text"]} for site in sites[:128]]


def _observed_calls(functions: list[dict]) -> dict[str, list[dict]]:
    """Index direct symbols and annotated GOT calls; never infer unnamed targets."""
    calls: dict[str, list[dict]] = {}
    for function in functions:
        for insn in parse_instruction_lines(str(function.get("assembly") or "")):
            if not re.match(r"^(?:(?:bnd|notrack)\s+)?call[qwl]?\s", insn["text"]):
                continue
            symbol = re.search(r"<([^>]+)>", insn["text"])
            if not symbol or "+" in symbol[1]:
                continue
            name = symbol[1].split("@", 1)[0]
            calls.setdefault(name, []).append({"function": str(function["name"]), "insn": insn})
    return calls


def _call_target(text: str) -> str:
    match = _CALL_RE.match(text or "")
    return match.group(1).split("@", 1)[0] if match else ""


def _length_candidates(instructions: list[dict], is64: bool) -> list[tuple[dict, str, int]]:
    """常量长度站点：寄存器必须正好落在该调用长度参数的位置，且紧邻该调用。

    amd64 只认 mov 之后的第一条 call（无关调用在前时不误报）；i386 按 cdecl
    从 call 向前回溯 push，长度参数序号来自 recipes.LENGTH_ARG_INDEX。
    """
    candidates: list[tuple[dict, str, int]] = []
    if is64:
        for index, insn in enumerate(instructions):
            match = _MOV_LENGTH_RE.match(str(insn.get("text") or ""))
            if not match:
                continue
            for item in instructions[index + 1:index + 6]:
                callee = _call_target(str(item.get("text") or ""))
                if not callee:
                    continue
                if LENGTH_REGISTERS.get(callee) == match.group(2):
                    candidates.append((insn, callee, int(match.group(1), 16)))
                break
        return candidates
    for call_index, call in enumerate(instructions):
        callee = _call_target(str(call.get("text") or ""))
        if callee not in LENGTH_ARG_INDEX:
            continue
        arg_index = LENGTH_ARG_INDEX[callee]
        pushes = []
        for item in reversed(instructions[max(0, call_index - 12):call_index]):
            text = str(item.get("text") or "").lstrip()
            if text.startswith("call"):
                break
            if text.startswith("push"):
                pushes.append(item)
        if len(pushes) > arg_index:
            match = _PUSH_LENGTH_RE.match(str(pushes[arg_index].get("text") or ""))
            if match:
                candidates.append((pushes[arg_index], callee, int(match.group(1), 16)))
    return candidates


def _length_findings(lab: PatchLab, functions: list[dict]) -> list[dict]:
    findings: list[dict] = []
    is64 = lab.geometry()["is64"]
    for function in functions:
        instructions = parse_instruction_lines(str(function.get("assembly") or ""))
        for insn, callee, size in _length_candidates(instructions, is64):
            if size <= 0x100:
                continue
            name = str(function.get("name") or "(未知函数)")
            findings.append({
                "id": f"length:{callee}:{name}:{insn['address']:x}",
                "severity": "high",
                "title": f"{name} 中 {callee} 读取长度为 0x{size:x}",
                "detail": "读取长度较大，需结合栈帧或目标缓冲区容量确认；建议先用 0x40 预览并按实际容量调整。",
                "evidence": [f"0x{insn['address']:x}: {insn['text']}"],
                "request": {"kind": "readlen", "function": name,
                            "callee": callee, "size": "0x40"},
                "action": "预览长度收紧",
                "confidence": "review", "category": "input_length",
                "locations": [{"function": name, "address": hex(insn["address"]),
                               "instruction": insn["text"]}],
                "remediation": "确认目标缓冲区的实际容量后收紧输入长度，再测试正常交互。",
            })
    return findings


def audit_patch_surface(lab: PatchLab, functions: list[dict], *, security: dict | None = None) -> dict:
    """Return evidence-backed risk findings and previewable mitigation requests."""
    stubs = extract_plt_stubs(functions)
    stop_target = next((name for name in _SAFE_STOP_TARGETS if name in stubs), "")
    findings: list[dict] = []
    calls = _observed_calls(functions)
    execution_surface = False
    for name, (severity, reason) in _RISK_IMPORTS.items():
        sites = calls.get(name, [])
        if not sites:
            continue
        execution_surface = execution_surface or name in _EXEC_IMPORTS
        evidence = [f"{site['function']} @ 0x{site['insn']['address']:x}" for site in sites[:8]]
        request = None
        action = ""
        if stop_target and name in stubs and find_call_sites(functions, name):
            request = {"kind": "plt_call", "source": name, "target": stop_target}
            action = f"预览 {name}→{stop_target}"
        findings.append({
            "id": f"import:{name}",
            "severity": severity,
            "title": f"{name}@plt：{reason}",
            "detail": f"发现 {len(sites)} 处直接调用。导入本身不等于漏洞，应结合参数可控性与正常业务复核。",
            "evidence": evidence,
            "request": request,
            "action": action,
            "locations": _locations(sites), "location_count": len(sites),
            "confidence": "dangerous_api" if name in {"gets", "strcpy", "strcat", "sprintf", "vsprintf"} else "review",
            "category": "command_execution" if name in _EXEC_IMPORTS else "unsafe_api",
            "remediation": ("复核命令字符串的来源与正常业务需求；优先限制输入或移除不需要的调用。"
                            if name in _EXEC_IMPORTS else "核对目标缓冲区容量、长度参数和终止符；优先使用有明确边界的接口。"),
        })

    for name in ("printf", "fprintf", "vprintf", "vfprintf", "__printf_chk", "__fprintf_chk", "snprintf", "vsnprintf"):
        sites = calls.get(name, [])
        if sites:
            findings.append({
                "id": f"format:{name}", "severity": "info", "confidence": "review",
                "category": "format_review", "title": f"{name}：格式字符串待复核",
                "detail": "检测到格式化输出调用；尚未证明格式字符串受外部输入控制，不能据此认定格式化字符串漏洞。",
                "evidence": [f"{site['function']} @ 0x{site['insn']['address']:x}" for site in sites[:8]],
                "locations": _locations(sites), "location_count": len(sites), "request": None,
                "remediation": "确认格式参数来自固定字符串；输出外部文本时使用固定的 %s 格式。",
            })

    for key, detail in {
        "NX": "栈不可执行保护未开启，建议在重编译时启用不可执行栈。",
        "CANARY": "未检测到栈保护导入，不能据此认定栈溢出；有源码时启用栈保护并确认覆盖范围。",
        "PIE": "位置无关可执行文件未开启，有源码时启用 PIE。",
        "RELRO": "重定位表保护不完整，有源码时启用 Full RELRO。",
    }.items():
        value = str((security or {}).get(key) or "UNKNOWN").upper()
        if value == "OFF" or (key == "RELRO" and value in {"NONE", "PARTIAL"}):
            findings.append({"id": f"hardening:{key}", "severity": "info",
                             "confidence": "hardening", "category": "hardening",
                             "title": f"{key} = {value}：加固建议", "detail": detail,
                             "evidence": [f"本地 ELF 解析：{key}={value}"],
                             "locations": [], "request": None, "remediation": detail})

    findings.extend(_length_findings(lab, functions))
    if execution_surface:
        findings.append({
            "id": "mitigation:seccomp",
            "severity": "high",
            "title": "存在命令或进程执行面，可增加 seccomp 兜底",
            "detail": "黑名单预设会拦截 execve/execveat；仍需防范 open/read/write 型读文件攻击。",
            "evidence": ["命令执行相关 PLT 调用已在上方列出"],
            "request": {"kind": "seccomp", "preset": "blacklist_min"},
            "action": "预览 seccomp",
            "confidence": "hardening", "category": "hardening", "locations": [],
        })

    findings.sort(key=lambda item: (_SEVERITY_ORDER.get(item["severity"], 9), item["id"]))
    counts = {key: 0 for key in _SEVERITY_ORDER}
    for finding in findings:
        counts[finding["severity"]] += 1
    risk_score = min(100, counts["critical"] * 30 + counts["high"] * 15 + counts["medium"] * 5)
    return {
        "summary": {**counts, "total": len(findings), "risk_score": risk_score},
        "findings": findings,
        "function_count": len(functions),
        "plt_imports": sorted(stubs),
        "binary": str(lab.binary),
        "coverage": {"functions": len(functions), "call_sites": sum(len(sites) for sites in calls.values()),
                     "truncated_functions": sum(bool(fn.get("truncated")) for fn in functions),
                     "rules": len(_RISK_IMPORTS) + 8 + 4 + 2},
        "limitations": [
            "静态规则检查，不证明漏洞可利用；保护缺失和格式化调用单独列为复核项。",
            "无符号、间接调用、优化后的参数传递和动态加载可能导致漏报；未发现风险不代表没有漏洞。",
            "本扫描不覆盖堆对象生命周期、线程竞争及跨函数的数据流。",
        ],
        "security": security or {},
    }
