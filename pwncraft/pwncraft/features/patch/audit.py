"""Fast AWDP risk audit that turns disassembly evidence into patch previews.

The audit does not claim a vulnerability from imports alone.  It highlights
high-risk primitives and only emits requests that still pass the normal patch
preview verification before the user can apply them.
"""
from __future__ import annotations

import re

from .patch_core import PatchLab, parse_instruction_lines
from .recipes import extract_plt_stubs, find_call_sites


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
}

_EXEC_IMPORTS = {"system", "popen", "execve", "execveat"}
_SAFE_STOP_TARGETS = ("_exit", "exit", "abort")
_MOV_LENGTH_RE = re.compile(r"^\s*mov[q]?\s+\$0x([0-9a-fA-F]+),%(edx|esi)\b")
_PUSH_LENGTH_RE = re.compile(r"^\s*push[l]?\s+\$0x([0-9a-fA-F]+)\b")
_CALL_RE = re.compile(r"^\s*call[qw]?\s+[0-9a-fA-F]+\s+<([^>]+)>")
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}


def _call_target(text: str) -> str:
    match = _CALL_RE.match(text or "")
    return match.group(1).split("@", 1)[0] if match else ""


def _length_findings(lab: PatchLab, functions: list[dict]) -> list[dict]:
    findings: list[dict] = []
    is64 = lab.geometry()["is64"]
    for function in functions:
        instructions = parse_instruction_lines(str(function.get("assembly") or ""))
        candidates: list[tuple[dict, str, int]] = []
        if is64:
            for index, insn in enumerate(instructions):
                match = _MOV_LENGTH_RE.match(str(insn.get("text") or ""))
                if match:
                    callee = "read" if match.group(2) == "edx" else "fgets"
                    if any(_call_target(str(item.get("text") or "")) == callee
                           for item in instructions[index + 1:index + 6]):
                        candidates.append((insn, callee, int(match.group(1), 16)))
        else:
            for call_index, call in enumerate(instructions):
                callee = _call_target(str(call.get("text") or ""))
                if callee not in ("read", "fgets"):
                    continue
                arg_index = 2 if callee == "read" else 1
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
        for insn, callee, size in candidates:
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
            })
    return findings


def audit_patch_surface(lab: PatchLab, functions: list[dict]) -> dict:
    """Return evidence-backed risk findings and previewable mitigation requests."""
    stubs = extract_plt_stubs(functions)
    stop_target = next((name for name in _SAFE_STOP_TARGETS if name in stubs), "")
    findings: list[dict] = []
    execution_surface = False
    for name, (severity, reason) in _RISK_IMPORTS.items():
        if name not in stubs:
            continue
        sites = find_call_sites(functions, name)
        if not sites:
            continue
        execution_surface = execution_surface or name in _EXEC_IMPORTS
        evidence = [f"{site['function']} @ 0x{site['insn']['address']:x}" for site in sites[:8]]
        request = None
        action = ""
        if stop_target and name != stop_target:
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
        })

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
    }
