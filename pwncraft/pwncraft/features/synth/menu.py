"""菜单交互识别 — 偏移测量与 EXP 执行前的预驱动（VNext.8 修复②）。

思路吸收自 intelpwn 的 menu.py，落到本项目的 objdump AT&T 文本真值上：
- 双通道锚点：rodata 扫 `N. 名称` 菜单项；main 内 scanf/atoi/strtol 后的
  cmp/je 分支链。
- options 映射：选项号 → handler 名（rodata 标签回填）。
- 预交互脚本：偏移测量（gdb 喂 cyclic 前）与 EXP 执行前先
  `recvuntil(锚点) + sendline(选项)`，否则 payload 会错位打进菜单 scanf。

诚实边界：识别不出菜单时返回 present=False，调用方按无菜单处理。
"""
from __future__ import annotations

import re
from pathlib import Path

from pwncraft.features.patch.patch_core import parse_instruction_lines
from pwncraft.features.synth.vuln_points import scan_functions

_MENU_INPUTS = ("scanf", "__isoc99_scanf", "atoi", "atoll", "strtol", "strtoul")
_CALL = re.compile(r"^call[qw]?\s+([0-9a-fA-F]+)\s+<([^>]+)>")
_CMP_IMM = re.compile(r"^cmp[q]?\s+\$0x([0-9a-fA-F]+),%e")
_RODATA_MENU = re.compile(r"^(\d+)[.、)]\s*(\S.*)$")


def _rodata_menu_items(binary) -> list[str]:
    """从可读段字节里找 `N. 名称` 菜单项（intelpwn 同款启发式）。"""
    from pwncraft.core.workbench import elf_geometry  # noqa: F401

    data = Path(binary).read_bytes()
    items: list[str] = []
    for raw in data.split(b"\x00"):
        if len(raw) < 3 or len(raw) > 80:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if _RODATA_MENU.match(text.strip()):
            items.append(text.strip())
    return items


def _anchor_from_items(items: list[str]) -> str:
    """从菜单项猜提示锚点：取含数字选项的最短行（choice 提示常在末尾）。"""
    if not items:
        return ""
    for item in items:
        if "choice" in item.lower() or "option" in item.lower():
            return item
    return items[0]


def detect_menu(binary, functions: list[dict]) -> dict:
    """识别数字菜单 → options + 锚点 + 触发选项。"""
    out = {"present": False, "anchor": "", "prompt": "",
           "options": {}, "numeric": False}
    items = _rodata_menu_items(binary)
    main = next((f for f in functions if str(f.get("name")) == "main"), None)
    if main is None:
        # stripped：取最大函数当主逻辑候选
        main = max(functions, key=lambda f: len(f.get("assembly") or "")) \
            if functions else None
    if main is not None:
        lines = parse_instruction_lines(main.get("assembly") or "")
        # 找菜单输入调用（scanf/atoi/strtol）后 40 条内的 cmp/je 链
        input_index = None
        for index, insn in enumerate(lines):
            call = _CALL.match(insn["text"] or "")
            if call and call[2].split("@")[0] in _MENU_INPUTS:
                input_index = index
                break
        if input_index is not None:
            window = lines[input_index + 1:input_index + 41]
            chain = [w for w in window if _CMP_IMM.match(w["text"] or "")]
            if len(chain) >= 2:
                out["numeric"] = True
                for cmp_insn in chain:
                    value = int(_CMP_IMM.match(cmp_insn["text"]).group(1), 16)
                    out["options"][str(value)] = {"handler": "", "address": ""}
    # rodata 项回填 handler 名（覆盖/补充分支链识别出的选项）
    for item in items:
        m = _RODATA_MENU.match(item)
        if not m:
            continue
        number, label = m.group(1), m.group(2).strip()
        out["options"].setdefault(number, {"handler": "", "address": ""})
        out["options"][number]["handler"] = label.split()[0].lower()
    if out["options"]:
        out["present"] = True
        out["prompt"] = " ".join(items) if items else ""
        out["anchor"] = _anchor_from_items(items)
    return out


def prelude_script(menu: dict, *, choice: str = "1") -> list[dict]:
    """菜单预交互步骤：recvuntil(锚点) + sendline(选项)。

    返回 [{'send': ..., 'expect': ...}] 供 gdb/EXP 执行器在喂 payload 前
    逐条驱动；菜单不可识别时为空列表。
    """
    if not menu or not menu.get("present"):
        return []
    anchor = menu.get("anchor") or ""
    steps: list[dict] = []
    if anchor:
        steps.append({"expect": anchor})
    steps.append({"send": choice})
    return steps


def scan_functions_menu(binary, functions: list[dict]) -> dict:
    """兼容既有入口：检测 + 返回与 vuln_points 同结构的报告。"""
    menu = detect_menu(binary, functions)
    vuln = scan_functions(functions, binary_path=binary)
    menu["vuln_points"] = vuln
    return menu
