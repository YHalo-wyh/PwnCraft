#!/usr/bin/env python3
"""Build a labeled pwn-vulnerability benchmark from the local training corpus.

`/mnt/f/PWN/PWN/99PWN` is organised **by vulnerability class** — the directory
name is the ground-truth label for every binary inside it.  That makes it the
only large labeled pwn corpus on this machine, so it is what the scanner's
recall should be measured against.

Writes a manifest of {binary, label, category} usable by tools/vuln_bench.py.
Nothing is copied; only paths and hashes are recorded.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
from pathlib import Path

# 目录名 → 期望被扫出的漏洞类别（与 vuln_points 的 category 字段对齐）
CATEGORY_RULES: list[tuple[re.Pattern, set[str], str]] = [
    (re.compile(r"^03_|栈溢出|stack"), {"memory_corruption"}, "stack-overflow"),
    (re.compile(r"^04_|格式化|format"), {"format_string"}, "format-string"),
    (re.compile(r"^05_|整数"), {"memory_corruption"}, "integer"),
    (re.compile(r"^07_|^08_|^11_|堆利用|heap"), {"memory_corruption", "heap_lifetime"}, "heap"),
    (re.compile(r"^12_|综合利用|综合"), {"memory_corruption", "heap_lifetime",
                                        "format_string", "command_execution"}, "combined"),
    (re.compile(r"^13_|技巧"), {"memory_corruption", "heap_lifetime"}, "technique"),
    (re.compile(r"^14_|其他漏洞"), {"memory_corruption", "heap_lifetime",
                                    "format_string", "command_execution"}, "other"),
    (re.compile(r"^15_|LLVM"), {"memory_corruption"}, "llvm"),
    (re.compile(r"^16_|WEB-PWN", re.I), {"memory_corruption"}, "web-pwn"),
]

# 这些类别是非 x86 / 内核，宿主 objdump 工具链不覆盖，单独标注而不是算失败
SPECIAL = {
    "17_MIPS-PWN": "mips",
    "18_ARM-PWN": "arm",
    "19_RISCV-PWN": "riscv",
    "20_Kernel-PWN": "kernel",
}

ELF_MAGIC = b"\x7fELF"
_MACHINE = {0x03: "i386", 0x3E: "amd64", 0x08: "mips", 0x28: "arm",
            0xB7: "aarch64", 0xF3: "riscv"}


def elf_machine(path: Path) -> str | None:
    try:
        with path.open("rb") as stream:
            header = stream.read(20)
    except OSError:
        return None
    if len(header) < 20 or header[:4] != ELF_MAGIC:
        return None
    little = header[5] == 1
    machine = struct.unpack_from("<H" if little else ">H", header, 18)[0]
    return _MACHINE.get(machine, f"unknown-{machine:#x}")


def classify(relative: Path) -> tuple[str, set[str]] | None:
    top = relative.parts[0]
    if top in SPECIAL:
        return SPECIAL[top], set()
    for pattern, categories, name in CATEGORY_RULES:
        if pattern.search(top):
            return name, categories
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default="/mnt/f/PWN/PWN/99PWN")
    parser.add_argument("--output", default="datasets/vuln_corpus/pwn99.json")
    parser.add_argument("--limit-per-category", type=int, default=0)
    args = parser.parse_args()

    root = Path(args.root)
    if not root.is_dir():
        print(f"目录不存在: {root}", file=sys.stderr)
        return 1

    cases: list[dict] = []
    skipped: list[dict] = []
    counted: dict[str, int] = {}
    seen: set[str] = set()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.stat().st_size < 1024:
            continue
        machine = elf_machine(path)
        if machine is None:
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest in seen:                      # 同题多份副本只留一个
            continue
        relative = path.relative_to(root)
        mapped = classify(relative)
        if mapped is None:
            skipped.append({"path": str(path), "why": "未归类的顶层目录"})
            continue
        category, expected = mapped
        if not expected:
            skipped.append({"path": str(path), "why": f"{category} 非宿主工具链覆盖范围",
                            "machine": machine})
            continue
        counted[category] = counted.get(category, 0) + 1
        if args.limit_per_category and counted[category] > args.limit_per_category:
            continue
        seen.add(digest)
        cases.append({
            "id": f"pwn99.{category}.{relative.parts[1] if len(relative.parts) > 1 else path.stem}",
            "binary": str(path),
            "category": category,
            "machine": machine,
            "sha256": digest[:16],
            "expected_categories": sorted(expected),
            "note": f"来源目录 {relative.parts[0]}（目录名即标签）",
        })

    manifest = {
        "corpus": "本地 PWN 训练靶场（按漏洞类别分目录，目录名即标签）",
        "root": str(root),
        "method": "每个二进制按所在目录归类；期望 = 该类别对应的 verdict category 集合。"
                  "非 x86（MIPS/ARM/RISCV）与内核单独列出，不计入召回。",
        "counts": counted,
        "cases": cases,
        "excluded": skipped[:80],
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"写入 {output}: {len(cases)} 个用例")
    for name in sorted(counted):
        print(f"  {name:14} {counted[name]:>4}")
    print(f"排除 {len(skipped)} 个（非 x86 / 未归类）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
