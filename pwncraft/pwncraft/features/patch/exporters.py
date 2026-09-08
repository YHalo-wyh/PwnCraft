"""Patch 文件导出：pwntools 补丁脚本、干净 patched ELF、字节 diff 文本。

三种产物共用同一份 PatchOp 真值：
- script：比赛提交常用的 patch.py（pwnlib ELF.write 以 vaddr 定位；
  段尾填充区的 cave 无法用 vaddr_to_offset 解析，脚本内按页对齐偏移补写）；
- patched：从只读原始副本按 vaddr 回放，避开工作副本上 patchelf 的改动；
- diff：offset | 原字节 | 新字节 | 说明 的核对文本。
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from pwncraft.core.workbench import elf_geometry
from .patch_core import PatchOp, page_aware_vaddr_to_offset

_TAIL_HELPER = '''def _tail_offset(elf, vaddr, page=0x1000):
    # 段尾填充区：pwntools 的 vaddr_to_offset 只认 filesz 区间；
    # 整页映射的段间填充按页对齐末端换算文件偏移
    for seg in elf.segments:
        h = seg.header
        if h.p_type == 'PT_LOAD' and (h.p_flags & 1):
            start, size = h.p_vaddr, h.p_filesz
            end = (start + size + page - 1) & ~(page - 1)
            if start <= vaddr < end:
                return h.p_offset + (vaddr - start)
    raise ValueError('vaddr %#x 不在任何可执行段页范围内' % vaddr)
'''


def export_pwntools_script(ops: list[PatchOp], *, binary_name: str, arch: str,
                           geometry: dict | None = None) -> str:
    """生成 patch.py。geometry 提供时，把段尾 cave 类 op 归入偏移补写段。"""
    from pwncraft.core.workbench import vaddr_to_offset as strict_offset

    body_ops: list[PatchOp] = []
    tail_ops: list[PatchOp] = []
    for op in ops:
        if geometry is not None and strict_offset(geometry, op.vaddr) is None:
            tail_ops.append(op)
        else:
            body_ops.append(op)

    lines = [
        "#!/usr/bin/env python3",
        "# 由 PwnCraft AWDP Patch 自动生成 —— 字节与地址来自当前工作区补丁记录",
        "# 用法: python3 patch.py [输入ELF] [输出ELF]",
        f"#   默认 ./{binary_name} → ./{binary_name}_patched",
        "import sys",
        "from pwn import *",
        "",
        f"context.arch = {arch!r}",
        f"source = sys.argv[1] if len(sys.argv) > 1 else './{binary_name}'",
        f"output = sys.argv[2] if len(sys.argv) > 2 else './{binary_name}_patched'",
        "elf = ELF(source, checksec=False)",
        "",
    ]
    if tail_ops:
        lines.append(_TAIL_HELPER.rstrip())
        lines.append("")
    total = len(ops)
    index = 0
    for op in body_ops:
        index += 1
        lines.append(f"# ---- [{index}/{total}] {op.kind} @ 0x{op.vaddr:x} ---- {op.note}")
        lines.append(f"elf.write(0x{op.vaddr:x}, bytes.fromhex({op.new_bytes.hex(' ')!r}))")
        lines.append("")
    if body_ops:
        lines.append("elf.save(output)")
        lines.append("")
    else:
        # 全部是段尾补丁时也需要先落盘再补写
        lines.append("elf.save(output)")
        lines.append("")
    for op in tail_ops:
        index += 1
        lines.append(f"# ---- [{index}/{total}] {op.kind} @ 0x{op.vaddr:x}（段尾填充区，按偏移补写）---- {op.note}")
        lines.append(f"with open(output, 'r+b') as _f:")
        lines.append(f"    _f.seek(_tail_offset(elf, 0x{op.vaddr:x}))")
        lines.append(f"    _f.write(bytes.fromhex({op.new_bytes.hex(' ')!r}))")
        lines.append("")
    lines += [
        "import os",
        "os.chmod(output, os.stat(source).st_mode)",
        'print(f"[+] 已生成 {output}")',
        "",
    ]
    return "\n".join(lines)


def export_diff_text(ops: list[PatchOp], *, binary_path: str) -> str:
    lines = [
        f"AWDP Patch 字节差异 —— {binary_path}",
        f"共 {len(ops)} 条补丁（全部等长替换，文件大小不变）",
        "",
    ]
    for index, op in enumerate(ops, start=1):
        lines.append(f"[{index}/{len(ops)}] {op.kind}  vaddr 0x{op.vaddr:x}  "
                     f"file 0x{op.file_offset:x}  {len(op.new_bytes)} 字节")
        lines.append(f"  原: {op.original_bytes.hex(' ')}")
        lines.append(f"  新: {op.new_bytes.hex(' ')}")
        if op.note:
            lines.append(f"  说明: {op.note}")
        lines.append("")
    return "\n".join(lines)


def materialize_patched(source: Path, ops: list[PatchOp], dest: Path) -> dict:
    """从只读原始副本回放全部补丁，生成干净的 patched ELF。"""
    source, dest = Path(source), Path(dest)
    geometry = elf_geometry(source)
    data = bytearray(source.read_bytes())
    for op in ops:
        offset = page_aware_vaddr_to_offset(geometry, op.vaddr)
        if offset is None:
            raise ValueError(f"补丁 vaddr 0x{op.vaddr:x} 在原始副本中无对应文件偏移")
        chunk = bytes(data[offset:offset + len(op.original_bytes)])
        if chunk != op.original_bytes:
            raise ValueError(
                f"原始副本在 0x{op.vaddr:x} 处字节为 {chunk.hex(' ')!r}，"
                f"与补丁记录的原字节 {op.original_bytes.hex(' ')!r} 不一致；"
                "原始文件可能与打补丁时不同，拒绝回放")
        data[offset:offset + len(op.new_bytes)] = op.new_bytes
    dest.write_bytes(bytes(data))
    digest = hashlib.sha256(bytes(data)).hexdigest()
    return {"path": str(dest), "count": len(ops), "sha256": digest,
            "size": len(data)}
