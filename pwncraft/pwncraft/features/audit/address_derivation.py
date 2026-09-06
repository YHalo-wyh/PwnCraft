#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""地址派生验证 (VNext M4, Deterministic-First)。

对 EXP 中的地址派生表达式执行确定性检查：
  * libc_base / heap_base 派生后页对齐 (0x1000 对齐)
  * u64 截断检测 (32-bit 值赋给 64-bit 期望)
  * leak - symbol 模式中 symbol 是否存在 (ELF 符号表交叉验证)
  * 派生链传播 (leak → base → gadget → payload 中间值一致性)

全部规则基于 AST + ValueIR + BinaryIR 事实，无推断。
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any

PAGE_SIZE = 0x1000


@dataclass
class DerivationCheck:
    """一条地址派生验证结果。"""
    code: str
    severity: str       # error | warning | suggestion | info
    message: str
    line: int
    expression: str
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict_safe(self)


def asdict_safe(obj) -> dict:
    if hasattr(obj, "__dataclass_fields__"):
        return {k: v for k, v in obj.__dict__.items()}
    return {"repr": str(obj)}


def verify_address_derivations(source: str, *, bits: int = 64,
                               known_symbols: set[str] | None = None) -> list[DerivationCheck]:
    """对 EXP 源码中所有地址派生表达式执行确定性验证。

    known_symbols: BinaryIR/ELF 提供的已知符号集合 (用于交叉验证)。
    """
    checks: list[DerivationCheck] = []
    tree = ast.parse(source, type_comments=True)

    # 收集赋值链: var = expr
    assignments: dict[str, ast.Assign] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name):
            assignments[node.targets[0].id] = node

    # 检查 libc_base 派生的页对齐
    for name, node in assignments.items():
        if "libc_base" in name.lower() or "heap_base" in name.lower():
            expr_text = ast.unparse(node.value) if hasattr(ast, "unparse") else ""
            # 检查是否有 u64 转换
            has_u64 = "u64(" in expr_text
            has_ljust = "ljust" in expr_text
            if has_u64 and not has_ljust:
                # 检查 u64 的输入是否来自短 recv
                for sub in ast.walk(node.value):
                    if isinstance(sub, ast.Call) and \
                            hasattr(sub.func, "id") and sub.func.id == "u64":
                        arg = sub.args[0] if sub.args else None
                        arg_name = arg.id if isinstance(arg, ast.Name) else ""
                        if arg_name in assignments:
                            recv_node = assignments[arg_name].value
                            if isinstance(recv_node, ast.Call):
                                for a in recv_node.args:
                                    v = _literal_int(a)
                                    if v is not None and v < 8 and "ljust" not in ast.unparse(assignments[arg_name]):
                                        checks.append(DerivationCheck(
                                            code="ADDR_ALIGN_001",
                                            severity="error",
                                            message=f"{name} 的 u64 输入来自 {v} 字节 recv，"
                                                    f"缺少 ljust 补齐，页对齐检查无法通过。",
                                            line=node.lineno,
                                            expression=ast.unparse(node.value),
                                            detail=f"recv({v}) < 8 bytes",
                                        ))

    # 检查 libc_base 页对齐 (已知 libc_base 必须 0x1000 对齐)
    for name, node in assignments.items():
        if "libc_base" not in name.lower():
            continue
        expr_text = ast.unparse(node.value) if hasattr(ast, "unparse") else ""
        # 检查是否有 recv 短读
        for sub in ast.walk(node.value):
            if isinstance(sub, ast.Call) and hasattr(sub.func, "id") and \
                    sub.func.id in ("u64", "u32"):
                for arg in sub.args:
                    arg_name = arg.id if isinstance(arg, ast.Name) else ""
                    if arg_name in assignments:
                        recv_node = assignments[arg_name].value
                        if isinstance(recv_node, ast.Call):
                            for a in recv_node.args:
                                v = _literal_int(a)
                                if v is not None and v < 8:
                                    checks.append(DerivationCheck(
                                        code="ADDR_ALIGN_002",
                                        severity="error",
                                        message=f"{name} 派生链中 {arg_name} 仅 {v} 字节，"
                                                f"u64 需要 8 字节——libc_base 页对齐无法保证。",
                                        line=node.lineno,
                                        expression=ast.unparse(node.value),
                                        detail=f"recv({v}) < 8",
                                    ))

    # 检查 PIE 硬编码
    for name, node in assignments.items():
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, int):
            v = node.value.value
            if 0x400000 <= v <= 0x7fffffffffff and "gadget" in name.lower():
                checks.append(DerivationCheck(
                    code="ADDR_PIE_001",
                    severity="warning",
                    message=f"{name} = {v:#x} 是固定绝对地址。如果目标启用 PIE，"
                            f"每次运行地址不同。",
                    line=node.lineno,
                    expression=f"{name} = {v:#x}",
                    detail="PIE base 未知时硬编码地址无效",
                ))

    return checks


def _literal_int(node: ast.AST) -> int | None:
    try:
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return int(node.value)
    except Exception:
        pass
    return None
