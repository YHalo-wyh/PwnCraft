from __future__ import annotations

import argparse

import pwndbg.aglib
import pwndbg.color.context as context_color
import pwndbg.color.memory as memory_color
import pwndbg.commands
from pwndbg.color import message
from pwndbg.commands import CommandCategory
from pwndbg.pwncraft.tutor.frame_state import format_address, inspect_frame


def _address(value: int | None) -> str:
    if value is None:
        return message.warn("UNKNOWN")
    try:
        return memory_color.get(value)
    except Exception:
        return message.info(format_address(value))


def _label(text: str) -> str:
    return message.hint(text)


def _state() -> dict:
    return inspect_frame()


frame_parser = argparse.ArgumentParser(
    description="基于 GDB unwinder / DWARF CFI 解释当前 frame。"
)
frame_parser.add_argument("level", nargs="?", type=int, help="可选 frame level")


@pwndbg.commands.Command(
    frame_parser,
    category=CommandCategory.STACK,
    command_name="frame-explain",
    aliases=["framex"],
)
@pwndbg.commands.OnlyWhenRunning
def frame_explain(level: int | None = None) -> None:
    if level is not None:
        import gdb

        gdb.execute(f"frame {level}")
    state = _state()
    print(message.notice("当前栈帧 FRAME EXPLAIN · 融合调试"))
    print(f"{_label('Frame')}  #{state['level']} {message.success(state['function'])}")
    print(f"{_label('PC')}     {_address(state.get('pc'))}  {message.info(state.get('pc_symbol', 'UNKNOWN'))}")
    print(f"{_label('RSP')}    {_address(state.get('rsp'))}")
    role = "帧指针" if state.get("rbp_role") == "frame_pointer" else "通用寄存器"
    print(f"{_label('RBP')}    {_address(state.get('rbp'))}  {message.info(role)}")
    print(f"{_label('返回')}   {_address(state.get('return_target'))}  {message.info(state.get('return_symbol', 'UNKNOWN'))}")
    print(f"{_label('恢复证据')} {message.info(state.get('frame_recovery', 'UNKNOWN'))}")


@pwndbg.commands.Command(
    "显示 GDB unwinder 确认的当前返回目标。",
    category=CommandCategory.STACK,
    command_name="return-info",
    aliases=["ret-info"],
)
@pwndbg.commands.OnlyWhenRunning
def return_info() -> None:
    state = _state()
    print(message.notice("返回目标 RETURN INFO"))
    print(f"{_label('Target')}   {_address(state.get('return_target'))}  {message.info(state.get('return_symbol', 'UNKNOWN'))}")
    print(f"{_label('Evidence')} {message.info(state.get('frame_recovery', 'GDB unwinder'))}")


@pwndbg.commands.Command(
    "判定 RBP 是已确认的帧指针还是通用寄存器。",
    category=CommandCategory.REGISTER,
    command_name="rbp-info",
)
@pwndbg.commands.OnlyWhenRunning
def rbp_info() -> None:
    state = _state()
    confirmed = state.get("rbp_role") == "frame_pointer"
    role = "帧指针" if confirmed else "通用寄存器（unwinder 未确认帧指针）"
    print(message.notice("RBP INFO"))
    print(f"{context_color.register('RBP')}  {_address(state.get('rbp'))}  {message.info(role)}")
    print(f"{_label('Evidence')} {message.info(state.get('frame_recovery', 'UNKNOWN'))}")
    if confirmed:
        print(f"{_label('saved RBP slot')} {_address(state.get('saved_rbp_slot'))} -> {_address(state.get('saved_rbp'))}")
        print(f"{_label('saved RIP slot')} {_address(state.get('saved_rip_slot'))} -> {_address(state.get('saved_rip'))}")


stackof_parser = argparse.ArgumentParser(description="定位栈地址属于哪个 GDB frame。")
stackof_parser.add_argument("address", type=str, help="地址或 GDB 表达式")


@pwndbg.commands.Command(stackof_parser, category=CommandCategory.STACK, command_name="stackof")
@pwndbg.commands.OnlyWhenRunning
def stackof(address: str) -> None:
    import gdb

    target = int(gdb.parse_and_eval(address))
    frame = gdb.newest_frame()
    level = 0
    owner = None
    while frame is not None:
        rsp = int(frame.read_register("rsp"))
        older = frame.older()
        upper = int(older.read_register("rsp")) if older is not None else rsp + 0x100000
        if rsp <= target < upper:
            owner = (level, frame.name() or "UNKNOWN", rsp, upper)
            break
        frame = older
        level += 1
    if owner is None:
        print(message.warn(f"{target:#x} 的 frame 归属 UNKNOWN"))
        return
    print(f"{_address(target)} 属于 {_label(f'frame #{owner[0]}')} {message.success(owner[1])}")
    print(f"{_address(owner[2])} <= address < {_address(owner[3])}")


safe_parser = argparse.ArgumentParser(
    description="使用 stored = ptr ^ (field_addr >> 12) 计算 Safe-Linking。"
)
safe_parser.add_argument("mode", type=str, choices=("encode", "decode"), help="encode 或 decode")
safe_parser.add_argument("field_address", type=str, help="next 字段自身地址")
safe_parser.add_argument("value", type=str, help="target pointer 或 stored value")


@pwndbg.commands.Command(
    safe_parser,
    category=CommandCategory.PTMALLOC2,
    command_name="safe-link",
    aliases=["safelink"],
)
def safe_link(mode: str, field_address: str, value: str) -> None:
    import gdb

    field = int(gdb.parse_and_eval(field_address))
    raw = int(gdb.parse_and_eval(value))
    result = raw ^ (field >> 12)
    print(message.notice("SAFE-LINKING"))
    print(f"{_label('mode')}   {message.info(mode)}")
    print(f"{_label('field')}  {_address(field)}")
    print(f"{_label('input')}  {_address(raw)}")
    print(f"{_label('result')} {_address(result)}")
    print(message.info("计算使用字段自身地址，不假定固定 heap_base。"))


cyclic_find_parser = argparse.ArgumentParser(
    description="cyclic --lookup 的兼容命令名；查找 cyclic pattern 偏移。"
)
cyclic_find_parser.add_argument("value", type=str, help="4/8-byte pattern 或整数")
cyclic_find_parser.add_argument("-n", "--length", type=int, default=4, help="唯一子序列长度")


@pwndbg.commands.Command(
    cyclic_find_parser,
    category=CommandCategory.MISC,
    command_name="cyclic-find",
)
def cyclic_find_command(value: str, length: int = 4) -> None:
    import gdb

    # Delegate to upstream's registered cyclic command and its parser instead
    # of copying pwntools lookup semantics into the fork.
    gdb.execute(f"cyclic -n {int(length)} -l {value}", from_tty=True)
