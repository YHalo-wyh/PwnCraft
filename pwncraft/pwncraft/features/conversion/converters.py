from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class ConversionResult:
    title: str
    value: str


def parse_int(value: str) -> int:
    text = value.strip().replace("_", "")
    if not text:
        raise ValueError("请输入数字")
    return int(text, 0)


def parse_bytes(value: str) -> bytes:
    text = value.strip()
    if not text:
        raise ValueError("请输入字节或字符串")
    if text.startswith(("b'", 'b"', "B'", 'B"')):
        parsed = ast.literal_eval(text)
        if not isinstance(parsed, bytes):
            raise ValueError("不是 bytes literal")
        return parsed
    if text.startswith(("'", '"')):
        parsed = ast.literal_eval(text)
        if not isinstance(parsed, str):
            raise ValueError("不是字符串 literal")
        return parsed.encode("utf-8")
    compact = text.replace(" ", "").replace("\\x", "")
    if compact.startswith("0x"):
        compact = compact[2:]
    if compact and all(c in "0123456789abcdefABCDEF" for c in compact):
        if len(compact) % 2:
            compact = "0" + compact
        return bytes.fromhex(compact)
    return text.encode("utf-8")


def bytes_literal(data: bytes) -> str:
    return "b'" + "".join(f"\\x{byte:02x}" for byte in data) + "'"


def _signed_cast(value: int, bits: int) -> int:
    mask = (1 << bits) - 1
    unsigned = value & mask
    sign = 1 << (bits - 1)
    return unsigned - (1 << bits) if unsigned & sign else unsigned


def _endian_name(endian: str) -> str:
    return "big" if endian == "big" else "little"


def _safe_var_name(name: str) -> str:
    text = (name or "").strip()
    if not text:
        return "system_addr"
    return text if text.replace("_", "").isalnum() and not text[0].isdigit() else "system_addr"


def _halfword_lines(var_name: str, bits: int) -> str:
    lines = [
        f"low  = {var_name} & 0xffff",
        f"high = ({var_name} >> 16) & 0xffff",
    ]
    if bits == 64:
        lines.extend(
            [
                "parts = [",
                f"    {var_name} & 0xffff,",
                f"    ({var_name} >> 16) & 0xffff,",
                f"    ({var_name} >> 32) & 0xffff,",
                f"    ({var_name} >> 48) & 0xffff,",
                "]",
                "write_order = sorted(enumerate(parts), key=lambda item: item[1])",
            ]
        )
    else:
        lines.append("write_order = sorted([(0, low), (1, high)], key=lambda item: item[1])")
    return "\n".join(lines)


def int_report(value: str, bits: int = 64, endian: str = "little", var_name: str = "system_addr") -> list[ConversionResult]:
    bits = 32 if int(bits) == 32 else 64
    width = bits // 8
    endian = _endian_name(endian)
    var_name = _safe_var_name(var_name)
    number = parse_int(value)
    mask = (1 << bits) - 1
    unsigned_value = number & mask
    signed_value = _signed_cast(number, bits)
    packed = unsigned_value.to_bytes(width, endian, signed=False)
    pack_func = "p32" if bits == 32 else "p64"
    unpack_func = "u32" if bits == 32 else "u64"
    c_int = "c_int32" if bits == 32 else "c_int64"
    c_uint = "c_uint32" if bits == 32 else "c_uint64"
    low = unsigned_value & 0xffff
    high = (unsigned_value >> 16) & 0xffff

    results = [
        ConversionResult("Python int 强转", f"int({number})"),
        ConversionResult(f"无符号 uint{bits} 值", str(unsigned_value)),
        ConversionResult(f"有符号 int{bits} 值", str(signed_value)),
        ConversionResult(f"uint{bits} hex", hex(unsigned_value)),
        ConversionResult(f"int{bits} hex补码", hex(unsigned_value)),
        ConversionResult(f"{endian}-endian bytes", bytes_literal(packed)),
        ConversionResult(f"{pack_func} 打包代码", f"{pack_func}({hex(unsigned_value)})"),
        ConversionResult(f"{unpack_func} 解析代码", f"{unpack_func}(data[:{width}].ljust({width}, b'\\x00'))"),
        ConversionResult("int.from_bytes unsigned", f"int.from_bytes(data[:{width}].ljust({width}, b'\\x00'), '{endian}', signed=False)"),
        ConversionResult("int.from_bytes signed", f"int.from_bytes(data[:{width}].ljust({width}, b'\\x00'), '{endian}', signed=True)"),
        ConversionResult("ctypes 有符号强转", f"ctypes.{c_int}({number}).value"),
        ConversionResult("ctypes 无符号强转", f"ctypes.{c_uint}({number}).value"),
        ConversionResult("低 16 位 low", f"low  = {hex(unsigned_value)} & 0xffff  # {hex(low)}"),
        ConversionResult("高 16 位 high", f"high = ({hex(unsigned_value)} >> 16) & 0xffff  # {hex(high)}"),
        ConversionResult(f"{bits}位 low/high 写入代码", _halfword_lines(var_name, bits)),
    ]

    if bits == 64:
        chunks = [
            (unsigned_value >> shift) & 0xffff
            for shift in range(0, 64, 16)
        ]
        results.append(
            ConversionResult(
                "64位四段 half-word",
                "chunks = [" + ", ".join(hex(item) for item in chunks) + "]",
            )
        )
        results.append(
            ConversionResult(
                "64位 half-word 地址偏移",
                "[(base + 0x0, parts[0]), (base + 0x2, parts[1]), (base + 0x4, parts[2]), (base + 0x6, parts[3])]",
            )
        )
    else:
        results.append(
            ConversionResult(
                "32位 half-word 地址偏移",
                "[(base + 0x0, low), (base + 0x2, high)]",
            )
        )
    return results


def bytes_report(value: str, bits: int = 64, endian: str = "little") -> list[ConversionResult]:
    bits = 32 if int(bits) == 32 else 64
    width = bits // 8
    endian = _endian_name(endian)
    data = parse_bytes(value)
    padded = data[:width].ljust(width, b"\x00")
    unsigned_value = int.from_bytes(padded, endian, signed=False)
    signed_value = int.from_bytes(padded, endian, signed=True)
    pack_func = "p32" if bits == 32 else "p64"
    unpack_func = "u32" if bits == 32 else "u64"
    return [
        ConversionResult("bytes literal", bytes_literal(data)),
        ConversionResult("hex", data.hex()),
        ConversionResult("长度", str(len(data))),
        ConversionResult(f"{endian}-endian uint{bits}", hex(unsigned_value)),
        ConversionResult(f"{endian}-endian int{bits}", str(signed_value)),
        ConversionResult("截断/补齐规则", f"data[:{width}].ljust({width}, b'\\x00')"),
        ConversionResult(f"{unpack_func} 解析", f"{unpack_func}({bytes_literal(data)}[:{width}].ljust({width}, b'\\x00'))"),
        ConversionResult(f"{pack_func} 反打包", f"{pack_func}({hex(unsigned_value)})"),
        ConversionResult("int.from_bytes unsigned", f"int.from_bytes({bytes_literal(data)}[:{width}].ljust({width}, b'\\x00'), '{endian}', signed=False)"),
        ConversionResult("int.from_bytes signed", f"int.from_bytes({bytes_literal(data)}[:{width}].ljust({width}, b'\\x00'), '{endian}', signed=True)"),
    ]
