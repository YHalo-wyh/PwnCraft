"""Read-only presentation of function boundaries emitted by objdump."""
from __future__ import annotations

import re

_FUNCTION = re.compile(r"^\s*([0-9a-fA-F]+) <(.+)>:\s*$")
_INSTRUCTION = re.compile(r"^\s*[0-9a-fA-F]+:\s+\S")


def parse_disassembly(output: str, *, max_functions: int = 1000,
                      max_lines: int = 500) -> dict:
    functions: list[dict] = []
    current = None
    count = 0
    section = ""
    for line in output.splitlines():
        if line.startswith("Disassembly of section "):
            section = line.removeprefix("Disassembly of section ").rstrip(":")
            current = None
        match = _FUNCTION.match(line)
        if match:
            count += 1
            current = None
            if len(functions) < max_functions:
                current = {"name": match[2], "address": "0x" + match[1].lstrip("0"),
                           "section": section, "lines": [], "instruction_count": 0,
                           "truncated": False}
                if current["address"] == "0x":
                    current["address"] = "0x0"
                functions.append(current)
        elif current is not None and _INSTRUCTION.match(line):
            current["instruction_count"] += 1
            if len(current["lines"]) < max_lines:
                current["lines"].append(line.rstrip())
            else:
                current["truncated"] = True
    for function in functions:
        function["assembly"] = "\n".join(function.pop("lines"))
    return {"functions": functions, "function_count": count,
            "truncated": count > len(functions)}
