"""patchers 公共助手：字节 diff 与输出落盘（被 __init__ 与各包装模块共用）。"""
from __future__ import annotations

from pathlib import Path

_MAX_DIFF_RUNS = 128


def diff_runs(old: bytes, new: bytes, max_runs: int = _MAX_DIFF_RUNS) -> dict:
    """等长字节差异 → 连续区间列表（{offset, length, old, new}，hex 展示）。"""
    if len(old) != len(new):
        return {"runs": [], "truncated": False, "same_size": False, "changed": -1}
    runs: list[dict] = []
    start = None
    for index, (a, b) in enumerate(zip(old, new)):
        if a != b and start is None:
            start = index
        elif a == b and start is not None:
            runs.append((start, index))
            start = None
    if start is not None:
        runs.append((start, len(old)))
    truncated = len(runs) > max_runs
    return {
        "runs": [
            {"offset": offset, "length": end - offset,
             "old": old[offset:end].hex(" "), "new": new[offset:end].hex(" ")}
            for offset, end in runs[:max_runs]
        ],
        "truncated": truncated,
        "same_size": True,
        "changed": sum(end - offset for offset, end in runs),
    }


def resolve_output(product: Path, source: Path, output_dir: str, output_name: str,
                   default_name: str, *, protected: tuple[Path, ...] = ()) -> Path:
    """把 scratch 产物落到用户可见的输出路径。

    默认目录 = 源文件所在目录（桥侧已解析为题目目录），默认文件名由各
    patcher 给出（evilPatcher → <名>.patch，elf-seccomp → <名>.protected）。
    任何情况下不允许覆盖原始副本、工作副本本身等显式保护路径。
    """
    directory = Path(str(output_dir or "").strip() or source.parent)
    name = str(output_name or "").strip() or default_name
    if "/" in name or "\\" in name or name in (".", ".."):
        raise ValueError(f"输出文件名不能包含路径分隔符: {name!r}（目录请填输出目录）")
    target = directory / name
    for guard in protected:
        if guard.is_file() and target.resolve() == guard.resolve():
            raise ValueError(f"输出路径会覆盖受保护文件（{guard}），请换一个输出名")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(product.read_bytes())
    return target
