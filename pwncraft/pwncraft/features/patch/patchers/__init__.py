"""社区通防 Patcher 注册表：每个第三方 patcher 一个独立包装模块。

目录约定：每个 patcher 内置在 third_party/<名字>/（如 third_party/evilPatcher、
third_party/elf-seccomp-patcher），对应本包里的同名包装模块。包装模块只暴露
meta()（卡片元数据与预设）、tool_dir()、env_report()、run()（options → 产物 +
字节 diff）；argv 形状全部固定在包装模块内，渲染层只能传预设 id / 选项字段。

公共职责见 common.py（diff_runs / resolve_output）。
"""
from __future__ import annotations

from pathlib import Path

from . import evilpatcher, elfseccomp

_REGISTRY = {evilpatcher.PATCHER_ID: evilpatcher, elfseccomp.PATCHER_ID: elfseccomp}


def catalog() -> list[dict]:
    """全部 patcher 的卡片元数据（含各自预设），供 patch_recipes 下发。"""
    return [module.meta() for module in _REGISTRY.values()]


def get(patcher_id: str):
    module = _REGISTRY.get(str(patcher_id or "").strip())
    if module is None:
        raise ValueError(
            f"未知通防 Patcher: {patcher_id!r}（可用: {', '.join(_REGISTRY)}）")
    return module


def presets_for(patcher_id: str) -> list[dict]:
    return get(patcher_id).meta()["presets"]
