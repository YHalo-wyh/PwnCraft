from __future__ import annotations

from dataclasses import dataclass

from pwncraft.features.heapviz.models import AllocatorConfig


@dataclass(frozen=True)
class TechniqueCompatibility:
    supported: bool
    level: str  # supported | conditional | unsupported
    summary: str
    requirements: tuple[str, ...] = ()
    alternatives: tuple[str, ...] = ()


# These ranges describe the classic form represented by pwncraft's teaching
# template, not every historical variant ever published under the same name.
_RULES: dict[str, dict[str, object]] = {
    "tcache_poison_safe_linking": {
        "min": (2, 32),
        "requirements": ("UAF/可控 freed chunk next", "heap 地址或 safe-linking key"),
    },
    "fastbin_to_unsorted_leak": {
        "min": (2, 23),
        "requirements": ("tcache 已满或被绕过", "可触发 malloc_consolidate"),
    },
    "stdout_environ_stack": {
        "min": (2, 27),
        "requirements": ("可控 FILE 字段或可写 stdout 附近", "libc 基址"),
    },
    "setcontext_orw": {
        "min": (2, 27),
        "requirements": ("可控控制流目标", "可写 fake frame/ROP 区域"),
    },
    "house_of_force": {
        "max": (2, 28),
        "requirements": ("top chunk size overwrite",),
        "unsupported": "glibc 2.29+ 会检查 top chunk size；经典 top.size=-1 路线不再成立。",
    },
    "house_of_orange": {
        "max": (2, 26),
        "requirements": ("top chunk overwrite", "旧式 _IO_list_all/FSOP 条件"),
        "unsupported": "该模板表示经典 House of Orange；新 glibc 的 top/vtable 检查使经典链不适用。",
    },
    "house_of_lore": {
        "requirements": ("smallbin 可控 bk/fd", "满足 unlink/smallbin 完整性检查"),
    },
    "house_of_spirit": {
        "requirements": ("可控 fake chunk 地址", "free 可接受该地址"),
    },
    "house_of_einherjar": {
        "requirements": ("off-by-null/prev_size overwrite", "可控 fake previous chunk"),
    },
    "house_of_botcake": {
        "min": (2, 29),
        "requirements": ("tcache", "UAF/overlap", "可绕开正常 duplicate 检测路径"),
    },
    "house_of_rust": {
        "min": (2, 30),
        "requirements": ("smallbin/tcache stashing unlink 条件", "可控写"),
    },
    "house_of_apple2": {
        "min": (2, 34),
        "requirements": ("可控 FILE/wide_data", "满足对应 glibc IO 检查"),
    },
}


def template_compatibility(template_id: str, config: AllocatorConfig) -> TechniqueCompatibility:
    rule = _RULES.get(template_id, {})
    minimum = rule.get("min")
    maximum = rule.get("max")
    requirements = tuple(rule.get("requirements") or ())
    if isinstance(minimum, tuple) and config.version < minimum:
        return TechniqueCompatibility(
            False,
            "unsupported",
            f"当前 glibc {config.version[0]}.{config.version[1]} 低于该模板的参考起点 {minimum[0]}.{minimum[1]}。",
            requirements,
        )
    if isinstance(maximum, tuple) and config.version > maximum:
        reason = str(rule.get("unsupported") or f"经典模板仅覆盖到 glibc {maximum[0]}.{maximum[1]}。")
        return TechniqueCompatibility(False, "unsupported", reason, requirements)
    if template_id == "tcache_poison_safe_linking" and not config.safe_linking:
        return TechniqueCompatibility(False, "unsupported", "当前版本没有 safe-linking，应使用未编码的对应 poisoning 逻辑。", requirements)
    if template_id == "fastbin_to_unsorted_leak" and config.tcache_enabled:
        return TechniqueCompatibility(True, "conditional", "可用，但必须先填满/绕过对应 tcache bin。", requirements)
    if template_id == "stdout_environ_stack" and config.hooks_available:
        return TechniqueCompatibility(True, "conditional", "可用；当前版本仍有 hooks，也可以比较 hook 路线和 FILE/stack 路线。", requirements)
    return TechniqueCompatibility(True, "supported", "该模板与当前版本没有已知的硬性版本冲突。", requirements)


def target_compatibility(target: str, config: AllocatorConfig) -> tuple[bool, str]:
    text = (target or "").lower()
    if ("__free_hook" in text or "__malloc_hook" in text) and not config.hooks_available:
        return False, "glibc 2.34+ 的 malloc hooks 已不再参与正常分配/释放流程，不能把它当作有效劫持目标。"
    if "top.size" in text and config.top_size_check:
        return False, "glibc 2.29+ 对 top size 有 sanity check，经典 House of Force 条件不成立。"
    return True, ""


def config_capability_summary(config: AllocatorConfig) -> tuple[str, ...]:
    lines = [
        f"tcache: {'on' if config.tcache_enabled else 'off'} / count={config.tcache_count_limit}",
        f"safe-linking: {'on' if config.safe_linking else 'off'}",
        f"tcache duplicate check: {'on' if config.tcache_key_check else 'off'}",
        f"malloc hooks: {'available' if config.hooks_available else 'removed/ineffective'}",
        f"top-size check: {'on' if config.top_size_check else 'off'}",
        f"IO vtable validation: {'on' if config.io_vtable_validation else 'legacy'}",
    ]
    return tuple(lines)
