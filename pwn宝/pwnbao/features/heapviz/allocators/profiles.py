from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from pwnbao.features.heapviz.models import AllocatorConfig
from pwnbao.features.heapviz.allocators.policy import GlibcPolicy


# 每当下面的机制表 / GlibcPolicy 阈值发生变化时递增：快照里的
# allocator.profile_revision 让前端能识别「同版本号、不同规则」的旧快照。
ALLOCATOR_PROFILE_REVISION = "2026.09-r1"

# 注册表覆盖的 glibc minor 版本（2.23 … 2.40）。机制差异由 GlibcPolicy 按
# 版本阈值推导 —— 这里是唯一真值；前端只允许提交 profile_id / 版本请求。
SUPPORTED_GLIBC_MINORS: tuple[int, ...] = tuple(range(23, 41))
DEFAULT_GLIBC_VERSION = (2, 35)


def parse_glibc_version(text: str | None) -> tuple[int, int]:
    raw = text or ""
    match = re.search(r"(\d+)\.(\d+)", raw)
    if not match:
        return DEFAULT_GLIBC_VERSION
    return (int(match.group(1)), int(match.group(2)))


def version_text(version: tuple[int, int]) -> str:
    return f"{version[0]}.{version[1]}"


def profile_id_for(version: tuple[int, int], arch: str) -> str:
    return f"glibc-{version_text(version)}-{'i386' if arch == 'i386' else 'amd64'}"


def supported_profile_ids() -> list[str]:
    return [profile_id_for((2, minor), "amd64") for minor in SUPPORTED_GLIBC_MINORS]


@dataclass(frozen=True)
class AllocatorProfile:
    """一个已解析的 allocator profile：版本 × 架构 → 全部机制真值。

    前端永远不会拿到「自己算机制」的权力：safe_linking / tcache / 检查
    规则等只在本表（经 GlibcPolicy）里存在。快照回传 requested_version
    与 effective_version 两个独立字段 —— 请求被钳制时 UI 必须显示真值。
    """

    profile_id: str
    profile_revision: str
    version: tuple[int, int]
    requested_version: str
    arch: str
    simulation_mode: str
    heap_base: str
    clamp_note: str = ""
    policy: GlibcPolicy | None = None

    @property
    def effective_version(self) -> str:
        return version_text(self.version)

    @property
    def bits(self) -> int:
        return 32 if self.arch == "i386" else 64

    def to_config(self) -> AllocatorConfig:
        policy = self.policy or GlibcPolicy.for_version(self.version)
        return AllocatorConfig(
            family="glibc",
            version=self.version,
            arch=self.arch,
            bits=self.bits,
            alignment=0x10 if self.bits == 64 else 0x8,
            tcache_enabled=policy.tcache.enabled,
            tcache_count_limit=policy.tcache.count_limit,
            tcache_max_chunk_size=policy.tcache_max(self.bits),
            safe_linking=policy.tcache.safe_linking,
            tcache_key_check=policy.integrity.tcache_duplicate,
            hooks_available=policy.hooks.malloc_free_hooks,
            top_size_check=policy.integrity.top_size,
            io_vtable_validation=policy.integrity.io_vtable,
            max_fast_chunk_size=policy.max_fast(self.bits),
            heap_base=self.heap_base,
            simulation_mode="plan" if self.simulation_mode == "plan" else "strict",
            profile_id=self.profile_id,
            profile_revision=self.profile_revision,
            requested_version=self.requested_version,
        )

    def to_wire_dict(self) -> dict[str, Any]:
        """快照回传的 allocator 形态：身份 + 请求/生效版本 + 只读机制表。

        ``version`` 保留为 effective 的别名，兼容仍读 ``allocator.version``
        的旧前端/测试；机制字段同时给嵌套 ``mechanisms`` 与旧的平铺键。
        """
        policy = self.policy or GlibcPolicy.for_version(self.version)
        bits = self.bits
        mechanisms = {
            "tcache": policy.tcache.enabled,
            "tcache_count_limit": policy.tcache.count_limit,
            "tcache_max": hex(policy.tcache_max(bits)),
            "safe_linking": policy.tcache.safe_linking,
            "tcache_key_check": policy.integrity.tcache_duplicate,
            "hooks": policy.hooks.malloc_free_hooks,
            "top_size_check": policy.integrity.top_size,
            "io_vtable_validation": policy.integrity.io_vtable,
            "max_fast": hex(policy.max_fast(bits)),
        }
        return {
            "profile_id": self.profile_id,
            "profile_revision": self.profile_revision,
            "requested_version": self.requested_version,
            "effective_version": self.effective_version,
            "version": self.effective_version,   # legacy 别名 = effective
            "family": "glibc",
            "arch": self.arch,
            "bits": bits,
            "alignment": 0x10 if bits == 64 else 0x8,
            "simulation_mode": "plan" if self.simulation_mode == "plan" else "strict",
            "heap_base": self.heap_base,
            "clamp_note": self.clamp_note,
            "mechanisms": mechanisms,
            # 平铺机制键（只读，兼容旧消费者；后端永远以此表为准重建）
            "tcache_enabled": mechanisms["tcache"],
            "tcache_count_limit": mechanisms["tcache_count_limit"],
            "tcache_max_chunk_size": int(mechanisms["tcache_max"], 16),
            "safe_linking": mechanisms["safe_linking"],
            "tcache_key_check": mechanisms["tcache_key_check"],
            "hooks_available": mechanisms["hooks"],
            "top_size_check": mechanisms["top_size_check"],
            "io_vtable_validation": mechanisms["io_vtable_validation"],
            "max_fast_chunk_size": int(mechanisms["max_fast"], 16),
        }


def normalize_arch(arch: str | None) -> str:
    return "i386" if str(arch or "").strip().lower() in {"i386", "x86", "ia32", "32"} else "amd64"


def resolve_allocator_profile(
    request: Mapping[str, Any] | None = None,
    *,
    default_arch: str = "amd64",
) -> AllocatorProfile:
    """把前端请求解析成注册表里的 AllocatorProfile。

    接受 ``profile_id``（"glibc-2.31-amd64"，最权威）或 ``version`` /
    ``requested_version`` 文本；arch / heap_base / simulation_mode 一并
    归一。**故意忽略**请求里的任何机制布尔（safe_linking、tcache_* …）——
    它们是后端表的输出，不是输入；前端自己算出来的机制位是双重真值，
    在这里被丢掉而不是被信任。

    版本不在注册表内时钳到最近的受支持版本，``clamp_note`` 记录钳制原因，
    ``requested_version`` 保留原始请求供 UI 显示「请求 vs 生效」。
    """
    raw = dict(request or {})
    arch = normalize_arch(raw.get("arch") or default_arch)

    requested_text = str(
        raw.get("requested_version")
        or raw.get("version")
        or ""
    ).strip()
    profile_id = str(raw.get("profile_id") or "").strip()
    if not requested_text and profile_id:
        # profile_id 是权威请求：glibc-2.31-amd64 → 2.31 + arch
        match = re.match(r"^glibc-(\d+)\.(\d+)-(\w+)$", profile_id)
        if match:
            requested_text = f"{match.group(1)}.{match.group(2)}"
            arch = normalize_arch(match.group(3))
    if not requested_text:
        requested_text = version_text(DEFAULT_GLIBC_VERSION)

    requested = parse_glibc_version(requested_text)
    effective = requested
    clamp_note = ""
    if effective[1] < SUPPORTED_GLIBC_MINORS[0]:
        effective = (2, SUPPORTED_GLIBC_MINORS[0])
        clamp_note = (
            f"请求 glibc {version_text(requested)} 低于注册表下限，"
            f"已钳到 {version_text(effective)}"
        )
    elif effective[1] > SUPPORTED_GLIBC_MINORS[-1]:
        effective = (2, SUPPORTED_GLIBC_MINORS[-1])
        clamp_note = (
            f"请求 glibc {version_text(requested)} 高于注册表上限，"
            f"已钳到 {version_text(effective)}"
        )

    return AllocatorProfile(
        profile_id=profile_id_for(effective, arch),
        profile_revision=ALLOCATOR_PROFILE_REVISION,
        version=effective,
        requested_version=requested_text,
        arch=arch,
        simulation_mode=str(raw.get("simulation_mode") or "strict"),
        heap_base=str(raw.get("heap_base") or "heap_base"),
        clamp_note=clamp_note,
        policy=GlibcPolicy.for_version(effective),
    )


def profile_list() -> list[dict[str, str]]:
    """下拉框单一真值：后端支持的 profile 清单（前端不再各写一份版本表）。"""
    return [
        {
            "profile_id": profile_id_for((2, minor), "amd64"),
            "profile_id_i386": profile_id_for((2, minor), "i386"),
            "version": f"2.{minor}",
        }
        for minor in SUPPORTED_GLIBC_MINORS
    ]


def build_allocator_config(
    arch: str = "amd64",
    libc_version: str = "glibc 2.35",
    *,
    simulation_mode: str = "strict",
) -> AllocatorConfig:
    """兼容旧调用点：等价于 resolve_allocator_profile(...).to_config()。"""
    return resolve_allocator_profile({
        "arch": arch,
        "version": libc_version,
        "simulation_mode": simulation_mode,
    }).to_config()
