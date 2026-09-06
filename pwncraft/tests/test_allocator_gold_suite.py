"""Allocator Gold Suite — glibc 版本边界的真实验证（训练集喂入前的闸门）。

前端已经把机制真值交给后端 AllocatorProfile，但「2.23 … 2.40 每个版本
背后真的有独立行为」必须在这里用引擎行为证明，否则 Agent 可能在给
allocator 自己的错误打标签。每条断言都锚定一个真实 glibc 版本边界：

  2.23 → 2.26/2.27   tcache 引入：free 去向 fastbin vs tcache
  2.27 → 2.29        tcache key + double-free 检测：重复释放被接受 vs abort
  2.27 → 2.29        top chunk PREV_INUSE 校验：接受 vs invalid_top_prev_inuse
  2.31 → 2.32        safe-linking：fd 原样 vs PROTECT_PTR 编码
  2.33 → 2.34        __malloc_hook/__free_hook 移除
  2.23 → 2.24        IO vtable 校验开启
"""
from __future__ import annotations

import unittest

from pwncraft.features.heapviz.allocators.profiles import (
    build_allocator_config,
    profile_list,
    resolve_allocator_profile,
)
from pwncraft.features.heapviz.analyzer import analyze_heap_source
from pwncraft.features.heapviz.engine import GlibcHeapEngine


def _replay(version: str, source: str):
    operations = analyze_heap_source(source).operations
    engine = GlibcHeapEngine(build_allocator_config("amd64", f"glibc {version}"))
    return engine.replay(operations)


class AllocatorGoldSuiteTests(unittest.TestCase):
    def test_tcache_boundary_2_23_vs_2_27_free_destination(self) -> None:
        source = "add(0x40, b'AA')\ndelete(0)\n"
        old = _replay("2.23", source)[-1]
        new = _replay("2.27", source)[-1]
        # glibc 2.26 才引入 tcache：2.23 的小 chunk 释放必须进 fastbin。
        self.assertEqual(old.chunks["A"].bin_location, "fastbin[0x50]")
        self.assertEqual(old.free_events[-1].destination_bin, "fastbin[0x50]")
        self.assertEqual(dict(old.bins.tcache), {})
        self.assertEqual(dict(old.bins.fastbins), {"0x50": ("A",)})
        self.assertEqual(new.chunks["A"].bin_location, "tcache[0x50]")
        self.assertEqual(new.free_events[-1].destination_bin, "tcache[0x50]")
        self.assertEqual(dict(new.bins.tcache), {"0x50": ("A",)})
        self.assertEqual(dict(new.bins.fastbins), {})

    def test_tcache_key_boundary_2_27_vs_2_29_double_free(self) -> None:
        source = "add(0x20, b'A')\ndelete(0)\ndelete(0)\n"
        old = _replay("2.27", source)[-1]
        new = _replay("2.29", source)[-1]
        # 2.27 没有 key/dup 检查：同一 chunk 可以在 tcache 里出现两次。
        self.assertIsNone(old.allocator_abort)
        self.assertEqual(dict(old.bins.tcache), {"0x30": ("A", "A")})
        # 2.29 引入 tcache_entry key：命中 key 后的重复释放直接 abort。
        self.assertIsNotNone(new.allocator_abort)
        self.assertEqual(new.allocator_abort.reason, "tcache_double_free_abort")
        self.assertEqual(new.allocator_abort.metadata["key_match"], "true")

    def test_safe_linking_boundary_2_31_vs_2_32_fd_encoding(self) -> None:
        source = "add(0x40, b'AA')\ndelete(0)\n"
        old = _replay("2.31", source)[-1]
        new = _replay("2.32", source)[-1]
        old_chunk = old.chunks.get("A") or next(iter(old.chunks.values()))
        new_chunk = new.chunks.get("A") or next(iter(new.chunks.values()))
        # 2.31 的 tcache fd 是裸指针；2.32 起默认 safe-linking（PROTECT_PTR 编码）。
        self.assertNotIn("PROTECT_PTR", old_chunk.fd)
        self.assertIn("PROTECT_PTR", new_chunk.fd)

    def test_top_prev_inuse_boundary_2_27_vs_2_29(self) -> None:
        source = "add(0x20, b'A')\nedit(0, b'X'*0x28 + p64(0x1000))\nadd(0x100, b'B')\n"
        old = _replay("2.27", source)[-1]
        new = _replay("2.29", source)[-1]
        # top size 校验（含 PREV_INUSE）是 2.29 引入的；2.27 接受这种破坏。
        self.assertFalse(old.aborted)
        self.assertIsNone(old.allocator_abort)
        self.assertTrue(new.aborted)
        self.assertEqual(new.allocator_abort.reason, "invalid_top_prev_inuse")

    def test_hook_and_iovtable_policy_flags_per_version(self) -> None:
        expected = {
            # (tcache, key_check, safe_linking, hooks, io_vtable, top_size)
            "2.23": (False, False, False, True, False, False),
            "2.24": (False, False, False, True, True, False),
            "2.27": (True, False, False, True, True, False),
            "2.29": (True, True, False, True, True, True),
            "2.31": (True, True, False, True, True, True),
            "2.32": (True, True, True, True, True, True),
            "2.34": (True, True, True, False, True, True),
            "2.39": (True, True, True, False, True, True),
        }
        for version, flags in expected.items():
            config = build_allocator_config("amd64", f"glibc {version}")
            actual = (
                config.tcache_enabled,
                config.tcache_key_check,
                config.safe_linking,
                config.hooks_available,
                config.io_vtable_validation,
                config.top_size_check,
            )
            self.assertEqual(actual, flags, f"glibc {version} 机制位与版本边界不符")

    def test_profile_identity_and_registry(self) -> None:
        # profile_id 是「版本 × 架构」的确定函数；revision 随快照保存。
        profile = resolve_allocator_profile({"version": "2.31", "arch": "amd64"})
        self.assertEqual(profile.profile_id, "glibc-2.31-amd64")
        self.assertTrue(profile.profile_revision)
        wire = profile.to_wire_dict()
        self.assertEqual(wire["requested_version"], "2.31")
        self.assertEqual(wire["effective_version"], "2.31")
        # 注册表覆盖 2.23 … 2.40 全部 18 个 minor 版本。
        versions = [item["version"] for item in profile_list()]
        self.assertEqual(versions, [f"2.{minor}" for minor in range(23, 41)])

    def test_gold_versions_replay_end_to_end(self) -> None:
        """六个 gold 版本各跑通一个含 alloc/free/edit/show 的完整场景。"""
        source = (
            "add(0x88, b'A')\nadd(0x88, b'B')\nshow(0)\n"
            "delete(0)\ndelete(1)\nadd(0x88, b'C')\n"
        )
        for version in ("2.23", "2.27", "2.31", "2.32", "2.35", "2.39"):
            snapshots = _replay(version, source)
            self.assertFalse(snapshots[-1].aborted, f"glibc {version} 回放不应终止")
            self.assertTrue(snapshots[-1].chunks, f"glibc {version} 回放必须产出 chunk")


if __name__ == "__main__":
    unittest.main()
