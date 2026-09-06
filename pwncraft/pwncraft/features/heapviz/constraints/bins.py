from __future__ import annotations

from pwncraft.features.heapviz.constraints.result import ConstraintResult


def validate_doubly_linked_node(victim: int, fd_bk: int | None, bk_fd: int | None) -> ConstraintResult:
    if fd_bk is None or bk_fd is None:
        return ConstraintResult.unknown("bin_neighbors_unknown", "无法静态读取 fd->bk 或 bk->fd。", "fd/bk")
    if fd_bk != victim or bk_fd != victim:
        return ConstraintResult.corruption(
            "bin_reciprocity",
            "当前 fd/bk 字节可表示，但双向链表互指关系已损坏。",
            "fd/bk",
        )
    return ConstraintResult.valid(victim=victim)
