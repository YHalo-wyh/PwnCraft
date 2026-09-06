from __future__ import annotations

from dataclasses import dataclass

from pwncraft.features.heapviz.operations import HeapOperation, HeapOperationKind


@dataclass(frozen=True)
class HeapTemplate:
    template_id: str
    title: str
    category: str
    description: str
    operations: tuple[HeapOperation, ...]


def _op(step: int, kind: HeapOperationKind, **kwargs) -> HeapOperation:
    return HeapOperation(op_id=f"op_{step:03d}", kind=kind, **kwargs)


HEAP_TEMPLATES: tuple[HeapTemplate, ...] = (
    HeapTemplate(
        "basic_heap_layout",
        "chunk 地址与 header 布局",
        "入门演示",
        "只做三次真实 malloc，用于认识 request2size、chunk header、user data 和 top chunk 的位置；不包含任何利用假设。",
        (
            _op(1, HeapOperationKind.ALLOC, chunk="A", index="0", request_size="0x18", data="b'A'"),
            _op(2, HeapOperationKind.ALLOC, chunk="B", index="1", request_size="0x38", data="b'BBBBBBBB'"),
            _op(3, HeapOperationKind.ALLOC, chunk="C", index="2", request_size="0x68", data="b'CCCCCCCC'"),
        ),
    ),
    HeapTemplate(
        "basic_tcache_chain",
        "tcache 入链顺序",
        "入门演示",
        "三个同尺寸 chunk 按 A、B、C 顺序释放，最终严格状态应为 C -> B -> A，用于观察 next/fd 和 safe-linking。",
        (
            _op(1, HeapOperationKind.ALLOC, chunk="A", index="0", request_size="0x68", data="b'A'"),
            _op(2, HeapOperationKind.ALLOC, chunk="B", index="1", request_size="0x68", data="b'B'"),
            _op(3, HeapOperationKind.ALLOC, chunk="C", index="2", request_size="0x68", data="b'C'"),
            _op(4, HeapOperationKind.FREE, chunk="A", index="0"),
            _op(5, HeapOperationKind.FREE, chunk="B", index="1"),
            _op(6, HeapOperationKind.FREE, chunk="C", index="2"),
        ),
    ),
    HeapTemplate(
        "tcache_poison_safe_linking",
        "tcache poisoning / safe-linking",
        "高频打法",
        "UAF/double free 后改 freed chunk 的 fd，glibc 2.32+ 使用 pos >> 12 编码。",
        (
            _op(1, HeapOperationKind.ALLOC, chunk="A", index="0", request_size="0x68", data="b'A'"),
            _op(2, HeapOperationKind.ALLOC, chunk="B", index="1", request_size="0x68", data="b'B'"),
            _op(3, HeapOperationKind.FREE, chunk="A", index="0", note="A 进入 tcache"),
            _op(4, HeapOperationKind.SAFE_LINK_FD, chunk="A", index="0", target="target_addr", fd_storage="heap_base + 0x2a0", note="UAF: 按 fd 字段地址编码 next；target_addr 请换成当前 glibc 有效目标"),
            _op(5, HeapOperationKind.ALLOC, chunk="take_A", index="2", request_size="0x68", data="b'TAKE'"),
            _op(6, HeapOperationKind.MALLOC_TO_TARGET, chunk="hook_chunk", index="3", request_size="0x68", target="target_addr", data="target_payload"),
        ),
    ),
    HeapTemplate(
        "fastbin_to_unsorted_leak",
        "fastbin -> unsorted leak",
        "高频打法",
        "填满 tcache 后让 fastbin 通过 consolidate 进入 unsorted，观察 main_arena 泄漏点。",
        (
            _op(1, HeapOperationKind.ALLOC, chunk="F0", index="0", request_size="0x28", data="b'F0'"),
            _op(2, HeapOperationKind.ALLOC, chunk="F1", index="1", request_size="0x28", data="b'F1'"),
            _op(3, HeapOperationKind.ALLOC, chunk="guard", index="2", request_size="0x28", data="b'GUARD'", note="阻止 F0/F1 consolidate 后直接并回 top"),
            _op(4, HeapOperationKind.FILL_TCACHE, chunk="pad", request_size="0x28", count=7, meta={"start_index": "3"}, note="有 tcache 的版本先填满；旧版本这些 pad 会进入 fastbin"),
            _op(5, HeapOperationKind.FREE, chunk="F0", index="0"),
            _op(6, HeapOperationKind.FREE, chunk="F1", index="1"),
            _op(7, HeapOperationKind.CONSOLIDATE, request_size="0x500", note="通过大块申请或输入路径触发 malloc_consolidate"),
            _op(8, HeapOperationKind.LEAK_MAIN_ARENA, chunk="F1", index="1", value="main_arena_off"),
        ),
    ),
    HeapTemplate(
        "stdout_environ_stack",
        "stdout -> environ -> stack",
        "高频打法",
        "glibc 2.34+ 无 hooks 时，先做 stdout 泄漏口，再从 environ 转 stack。",
        (
            _op(1, HeapOperationKind.ALLOC, chunk="victim", index="0", request_size="0x68", data="b'A'"),
            _op(2, HeapOperationKind.FREE, chunk="victim", index="0"),
            _op(3, HeapOperationKind.POISON_FD, chunk="victim", index="0", target="libc.sym['_IO_2_1_stdout_'] - 0x43", fd_storage="heap_base + 0x2a0"),
            _op(4, HeapOperationKind.MALLOC_TO_TARGET, chunk="stdout_fake", index="1", request_size="0x68", target="libc.sym['_IO_2_1_stdout_'] - 0x43"),
            _op(5, HeapOperationKind.STDOUT_ENVIRON_LEAK, chunk="stdout_fake", index="1"),
        ),
    ),
    HeapTemplate(
        "setcontext_orw",
        "setcontext ORW 收尾",
        "高频打法",
        "一次函数指针/虚表/exit handler 劫持时，把 fake frame 和 ORW ROP 放到堆上。",
        (
            _op(1, HeapOperationKind.FAKE_CHUNK, chunk="fake_ucontext", request_size="0x300", target="heap_frame", note="伪造 ucontext 和 ROP 链"),
            _op(2, HeapOperationKind.SETCONTEXT_ROP, chunk="fake_ucontext", target="heap_frame", value="61"),
        ),
    ),
    HeapTemplate(
        "house_of_spirit",
        "House of Spirit",
        "House 系列",
        "在可控地址伪造 fake chunk，再诱导 free/malloc 返回这块可控内存。",
        (
            _op(1, HeapOperationKind.FAKE_CHUNK, chunk="spirit_fake", request_size="0x70", target="controlled_addr", note="在 stack/bss 伪造 fake chunk"),
            _op(2, HeapOperationKind.FREE, chunk="spirit_fake", note="把 fake chunk 释放进 tcache/fastbin"),
            _op(3, HeapOperationKind.MALLOC_TO_TARGET, chunk="spirit_return", request_size="0x60", target="controlled_addr + 0x10", data="b'SPIRIT'", note="malloc 返回 fake chunk 的 user pointer"),
        ),
    ),
    HeapTemplate(
        "house_of_einherjar",
        "House of Einherjar",
        "House 系列",
        "off-by-null/prev_size 伪造，向前合并到 fake chunk，制造重叠或目标分配。",
        (
            _op(1, HeapOperationKind.ALLOC, chunk="B", index="0", request_size="0xf8", data="b'B'"),
            _op(2, HeapOperationKind.ALLOC, chunk="C", index="1", request_size="0xf8", data="b'C'"),
            _op(3, HeapOperationKind.FAKE_CHUNK, chunk="fake_prev", request_size="distance_to_C", target="target_addr", meta={"fd": "fake_prev", "bk": "fake_prev"}),
            _op(4, HeapOperationKind.OVERFLOW_HEADER, chunk="B", index="0", field="C.prev_size / PREV_INUSE", value="distance_to_C / 0", note="off-by-null 清掉 PREV_INUSE 位"),
            _op(5, HeapOperationKind.FREE, chunk="C", index="1", note="释放 C 触发向后合并"),
            _op(6, HeapOperationKind.MALLOC_TO_TARGET, chunk="overlap", request_size="0xf8", target="target_addr"),
        ),
    ),
    HeapTemplate(
        "house_of_force",
        "House of Force",
        "House 系列",
        "覆盖 top chunk size，通过巨大 malloc 把 top 指针推到目标地址前。",
        (
            _op(1, HeapOperationKind.ALLOC, chunk="A", index="0", request_size="0x80", data="b'A'"),
            _op(2, HeapOperationKind.OVERFLOW_HEADER, chunk="A", index="0", field="top.size", value="-1", note="覆盖 top chunk size"),
            _op(3, HeapOperationKind.MALLOC_TO_TARGET, chunk="force_pad", request_size="target - top - header", target="target - 0x10", note="把 top 推到目标地址附近"),
            _op(4, HeapOperationKind.MALLOC_TO_TARGET, chunk="force_target", request_size="0x60", target="target", data="p64(system)"),
        ),
    ),
    HeapTemplate(
        "house_of_lore",
        "House of Lore",
        "House 系列",
        "smallbin bk 指向 fake chunk，申请同 size 时把分配引向可控地址。",
        (
            _op(1, HeapOperationKind.ALLOC, chunk="guard", index="0", request_size="0x100", data="b'G'"),
            _op(2, HeapOperationKind.ALLOC, chunk="victim", index="1", request_size="0x100", data="b'V'"),
            _op(3, HeapOperationKind.FREE, chunk="victim", index="1", note="victim 先进入 unsorted 再进入 smallbin"),
            _op(4, HeapOperationKind.FAKE_CHUNK, chunk="lore_fake", request_size="0x110", target="target_addr", meta={"fd": "victim", "bk": "target_addr"}),
            _op(5, HeapOperationKind.UNLINK_PREPARE, chunk="victim", index="1", target="target_addr", fd_storage="main_arena.smallbin"),
            _op(6, HeapOperationKind.MALLOC_TO_TARGET, chunk="lore_return", request_size="0x100", target="target_addr"),
        ),
    ),
    HeapTemplate(
        "house_of_orange",
        "House of Orange",
        "House 系列",
        "把 old top 放入 unsorted，配合 _IO_list_all / FILE 结构走 FSOP 思路。",
        (
            _op(1, HeapOperationKind.ALLOC, chunk="A", index="0", request_size="0x400", data="b'A'"),
            _op(2, HeapOperationKind.OVERFLOW_HEADER, chunk="A", index="0", field="top.size", value="0x1000", note="缩小 top chunk"),
            _op(3, HeapOperationKind.CONSOLIDATE, request_size="0x2000", note="old top 进入 unsorted"),
            _op(4, HeapOperationKind.FAKE_CHUNK, chunk="fake_file", request_size="0x100", target="old_top", data="伪造 _IO_FILE"),
            _op(5, HeapOperationKind.UNLINK_PREPARE, chunk="fake_file", target="_IO_list_all - 0x10", fd_storage="main_arena"),
        ),
    ),
    HeapTemplate(
        "house_of_rabbit",
        "House of Rabbit",
        "House 系列",
        "利用 malloc_consolidate 整理 fastbin，制造大块/重叠/后续 unsorted 泄漏。",
        (
            _op(1, HeapOperationKind.ALLOC, chunk="R0", index="0", request_size="0x28", data="b'R0'"),
            _op(2, HeapOperationKind.ALLOC, chunk="R1", index="1", request_size="0x28", data="b'R1'"),
            _op(3, HeapOperationKind.FILL_TCACHE, chunk="rb", request_size="0x28", count=7, meta={"start_index": "2"}),
            _op(4, HeapOperationKind.FREE, chunk="R0", index="0"),
            _op(5, HeapOperationKind.FREE, chunk="R1", index="1"),
            _op(6, HeapOperationKind.CONSOLIDATE, request_size="0x500"),
            _op(7, HeapOperationKind.MALLOC_TO_TARGET, chunk="rabbit_overlap", request_size="0x200", target="overlap_area"),
        ),
    ),
    HeapTemplate(
        "house_of_botcake",
        "House of Botcake",
        "House 系列",
        "tcache 满 + unsorted 重叠，构造可重复利用的 tcache dup/overlap 视角。",
        (
            _op(1, HeapOperationKind.ALLOC, chunk="prev", index="0", request_size="0x100", data="b'P'"),
            _op(2, HeapOperationKind.ALLOC, chunk="victim", index="1", request_size="0x100", data="b'V'"),
            _op(3, HeapOperationKind.FILL_TCACHE, chunk="bot", request_size="0x100", count=7, meta={"start_index": "2"}),
            _op(4, HeapOperationKind.FREE, chunk="victim", index="1"),
            _op(5, HeapOperationKind.FREE, chunk="prev", index="0", note="合并形成 overlap 候选块"),
            _op(6, HeapOperationKind.MALLOC_TO_TARGET, chunk="botcake_overlap", request_size="0x210", target="prev/victim overlap"),
        ),
    ),
    HeapTemplate(
        "house_of_rust",
        "House of Rust",
        "House 系列",
        "tcache stashing unlink + stdout 泄漏链的可视化骨架。",
        (
            _op(1, HeapOperationKind.FILL_TCACHE, chunk="rust", request_size="0x90", count=6),
            _op(2, HeapOperationKind.FAKE_CHUNK, chunk="rust_fake", request_size="0xa0", target="target_addr", meta={"bk": "target_addr - 0x10"}),
            _op(3, HeapOperationKind.UNLINK_PREPARE, chunk="rust_fake", target="target_addr - 0x10", fd_storage="smallbin_head"),
            _op(4, HeapOperationKind.MALLOC_TO_TARGET, chunk="rust_target", request_size="0x90", target="target_addr"),
            _op(5, HeapOperationKind.STDOUT_ENVIRON_LEAK, chunk="rust_stdout"),
        ),
    ),
    HeapTemplate(
        "house_of_apple2",
        "House of Apple2",
        "House 系列",
        "伪造 FILE / wide_data / vtable 相关结构，作为 FSOP 收尾模板入口。",
        (
            _op(1, HeapOperationKind.FAKE_CHUNK, chunk="fake_io_file", request_size="0x200", target="heap_file", data="伪造 FILE 字段"),
            _op(2, HeapOperationKind.FAKE_CHUNK, chunk="fake_wide_data", request_size="0x100", target="heap_wide_data", data="伪造 wide_data"),
            _op(3, HeapOperationKind.MALLOC_TO_TARGET, chunk="io_target", request_size="0x200", target="_IO_list_all / stderr chain"),
            _op(4, HeapOperationKind.SETCONTEXT_ROP, chunk="apple2_frame", target="heap_frame", value="61"),
        ),
    ),
    HeapTemplate(
        "basic_overflow_paint",
        "A 向下覆盖 B：逐 +8 覆盖（PhysicalGrid）",
        "入门演示",
        "两次 malloc 后 A 逐次多写 8 字节：第一次盖 B.prev_size，第二次盖 B.size，第三次盖 user qword0，第四次盖 user qword1。"
        "视觉行结构始终不变，覆盖 = CoverageSpan ∩ Cell 的格内着色。",
        (
            _op(1, HeapOperationKind.ALLOC, chunk="A", index="0", request_size="0x18", data="b'A'"),
            _op(2, HeapOperationKind.ALLOC, chunk="B", index="1", request_size="0x18", data="b'B'"),
            _op(3, HeapOperationKind.EDIT, chunk="A", index="0", data="b'A' * 24", note="第一次 +8：覆盖 B.prev_size"),
            _op(4, HeapOperationKind.EDIT, chunk="A", index="0", data="b'A' * 32", note="第二次 +8：覆盖 B.size"),
            _op(5, HeapOperationKind.EDIT, chunk="A", index="0", data="b'A' * 40", note="第三次 +8：覆盖 B.user qword0"),
            _op(6, HeapOperationKind.EDIT, chunk="A", index="0", data="b'A' * 48", note="第四次 +8：覆盖 B.user qword1"),
        ),
    ),
)
