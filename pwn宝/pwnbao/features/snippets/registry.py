from __future__ import annotations

from typing import Iterable, Mapping

from .model import SnippetDefinition, SnippetParameter


P = SnippetParameter


def _snippet(snippet_id: str, title: str, category: str, body: str, description: str, **kwargs) -> SnippetDefinition:
    return SnippetDefinition(snippet_id, title, category, description, body, **kwargs)


def default_heap_snippets() -> tuple[SnippetDefinition, ...]:
    return (
        _snippet(
            "tcache_fill", "Tcache fill", "Tcache",
            "# tcache fill\n" + "".join(f"{{alloc}}(0x80, b'T{i}')\n" for i in range(7))
            + "".join(f"{{free}}({i})\n" for i in range(7)),
            "填充一个 tcache size class。", operations=("alloc", "free"),
        ),
        _snippet("tcache_drain", "Tcache drain", "Tcache", "# tcache drain\n" + "{alloc}(0x80, b'D')\n" * 7, "从同一 size class 逐项申请。", operations=("alloc",)),
        _snippet("safe_link", "Safe-Linking encode", "Tcache", "# 必须使用实际 next 字段地址\ntarget = {target}\nfield_addr = {field_addr}\nencoded = target ^ (field_addr >> 12)\n{edit}({index}, p64(encoded))\n", "只生成编码和值写入，不特判 allocator。", parameters=(P("target", "0"), P("field_addr", "0"), P("index", "0")), minimum_glibc=(2, 32), operations=("edit",)),
        _snippet("tcache_dup", "Tcache dup / Botcake preparation", "Tcache", "# 根据题目真实 helper 补齐中间申请\n{alloc}(0x80, b'A')\n{alloc}(0x80, b'B')\n{free}(0)\n{free}(1)\n", "仅准备双重引用所需布局。", operations=("alloc", "free")),
        _snippet(
            "fastbin_fill", "Fastbin fill", "Fastbin",
            "# fastbin fill\n" + "".join(f"{{alloc}}(0x60, b'F{i}')\n" for i in range(8))
            + "".join(f"{{free}}({i})\n" for i in range(8)),
            "准备 fastbin/tcache 边界。", operations=("alloc", "free"),
        ),
        _snippet("fastbin_dup", "Fastbin dup preparation", "Fastbin", "{alloc}(0x60, b'A')\n{alloc}(0x60, b'B')\n{free}(0)\n{free}(1)\n# 仅在真实流程允许时再次释放 A\n", "不绕过 double-free 检查。", operations=("alloc", "free")),
        _snippet("consolidate", "Consolidate trigger", "Fastbin", "# 大申请触发路径；以目标 glibc/runtime 为准\n{alloc}(0x500, b'C')\n", "生成触发调用，不直接合并模型。", operations=("alloc",)),
        _snippet("unsorted", "Unsorted preparation", "Unsorted", "{alloc}(0x420, b'U')\n{alloc}(0x20, b'guard')\n{free}(0)\n{show}(0)\n", "准备并观察大 chunk。", operations=("alloc", "free", "show")),
        _snippet("smallbin", "Smallbin preparation", "Small/Large Bin", "{alloc}(0x100, b'S')\n{alloc}(0x20, b'guard')\n{free}(0)\n{alloc}(0x500, b'trigger')\n", "仅生成真实调用。", operations=("alloc", "free")),
        _snippet("largebin", "Largebin metadata layout", "Small/Large Bin", "# fd/bk/fd_nextsize/bk_nextsize skeleton\npayload = flat({fd}, {bk}, {fd_nextsize}, {bk_nextsize})\n{edit}({index}, payload)\n", "只准备四个字段，不自动写 target。", parameters=(P("fd", "0"), P("bk", "0"), P("fd_nextsize", "0"), P("bk_nextsize", "0"), P("index", "0")), operations=("edit",)),
        _snippet("off_by_one", "Off-by-one metadata write", "Overlap / Consolidation", "# 必须通过真实 edit/copy/read 路径形成跨界写\npayload = b'A' * {length} + p8({byte})\n{edit}({index}, payload)\n", "跨界范围由 PhysicalMemory 写事件判定。", parameters=(P("length", "0x18"), P("byte", "0"), P("index", "0")), operations=("edit",)),
        _snippet("einherjar", "House of Einherjar layout", "Overlap / Consolidation", "# fake prev_size/size skeleton\npayload = flat({prev_size}, {size})\n{edit}({index}, payload)\n", "只准备 metadata，consolidation 由 allocator 验证。", parameters=(P("prev_size", "0"), P("size", "0"), P("index", "0")), operations=("edit",)),
        _snippet("fake_bss", "Fake chunk on BSS", "Fake Chunk", "fake_addr = {address}\nfake = flat(0, {size})\n# 用题目真实写入 primitive 把 fake 写到 BSS\n", "结构草稿，不宣称 malloc 会返回。", parameters=(P("address", "0"), P("size", "0x71"))),
        _snippet("fake_stack", "Fake chunk on stack", "Fake Chunk", "fake_addr = {address}\nfake = flat(0, {size})\n", "结构草稿，不宣称可用。", parameters=(P("address", "0"), P("size", "0x71"))),
        _snippet("top_inspect", "Top chunk inspection", "Top", "# 只观察当前 top 邻接状态\n{show}({index})\n", "不自动推断 House。", parameters=(P("index", "0"),), operations=("show",)),
        _snippet("house_force", "House of Force (historical)", "Top", "# historical skeleton: top size write\n{edit}({index}, p64({top_size}))\n", "现代 glibc 有额外 top-size 检查。", parameters=(P("index", "0"), P("top_size", "0xffffffffffffffff")), maximum_glibc=(2, 28), operations=("edit",)),
    )


def default_iofile_snippets() -> tuple[SnippetDefinition, ...]:
    return (
        _snippet("stdout_prepare", "stdout field preparation", "IO FILE", "# version-aware offsets are shown in IO FILE inspector\nfile_addr = {address}\npayload = flat({flags}, {read_ptr}, {read_end})\n", "只生成字段草稿。", parameters=(P("address", "0"), P("flags", "0xfbad1800"), P("read_ptr", "0"), P("read_end", "0")), structure_type="iofile"),
        _snippet("file_writer", "_IO_FILE field writer", "IO FILE", "file_addr = {address}\nfield_offset = {offset}\nvalue = {value}\n# 使用题目真实任意写 helper\n", "按选中版本字段 offset 写值。", parameters=(P("address", "0"), P("offset", "0"), P("value", "0")), structure_type="iofile"),
        _snippet("wide_skeleton", "wide_data / wide_vtable skeleton", "IO FILE", "wide_data = {wide_data}\nwide_vtable = {wide_vtable}\n# House of Apple 2 style layout skeleton；真实控制流由 runtime 验证\n", "版本敏感的 wide 结构草稿。", parameters=(P("wide_data", "0"), P("wide_vtable", "0")), minimum_glibc=(2, 24), structure_type="iofile"),
        _snippet("io_list_all", "_IO_list_all (historical)", "IO FILE", "# historical _IO_list_all linkage skeleton\nchain = {chain}\nvtable = {vtable}\n", "现代 glibc vtable 检查已变化。", parameters=(P("chain", "0"), P("vtable", "0")), maximum_glibc=(2, 23), structure_type="iofile"),
    )


class SnippetRegistry:
    def __init__(self, snippets: Iterable[SnippetDefinition] = ()):
        self._snippets = {item.snippet_id: item for item in snippets}

    @property
    def snippets(self) -> tuple[SnippetDefinition, ...]:
        return tuple(self._snippets.values())

    def register(self, snippet: SnippetDefinition) -> None:
        self._snippets[snippet.snippet_id] = snippet

    def search(self, query: str = "", category: str = "") -> tuple[SnippetDefinition, ...]:
        query = query.casefold().strip()
        return tuple(
            item for item in self._snippets.values()
            if (not category or item.category == category)
            and (not query or query in f"{item.title} {item.category} {item.description}".casefold())
        )

    def render(self, snippet_id: str, values: Mapping[str, str], helper_names: Mapping[str, str] | None = None) -> str:
        return self._snippets[snippet_id].render(values, helper_names)
