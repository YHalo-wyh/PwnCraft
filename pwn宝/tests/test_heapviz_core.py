from __future__ import annotations

from dataclasses import replace
import unittest

from pwnbao.features.conversion.converters import bytes_report, int_report
from pwnbao.features.blocks import BlockCatalog, SnippetRenderer
from pwnbao.features.fmtstr import i386_hn_payload_template, low_high_template, manual_hn_got_overwrite_template
from pwnbao.features.heapviz.allocators.profiles import build_allocator_config
from pwnbao.features.heapviz.api_profile import infer_api_profile_from_source
from pwnbao.features.heapviz.codegen import generate_pwntools
from pwnbao.features.heapviz.compatibility import target_compatibility, template_compatibility
from pwnbao.features.heapviz.expressions import collect_integer_assignments, parse_int_expr
from pwnbao.features.heapviz.pwndbg import diff_snapshot, parse_pwndbg_snapshot
from pwnbao.features.heapviz.engine import GlibcHeapEngine
from pwnbao.features.heapviz.operations import HeapOperation, HeapOperationKind
from pwnbao.features.heapviz.templates import HEAP_TEMPLATES


class HeapVizCoreTests(unittest.TestCase):
    def test_unknown_size_never_fabricates_same_address_or_unsorted_links(self) -> None:
        config = build_allocator_config("amd64", "glibc 2.35")
        operations = [
            HeapOperation("a", HeapOperationKind.ALLOC, "A", "1", "unknown", "b'A'"),
            HeapOperation("b", HeapOperationKind.ALLOC, "B", "2", "unknown", "b'B'"),
            HeapOperation("free-a", HeapOperationKind.FREE, "A", "1"),
        ]
        final = GlibcHeapEngine(config).replay(operations)[-1]
        self.assertNotEqual(final.chunks["A"].address, final.chunks["B"].address)
        self.assertIn("?<A:chunk>", final.chunks["A"].address)
        self.assertEqual(final.chunks["A"].bin_location, "unknown")
        self.assertEqual((final.chunks["A"].fd, final.chunks["A"].bk), ("", ""))
        self.assertEqual(final.bins.unsorted, ())
        self.assertIn("unknown_free_bin", [item.code for item in final.warnings])

    def test_custom_io_name_is_a_real_code_block_placeholder(self) -> None:
        block = BlockCatalog.load_default().by_id["fmt_s_read_payload"]
        rendered = SnippetRenderer().render(block, {
            "TARGET_ADDR": "elf.got['puts']",
            "FMT_OFFSET": "7",
            "IO_NAME": "tube",
            "PROMPT": "b'> '",
        })
        self.assertIn("tube.sendlineafter", rendered)
        self.assertNotIn("{{IO_NAME}}", rendered)

    def test_ret2syscall_block_is_available_and_renders_all_gadgets(self) -> None:
        block = BlockCatalog.load_default().by_id["ret2syscall"]
        values = {name: f"value_{name.lower()}" for name in block.placeholders}
        rendered = SnippetRenderer().render(block, values)
        self.assertIn("p64(pop_rax) + p64(59)", rendered)
        self.assertIn("p64(syscall)", rendered)
        self.assertNotIn("{{", rendered)

    def test_every_operation_generates_compilable_python(self) -> None:
        for kind in HeapOperationKind:
            operation = HeapOperation(
                op_id="op_001",
                kind=kind,
                chunk="A",
                index="0",
                request_size="0x80",
                data="b'A'",
                target="target",
                fd_storage="heap_base + 0x2a0",
                value="0x90",
            )
            code = generate_pwntools([operation])
            self.assertNotIn("\x00", code, kind.value)
            compile(code, f"<{kind.value}>", "exec")

    def test_every_template_replays_and_compiles_for_supported_word_sizes(self) -> None:
        for bits, arch in ((32, "i386"), (64, "amd64")):
            config = build_allocator_config(arch, "glibc 2.35")
            for template in HEAP_TEMPLATES:
                snapshots = GlibcHeapEngine(config).replay(template.operations)
                self.assertEqual(len(snapshots), len(template.operations) + 1)
                compile(generate_pwntools(list(template.operations), bits=bits), template.template_id, "exec")

    def test_safe_linking_template_encodes_fd(self) -> None:
        template = next(item for item in HEAP_TEMPLATES if item.template_id == "tcache_poison_safe_linking")
        code = generate_pwntools(list(template.operations), bits=64)
        self.assertIn("target ^ (fd_storage >> 12)", code)
        self.assertIn("edit(0, p64(encoded_fd))", code)

    def test_beginner_templates_reach_real_allocator_states(self) -> None:
        config = build_allocator_config("amd64", "glibc 2.35")
        layout = next(item for item in HEAP_TEMPLATES if item.template_id == "basic_heap_layout")
        layout_snapshot = GlibcHeapEngine(config).replay(layout.operations)[-1]
        self.assertEqual(list(layout_snapshot.chunks), ["A", "B", "C"])
        self.assertFalse(layout_snapshot.bins.tcache)
        self.assertFalse(layout_snapshot.warnings)

        chain = next(item for item in HEAP_TEMPLATES if item.template_id == "basic_tcache_chain")
        chain_snapshot = GlibcHeapEngine(config).replay(chain.operations)[-1]
        self.assertEqual(chain_snapshot.bins.tcache["0x70"], ("C", "B", "A"))
        self.assertFalse(chain_snapshot.aborted)

    def test_api_profile_infers_custom_helper_signatures(self) -> None:
        source = """
def create(idx, size, content):
    pass

def remove(idx):
    pass

def update(idx, content):
    pass

def leak(idx):
    return b''
"""
        profile, found = infer_api_profile_from_source(source)
        self.assertEqual(found, {"alloc": "create", "free": "remove", "edit": "update", "show": "leak"})
        code = generate_pwntools(
            [
                HeapOperation("op_001", HeapOperationKind.ALLOC, chunk="A", index="3", request_size="0x68", data="payload"),
                HeapOperation("op_002", HeapOperationKind.EDIT, chunk="A", index="3", data="p64(system)"),
                HeapOperation("op_003", HeapOperationKind.SHOW, chunk="A", index="3"),
            ],
            api=profile,
        )
        self.assertIn("create(3, 0x68, payload)", code)
        self.assertIn("update(3, p64(system))", code)
        self.assertIn("leak = leak(3)", code)

    def test_api_profile_recognizes_common_ctf_helper_aliases(self) -> None:
        source = """
def buy(slot, length, message):
    pass

def release(slot):
    pass

def rename(slot, msg):
    pass

def dump(slot):
    pass
"""
        profile, found = infer_api_profile_from_source(source)
        self.assertEqual(found, {"alloc": "buy", "free": "release", "edit": "rename", "show": "dump"})
        code = generate_pwntools(
            [
                HeapOperation("op_001", HeapOperationKind.ALLOC, chunk="A", index="3", request_size="0x88", data="payload"),
                HeapOperation("op_002", HeapOperationKind.FREE, chunk="A", index="3"),
                HeapOperation("op_003", HeapOperationKind.EDIT, chunk="A", index="3", data="p64(system)"),
                HeapOperation("op_004", HeapOperationKind.SHOW, chunk="A", index="3"),
            ],
            api=profile,
        )
        self.assertIn("buy(3, 0x88, payload)", code)
        self.assertIn("release(3)", code)
        self.assertIn("rename(3, p64(system))", code)
        self.assertIn("leak = dump(3)", code)

    def test_api_profile_infers_copy_helper_and_codegen(self) -> None:
        source = """
def copy_chunk(src, dst, length):
    pass

def move(dst, src, n):
    pass
"""
        profile, found = infer_api_profile_from_source(source)
        self.assertEqual(found, {"copy": "copy_chunk"})
        self.assertEqual(profile.copy_template, "copy_chunk({src}, {dst}, {length})")
        code = generate_pwntools(
            [
                HeapOperation(
                    "op_001",
                    HeapOperationKind.COPY,
                    chunk="B",
                    index="2",
                    request_size="0x18",
                    target="1",
                    meta={"src": "1", "dst": "2", "length": "0x18"},
                )
            ],
            api=profile,
        )
        self.assertIn("copy_chunk(1, 2, 0x18)", code)

    def test_category_preference_allows_custom_copy_name_order(self) -> None:
        profile, found = infer_api_profile_from_source("def move(dst, src, n):\n    pass\n", preferred_kind="copy")
        self.assertEqual(found, {"copy": "move"})
        self.assertEqual(profile.copy_template, "move({dst}, {src}, {length})")
        code = generate_pwntools(
            [
                HeapOperation(
                    "op_001",
                    HeapOperationKind.COPY,
                    chunk="B",
                    index="2",
                    request_size="0x20",
                    target="1",
                    meta={"src": "1", "dst": "2", "length": "0x20"},
                )
            ],
            api=profile,
        )
        self.assertIn("move(2, 1, 0x20)", code)

    def test_alloc_codegen_preserves_explicit_data_and_keeps_missing_data_empty(self) -> None:
        code = generate_pwntools(
            [
                HeapOperation("op_001", HeapOperationKind.ALLOC, chunk="A", index="0", request_size="0x68", data="b'A'"),
                HeapOperation("op_002", HeapOperationKind.ALLOC, chunk="B", index="1", request_size="0x68", data="b'A'"),
                HeapOperation("op_003", HeapOperationKind.ALLOC, chunk="chunkc", index="2", request_size="0x68", data=""),
            ]
        )
        self.assertEqual(code.splitlines(), [
            "add(0x68, b'A')",
            "add(0x68, b'A')",
            "add(0x68, b'')",
        ])

    def test_codegen_never_invents_payload_for_allocator_macros(self) -> None:
        code = generate_pwntools([
            HeapOperation("fill", HeapOperationKind.FILL_TCACHE, chunk="pad", request_size="0x20", count=2),
            HeapOperation("drain", HeapOperationKind.DRAIN_TCACHE, chunk="take", request_size="0x20", count=2),
            HeapOperation("target", HeapOperationKind.MALLOC_TO_TARGET, chunk="hit", request_size="0x60", target="target"),
        ])
        self.assertEqual(code.count("b''"), 5)
        self.assertNotIn("b'TARGET'", code)
        self.assertNotIn("b'DRAIN'", code)
        self.assertNotIn("ljust(8", code)

    def test_request2size_matches_common_glibc_sizes(self) -> None:
        amd64 = GlibcHeapEngine(build_allocator_config("amd64", "glibc 2.35"))
        i386 = GlibcHeapEngine(build_allocator_config("i386", "glibc 2.35"))
        self.assertEqual(amd64.request2size("0x18"), 0x20)
        self.assertEqual(amd64.request2size("0x68"), 0x70)
        self.assertEqual(amd64.request2size("0x100"), 0x110)
        self.assertEqual(i386.request2size("0x18"), 0x20)
        self.assertEqual(i386.request2size("0x68"), 0x70)

    def test_payload_truth_is_source_derived_and_missing_bytes_stay_unknown(self) -> None:
        config = build_allocator_config("amd64", "glibc 2.35")
        operations = [
            HeapOperation("empty", HeapOperationKind.ALLOC, chunk="empty", index="0", request_size="0x30"),
            HeapOperation("zero-length", HeapOperationKind.ALLOC, chunk="zero", index="1", request_size="0x30", data="b''"),
            HeapOperation("known", HeapOperationKind.ALLOC, chunk="known", index="2", request_size="0x30", data="b'BETA'"),
            HeapOperation("symbolic", HeapOperationKind.ALLOC, chunk="symbolic", index="3", request_size="0x30", data="p64(target)"),
        ]
        snapshot = GlibcHeapEngine(config).replay(operations)[-1]
        for chunk_id in ("empty", "zero"):
            user_regions = snapshot.chunks[chunk_id].memory_regions[2:]
            self.assertTrue(user_regions)
            self.assertTrue(all(region.state == "unknown" for region in user_regions))
            self.assertTrue(all(region.provenance == "unknown" for region in user_regions))
        known = snapshot.chunks["known"].memory_regions[2]
        self.assertEqual((known.value, known.state, known.provenance), ("b'BETA'", "known", "derived"))
        symbolic = snapshot.chunks["symbolic"].memory_regions[2]
        self.assertEqual((symbolic.value, symbolic.provenance), ("p64(target)", "inferred"))

    def test_demo_allocator_operations_do_not_synthesize_chunk_payload(self) -> None:
        config = build_allocator_config("amd64", "glibc 2.35")
        fill = HeapOperation("fill", HeapOperationKind.FILL_TCACHE, chunk="pad", request_size="0x20", count=2)
        filled = GlibcHeapEngine(config).replay([fill])[-1]
        self.assertTrue(filled.chunks)
        self.assertTrue(all(not chunk.data for chunk in filled.chunks.values()))

        drain = HeapOperation("drain", HeapOperationKind.DRAIN_TCACHE, chunk="take", request_size="0x20", count=2)
        drained = GlibcHeapEngine(config).replay([fill, drain])[-1]
        self.assertTrue(all(not chunk.data for chunk in drained.chunks.values()))

        plan_config = build_allocator_config("amd64", "glibc 2.35", simulation_mode="plan")
        assumed = GlibcHeapEngine(plan_config).replay([
            HeapOperation("stdout", HeapOperationKind.STDOUT_ENVIRON_LEAK, chunk="fake_stdout"),
            HeapOperation("ctx", HeapOperationKind.SETCONTEXT_ROP, chunk="fake_ctx"),
        ])[-1]
        self.assertEqual(assumed.chunks["fake_stdout"].data, "")
        self.assertEqual(assumed.chunks["fake_ctx"].data, "")

    def test_bin_membership_is_exclusive_and_malloc_reuse_removes_entry(self) -> None:
        config = build_allocator_config("amd64", "glibc 2.35")
        operations = [
            HeapOperation("op_001", HeapOperationKind.ALLOC, chunk="A", index="0", request_size="0x68", data="b'A'"),
            HeapOperation("op_002", HeapOperationKind.FREE, chunk="A", index="0"),
            HeapOperation("op_003", HeapOperationKind.ALLOC, chunk="B", index="1", request_size="0x68", data="b'B'"),
        ]
        snapshots = GlibcHeapEngine(config).replay(operations)
        self.assertEqual(snapshots[2].bins.tcache["0x70"], ("A",))
        self.assertNotIn("0x70", snapshots[3].bins.tcache)
        self.assertEqual(snapshots[3].chunks["A"].lifecycle, "stale")
        self.assertEqual(snapshots[3].chunks["B"].address, snapshots[3].chunks["A"].address)

    def test_copy_chunk_overflow_marks_following_physical_chunks(self) -> None:
        config = build_allocator_config("amd64", "glibc 2.35")
        operations = [
            HeapOperation("op_001", HeapOperationKind.ALLOC, chunk="A", index="0", request_size="0x20", data="b'A'"),
            HeapOperation("op_002", HeapOperationKind.ALLOC, chunk="B", index="1", request_size="0x20", data="b'B'"),
            HeapOperation("op_003", HeapOperationKind.ALLOC, chunk="C", index="2", request_size="0x20", data="b'C'"),
            HeapOperation(
                "op_004",
                HeapOperationKind.COPY,
                chunk="A",
                index="0",
                request_size="0x80",
                target="B",
                meta={"src": "1", "dst": "0", "src_chunk": "B", "dst_chunk": "A", "length": "0x80"},
            ),
        ]
        snapshot = GlibcHeapEngine(config).replay(operations)[-1]
        self.assertEqual(snapshot.chunks["A"].role, "copy-overflow")
        self.assertEqual(snapshot.chunks["B"].role, "copy-overlapped")
        self.assertEqual(snapshot.chunks["C"].role, "copy-overlapped")
        self.assertEqual(snapshot.warnings[-1].code, "copy_overlap")
        self.assertEqual(snapshot.warnings[-1].related_chunks, ("A", "B", "C"))

    def test_custom_heap_base_calculates_absolute_addresses(self) -> None:
        config = replace(build_allocator_config("amd64", "glibc 2.35"), heap_base="0x555555559000")
        snapshot = GlibcHeapEngine(config).replay([
            HeapOperation("op_001", HeapOperationKind.ALLOC, chunk="A", index="0", request_size="0x100", data="0")
        ])[-1]
        chunk = snapshot.chunks["A"]
        self.assertEqual(snapshot.heap_base, "0x555555559000")
        self.assertEqual(chunk.address, "0x555555559290")
        self.assertEqual(chunk.heap_offset, "0x290")
        self.assertEqual(chunk.fields[2].address, "0x5555555592a0")

    def test_chunk_header_metadata_tracks_previous_physical_state(self) -> None:
        config = build_allocator_config("amd64", "glibc 2.35")
        operations = [
            HeapOperation("op_001", HeapOperationKind.ALLOC, chunk="A", index="0", request_size="0x68", data="b'A'"),
            HeapOperation("op_002", HeapOperationKind.ALLOC, chunk="B", index="1", request_size="0x68", data="b'B'"),
            HeapOperation("op_003", HeapOperationKind.FREE, chunk="A", index="0"),
        ]
        snapshots = GlibcHeapEngine(config).replay(operations)
        allocated_a = snapshots[1].chunks["A"]
        allocated_b = snapshots[2].chunks["B"]
        after_free_b = snapshots[3].chunks["B"]
        freed_a = snapshots[3].chunks["A"]

        self.assertEqual(allocated_a.fields[0].value, "0x0")
        self.assertIn("0x71", allocated_a.fields[1].value)
        self.assertIn("PREV_INUSE=1", allocated_a.fields[1].value)
        self.assertEqual(allocated_a.fields[2].value, "b'A'")
        self.assertEqual(allocated_b.fields[0].value, "0x70")
        # glibc 2.35 tcache insertion deliberately does not consolidate and
        # does not clear the next physical chunk's PREV_INUSE bit.
        self.assertEqual(after_free_b.fields[0].value, "0x70")
        self.assertIn("PREV_INUSE=1", after_free_b.fields[1].value)
        self.assertEqual(freed_a.fields[2].value, "PROTECT_PTR(heap_base+0x2a0, NULL)")
        self.assertEqual(freed_a.fields[2].name, "next")
        self.assertEqual(freed_a.fields[3].name, "key")
        self.assertEqual(freed_a.fields[3].value, "tcache_key")

    def test_show_and_unpack_shift_keep_a_strict_value_flow(self) -> None:
        config = replace(build_allocator_config("amd64", "glibc 2.35"), heap_base="0x555555559000")
        operations = [
            HeapOperation("op_001", HeapOperationKind.ALLOC, chunk="A", index="7", request_size="0x100"),
            HeapOperation("op_002", HeapOperationKind.ALLOC, chunk="guard", index="8", request_size="0x20"),
            HeapOperation("op_003", HeapOperationKind.FREE, chunk="A", index="7"),
            HeapOperation(
                "op_004",
                HeapOperationKind.SHOW,
                chunk="A",
                index="7",
                meta={"result_var": "data", "expression": "show(7)"},
            ),
            HeapOperation(
                "op_005",
                HeapOperationKind.DERIVE_VALUE,
                chunk="heap",
                value="u64(data[:5].ljust(8,b'\\x00'))<<12",
                meta={
                    "result_var": "heap",
                    "expression": "u64(data[:5].ljust(8,b'\\x00'))<<12",
                    "dependencies": "data",
                },
            ),
        ]
        snapshot = GlibcHeapEngine(config).replay(operations)[-1]
        self.assertEqual([item.name for item in snapshot.observations], ["data", "heap"])
        self.assertEqual(snapshot.observations[0].integer_value, "0x555555559")
        self.assertIn("p64(0x555555559)", snapshot.observations[0].value)
        self.assertEqual(snapshot.observations[1].value, "0x555555559000")
        self.assertEqual(snapshot.observations[1].dependencies, ("data",))
        code = generate_pwntools(operations)
        self.assertIn("data = show(7)", code)
        self.assertIn("heap = u64(data[:5].ljust(8,b'\\x00'))<<12", code)

    def test_api_profile_infers_menu_prompt_order_from_helper_body(self) -> None:
        source = """
def add(size, idx, data):
    sla(b'> ', b'1')
    sla(b'Size: ', str(size).encode())
    sla(b'Index: ', str(idx).encode())
    sa(b'Content: ', data)

def wipe(no):
    sla(b'> ', b'3')
    sla(b'Index: ', str(no).encode())

def change(no, payload):
    sla(b'> ', b'2')
    sla(b'Index: ', str(no).encode())
    sa(b'Data: ', payload)

def leak(no):
    sla(b'> ', b'4')
    sla(b'Index: ', str(no).encode())
"""
        profile, found = infer_api_profile_from_source(source)
        self.assertEqual(found, {"alloc": "add", "free": "wipe", "edit": "change", "show": "leak"})
        code = generate_pwntools(
            [
                HeapOperation("op_001", HeapOperationKind.ALLOC, chunk="A", index="2", request_size="0x68", data="b'A'"),
                HeapOperation("op_002", HeapOperationKind.FREE, chunk="A", index="2"),
                HeapOperation("op_003", HeapOperationKind.EDIT, chunk="A", index="2", data="p64(fake)"),
                HeapOperation("op_004", HeapOperationKind.SHOW, chunk="A", index="2"),
            ],
            api=profile,
        )
        self.assertIn("add(0x68, 2, b'A')", code)
        self.assertIn("wipe(2)", code)
        self.assertIn("change(2, p64(fake))", code)
        self.assertIn("leak = leak(2)", code)

    def test_api_profile_rejects_incidental_heap_words_and_recv_parsers(self) -> None:
        source = """
def free_size_for_count(count):
    return count * 0x210

def build_prompt(path):
    return 'size=' + path

def read_payload(io):
    return io.recvn(8)
"""
        _profile, found = infer_api_profile_from_source(source)
        self.assertEqual(found, {})

    def test_free_codegen_respects_index_and_custom_free_helper(self) -> None:
        operation = HeapOperation("op_001", HeapOperationKind.FREE, chunk="A", index="2")
        self.assertIn("delete(2)", generate_pwntools([operation]))

        profile, found = infer_api_profile_from_source("def free(idx):\n    pass\n")
        self.assertEqual(found, {"free": "free"})
        self.assertIn("free(2)", generate_pwntools([operation], api=profile))

    def test_fake_chunk_operation_preserves_exp_header_words(self) -> None:
        config = build_allocator_config("amd64", "glibc 2.35")
        operation = HeapOperation(
            "op_001",
            HeapOperationKind.FAKE_CHUNK,
            chunk="fake_chunk",
            request_size="0x70",
            target="fake_chunk",
            fd_storage="fake_chunk",
            data="fake_chunk = p64(0) + p64(0x70) + p64(fake_chunk) + p64(controlled_addr)",
            meta={
                "prev_size": "0",
                "size": "0x70",
                "fd": "fake_chunk",
                "bk": "controlled_addr",
                "address": "fake_chunk",
            },
        )
        chunk = GlibcHeapEngine(config).replay([operation])[-1].chunks["fake_chunk"]
        self.assertEqual([field.value for field in chunk.fields[:4]], ["0", "0x70", "fake_chunk", "controlled_addr"])

    def test_template_fastbin_to_unsorted_reaches_unsorted_not_tcache(self) -> None:
        template = next(item for item in HEAP_TEMPLATES if item.template_id == "fastbin_to_unsorted_leak")
        snapshot = GlibcHeapEngine(build_allocator_config("amd64", "glibc 2.35")).replay(template.operations)[-1]
        self.assertIn("F0", snapshot.bins.unsorted)
        self.assertNotIn("F1", snapshot.bins.unsorted)
        self.assertNotIn("F0", snapshot.bins.tcache.get("0x30", ()))
        self.assertEqual(snapshot.chunks["F0"].bin_location, "unsorted")
        self.assertEqual(snapshot.chunks["F0"].chunk_size, "0x60")
        self.assertEqual(snapshot.chunks["F1"].bin_location, "merged into F0")
        self.assertEqual(snapshot.chunks["F0"].physical_id, snapshot.chunks["F1"].physical_id)

    def test_unpack_conversion_truncates_to_word_size(self) -> None:
        result = next(item for item in bytes_report("b'123456789'", bits=64) if item.title.startswith("u64"))
        self.assertIn("[:8].ljust(8", result.value)

    def test_conversion_low_high_and_halfword_parts(self) -> None:
        results = {item.title: item.value for item in int_report("0xdeadbeefcafebabe", bits=64, var_name="system_addr")}
        self.assertIn("low  = system_addr & 0xffff", results["64位 low/high 写入代码"])
        self.assertIn("(system_addr >> 48) & 0xffff", results["64位 low/high 写入代码"])
        self.assertEqual(results["64位四段 half-word"], "chunks = [0xbabe, 0xcafe, 0xbeef, 0xdead]")

    def test_i386_fmt_fragments_are_modular_and_payload_first(self) -> None:
        low_high = low_high_template("system_addr", 32)
        self.assertEqual(
            low_high,
            "low  = system_addr & 0xffff\nhigh = (system_addr >> 16) & 0xffff\n",
        )
        code = i386_hn_payload_template(
            offset=6,
            target_addr="printf_got",
            io_name="io",
            send_mode="send",
            timeout=10,
        )
        self.assertNotIn("import time", code)
        self.assertIn("write_targets = [(0, printf_got, low), (1, printf_got + 2, high)]", code)
        self.assertIn("payload = fmt.ljust", code)
        self.assertIn("payload += b''.join(p32(addr)", code)
        self.assertIn("io.send(payload)", code)
        self.assertNotIn("from pwn import", code)
        self.assertNotIn("interactive", code)
        self.assertNotIn("flat(", code)
        self.assertNotIn("fmtstr_payload", code)
        compile(code, "<i386_fmt>", "exec")
        manual = manual_hn_got_overwrite_template(6, "elf.got['printf']", "system_addr", arch_bits=32)
        self.assertNotIn("import time", manual)
        self.assertIn("write_targets", manual)
        self.assertNotIn("io.send", manual)

    def test_amd64_s_read_places_format_before_p64_address(self) -> None:
        from pwnbao.features.fmtstr import s_read_payload_template

        code = s_read_payload_template(8, "elf.got['puts']", 64)
        self.assertLess(code.index("payload = fmt"), code.index("payload += p64"))
        self.assertNotIn("payload  = p64", code)
        compile(code, "<fmt-s-read>", "exec")

    def test_expression_engine_resolves_named_sizes_without_executing_code(self) -> None:
        source = "chunk_size = 0x68\nrequest_size = chunk_size + 8\n"
        variables = collect_integer_assignments(source)
        self.assertEqual(parse_int_expr("request_size", variables), 0x70)
        self.assertEqual(parse_int_expr("chunk_size << 1", variables), 0xD0)
        self.assertIsNone(parse_int_expr("__import__('os').system('id')", variables))

    def test_strict_double_free_stops_allocator_progress(self) -> None:
        config = build_allocator_config("amd64", "glibc 2.35", simulation_mode="strict")
        operations = [
            HeapOperation("op_001", HeapOperationKind.ALLOC, chunk="A", index="0", request_size="0x68"),
            HeapOperation("op_002", HeapOperationKind.FREE, index="0"),
            HeapOperation("op_003", HeapOperationKind.FREE, index="0"),
            HeapOperation("op_004", HeapOperationKind.ALLOC, chunk="B", index="1", request_size="0x68"),
        ]
        snapshots = GlibcHeapEngine(config).replay(operations)
        self.assertTrue(snapshots[3].aborted)
        self.assertIn("tcache_double_free_abort", {warning.code for warning in snapshots[3].warnings})
        self.assertTrue(snapshots[4].aborted)
        self.assertNotIn("B", snapshots[4].chunks)

    def test_unsorted_chunk_is_reused_before_top(self) -> None:
        config = build_allocator_config("amd64", "glibc 2.35")
        operations = [
            HeapOperation("op_001", HeapOperationKind.ALLOC, chunk="A", index="0", request_size="0x500"),
            HeapOperation("op_002", HeapOperationKind.ALLOC, chunk="guard", index="1", request_size="0x20"),
            HeapOperation("op_003", HeapOperationKind.FREE, index="0"),
            HeapOperation("op_004", HeapOperationKind.ALLOC, chunk="B", index="2", request_size="0x500"),
        ]
        snapshot = GlibcHeapEngine(config).replay(operations)[-1]
        self.assertEqual(snapshot.chunks["B"].address, snapshot.chunks["A"].address)
        self.assertEqual(snapshot.chunks["B"].physical_id, snapshot.chunks["A"].physical_id)
        self.assertEqual(snapshot.bins.unsorted, ())

    def test_poisoned_tcache_target_is_user_pointer_not_chunk_header(self) -> None:
        config = build_allocator_config("amd64", "glibc 2.35")
        operations = [
            HeapOperation("op_001", HeapOperationKind.ALLOC, chunk="A", index="0", request_size="0x68"),
            HeapOperation("op_002", HeapOperationKind.ALLOC, chunk="guard", index="1", request_size="0x68"),
            HeapOperation("op_003", HeapOperationKind.FREE, index="0"),
            HeapOperation("op_004", HeapOperationKind.POISON_FD, index="0", target="target_addr"),
            HeapOperation("op_005", HeapOperationKind.ALLOC, chunk="take", index="2", request_size="0x68"),
            HeapOperation("op_006", HeapOperationKind.ALLOC, chunk="hit", index="3", request_size="0x68"),
        ]
        snapshot = GlibcHeapEngine(config).replay(operations)[-1]
        self.assertEqual(snapshot.chunks["hit"].user_address, "target_addr")
        self.assertEqual(snapshot.chunks["hit"].address, "target_addr-0x10")
        self.assertEqual(snapshot.chunks["A"].user_address, "heap_base+0x2a0")

    def test_malloc_to_target_is_intent_until_allocator_proves_it(self) -> None:
        config = build_allocator_config("amd64", "glibc 2.35", simulation_mode="strict")
        operation = HeapOperation("op_001", HeapOperationKind.MALLOC_TO_TARGET, chunk="hit", request_size="0x68", target="target_addr")
        snapshot = GlibcHeapEngine(config).replay([operation])[-1]
        self.assertIn("hit", snapshot.chunks)
        self.assertEqual(snapshot.chunks["hit"].user_address, "heap_base+0x2a0")
        self.assertEqual(snapshot.intents[0].status, "invalid")
        self.assertIn("malloc_target_unverified", {warning.code for warning in snapshot.warnings})

    def test_glibc_compatibility_rejects_removed_hooks_and_house_of_force(self) -> None:
        config = build_allocator_config("amd64", "glibc 2.35")
        ok, reason = target_compatibility("__free_hook", config)
        self.assertFalse(ok)
        self.assertIn("2.34", reason)
        result = template_compatibility("house_of_force", config)
        self.assertFalse(result.supported)
        self.assertEqual(result.level, "unsupported")

    def test_pwndbg_parser_and_diff_accept_user_pointer_addresses(self) -> None:
        config = replace(build_allocator_config("amd64", "glibc 2.35"), heap_base="0x555555559000")
        operations = [
            HeapOperation("op_001", HeapOperationKind.ALLOC, chunk="A", index="0", request_size="0x68"),
            HeapOperation("op_002", HeapOperationKind.FREE, index="0"),
        ]
        snapshot = GlibcHeapEngine(config).replay(operations)[-1]
        observed = parse_pwndbg_snapshot("tcachebins\n0x70 [  1]: 0x5555555592a0\n")
        result = diff_snapshot(snapshot, observed)
        self.assertEqual(result.matched, 1)
        self.assertEqual(result.mismatched, 0)


    def test_uaf_edit_infers_safe_linking_poison_from_real_exp_shape(self) -> None:
        variables = {"encoded_fd": "target_addr ^ (heap_base >> 12)"}
        config = replace(build_allocator_config("amd64", "glibc 2.35"), heap_base="heap_base")
        operations = [
            HeapOperation("op_001", HeapOperationKind.ALLOC, chunk="A", index="0", request_size="0x68"),
            HeapOperation("op_002", HeapOperationKind.ALLOC, chunk="guard", index="1", request_size="0x68"),
            HeapOperation("op_003", HeapOperationKind.FREE, index="0"),
            HeapOperation("op_004", HeapOperationKind.EDIT, index="0", data="p64(encoded_fd)"),
            HeapOperation("op_005", HeapOperationKind.ALLOC, chunk="take", index="2", request_size="0x68"),
            HeapOperation("op_006", HeapOperationKind.ALLOC, chunk="hit", index="3", request_size="0x68"),
        ]
        snapshots = GlibcHeapEngine(config, variables=variables).replay(operations)
        self.assertIn("freelist_poison_inferred", {warning.code for warning in snapshots[4].warnings})
        self.assertEqual(snapshots[-1].chunks["hit"].user_address, "target_addr")



if __name__ == "__main__":
    unittest.main()
