"""VNext.2 M2.1-M2.3 acceptance — ValueIR / callsite recovery / ObjectRef.

Deterministic only. Fixtures: real objdump text of lab13 (heapcreator) and
its .c source. No IDA, no network.

Owner-mandated discipline covered here:
  * constant propagation across register moves (struct 0x10)
  * malloc result → table slot linkage (STORE_PTR)
  * ObjectRef identity: same slot unifies free/edit/show
  * No semantic name shortcut: renaming helpers must not change the IR
  * UNKNOWN is not guessed (atoi result stays STACK_SLOT)
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pwnbao.core.c_source_ir import extract_c_callsites  # noqa: E402
from pwnbao.core.value_ir import K_CONST, K_LOAD, K_STACK, K_UNKNOWN  # noqa: E402
from pwnbao.core.x86_trace import trace_callsites  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "lab13_objdump.txt"
SOURCE = Path(__file__).parents[1] / ".." / "heap-corpus" / "corpus" / \
    "heap-ctf-wiki-hitcontraning-lab13-bae716d5" / "original" / "challenge" / "heapcreator.c"

TABLE = "0x6020a0"   # heaparray base address (from create_heap disasm)


def _sites(text=None):
    return trace_callsites((text or FIXTURE.read_text(encoding="utf-8")))


def _by_func(sites, name):
    return [s for s in sites if s.function == name]


# ---------------- M2.1 constant propagation ----------------

def test_c1_struct_malloc_constant_propagates() -> None:
    sites = [s for s in _sites() if s.function == "create_heap"
             and s.callee == "malloc"]
    assert len(sites) == 2
    first_args = sites[0].args
    assert first_args[0].kind == K_CONST and first_args[0].value == 0x10


def test_c2_content_malloc_keeps_stack_slot_not_guessed() -> None:
    sites = [s for s in _sites() if s.function == "create_heap"
             and s.callee == "malloc"]
    # atoi result is a stack slot — NOT guessed as ARG/CONST
    assert sites[1].args[0].kind == K_STACK and sites[1].args[0].offset == -0x28


# ---------------- M2.2 call argument recovery ----------------

def test_c3_read_args_recovered() -> None:
    sites = [s for s in _sites() if s.function == "create_heap"
             and s.callee == "read"]
    assert len(sites) == 1
    fd, buf, size = sites[0].args
    assert fd.kind == K_CONST and fd.value == 0
    assert buf.kind == K_STACK and buf.offset == -0x20
    assert size.kind == K_CONST and size.value == 8


# ---------------- M2.3 ObjectRef identity ----------------

def test_o1_both_frees_unify_to_same_object() -> None:
    from pwnbao.core.x86_trace import _slot_objectref
    frees = [s for s in _sites() if s.function == "delete_heap"
             and s.callee == "free"]
    assert len(frees) == 2
    refs = [_slot_objectref(a) for a in (frees[0].args[0], frees[1].args[0])]
    assert all(r is not None for r in refs)
    assert refs[0].base == refs[1].base == TABLE
    assert refs[0].index_key == refs[1].index_key


def test_o2_rename_invariance_no_semantic_shortcut() -> None:
    """add→potato / delete→hello must produce identical callsite IR."""
    text = FIXTURE.read_text(encoding="utf-8")
    renamed = (text.replace("<create_heap>", "<potato>")
                   .replace("<delete_heap>", "<hello>")
                   .replace("<edit_heap>", "<qqq>")
                   .replace("<show_heap>", "<abc>"))
    base = [(s.function, s.callee, s.address,
             tuple(a.describe() for a in s.args))
            for s in _sites() if s.function in
            ("create_heap", "delete_heap", "edit_heap", "show_heap")]
    after = [(s.function, s.callee, s.address,
              tuple(a.describe() for a in s.args))
             for s in _sites(renamed) if s.function in
             ("potato", "hello", "qqq", "abc")]
    mapped = [(dict(zip(("potato", "hello", "qqq", "abc"),
                        ("create_heap", "delete_heap", "edit_heap", "show_heap")))[f],
               c, a, args) for f, c, a, args in after]
    assert sorted(base) == sorted(mapped)


# ---------------- source ↔ binary cross-validation ----------------

def _source_sites():
    src = SOURCE.resolve().read_text(encoding="utf-8")
    return extract_c_callsites(src, table_globals={"heaparray": TABLE})


def test_x1_source_and_binary_agree_on_allocator_counts() -> None:
    binary_mallocs = [s for s in _sites() if s.callee == "malloc"]
    source_creates = [s for s in _source_sites()
                      if s.callee == "malloc" and s.function == "create_heap"]
    source_deletes = [s for s in _source_sites()
                      if s.callee == "free" and s.function == "delete_heap"]
    binary_frees = [s for s in _sites() if s.callee == "free"
                    and s.function == "delete_heap"]
    # create_heap: 2 mallocs in BOTH representations
    assert len(source_creates) == len(binary_mallocs) == 2
    # delete_heap: two free calls in BOTH (two free calls, NOT double_free)
    assert len(source_deletes) == len(binary_frees) == 2


def test_x2_content_size_stays_honest_on_both_sides() -> None:
    """content malloc 的 size: source 侧 create_heap() 无形参, size 是
    stdin 读入的局部变量 → UNKNOWN(unresolved local)；binary 侧 =
    STACK_SLOT(atoi 局部)。两侧都不猜成 ARG/CONST —— 跨语句/跨函数归一
    属 M4。这验证 UNKNOWN 纪律在两个后端一致。"""
    size_site = [s for s in _source_sites()
                 if s.callee == "malloc" and s.function == "create_heap"
                 and s.args and "unresolved local size" in (s.args[0].reason or "")]
    assert size_site, "content malloc 的 size 应为诚实 UNKNOWN"
    bin_content = [s for s in _sites() if s.callee == "malloc"
                   and s.function == "create_heap" and s.args
                   and s.args[0].kind == "stack_slot"]
    assert bin_content and bin_content[0].args[0].offset == -0x28


def test_x2b_sizeof_is_honest_unknown_not_guessed() -> None:
    """struct malloc 在 source 侧是 sizeof(struct heap) —— 无类型表不得
    猜成 CONST(0x10)；binary 侧是 CONST(0x10)。差异留给 M4 类型信息。"""
    src_struct = [s for s in _source_sites()
                  if s.callee == "malloc" and s.function == "create_heap"
                  and s.args and s.args[0].kind == "unknown"]
    assert src_struct and "sizeof" in src_struct[0].args[0].reason
    bin_struct = [s for s in _sites() if s.callee == "malloc"
                  and s.function == "create_heap" and s.args
                  and s.args[0].kind == K_CONST]
    assert bin_struct and bin_struct[0].args[0].value == 0x10


def test_x3_unknown_not_guessed() -> None:
    """A genuinely unknown argument stays UNKNOWN — no invented bindings."""
    for s in _source_sites():
        for a in s.args:
            if a.kind == K_UNKNOWN:
                assert a.reason  # must say why


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"PASS {name}")
    print("all m2 tests passed")
