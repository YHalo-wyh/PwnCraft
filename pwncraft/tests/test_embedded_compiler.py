from pwncraft.features.audit.embedded_compiler import (
    EmbeddedCompilerPolicy,
    analyze_embedded_compiler_semantics,
)
from pwncraft.features.audit.embedded_program import extract_embedded_function_program
from pwncraft.features.audit.semantic_facts import analyze_exp_semantics


SLANG = r'''function pwn(int round, vec forged_vec) : -> void {
  return;
}

function forge() : -> str {
  return "x";
}

function main() : int round, int keep_marker, vec vec_slot, str forged_header -> int {
  vec_slot := vec_new(0);
  round := 0;
  keep_vec(vec_slot);
  do {
    pwn(round, vec_slot);
    forged_header := forge();
    keep_marker := one() + 1234;
    round := round + 1;
  } while (round < 2);
  keep_str(forged_header);
  keep_int(keep_marker);
  return 0;
}
'''


BUGGY_POLICY = EmbeddedCompilerPolicy(
    name="reviewed-loop-void-arg-scan-omission",
    skip_loop_void_call_arguments_in_liveness=True,
    codegen_preserves_call_arguments=True,
    slot_allocator="first_fit_nonoverlap",
)


def _main_fact(result: dict) -> dict:
    return next(item for item in result["functions"] if item["function"] == "main")


def test_compiler_semantics_require_an_explicit_reviewed_policy() -> None:
    wrapper = "PAYLOAD = " + repr(SLANG) + r'''
def main():
    sock.sendall(PAYLOAD.encode())
'''
    result = analyze_exp_semantics(wrapper)
    assert result["embedded_programs"]
    assert result["embedded_compiler_semantics"] == []
    assert result["primitives"] == []


def test_loop_void_call_arguments_are_omitted_only_under_reviewed_policy() -> None:
    program = extract_embedded_function_program(SLANG)
    assert program is not None
    result = analyze_embedded_compiler_semantics(program, BUGGY_POLICY)
    main = _main_fact(result)
    omission = next(item for item in main["liveness_omissions"] if item["callee"] == "pwn")
    assert omission["variables"] == ["round", "vec_slot"]
    assert omission["codegen_preserves_arguments"] is True
    assert omission["loop_depth"] == 1


def test_first_fit_reconstructs_cross_type_slot_reuse_from_buggy_lifetimes() -> None:
    program = extract_embedded_function_program(SLANG)
    assert program is not None
    result = analyze_embedded_compiler_semantics(program, BUGGY_POLICY)
    main = _main_fact(result)
    slots = {item["variable"]: item["slot"] for item in main["slot_assignments"]}
    assert slots["vec_slot"] == slots["forged_header"]
    relation = next(
        item for item in main["slot_reuse_relations"]
        if item["from_variable"] == "vec_slot" and item["to_variable"] == "forged_header"
    )
    assert relation["from_type"] == "vec"
    assert relation["to_type"] == "str"
    assert relation["cross_type"] is True


def test_non_void_loop_call_is_not_omitted() -> None:
    source = r'''function use(vec value) : -> int {
  return 1;
}
function main() : vec a, str b -> int {
  a := vec_new(0);
  do {
    use(a);
    b := make_str();
  } while (1);
  return 0;
}
'''
    program = extract_embedded_function_program(source)
    assert program is not None
    result = analyze_embedded_compiler_semantics(program, BUGGY_POLICY)
    main = _main_fact(result)
    assert main["liveness_omissions"] == []
    slots = {item["variable"]: item["slot"] for item in main["slot_assignments"]}
    assert slots["a"] != slots["b"]


def test_disabling_bug_policy_keeps_loop_call_arguments_live() -> None:
    program = extract_embedded_function_program(SLANG)
    assert program is not None
    safe_policy = EmbeddedCompilerPolicy(
        name="reviewed-normal-liveness",
        skip_loop_void_call_arguments_in_liveness=False,
        codegen_preserves_call_arguments=True,
    )
    result = analyze_embedded_compiler_semantics(program, safe_policy)
    main = _main_fact(result)
    assert main["liveness_omissions"] == []
    vec = next(item for item in main["lifetimes"] if item["name"] == "vec_slot")
    assert vec["effective_use_orders"][-1] >= 4


def test_semantic_pipeline_publishes_compiler_facts_but_not_memory_primitive() -> None:
    wrapper = "PAYLOAD = " + repr(SLANG) + r'''
def main():
    sock.sendall(PAYLOAD.encode())
'''
    result = analyze_exp_semantics(wrapper, embedded_compiler_policy=BUGGY_POLICY)
    assert len(result["embedded_compiler_semantics"]) == 1
    compiler = result["embedded_compiler_semantics"][0]
    assert compiler["provenance"] == "EMBEDDED_STRUCTURE_PLUS_REVIEWED_COMPILER_POLICY"
    assert result["primitives"] == []
