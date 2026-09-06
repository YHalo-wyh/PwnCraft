from pwncraft.features.audit.embedded_compiler import EmbeddedCompilerPolicy
from pwncraft.features.audit.semantic_facts import analyze_exp_semantics


POLICY = EmbeddedCompilerPolicy(
    name="reviewed-loop-void-arg-scan-omission",
    skip_loop_void_call_arguments_in_liveness=True,
    codegen_preserves_call_arguments=True,
    slot_allocator="first_fit_nonoverlap",
)


def _wrapper(payload: str) -> str:
    return "PAYLOAD = " + repr(payload) + "\n" + "sock.sendall(PAYLOAD.encode())\n"


def _execution_main(result: dict) -> dict:
    execution = result["embedded_execution_semantics"][0]
    return next(item for item in execution["functions"] if item["function"] == "main")


def test_cross_iteration_reused_slot_proves_static_type_confusion_relation() -> None:
    payload = r'''function pwn(int round, vec forged_vec) : -> void {
  return;
}
function forge() : -> str {
  return "x";
}
function main() : int round, vec vec_slot, str forged_header -> int {
  vec_slot := vec_new(0);
  round := 0;
  do {
    pwn(round, vec_slot);
    forged_header := forge();
    round := round + 1;
  } while (round < 2);
  return 0;
}
'''
    result = analyze_exp_semantics(_wrapper(payload), embedded_compiler_policy=POLICY)
    main = _execution_main(result)
    loop = main["loops"][0]
    assert loop["integer_state_before_first_iteration"]["round"] == 0
    assert loop["integer_state_after_first_iteration"]["round"] == 1
    assert loop["condition_after_first_iteration"] is True
    assert loop["proves_second_iteration"] is True

    flow = main["cross_iteration_value_flows"][0]
    assert flow["producer_variable"] == "forged_header"
    assert flow["producer_type"] == "str"
    assert flow["consumer_variable"] == "vec_slot"
    assert flow["consumer_type"] == "vec"
    assert flow["resident_value_survives_loop_backedge"] is True

    confusion = main["runtime_type_confusions"][0]
    assert confusion["iteration"] == 2
    assert confusion["resident_type"] == "str"
    assert confusion["consumed_as_type"] == "vec"
    assert confusion["state"] == "derived_static"
    assert confusion["runtime_observed"] is False
    assert result["primitives"] == []


def test_single_iteration_loop_does_not_promote_slot_reuse_to_type_confusion() -> None:
    payload = r'''function pwn(int round, vec forged_vec) : -> void {
  return;
}
function forge() : -> str {
  return "x";
}
function main() : int round, vec vec_slot, str forged_header -> int {
  vec_slot := vec_new(0);
  round := 0;
  do {
    pwn(round, vec_slot);
    forged_header := forge();
    round := round + 1;
  } while (round < 1);
  return 0;
}
'''
    result = analyze_exp_semantics(_wrapper(payload), embedded_compiler_policy=POLICY)
    main = _execution_main(result)
    assert main["loops"][0]["condition_after_first_iteration"] is False
    assert main["cross_iteration_value_flows"] == []
    assert main["runtime_type_confusions"] == []


def test_unknown_loop_condition_remains_unknown_instead_of_guessing() -> None:
    payload = r'''function pwn(int round, vec forged_vec) : -> void {
  return;
}
function forge() : -> str {
  return "x";
}
function main() : int round, vec vec_slot, str forged_header -> int {
  vec_slot := vec_new(0);
  round := 0;
  do {
    pwn(round, vec_slot);
    forged_header := forge();
    round := round + opaque();
  } while (round < 2);
  return 0;
}
'''
    result = analyze_exp_semantics(_wrapper(payload), embedded_compiler_policy=POLICY)
    main = _execution_main(result)
    assert main["loops"][0]["condition_after_first_iteration"] is None
    assert main["runtime_type_confusions"] == []


def test_next_iteration_refresh_before_call_blocks_stale_resident_value_claim() -> None:
    payload = r'''function pwn(int round, vec forged_vec) : -> void {
  return;
}
function forge() : -> str {
  return "x";
}
function main() : int round, vec vec_slot, str forged_header -> int {
  vec_slot := vec_new(0);
  round := 0;
  do {
    vec_slot := vec_new(0);
    pwn(round, vec_slot);
    forged_header := forge();
    round := round + 1;
  } while (round < 2);
  return 0;
}
'''
    result = analyze_exp_semantics(_wrapper(payload), embedded_compiler_policy=POLICY)
    main = _execution_main(result)
    assert main["loops"][0]["proves_second_iteration"] is True
    assert main["runtime_type_confusions"] == []


def test_no_reviewed_policy_means_no_execution_semantics() -> None:
    payload = r'''function main() : int round -> int {
  round := 0;
  do {
    round := round + 1;
  } while (round < 2);
  return 0;
}
'''
    result = analyze_exp_semantics(_wrapper(payload))
    assert result["embedded_programs"]
    assert result["embedded_compiler_semantics"] == []
    assert result["embedded_execution_semantics"] == []
