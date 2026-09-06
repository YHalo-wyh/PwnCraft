from pwncraft.features.audit.embedded_program import extract_embedded_function_program
from pwncraft.features.audit.semantic_facts import analyze_exp_semantics


SLANG = r'''function one() : -> int {
  return 1;
}

function forge() : -> str {
  return "\\x00\\x00\\xff\\xff";
}

function pwn(int round, vec forged_vec) : -> void {
  if (round == 0) {
    return;
  };
  say("resolve puts");
  scribble(forged_vec, 526339, -205200);
  say("/bin/sh");
  return;
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


def _function(program, name: str):
    return next(fn for fn in program.functions if fn.name == name)


def test_typed_function_headers_preserve_parameter_and_local_types() -> None:
    program = extract_embedded_function_program(SLANG)
    assert program is not None
    pwn = _function(program, "pwn")
    assert [(item.type_name, item.name) for item in pwn.parameters] == [
        ("int", "round"), ("vec", "forged_vec")
    ]
    main = _function(program, "main")
    assert [(item.type_name, item.name) for item in main.locals] == [
        ("int", "round"),
        ("int", "keep_marker"),
        ("vec", "vec_slot"),
        ("str", "forged_header"),
    ]


def test_loop_membership_and_source_order_are_preserved() -> None:
    program = extract_embedded_function_program(SLANG)
    assert program is not None
    main = _function(program, "main")
    loop_statements = [item for item in main.statements if item.loop_depth == 1]
    assert [(item.kind, item.callee, item.target) for item in loop_statements] == [
        ("call", "pwn", ""),
        ("assignment", "forge", "forged_header"),
        ("assignment", "", "keep_marker"),
        ("assignment", "", "round"),
    ]
    assert [item.order for item in loop_statements] == sorted(item.order for item in loop_statements)


def test_direct_call_arguments_are_structured_without_execution() -> None:
    program = extract_embedded_function_program(SLANG)
    assert program is not None
    pwn = _function(program, "pwn")
    scribble = next(item for item in pwn.statements if item.callee == "scribble")
    assert list(scribble.arguments) == ["forged_vec", "526339", "-205200"]
    assert scribble.expression == "scribble(forged_vec, 526339, -205200)"


def test_assignment_call_shape_is_preserved_but_not_promoted_to_alias_truth() -> None:
    program = extract_embedded_function_program(SLANG)
    assert program is not None
    main = _function(program, "main")
    assignment = next(item for item in main.statements if item.target == "vec_slot")
    assert assignment.callee == "vec_new"
    assert list(assignment.arguments) == ["0"]
    assert assignment.kind == "assignment"


def test_non_matching_text_is_not_forced_into_embedded_program_schema() -> None:
    assert extract_embedded_function_program("function maybe but not a valid header") is None
    assert extract_embedded_function_program(b"\xff\xfe\xfd") is None


def test_semantic_pipeline_only_parses_programs_proven_to_reach_outbound_send() -> None:
    wrapper = "PAYLOAD = " + repr(SLANG) + r'''
def main():
    source = PAYLOAD + "END_OF_SOURCE\n"
    sock.sendall(source.encode())
'''
    result = analyze_exp_semantics(wrapper)
    assert result["status"] == "ok"
    assert len(result["outbound_literal_payloads"]) == 1
    assert len(result["embedded_programs"]) == 1
    program = result["embedded_programs"][0]
    assert program["syntax_family"] == "typed_function_dsl"
    assert {fn["name"] for fn in program["functions"]} == {"one", "forge", "pwn", "main"}
    # Structure is evidence, not a target-side corruption primitive.
    assert result["primitives"] == []
