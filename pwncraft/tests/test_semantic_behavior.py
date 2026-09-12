from pwncraft.core.semantic_behavior import classify_function, summarize_labels


def _function(assembly):
    return {"name": "sub_401000", "address": "0x401000", "assembly": assembly}


def test_extracts_behavior_without_function_name_semantics():
    result = classify_function(_function("""
  401000: 48 83 ec 10    sub $0x10,%rsp
  401004: 48 39 d8       cmp %rbx,%rax
  401007: 75 f7          jne 401000
  401009: 48 89 45 f8    mov %rax,-0x8(%rbp)
  40100d: ff d0          call *%rax
"""))
    assert "CHECK_SIZE" in result["labels"]
    assert "LOOP_PRESENT" in result["labels"]
    assert "CALL_INDIRECT" in result["labels"]
    assert result["coverage"]["complete"] is True


def test_summary_is_stable_and_sorted():
    functions = [
        classify_function(_function("401000: 48 89 45 f8    mov %rax,-0x8(%rbp)")),
        classify_function(_function("401000: 48 39 d8       cmp %rbx,%rax")),
    ]
    summary = summarize_labels(functions)
    assert summary["WRITE_OBJECT"] == 1
    assert summary["CHECK_SIZE"] == 1
    assert list(summary) == sorted(summary)


def test_integer_and_signed_branch_observations_are_not_vulnerability_claims():
    result = classify_function(_function("""
  401000: 0f b7 c0       movzwl %ax,%eax
  401003: 83 f8 20       cmp $0x20,%eax
  401006: 7f 02          jg 40100a
  401008: c3             ret
"""))
    assert "NARROWING_CONVERSION" in result["labels"]
    assert "SIGNED_BOUNDS_CHECK" in result["labels"]
    assert "vulnerability" not in result
    assert any(item["kind"] == "SIGNED_BRANCH" for item in result["evidence"])


def test_source_sink_labels_are_name_independent_for_common_calls():
    result = classify_function(_function("""
  401000: e8 00 00 00 00    call 401005 <read>
  401005: e8 00 00 00 00    call 40100a <system>
  40100a: e8 00 00 00 00    call 40100f <puts>
"""))
    assert "READ_EXTERNAL_INPUT" in result["labels"]
    assert "EXECUTION_SINK" in result["labels"]
    assert "WRITE_EXTERNAL_OUTPUT" in result["labels"]


def test_recognizes_input_adjacent_fixed_value_pointer_write_without_claiming_control():
    result = classify_function(_function("""
  401000: e8 00 00 00 00    call 401005 <read>
  401005: 48 8b 45 f0       mov -0x10(%rbp),%rax
  401009: c7 00 2a 2c 0a 00 movl $0xa2c2a,(%rax)
"""))
    assert "FIXED_VALUE_POINTER_WRITE" in result["labels"]
    assert "INPUT_TO_POINTER_WRITE_CANDIDATE" in result["labels"]
    assert any(item["kind"] == "FIXED_VALUE_POINTER_WRITE" for item in result["evidence"])
    assert "vulnerability" not in result


def test_recognizes_scaled_indexed_object_access_in_both_disassembly_dialects():
    result = classify_function(_function("""
  401000: 48 8d 14 c5 00 00 00 00 lea 0x0(,%rax,8),%rdx
  401008: 48 8b 04 02             mov (%rdx,%rax,1),%rax
"""))
    assert "INDEXED_OBJECT_ACCESS" in result["labels"]


def test_ignores_rip_global_initialization_and_nulling_pointer_store_as_fixed_write():
    result = classify_function(_function("""
  401000: c6 05 00 00 00 00 01 movb $0x1,0x0(%rip)
  401007: 48 c7 04 02 00 00 00 00 movq $0x0,(%rdx,%rax,1)
"""))
    assert "FIXED_VALUE_POINTER_WRITE" not in result["labels"]


def test_marks_custom_allocator_imports_as_lifecycle_facts_without_vulnerability_claim():
    result = classify_function(_function("""
  401000: e8 00 00 00 00    call 401005 <pMalloc>
  401005: e8 00 00 00 00    call 40100a <pFree>
"""))
    assert {"ALLOCATE_OBJECT", "FREE_OBJECT", "CUSTOM_ALLOCATOR_API"} <= set(result["labels"])
    assert [item["operation"] for item in result["evidence"]
            if item["kind"] == "CUSTOM_ALLOCATOR_API"] == ["allocate", "free"]
    assert "vulnerability" not in result


def test_marks_input_division_and_custom_allocator_truncation_as_candidates():
    result = classify_function(_function("""
  401000: e8 00 00 00 00    call 401005 <read>
  401005: 0f af c0          imul %eax,%eax
  401008: f7 7d d0          idivl -0x30(%rbp)
  40100b: 0f b6 c0          movzbl %al,%eax
  40100e: e8 00 00 00 00    call 401013 <pMalloc>
"""))
    assert "DIVISION_OPERATION" in result["labels"]
    assert "INPUT_DIVISION_BY_ZERO_CANDIDATE" in result["labels"]
    assert "CUSTOM_ALLOCATOR_API" in result["labels"]
    assert "CUSTOM_ALLOCATOR_SIZE_TRUNCATION_CANDIDATE" in result["labels"]


def test_marks_global_free_without_clear_as_cross_function_uaf_candidate():
    result = classify_function(_function("""
  401000: 48 8b 05 10 00 00 00 mov 0x10(%rip),%rax
  401007: 48 89 c7             mov %rax,%rdi
  40100a: e8 00 00 00 00       call 40100f <free>
"""))
    assert "GLOBAL_POINTER_FREE_NO_CLEAR_CANDIDATE" in result["labels"]
