from pwncraft.features.audit.integer_flow import analyze_c_integer_exp_flow


SOURCE = r'''
void *handle_connection(void *arg) {
    Worker *self = (Worker *)arg;
    Header *content_length = find_header(headers, "Content-Length");
    if (strcmp(method, "POST") == 0) {
      char *end = NULL;
      size_t body_len = strtoll(content_length->val, &end, 10);
      body = malloc(body_len + 1);
      size_t nbytes = readn(self->fd, body, body_len);
    }
    return NULL;
}
'''


def _by_kind(result: dict) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for fact in result["composed_facts"]:
        grouped.setdefault(fact["kind"], []).append(fact)
    return grouped


def test_negative_one_header_composes_to_exact_modular_mismatch() -> None:
    exp = r'''
io.send(b"POST /reset HTTP/1.1\r\nContent-Length: -1\r\n\r\n")
'''
    result = analyze_c_integer_exp_flow(SOURCE, exp)
    assert result["status"] == "ok"
    assert {fact["function"] for fact in result["source_facts"]} == {"handle_connection"}

    grouped = _by_kind(result)
    assert set(grouped) == {
        "EXP_INPUT_REACHES_SIGNED_PARSER",
        "UNSIGNED_CONVERSION_EXACT_MAX",
        "ALLOCATION_ARGUMENT_WRAP_TO_ZERO",
        "COPY_BOUND_REMAINS_UNSIGNED_MAX",
    }
    reach = grouped["EXP_INPUT_REACHES_SIGNED_PARSER"][0]
    assert reach["input_field"] == "Content-Length"
    assert reach["input_value"] == -1
    assert grouped["ALLOCATION_ARGUMENT_WRAP_TO_ZERO"][0]["result"] == 0
    assert grouped["COPY_BOUND_REMAINS_UNSIGNED_MAX"][0]["result"] == "UNSIGNED_MAX(N)"


def test_positive_header_is_input_evidence_but_not_wrap_evidence() -> None:
    exp = 'request = "POST / HTTP/1.1\\r\\nContent-Length: 8\\r\\n\\r\\n"'
    result = analyze_c_integer_exp_flow(SOURCE, exp)
    grouped = _by_kind(result)
    assert set(grouped) == {"EXP_INPUT_REACHES_SIGNED_PARSER"}
    assert grouped["EXP_INPUT_REACHES_SIGNED_PARSER"][0]["input_value"] == 8


def test_mismatched_protocol_field_does_not_compose() -> None:
    exp = 'request = "POST / HTTP/1.1\\r\\nX-Length: -1\\r\\n\\r\\n"'
    result = analyze_c_integer_exp_flow(SOURCE, exp)
    assert result["status"] == "ok"
    assert result["composed_facts"] == []


def test_unrelated_strtoll_without_find_header_binding_does_not_guess_channel() -> None:
    source = r'''
int parse(const char *text) {
    size_t n = strtoll(text, 0, 10);
    char *p = malloc(n + 1);
    readn(0, p, n);
    return 0;
}
'''
    exp = 'payload = b"Content-Length: -1\\r\\n"'
    result = analyze_c_integer_exp_flow(source, exp)
    assert result["composed_facts"] == []


def test_exp_syntax_error_blocks_composition_without_discarding_source_facts() -> None:
    result = analyze_c_integer_exp_flow(SOURCE, "if :")
    assert result["status"] == "blocked"
    assert result["reason"] == "EXP_PARSE"
    assert result["composed_facts"] == []
    assert result["source_facts"]
