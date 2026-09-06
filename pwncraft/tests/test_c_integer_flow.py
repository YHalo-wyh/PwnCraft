from pwncraft.core.c_source_ir import extract_c_integer_flows


def kinds(source: str):
    return [fact.kind for fact in extract_c_integer_flows(source)]


def test_signed_parse_to_size_t_links_allocation_and_copy_bound() -> None:
    source = r'''
int handle(int fd, const char *text) {
    char *end = 0;
    size_t body_len = strtoll(text, &end, 10);
    char *body = malloc(body_len + 1);
    readn(fd, body, body_len);
    return 0;
}
'''
    facts = extract_c_integer_flows(source)
    assert [f.kind for f in facts] == [
        "SIGNED_PARSE_TO_UNSIGNED",
        "UNSIGNED_LENGTH_ALLOCATION_USE",
        "UNSIGNED_LENGTH_COPY_BOUND_USE",
    ]
    seed = facts[0]
    assert seed.variable == "body_len"
    assert seed.details["parser"] == "strtoll"
    assert seed.details["destination_type"] == "size_t"
    assert seed.details["negative_input_mapping"] == "modulo_destination_width"
    assert facts[1].details["callee"] == "malloc"
    assert facts[2].details["callee"] == "readn"
    assert facts[2].details["length_argument_indexes"] == [2]


def test_parser_name_alone_is_not_a_flow() -> None:
    source = r'''
int handle(const char *text) {
    long long value = strtoll(text, 0, 10);
    return value == 1;
}
'''
    assert extract_c_integer_flows(source) == []


def test_unsigned_length_in_wrong_argument_is_not_copy_bound() -> None:
    source = r'''
int handle(int fd, const char *text) {
    size_t body_len = strtoll(text, 0, 10);
    readn(body_len, 0, 8);
    return 0;
}
'''
    assert "UNSIGNED_LENGTH_COPY_BOUND_USE" not in kinds(source)


def test_same_variable_name_in_other_function_is_not_cross_linked() -> None:
    source = r'''
int parse(const char *text) {
    size_t body_len = strtoll(text, 0, 10);
    return 0;
}
int consume(int fd) {
    size_t body_len = 16;
    char buf[16];
    readn(fd, buf, body_len);
    return 0;
}
'''
    facts = extract_c_integer_flows(source)
    assert [f.kind for f in facts] == ["SIGNED_PARSE_TO_UNSIGNED"]
