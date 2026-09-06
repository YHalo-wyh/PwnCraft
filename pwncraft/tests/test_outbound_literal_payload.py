from pwncraft.features.audit.outbound_payload import extract_outbound_literal_payloads
from pwncraft.features.audit.semantic_facts import analyze_exp_semantics


def test_module_literal_plus_terminator_flows_through_encode_to_sendall() -> None:
    source = r'''
PAYLOAD = "hello\n"

def main():
    source = PAYLOAD + "END\n"
    sock.sendall(source.encode())
'''
    facts, error = extract_outbound_literal_payloads(source)
    assert error is None
    assert len(facts) == 1
    fact = facts[0]
    assert fact.content == b"hello\nEND\n"
    assert fact.content_kind == "bytes"
    assert fact.byte_length == len(b"hello\nEND\n")
    assert fact.provenance == "EXP_AST_LITERAL_DATAFLOW"


def test_dynamic_input_is_not_promoted_to_literal_payload() -> None:
    source = r'''
def main():
    payload = input() + "END\n"
    sock.sendall(payload.encode())
'''
    facts, error = extract_outbound_literal_payloads(source)
    assert error is None
    assert facts == []


def test_unknown_or_dynamic_encoding_stays_unknown() -> None:
    source = r'''
PAYLOAD = "abc"

def main():
    sock.sendall(PAYLOAD.encode(codec_name))
'''
    facts, error = extract_outbound_literal_payloads(source)
    assert error is None
    assert facts == []


def test_direct_literal_bytes_send_is_supported() -> None:
    source = r'''
def main():
    io.send(b"ABC\x00DEF")
'''
    facts, error = extract_outbound_literal_payloads(source)
    assert error is None
    assert len(facts) == 1
    assert facts[0].content == b"ABC\x00DEF"
    assert facts[0].byte_length == 7


def test_semantic_facts_publish_payloads_without_claiming_memory_primitive() -> None:
    source = r'''
PAYLOAD = "function main() { return 0; }\n"

def main():
    source = PAYLOAD + "END_OF_SOURCE\n"
    sock.sendall(source.encode())
'''
    result = analyze_exp_semantics(source)
    assert result["status"] == "ok"
    assert len(result["outbound_literal_payloads"]) == 1
    assert result["outbound_literal_payloads"][0]["expression"] == "source.encode()"
    assert result["primitives"] == []


def test_sctf_slang_wrapper_shape_recovers_embedded_program_and_terminator() -> None:
    source = r'''#!/usr/bin/env python3
PAYLOAD = r''' + "'''" + r'''function forge() : -> str {
  return "\\x00\\x00\\xff\\xff";
}
function pwn(int round, vec forged_vec) : -> void {
  say("resolve puts");
  scribble(forged_vec, 526339, -205200);
  say("/bin/sh");
  return;
}
''' + "'''" + r'''

def main():
    source = PAYLOAD + "END_OF_SOURCE\n"
    with socket.create_connection(("127.0.0.1", 9999)) as sock:
        sock.sendall(source.encode())
'''
    result = analyze_exp_semantics(source)
    assert result["status"] == "ok"
    payloads = result["outbound_literal_payloads"]
    assert len(payloads) == 1
    payload = payloads[0]
    assert "scribble(forged_vec, 526339, -205200);" in payload["content"].decode()
    assert payload["content"].endswith(b"END_OF_SOURCE\n")
    assert payload["byte_length"] == len(payload["content"])
