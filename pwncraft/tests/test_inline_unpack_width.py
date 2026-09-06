from pwncraft.features.audit.audit import audit_exp
from pwncraft.features.audit.extract import extract_exploit_ir


def _codes(source: str) -> list[str]:
    return [item["code"] for item in audit_exp(source, bits=64, pie=False)]


def test_recvn_plus_bytes_padding_is_exact_unpack_width() -> None:
    source = "from pwn import *\nio = None\nx = u64(io.recvn(6) + b'\\x00\\x00')\n"
    ir, error = extract_exploit_ir(source)
    assert error is None
    op = next(op for op in ir.unpacks if op.fn == "u64")
    assert getattr(op, "meta_input_width", None) == 8
    assert getattr(op, "meta_recv_length", None) == 8
    assert [x["kind"] for x in getattr(op, "meta_input_width_evidence", [])] == [
        "RECVN_EXACT", "LITERAL_WIDTH", "CONCAT_WIDTH"
    ]
    assert "EXP_LEAK_001" not in _codes(source)
    assert "EXP_LEAK_003" not in _codes(source)


def test_python2_style_string_padding_is_counted_when_byte_representable() -> None:
    source = "from pwn import *\nio = None\nx = u64(io.recvn(6) + '\\x00\\x00')\n"
    ir, error = extract_exploit_ir(source)
    assert error is None
    op = next(op for op in ir.unpacks if op.fn == "u64")
    assert getattr(op, "meta_input_width", None) == 8
    assert "EXP_LEAK_003" not in _codes(source)


def test_recv_is_not_promoted_to_exact_length() -> None:
    source = "from pwn import *\nio = None\nx = u64(io.recv(6) + b'\\x00\\x00')\n"
    ir, error = extract_exploit_ir(source)
    assert error is None
    op = next(op for op in ir.unpacks if op.fn == "u64")
    assert getattr(op, "meta_input_width", None) is None
    assert "EXP_LEAK_003" in _codes(source)


def test_exact_composed_width_below_u64_requirement_still_errors() -> None:
    source = "from pwn import *\nio = None\nx = u64(io.recvn(5) + b'\\x00')\n"
    ir, error = extract_exploit_ir(source)
    assert error is None
    op = next(op for op in ir.unpacks if op.fn == "u64")
    assert getattr(op, "meta_input_width", None) == 6
    assert "EXP_LEAK_001" in _codes(source)
