"""Deterministic cyclic pattern generation and crash-offset lookup.

The pattern is the classic de Bruijn sequence B(26, 8) (or B(26, 4) for
32-bit) built with du Val's algorithm — byte-for-byte the same prefix that
pwntools' ``cyclic()`` produces, so offsets found here match offsets found
by pwntools on the same crash.
"""
from __future__ import annotations

LOWERCASE_ALPHABET = b"abcdefghijklmnopqrstuvwxyz"
# pwntools' default cyclic_size is 4, so the classic ``aaaabaaa`` pattern and
# ``cyclic(N)`` in an EXP both use n=4.  A full 8-byte RIP window only exists
# in the n=8 pattern (``cyclic(N, n=8)``), which starts ``aaaaaaaab``.
DEFAULT_SUBSEQUENCE = 4
DEFAULT_PATTERN_SIZE = 8192

# Reference values taken from an independent pwntools installation.
_KNOWN_PREFIX_N4 = b"aaaabaaacaaadaaaeaaafaaa"
_KNOWN_PREFIX_N8 = b"aaaaaaaabaaaaaaacaaa"
_KNOWN_FIND = {b"baaa": 4, b"saaa": 72}


def _de_bruijn_bytes(alphabet: bytes, subsequence_len: int, length: int) -> bytes:
    """Prefix of B(len(alphabet), subsequence_len), generated lazily."""
    k = len(alphabet)
    n = int(subsequence_len)
    if k < 1 or n < 1:
        raise ValueError("alphabet 与子序列长度必须为正")
    a = [0] * (k * n)
    out = bytearray()
    state = {"enough": False}

    def db(t: int, p: int) -> None:
        if state["enough"]:
            return
        if t > n:
            if n % p == 0:
                for index in range(1, p + 1):
                    out.append(alphabet[a[index]])
                    if length is not None and len(out) >= length:
                        state["enough"] = True
                        return
            return
        a[t] = a[t - p]
        db(t + 1, p)
        if state["enough"]:
            return
        for j in range(a[t - p] + 1, k):
            a[t] = j
            db(t + 1, t)
            if state["enough"]:
                return

    db(1, 1)
    return bytes(out)


def cyclic_pattern(
    length: int = DEFAULT_PATTERN_SIZE,
    *,
    n: int = DEFAULT_SUBSEQUENCE,
    alphabet: bytes = LOWERCASE_ALPHABET,
) -> bytes:
    """Return the first ``length`` bytes of the cyclic pattern."""
    length = int(length)
    if length <= 0:
        raise ValueError("pattern 长度必须为正")
    return _de_bruijn_bytes(bytes(alphabet), int(n), length)


def parse_crash_value(value: str | int | bytes) -> bytes:
    """Normalise a crash register dump into pattern-window bytes.

    Accepts hex/decimal integers (interpreted little-endian, as a register
    value read off the stack would be) and raw ASCII windows.
    """
    if isinstance(value, bytes):
        window = value
    elif isinstance(value, int):
        if value < 0:
            raise ValueError("崩溃值不能为负数")
        raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "little")
        window = raw
    else:
        text = str(value).strip()
        if not text:
            raise ValueError("崩溃值不能为空")
        try:
            parsed = int(text, 0)
        except ValueError:
            window = text.encode("utf-8")
        else:
            if parsed < 0:
                raise ValueError("崩溃值不能为负数")
            window = parsed.to_bytes((parsed.bit_length() + 7) // 8 or 1, "little")
    if len(window) > 8:
        # A wide register dump still contains the 8-byte window of interest.
        window = window[:8]
    return window


def cyclic_find(
    value: str | int | bytes,
    *,
    n: int | None = None,
    length: int = DEFAULT_PATTERN_SIZE,
    alphabet: bytes = LOWERCASE_ALPHABET,
) -> int:
    """Return the pattern offset whose window equals ``value``.

    ``n`` defaults to pwntools' behaviour: the window is looked up in the
    classic n=4 pattern first (``cyclic(N)`` in an EXP), and a wider window
    that only exists in the n=8 pattern falls back to ``cyclic(N, n=8)``.
    """
    window = parse_crash_value(value)
    if not window:
        raise ValueError("崩溃值为空")
    subsequence = int(n) if n is not None else None
    tried: list[int] = []
    for candidate in ([subsequence] if subsequence is not None else [4, 8]):
        pattern = cyclic_pattern(max(int(length), len(window)), n=candidate, alphabet=alphabet)
        offset = pattern.find(window)
        if offset >= 0:
            return offset
        tried.append(candidate)
    raise ValueError(f"崩溃值 {window!r} 不在 n={'/'.join(str(item) for item in tried)} pattern 内")


def self_check() -> None:
    """Cheap invariant probe used by tests and startup diagnostics."""
    n4 = cyclic_pattern(1024, n=4)
    n8 = cyclic_pattern(1024, n=8)
    assert n4[: len(_KNOWN_PREFIX_N4)] == _KNOWN_PREFIX_N4
    assert n8[: len(_KNOWN_PREFIX_N8)] == _KNOWN_PREFIX_N8
    for window, expected in _KNOWN_FIND.items():
        assert cyclic_find(window) == expected
    for probe in (0, 5, 72, 504, 1000):
        assert cyclic_find(n4[probe : probe + 4], n=4) == probe
        assert cyclic_find(n8[probe : probe + 8], n=8) == probe
