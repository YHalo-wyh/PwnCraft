from __future__ import annotations


def protect_ptr(field_address: int, pointer: int) -> int:
    """glibc PROTECT_PTR(pos, ptr); ``pos`` is the field address, not heap_base."""

    return int(pointer) ^ (int(field_address) >> 12)


def reveal_ptr(field_address: int, encoded: int) -> int:
    return protect_ptr(field_address, encoded)


def pointer_aligned(pointer: int, alignment: int) -> bool:
    return int(pointer) >= 0 and int(pointer) % max(1, int(alignment)) == 0
