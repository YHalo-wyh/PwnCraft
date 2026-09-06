"""Regression: PROMPT_SYNC vs OUTPUT_DATA_FLOW in helper contract inference.

A recvuntil of a constant prompt label with a discarded result only
synchronizes a menu; it must NOT be treated as evidence that a helper reads
chunk data back (SHOW). Only a real data readback (recv-family value that is
bound/returned, or non-until recv calls) proves output. Synthetic cases only —
no challenge-specific names, shapes, or literals.

Covers the generic rules:
  R1: index-only helper + prompt-sync-only body + delete/free verb
      -> structural DELETE (verb disambiguates an already-proven shape).
  R2: same body shape with an unrelated name stays UNKNOWN (no fake SHOW).
  R3: index-only helper whose body actually reads data into a variable
      -> structural SHOW regardless of the verb.
"""
from __future__ import annotations

from pwncraft.features.heapviz.contracts import HelperContractResolver

PROMPT_SYNC_DELETE = """
def free_slot(idx):
    io.recvuntil(":")
    io.sendline("9")
    io.recvuntil("Position: ")
    io.sendline(str(idx))
"""

PROMPT_SYNC_UNNAMED = """
def handle_slot(idx):
    io.recvuntil(":")
    io.sendline("9")
    io.recvuntil("Position: ")
    io.sendline(str(idx))
"""

DATA_READBACK = """
def peek_slot(idx):
    io.recvuntil(":")
    io.sendline("7")
    io.recvuntil("Position: ")
    io.sendline(str(idx))
    blob = io.recvline()
    return blob
"""


def _contract(source: str, function: str):
    resolution = HelperContractResolver().resolve(source)
    contract = resolution.contract_for(function)
    assert contract is not None, f"no contract for {function}: {resolution.diagnostics}"
    return contract


def test_prompt_sync_only_delete_shape_resolves_delete() -> None:
    contract = _contract(PROMPT_SYNC_DELETE, "free_slot")
    assert contract.operation.value == "delete"
    assert contract.roles["index"].parameter == "idx"


def test_prompt_sync_only_unknown_verb_stays_unknown() -> None:
    contract = _contract(PROMPT_SYNC_UNNAMED, "handle_slot")
    assert contract.operation.value == "unknown"


def test_real_data_readback_proves_show() -> None:
    contract = _contract(DATA_READBACK, "peek_slot")
    assert contract.operation.value == "show"
    assert contract.roles["index"].parameter == "idx"


def test_assigned_recvuntil_counts_as_output() -> None:
    source = """
def grab(idx):
    io.recvuntil(":")
    io.sendline("6")
    io.recvuntil("Position: ")
    io.sendline(str(idx))
    marker = io.recvuntil("Done")
    return marker
"""
    contract = _contract(source, "grab")
    assert contract.operation.value == "show"
