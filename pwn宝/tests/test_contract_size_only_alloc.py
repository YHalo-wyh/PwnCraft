"""Cycle-4 regression: generic size-only allocation contracts.

The rule under test is deliberately narrower than "one argument + alloc-like
name": the sole parameter must be proven to flow to an outbound send/write as a
SIZE value.  A size prompt may establish the role even when the parameter name
is arbitrary; promptless wrappers may use conventional size parameter names.
Helper names only disambiguate an already-proven structural shape.
"""
from __future__ import annotations

from pwnbao.features.heapviz.contracts import HelperContractResolver, lower_source_calls


PROMPT_BOUND_ARBITRARY_NAME = r'''
def allocate(amount):
    io.recvuntil(b"Choice: ")
    io.sendline(b"1")
    io.recvuntil(b"Size: ")
    io.sendline(str(amount))

allocate(0x80)
'''

PROMPTLESS_CONVENTIONAL_SIZE = r'''
def alloc(n):
    io.sendline(str(n))

alloc(0x90)
'''

ALLOC_NAME_WITHOUT_SIZE_EVIDENCE = r'''
def allocate(token):
    io.recvuntil(b"Token: ")
    io.sendline(token)
'''

ALLOC_NAME_WITHOUT_PARAMETER_FLOW = r'''
def allocate(size):
    io.recvuntil(b"Size: ")
    io.sendline(b"fixed")
'''

NON_ALLOC_SIZE_SENDER = r'''
def resize(size):
    io.recvuntil(b"Size: ")
    io.sendline(str(size))
'''


def _contract(source: str, function: str):
    resolution = HelperContractResolver().resolve(source)
    contract = resolution.contract_for(function)
    assert contract is not None, resolution.diagnostics
    return contract, resolution


def test_prompt_binds_arbitrary_parameter_to_size_only_alloc() -> None:
    contract, resolution = _contract(PROMPT_BOUND_ARBITRARY_NAME, "allocate")
    assert contract.operation.value == "alloc"
    assert contract.roles["size"].parameter == "amount"
    assert any(item.source.name == "STRUCTURAL_BODY" for item in contract.evidence)
    assert any(item.startswith("size_only_alloc:allocate:") for item in resolution.diagnostics)


def test_promptless_conventional_size_name_is_supported() -> None:
    contract, _ = _contract(PROMPTLESS_CONVENTIONAL_SIZE, "alloc")
    assert contract.operation.value == "alloc"
    assert contract.roles["size"].parameter == "n"


def test_alloc_like_name_alone_does_not_prove_size_role() -> None:
    contract, _ = _contract(ALLOC_NAME_WITHOUT_SIZE_EVIDENCE, "allocate")
    assert contract.operation.value == "unknown"


def test_size_prompt_without_parameter_flow_does_not_promote() -> None:
    contract, _ = _contract(ALLOC_NAME_WITHOUT_PARAMETER_FLOW, "allocate")
    assert contract.operation.value == "unknown"


def test_non_alloc_candidate_is_not_promoted_by_size_shape() -> None:
    contract, _ = _contract(NON_ALLOC_SIZE_SENDER, "resize")
    assert contract.operation.value == "unknown"


def test_lowering_receives_promoted_size_role() -> None:
    resolution = HelperContractResolver().resolve(PROMPT_BOUND_ARBITRARY_NAME)
    operations = lower_source_calls(PROMPT_BOUND_ARBITRARY_NAME, resolution)
    assert len(operations) == 1
    operation = operations[0]
    assert operation.kind.value == "alloc"
    assert getattr(operation.menu_request, "value", None) == 0x80
