"""Regression (cycle-1): PROMPT_SYNC vs OUTPUT_DATA_FLOW evidence classes.

Protocol v1.2 §H, generic rules under test (no challenge names; synthetic
helpers only):

  R1  SHOW strong structural evidence requires OUTPUT_DATA_FLOW: a recv-family
      call whose result is consumed (assigned / returned / printed / flows
      into a computation).
  R2  A discarded recvuntil is PROMPT_SYNC: it proves interaction sync and
      argument binding only — never SHOW output evidence.
  R3  A discarded recv/recvn/recvline drops its value: no data flow, not SHOW
      evidence either.
  R4  FREE/DELETE never depends on OUTPUT_DATA_FLOW (independent positive
      evidence path). The pre-existing single-index-outbound + delete-verb
      disambiguation branch becomes reachable once prompt-syncs stop counting
      as recv evidence — locked here as the recorded downstream effect.
"""
from __future__ import annotations

from pwnbao.features.heapviz.contracts import HelperContractResolver

PROMPT_SYNC_ONLY = """
def view_slot(idx):
    io.recvuntil("Choice:")
    io.sendline("3")
    io.recvuntil("Position:")
    io.sendline(str(idx))
"""

CONSUMED_RECV = """
def view_slot(idx):
    io.recvuntil("Choice:")
    io.sendline("3")
    io.recvuntil("Position:")
    io.sendline(str(idx))
    blob = io.recv(64)
    return blob
"""

PRINTED_RECV = """
def view_slot(idx):
    io.recvuntil("Choice:")
    io.sendline("3")
    io.recvuntil("Position:")
    io.sendline(str(idx))
    log.info(io.recvline())
"""

BOUND_RECVUNTIL = """
def view_slot(idx):
    io.recvuntil("Choice:")
    io.sendline("3")
    io.recvuntil("Position:")
    io.sendline(str(idx))
    marker = io.recvuntil("Done")
    return marker
"""

DISCARDED_RECVLINE = """
def view_slot(idx):
    io.recvuntil("Choice:")
    io.sendline("3")
    io.recvuntil("Position:")
    io.sendline(str(idx))
    io.recvline()
"""

SINGLE_INDEX_OUTBOUND_DELETE = """
def remove_slot(idx):
    io.recvuntil("Choice:")
    io.sendline("4")
    io.recvuntil("Position:")
    io.sendline(str(idx))
"""

SIZE_AND_DATA_SHAPE = """
def make_entry(size, content):
    io.recvuntil("Choice:")
    io.sendline("1")
    io.recvuntil("Length:")
    io.sendline(str(size))
    io.recvuntil("Data:")
    io.sendline(content)
"""


def _contract(source: str, function: str):
    resolution = HelperContractResolver().resolve(source)
    contract = resolution.contract_for(function)
    assert contract is not None, f"no contract for {function}: {resolution.diagnostics}"
    return contract


def _evidence_sources(contract) -> set[str]:
    return {getattr(e.source, "name", str(e.source)) for e in contract.evidence}


def test_r2_prompt_sync_only_body_is_not_structural_show() -> None:
    contract = _contract(PROMPT_SYNC_ONLY, "view_slot")
    assert contract.operation.value == "unknown"
    assert "STRUCTURAL_BODY" not in _evidence_sources(contract)


def test_r1_consumed_recv_proves_show() -> None:
    contract = _contract(CONSUMED_RECV, "view_slot")
    assert contract.operation.value == "show"
    assert "STRUCTURAL_BODY" in _evidence_sources(contract)
    assert contract.roles["index"].parameter == "idx"


def test_r1_printed_recv_argument_proves_show() -> None:
    contract = _contract(PRINTED_RECV, "view_slot")
    assert contract.operation.value == "show"
    assert "STRUCTURAL_BODY" in _evidence_sources(contract)


def test_r1_bound_recvuntil_proves_show() -> None:
    contract = _contract(BOUND_RECVUNTIL, "view_slot")
    assert contract.operation.value == "show"
    assert "STRUCTURAL_BODY" in _evidence_sources(contract)


def test_r3_discarded_recvline_is_not_output_dataflow() -> None:
    contract = _contract(DISCARDED_RECVLINE, "view_slot")
    assert contract.operation.value == "unknown"
    assert "STRUCTURAL_BODY" not in _evidence_sources(contract)


def test_r4_downstream_single_index_outbound_delete_verb() -> None:
    # Downstream-effect lock from cycle-1: with prompt-syncs no longer counting
    # as recv evidence, the pre-existing "single index outbound body; delete
    # verb disambiguates" branch is reachable again. FREE/DELETE does not
    # depend on OUTPUT_DATA_FLOW (v1.2 §H).
    contract = _contract(SINGLE_INDEX_OUTBOUND_DELETE, "remove_slot")
    assert contract.operation.value == "delete"
    assert "STRUCTURAL_BODY" in _evidence_sources(contract)


def test_send_shapes_still_prove_alloc() -> None:
    # Sanity: interaction send shapes (size + data) keep proving ALLOC — the
    # evidence reclassification must not disturb send-based proofs.
    contract = _contract(SIZE_AND_DATA_SHAPE, "make_entry")
    assert contract.operation.value == "alloc"
    assert "STRUCTURAL_BODY" in _evidence_sources(contract)
