from pwncraft.core.capability import analyze_capabilities
from pwncraft.core.workspace import AddressKind, PwnWorkspace, TypedAddress, WorkspaceVariable


def _caps(workspace: PwnWorkspace):
    return {item.name: item for item in analyze_capabilities(workspace)}


def test_typed_libc_base_variable_feeds_ret2libc_capability() -> None:
    workspace = PwnWorkspace()
    workspace.set_gadgets(
        [{"instructions": ["pop rdi", "ret"], "controls": ["rdi"]}],
        source="ROPgadget",
    )
    workspace.symbols.update({
        "got": {"puts": 0x404018},
        "plt": {"puts": 0x401020},
    })
    workspace.set_variable(WorkspaceVariable(
        "libc_base",
        TypedAddress(0x7FFFF7A00000, AddressKind.LIBC_OFFSET, "libc_base"),
        "LeakManager",
        "0x7ffff7a52290 - 0x52290",
        address_kind=AddressKind.LIBC_OFFSET,
    ))

    capability = _caps(workspace)["ret2libc"]
    assert capability.state == "available"
    assert any("libc_base=0x7ffff7a00000" in reason for reason in capability.reasons)


def test_unparseable_libc_variable_does_not_become_a_base() -> None:
    workspace = PwnWorkspace()
    workspace.set_variable(WorkspaceVariable(
        "libc_base",
        "unknown_base",
        "manual",
        state="unknown",
    ))
    capability = _caps(workspace)["ret2libc"]
    assert capability.state == "blocked"
    assert any("libc_base" in item for item in capability.missing)
