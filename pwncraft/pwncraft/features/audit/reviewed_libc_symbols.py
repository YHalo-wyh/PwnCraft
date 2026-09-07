"""Runtime-bound libc symbol evidence from an exact ELF artifact.

A runtime libc base is useful only when it is tied to the exact libc artifact
whose symbol table is being queried.  This layer resolves requested symbols and
checks role-specific executable/writable properties without inferring exploit
semantics from symbol names.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from pwncraft.core.elf_artifact_provider import (
    ElfArtifactSnapshot,
    address_is_executable,
    address_is_runtime_writable,
    resolve_symbol,
    runtime_symbol_address,
)


@dataclass(frozen=True)
class ReviewedLibcSymbolRequest:
    role: str
    symbol: str
    require_executable: bool = False
    require_runtime_writable: bool = False

    def validate(self) -> None:
        if not self.role.strip() or not self.symbol.strip():
            raise ValueError("libc symbol request role/name must be non-empty")
        if self.require_executable and self.require_runtime_writable:
            raise ValueError("one symbol request cannot require executable and writable simultaneously")


@dataclass(frozen=True)
class ReviewedLibcSymbolPolicy:
    name: str
    requests: tuple[ReviewedLibcSymbolRequest, ...]
    provenance: str = "REVIEWED_RUNTIME_LIBC_SYMBOL_POLICY"

    def validate(self) -> None:
        if not self.name.strip() or not self.requests:
            raise ValueError("libc symbol policy identity/requests are required")
        roles: set[str] = set()
        for request in self.requests:
            request.validate()
            if request.role in roles:
                raise ValueError("libc symbol request roles must be unique")
            roles.add(request.role)


def _observed_libc_base(upstream: dict[str, Any]) -> int | None:
    if upstream.get("runtime_observed") is not True:
        return None
    if "libc_base_derived_from_stdout_observation" not in (upstream.get("capabilities") or []):
        return None
    for fact in upstream.get("facts") or []:
        if isinstance(fact, dict) and fact.get("kind") == "libc_base_formula":
            value = fact.get("result")
            return int(value) if isinstance(value, int) else None
    return None


def derive_reviewed_runtime_libc_symbols(
    libc: ElfArtifactSnapshot,
    libc_base_upstream: dict[str, Any],
    policy: ReviewedLibcSymbolPolicy,
) -> dict[str, Any] | None:
    """Resolve exact runtime symbol addresses from one observed libc base."""
    policy.validate()
    if libc.degraded or libc.elf_type != "DYN":
        return None
    libc_base = _observed_libc_base(libc_base_upstream)
    if libc_base is None:
        return None

    facts: list[dict[str, Any]] = []
    bindings: dict[str, int] = {}
    for request in policy.requests:
        symbol = resolve_symbol(libc, request.symbol)
        if symbol is None:
            return None
        if request.require_executable and not address_is_executable(libc, symbol.value):
            return None
        if request.require_runtime_writable and not address_is_runtime_writable(libc, symbol.value):
            return None
        runtime = runtime_symbol_address(libc, request.symbol, load_base=libc_base)
        if runtime is None:
            return None
        bindings[request.role] = runtime
        facts.append({
            "kind": "reviewed_runtime_libc_symbol",
            "role": request.role,
            "symbol": request.symbol,
            "resolved_symbol_name": symbol.name,
            "symbol_type": symbol.symbol_type,
            "symbol_offset": symbol.value,
            "runtime_address": runtime,
            "requires_executable": request.require_executable,
            "requires_runtime_writable": request.require_runtime_writable,
        })

    return {
        "kind": "reviewed_runtime_libc_symbol_bindings",
        "state": "derived_runtime_bound",
        "runtime_observed": True,
        "artifact": {
            "libc_sha256": libc.artifact_sha256,
            "artifact_name": libc.artifact_name,
        },
        "libc_base": libc_base,
        "policy": {
            "name": policy.name,
            "requests": [asdict(item) for item in policy.requests],
            "provenance": policy.provenance,
        },
        "facts": facts,
        "bindings": bindings,
        "capabilities": ["reviewed_runtime_libc_symbols_resolved"],
        "provenance": policy.provenance,
        "limitations": [
            "resolved symbol addresses are artifact/runtime facts, not exploit capabilities",
            "a resolved executable symbol does not prove any dispatch reaches it",
            "a resolved writable libc object does not prove the object can be safely replaced or used as FILE state",
        ],
    }
