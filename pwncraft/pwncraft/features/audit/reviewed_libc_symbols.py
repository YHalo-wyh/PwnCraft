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
class ReviewedLibcBaseAnchor:
    symbol: str
    upstream_fact_kind: str = "libc_base_formula"
    upstream_symbol_offset_key: str = "stdout_symbol_offset"

    def validate(self) -> None:
        if not self.symbol.strip() or not self.upstream_fact_kind.strip() or not self.upstream_symbol_offset_key.strip():
            raise ValueError("libc base anchor identity must be complete")


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
    base_anchor: ReviewedLibcBaseAnchor
    requests: tuple[ReviewedLibcSymbolRequest, ...]
    provenance: str = "REVIEWED_RUNTIME_LIBC_SYMBOL_POLICY"

    def validate(self) -> None:
        if not self.name.strip() or not self.requests:
            raise ValueError("libc symbol policy identity/requests are required")
        self.base_anchor.validate()
        roles: set[str] = set()
        for request in self.requests:
            request.validate()
            if request.role in roles:
                raise ValueError("libc symbol request roles must be unique")
            roles.add(request.role)


def _observed_libc_base_fact(upstream: dict[str, Any]) -> dict[str, Any] | None:
    if upstream.get("runtime_observed") is not True:
        return None
    if "libc_base_derived_from_stdout_observation" not in (upstream.get("capabilities") or []):
        return None
    for fact in upstream.get("facts") or []:
        if isinstance(fact, dict) and fact.get("kind") == "libc_base_formula":
            return fact
    return None


def _artifact_matches_base_anchor(
    libc: ElfArtifactSnapshot,
    base_fact: dict[str, Any],
    anchor: ReviewedLibcBaseAnchor,
) -> bool:
    if base_fact.get("kind") != anchor.upstream_fact_kind:
        return False
    reviewed_offset = base_fact.get(anchor.upstream_symbol_offset_key)
    if not isinstance(reviewed_offset, int):
        return False
    symbol = resolve_symbol(libc, anchor.symbol)
    return symbol is not None and symbol.value == reviewed_offset


def derive_reviewed_runtime_libc_symbols(
    libc: ElfArtifactSnapshot,
    libc_base_upstream: dict[str, Any],
    policy: ReviewedLibcSymbolPolicy,
) -> dict[str, Any] | None:
    """Resolve exact runtime symbol addresses from one artifact-anchored base."""
    policy.validate()
    if libc.degraded or libc.elf_type != "DYN":
        return None
    base_fact = _observed_libc_base_fact(libc_base_upstream)
    if base_fact is None or not _artifact_matches_base_anchor(libc, base_fact, policy.base_anchor):
        return None
    libc_base = base_fact.get("result")
    if not isinstance(libc_base, int) or libc_base < 0:
        return None

    facts: list[dict[str, Any]] = [{
        "kind": "reviewed_libc_base_artifact_anchor",
        "anchor_symbol": policy.base_anchor.symbol,
        "anchor_symbol_offset": base_fact[policy.base_anchor.upstream_symbol_offset_key],
        "libc_base": libc_base,
        "libc_sha256": libc.artifact_sha256,
    }]
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
            "base_anchor": asdict(policy.base_anchor),
            "requests": [asdict(item) for item in policy.requests],
            "provenance": policy.provenance,
        },
        "facts": facts,
        "bindings": bindings,
        "capabilities": ["reviewed_runtime_libc_symbols_resolved"],
        "provenance": policy.provenance,
        "limitations": [
            "the runtime base is accepted only when its reviewed anchor offset matches this exact libc artifact",
            "resolved symbol addresses are artifact/runtime facts, not exploit capabilities",
            "a resolved executable symbol does not prove any dispatch reaches it",
            "a resolved writable libc object does not prove the object can be safely replaced or used as FILE state",
        ],
    }
