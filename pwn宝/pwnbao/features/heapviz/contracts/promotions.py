from __future__ import annotations

import ast
import re
from dataclasses import replace

from pwnbao.features.heapviz.source_compat import parse_module_source
from pwnbao.features.heapviz.semantics.canonical_ir import CanonicalOperationKind

from .model import (
    ArgumentBinding,
    ContractConfidence,
    ContractEvidence,
    ContractEvidenceSource,
    ContractStatus,
)
from .resolver import (
    ContractResolution,
    HelperContractResolver as _BaseHelperContractResolver,
    lower_source_calls as _base_lower_source_calls,
)


_SIZE_NAMES = {
    "size", "sz", "request", "request_size", "length", "len", "n",
    "count", "bytes", "amount", "capacity",
}
_PROMPT_ROLES = {
    "index": ("index", "idx", "slot", "id", "number", "note"),
    "size": ("size", "length", "len", "bytes", "malloc", "capacity"),
    "offset": ("offset", "off", "position"),
    "data": ("content", "data", "payload", "text", "message", "name"),
}
_SEND_VERBS = {
    "send", "sendline", "sendafter", "sendlineafter", "sendthen",
    "sendlinethen", "sa", "sla", "sl", "s", "write", "writeline",
}
_PROMPT_RECV_VERBS = {"recvuntil", "ru", "readuntil"}


def _call_name(call: ast.Call) -> str:
    node = call.func
    if isinstance(node, ast.Name):
        return node.id.lower()
    if isinstance(node, ast.Attribute):
        return node.attr.lower()
    return ""


def _literal_text(call: ast.Call) -> str:
    values: list[str] = []
    for argument in [*call.args, *(kw.value for kw in call.keywords)]:
        for node in ast.walk(argument):
            if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
                value = node.value.decode(errors="ignore") if isinstance(node.value, bytes) else node.value
                values.append(value)
    return " ".join(values)


def _prompt_role(text: str) -> str:
    normalized = re.sub(r"[^a-z0-9_]+", " ", (text or "").lower())
    for role, words in _PROMPT_ROLES.items():
        if any(re.search(rf"\b{re.escape(word)}\b", normalized) for word in words):
            return role
    return ""


def _argument_uses_parameter(call: ast.Call, parameter: str) -> bool:
    for argument in [*call.args, *(kw.value for kw in call.keywords)]:
        if any(isinstance(node, ast.Name) and node.id == parameter for node in ast.walk(argument)):
            return True
    return False


def _size_outbound_flow(node: ast.FunctionDef | ast.AsyncFunctionDef, parameter: str) -> tuple[int, str] | None:
    """Prove that a single helper parameter is the outbound SIZE value.

    Prompt evidence wins over parameter spelling.  A promptless helper may use
    a conventional size parameter name, but merely having an alloc-like helper
    name is never enough: the parameter must actually flow into an outbound
    send/write call.
    """

    calls = sorted(
        (item for item in ast.walk(node) if isinstance(item, ast.Call)),
        key=lambda item: (int(getattr(item, "lineno", 0)), int(getattr(item, "col_offset", 0))),
    )
    parameter_role = "size" if parameter.lower() in _SIZE_NAMES else ""
    pending_prompt_role = ""

    for call in calls:
        verb = _call_name(call)
        if verb in _PROMPT_RECV_VERBS:
            role = _prompt_role(_literal_text(call))
            pending_prompt_role = role or ""
            continue

        is_send = verb in _SEND_VERBS or "send" in verb
        if not is_send:
            continue

        uses_parameter = _argument_uses_parameter(call, parameter)
        inline_prompt_role = _prompt_role(_literal_text(call)) if verb in {"sendafter", "sendlineafter", "sa", "sla"} else ""
        observed_role = inline_prompt_role or pending_prompt_role or parameter_role
        line = int(getattr(call, "lineno", 0))

        # A send consumes the immediately preceding prompt context.  This
        # prevents a stale "Size:" recv from accidentally labelling a later
        # unrelated outbound value.
        pending_prompt_role = ""

        if uses_parameter and observed_role == "size":
            source = "prompt-bound" if (inline_prompt_role or observed_role != parameter_role) else "parameter-bound"
            return line, f"single outbound parameter is SIZE ({source})"

    return None


def _definitions(tree: ast.Module):
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield "", node
        elif isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    yield node.name, child


class HelperContractResolver(_BaseHelperContractResolver):
    """Base resolver plus generic evidence promotions used by later cycles.

    Cycle-4 adds the classic size-only allocation shape without challenge-name
    hardcoding.  An ALLOC name candidate may only disambiguate after structural
    evidence proves a single helper parameter is the outbound SIZE value.
    """

    def resolve(self, source: str) -> ContractResolution:
        base = super().resolve(source)
        tree, _parse_error = parse_module_source(source or "")
        if tree is None:
            return base

        replacements = {contract.key: contract for contract in base.contracts}
        diagnostics = list(base.diagnostics)

        for receiver, node in _definitions(tree):
            contract = base.contract_for(node.name, receiver)
            if contract is None:
                continue
            if contract.status is not ContractStatus.ACTIVE:
                continue
            if contract.operation is not CanonicalOperationKind.UNKNOWN:
                continue
            if contract.candidate_operation is not CanonicalOperationKind.ALLOC:
                continue
            if len(contract.signature.parameters) != 1:
                continue
            strongest = contract.strongest_evidence
            if strongest is not None and strongest >= ContractEvidenceSource.INLINE_ANNOTATION:
                # Explicit analyst/profile/user truth always outranks inferred
                # structural promotion, including an intentional UNKNOWN.
                continue

            parameter = contract.signature.parameters[0]
            flow = _size_outbound_flow(node, parameter)
            if flow is None:
                continue
            line, detail = flow
            roles = dict(contract.roles)
            roles["size"] = ArgumentBinding(
                role="size",
                parameter=parameter,
                expression=parameter,
                position=0,
            )
            replacements[contract.key] = replace(
                contract,
                operation=CanonicalOperationKind.ALLOC,
                confidence=ContractConfidence.STRUCTURAL,
                roles=roles,
                evidence=(*contract.evidence, ContractEvidence(
                    ContractEvidenceSource.STRUCTURAL_BODY,
                    f"{detail}; alloc candidate disambiguates proven size-only shape",
                    line,
                    0.93,
                )),
            )
            diagnostics.append(f"size_only_alloc:{contract.key}:{line}")

        ordered = tuple(replacements.get(contract.key, contract) for contract in base.contracts)
        return ContractResolution(ordered, tuple(dict.fromkeys(diagnostics)))


def lower_source_calls(source: str, resolution: ContractResolution | None = None):
    """Lower with the promoted resolver even when callers omit a resolution."""

    resolution = resolution or HelperContractResolver().resolve(source)
    return _base_lower_source_calls(source, resolution)
