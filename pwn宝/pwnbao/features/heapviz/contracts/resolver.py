from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass, replace
from typing import Iterable, Mapping

from pwnbao.features.heapviz.contracts.aliases import assignment_aliases, name_candidate, partial_aliases
from pwnbao.features.heapviz.source_compat import parse_module_source
from pwnbao.features.heapviz.contracts.model import (
    ArgumentBinding,
    CanonicalEffect,
    ContractConfidence,
    ContractEvidence,
    ContractEvidenceSource,
    ContractStatus,
    FunctionSignature,
    HelperContract,
)
from pwnbao.features.heapviz.semantics.canonical_ir import (
    CanonicalHeapOperation,
    CanonicalOperationKind,
    CanonicalSourceBinding,
    SemanticConfidence,
)
from pwnbao.features.heapviz.semantics.values import LengthExpr, UnknownValue, byte_length, evaluate_value


_ROLE_ALIASES = {
    "index": {"idx", "index", "id", "slot", "pos", "key", "no", "num", "entry", "handle"},
    "size": {"size", "sz", "request", "request_size", "length", "len", "n", "count", "bytes"},
    "offset": {"offset", "off", "start", "where", "seek"},
    "data": {"data", "content", "payload", "text", "msg", "value", "buf", "body", "name", "note"},
    "src": {"src", "source", "from_idx", "old_idx"},
    "dst": {"dst", "dest", "destination", "to_idx", "target_idx", "new_idx"},
}
_PROMPT_ROLES = {
    "index": ("index", "idx", "slot", "id", "number", "note"),
    "size": ("size", "length", "len", "bytes", "malloc"),
    "offset": ("offset", "off", "position"),
    "data": ("content", "data", "payload", "text", "message", "name"),
}
_SEND = {"send", "sendline", "sendafter", "sendlineafter", "sa", "sla", "sl", "s", "write", "writeline"}
_RECV = {"recv", "recvn", "recvline", "recvuntil", "read", "readline", "ru", "rl"}


@dataclass(frozen=True)
class ContractResolution:
    contracts: tuple[HelperContract, ...]
    diagnostics: tuple[str, ...] = ()

    def contract_for(self, function: str, receiver: str = "") -> HelperContract | None:
        exact = [item for item in self.contracts if item.function == function and item.receiver == receiver]
        if len(exact) == 1:
            return exact[0]
        if not receiver:
            plain = [item for item in self.contracts if item.function == function and not item.receiver]
            return plain[0] if len(plain) == 1 else None
        suffix = [item for item in self.contracts if item.function == function and item.receiver in {receiver, receiver.split(".")[-1]}]
        return suffix[0] if len(suffix) == 1 else None

    @property
    def proven(self) -> tuple[HelperContract, ...]:
        return tuple(item for item in self.contracts if item.proven)


def _arg_text(node) -> str:
    try:
        return ast.unparse(node).strip()
    except Exception:
        return ""


_RECV_VERBS = {"recv", "recvn", "recvline", "recvall", "recvuntil",
               "recvuntilrepeat", "recvrepeat"}
_SEND_VERBS = {"send", "sendline", "sendafter", "sendlineafter",
               "sendthen", "sendlinethen"}


class HelperContractResolver:
    """AST-only resolver. Names recall candidates; only evidence proves semantics."""

    def __init__(
        self,
        user_contracts: Iterable[HelperContract | Mapping[str, object]] = (),
        imported_contracts: Iterable[HelperContract | Mapping[str, object]] = (),
        max_wrapper_depth: int = 12,
    ) -> None:
        self.user_contracts = tuple(_as_contract(item) for item in user_contracts)
        self.imported_contracts = tuple(_as_contract(item) for item in imported_contracts)
        self.max_wrapper_depth = max(1, int(max_wrapper_depth))

    def resolve(self, source: str) -> ContractResolution:
        tree, parse_error = parse_module_source(source or "")
        if tree is None:
            error = parse_error
            return ContractResolution((), (f"syntax_error:{error.lineno}:{error.msg}",))
        lines = (source or "").splitlines()
        definitions: dict[str, tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = {}
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                definitions[node.name] = ("", node)
            elif isinstance(node, ast.ClassDef):
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        definitions[f"{node.name}.{child.name}"] = (node.name, child)
        contracts: dict[str, HelperContract] = {}
        diagnostics: list[str] = []

        for key, (receiver, node) in definitions.items():
            fingerprint = function_fingerprint(node)
            selected = self._stored_contract(node.name, receiver, fingerprint, diagnostics)
            annotation = _inline_annotation(node, lines)
            if annotation:
                selected = _annotation_contract(node, receiver, fingerprint, annotation)
            structural = _structural_contract(node, receiver, fingerprint)
            if structural and (selected is None or _evidence_rank(structural) > _evidence_rank(selected)):
                selected = structural
            if selected is None:
                candidate = _kind_from_text(name_candidate(node.name))
                selected = _candidate_contract(node, receiver, fingerprint, candidate)
            contracts[key] = selected

        aliases = assignment_aliases(tree)
        for alias, target in aliases.items():
            base = contracts.get(target)
            if base is None:
                continue
            contracts[alias] = replace(
                base,
                contract_id=_contract_id("", alias, base.function_fingerprint),
                function=alias,
                receiver="",
                evidence=(*base.evidence, ContractEvidence(ContractEvidenceSource.SAFE_ALIAS, f"exact alias of {target}", score=0.88)),
                confidence=ContractConfidence.INFERRED,
            )

        partials = partial_aliases(tree)
        for alias, (callee, fixed_args, fixed_keywords) in partials.items():
            base = contracts.get(callee)
            if base is None or not base.proven:
                continue
            contracts[alias] = _partial_contract(alias, base, fixed_args, fixed_keywords)

        # Fixed-point wrapper propagation. A cycle simply reaches no new proof.
        for _depth in range(self.max_wrapper_depth):
            changed = False
            for key, (receiver, node) in definitions.items():
                current = contracts[key]
                if current.proven and _evidence_rank(current) >= ContractEvidenceSource.STRUCTURAL_BODY:
                    continue
                wrapper = _wrapper_contract(node, receiver, current.function_fingerprint, contracts)
                if wrapper and (not current.proven or _evidence_rank(wrapper) > _evidence_rank(current)):
                    contracts[key] = wrapper
                    changed = True
            if not changed:
                break
        else:
            diagnostics.append(f"wrapper_depth_limit:{self.max_wrapper_depth}")

        for component in _wrapper_cycles(definitions):
            diagnostics.append("wrapper_cycle:" + "->".join(component))

        self._callsite_output_flow_promotion(tree, contracts, diagnostics)

        ordered = tuple(sorted(contracts.values(), key=lambda item: (item.receiver, item.function)))
        return ContractResolution(ordered, tuple(dict.fromkeys(diagnostics)))

    # ------------------------------------------------------------------
    # VNext.2 M2: 调用点级 OUTPUT_DATA_FLOW 促销 (确定性, 纯 AST)。
    #
    # 规则: 入口函数 (main/exp/pwn/solve/attack) 体内, 若一个「unknown 语义
    # 且仅绑定 index 角色」的 helper 调用之后、下一个 helper/send 之前, 出现
    # 被消费的 recv 族调用 (赋值给变量且该变量随后被读取, 或作为表达式子项),
    # 则该 helper 的语义为 SHOW —— 证据 CALLSITE_OUTPUT_FLOW (structural 级:
    # 来自 EXP 自身的 AST 结构, 非 prompt-sync 猜测)。
    #
    # 只促销 SHOW 候选; DELETE 候选需动词证据 (precision-first)。
    # ------------------------------------------------------------------
    def _callsite_output_flow_promotion(self, tree, contracts, diagnostics):
        entry_names = {"main", "exp", "pwn", "solve", "attack"}
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in entry_names:
                self._promote_in_body(node, contracts, diagnostics)
        # 模块级脚本型 EXP (无入口函数): 顶层语句流本身即调用序列。
        # helper 定义体不参与 (其调用经 helper 调用点的内联展开处理)。
        if not any(isinstance(n, ast.FunctionDef) and n.name in entry_names
                   for n in tree.body):
            module_stmts = [st for st in tree.body
                            if not isinstance(st, ast.FunctionDef)]
            self._promote_in_body(module_stmts, contracts, diagnostics,
                                  scope="module")

    def _promote_in_body(self, entry_node, contracts, diagnostics, scope="main"):
        """两遍确定性扫描:
        A. 收集入口体内 recv 结果赋值 (var -> line) 与每个 var 的全部 load 行;
        B. 按行回放事件流 —— pending helper 调用之后若发生 recv 变量的
           消费 load, 促销该 helper 为 SHOW (证据 CALLSITE_OUTPUT_FLOW)。
        DELETE 候选不走此路径 (precision-first); 不足即 UNKNOWN。"""
        recv_assign: dict[str, int] = {}
        var_loads: dict[str, set[int]] = {}
        events: list[tuple[int, int, str, str]] = []

        if isinstance(entry_node, ast.FunctionDef):
            stmts = sorted((st for st in ast.walk(entry_node)
                            if isinstance(st, (ast.Assign, ast.Expr,
                                               ast.Return))),
                           key=lambda st: getattr(st, "lineno", 0))
        else:
            stmts = entry_node

        def classify_call(call):
            return _qualified_name(call.func).rsplit(".", 1)[-1].lower()

        for st in stmts:
            line = getattr(st, "lineno", 0)
            for n in ast.walk(st):
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                    var_loads.setdefault(n.id, set()).add(line)
            if isinstance(st, ast.Assign) and isinstance(st.value, ast.Call):
                verb = _qualified_name(st.value.func).rsplit(".", 1)[-1].lower()
                if verb in _RECV_VERBS and st.targets and isinstance(st.targets[0], ast.Name):
                    recv_assign[st.targets[0].id] = line
            for call in [c for c in ast.walk(st) if isinstance(c, ast.Call)]:
                verb = classify_call(call)
                if verb in _RECV_VERBS:
                    events.append((line, 1, "recv", ""))
                elif verb in _SEND_VERBS:
                    events.append((line, 1, "send", ""))

        for name, contract in contracts.items():
            if (contract.operation is CanonicalOperationKind.UNKNOWN
                    and set(contract.roles) <= {"index"}
                    and contract.candidate_operation
                    in (CanonicalOperationKind.SHOW,
                        CanonicalOperationKind.UNKNOWN)):
                # unknown 语义 + 仅 index 角色 (owner 批准规则);
                # 调用点后消费 recv 才促销 —— DELETE 候选需动词证据
                call_lines = []
                for st in (entry_node if isinstance(entry_node, list)
                           else [entry_node]):
                    for c in ast.walk(st):
                        if isinstance(c, ast.Call) and                                 _qualified_name(c.func).rsplit(".", 1)[-1] == name:
                            call_lines.append(getattr(c, "lineno", 0))
                for cl in call_lines:
                    events.append((cl, 2, "helper_pending", name))

        # consume 事件: recv 变量在其赋值行之后被 load
        consume_events = []
        for var, assign_line in recv_assign.items():
            for load_line in sorted(var_loads.get(var, ())):
                if load_line > assign_line:
                    consume_events.append((load_line, 1, "consume", var))
                    break
        events.extend(consume_events)

        events.sort(key=lambda e: (e[0], 0 if e[2] == "helper_pending" else 1))
        pending: tuple[str, int] | None = None
        promoted: set[str] = set()
        for line, _order, kind, arg in events:
            if kind == "helper_pending":
                pending = (arg, line)
            elif kind == "send":
                pending = None
            elif kind == "consume":
                if pending is None:
                    continue
                name, call_line = pending
                var = arg
                if var in promoted or name in promoted:
                    continue
                contract = contracts.get(name)
                if contract is None:
                    continue
                promoted.add(name)
                # 从调用点实参构造 index 角色绑定 (首个实参 = 槽位选择)
                parameters = contract.signature.parameters
                param0 = parameters[0] if parameters else ""
                call_args_text = []
                for st in (entry_node if isinstance(entry_node, list)
                           else [entry_node]):
                    for c in ast.walk(st):
                        if isinstance(c, ast.Call) \
                                and _qualified_name(c.func).rsplit(".", 1)[-1] == name \
                                and getattr(c, "lineno", 0) == line:
                            call_args_text.append(_arg_text(c))
                index_binding = ArgumentBinding(
                    role="index", parameter=param0,
                    expression=call_args_text[0] if call_args_text else "",
                    position=0)
                contracts[name] = replace(
                    contract,
                    operation=CanonicalOperationKind.SHOW,
                    confidence=ContractConfidence.STRUCTURAL,
                    roles={"index": index_binding},
                    evidence=(*contract.evidence, ContractEvidence(
                        ContractEvidenceSource.CALLSITE_OUTPUT_FLOW,
                        f"callsite output dataflow: recv result of "
                        f"{name}(...) consumed at line {line}",
                        line, 0.9)),
                )
                diagnostics.append(f"callsite_output_flow:{name}:{line}")
        events.sort(key=lambda e: (e[0], 0 if e[2] != "send" else 1))
        pending = None
        promoted = set()
        for line, _order, kind, arg in events:
            if kind == "helper_pending":
                pending = (arg, line)
            elif kind == "send":
                pending = None
            elif kind == "consume":
                if pending is None or arg in promoted:
                    continue
                name, _call_line = pending
                contract = contracts.get(name)
                if contract is None or name in promoted:
                    continue
                promoted.add(name)
                contracts[name] = replace(
                    contract,
                    operation=CanonicalOperationKind.SHOW,
                    confidence=ContractConfidence.STRUCTURAL,
                    evidence=(*contract.evidence, ContractEvidence(
                        ContractEvidenceSource.CALLSITE_OUTPUT_FLOW,
                        f"callsite output dataflow: recv result of "
                        f"{name}(...) consumed at line {line}",
                        line, 0.9)),
                )
                diagnostics.append(f"callsite_output_flow:{name}:{line}")


    def _stored_contract(
        self,
        function: str,
        receiver: str,
        fingerprint: str,
        diagnostics: list[str],
    ) -> HelperContract | None:
        for source, contracts in (
            (ContractEvidenceSource.USER_CONFIRMED, self.user_contracts),
            (ContractEvidenceSource.IMPORTED_PROFILE, self.imported_contracts),
        ):
            for contract in contracts:
                if contract.function != function or contract.receiver != receiver:
                    continue
                if contract.function_fingerprint and contract.function_fingerprint != fingerprint:
                    diagnostics.append(f"stale_contract:{contract.contract_id}:{function}")
                    return replace(contract, status=ContractStatus.STALE, confidence=ContractConfidence.UNKNOWN)
                confidence = ContractConfidence.CONFIRMED if source is ContractEvidenceSource.USER_CONFIRMED else ContractConfidence.STRUCTURAL
                return replace(
                    contract,
                    function_fingerprint=fingerprint,
                    status=ContractStatus.ACTIVE,
                    confidence=confidence,
                    evidence=(*contract.evidence, ContractEvidence(source, "stored contract matched fingerprint", score=1.0)),
                )
        return None


def lower_source_calls(source: str, resolution: ContractResolution | None = None) -> tuple[CanonicalHeapOperation, ...]:
    resolution = resolution or HelperContractResolver().resolve(source)
    tree, _parse_error = parse_module_source(source or "")
    if tree is None:
        return ()
    try:
        from pwnbao.features.heapviz.payload import collect_payload_assignments

        module_assignments = collect_payload_assignments(source)
    except Exception:  # pragma: no cover - payload collector must never block lowering
        module_assignments = {}
    parent: dict[ast.AST, ast.AST] = {}
    instance_types: dict[str, str] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[child] = node
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Call):
            class_name = _qualified_name(node.value.func)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and class_name:
                    instance_types[target.id] = class_name
    operations: list[CanonicalHeapOperation] = []
    counter = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function, receiver = _call_target(node.func)
        receiver_type = instance_types.get(receiver.split(".", 1)[0], "") if receiver else ""
        contract = resolution.contract_for(function, receiver_type or receiver)
        if contract is None or not contract.proven:
            continue
        enclosing = _enclosing_definition(node, parent)
        if enclosing is not None:
            enclosing_contract = resolution.contract_for(enclosing.name)
            if enclosing_contract is not None and enclosing_contract.proven:
                continue
        bound = _bind_call(contract.signature, node)
        # Module-level payload assignments (payload = b"A" * 0x40 + p64(0)) are
        # folded into role expressions so len(payload) concretizes instead of
        # staying a symbolic name.  Call arguments win over module assignments.
        bound = {**module_assignments, **bound}
        role_sources = {
            role: _substitute(binding.expression or binding.parameter, bound)
            for role, binding in contract.roles.items()
        }
        # Second pass resolves module-level payload names left inside
        # substituted role expressions (len(data) -> len(payload) -> the
        # actual builder expression), so len(payload) concretizes.
        role_sources = {
            role: _substitute(expression, module_assignments) for role, expression in role_sources.items()
        }
        payload_source = role_sources.get("data", "")
        payload = evaluate_value(payload_source) if payload_source else UnknownValue("payload not bound")
        length_source = role_sources.get("length", "")
        if length_source:
            length = evaluate_value(length_source)
        elif contract.operation is CanonicalOperationKind.EDIT:
            length = byte_length(payload)
            if isinstance(length, UnknownValue) and payload_source:
                length = LengthExpr(f"len({payload_source})", ())
        else:
            length = UnknownValue("length not bound")
        allocator_source = next((effect.expression for effect in contract.effects if effect.kind == "allocator_request"), "")
        allocator_source = _substitute(allocator_source, bound) if allocator_source else ""
        counter += 1
        source_text = ast.get_source_segment(source, node) or _unparse(node)
        operations.append(CanonicalHeapOperation(
            f"cop_{counter:03d}",
            contract.operation,
            handle=evaluate_value(role_sources.get("index", role_sources.get("target", ""))) if role_sources.get("index", role_sources.get("target", "")) else UnknownValue("handle not bound"),
            menu_request=evaluate_value(role_sources.get("size", "")) if role_sources.get("size") else UnknownValue("menu request not bound"),
            allocator_request=evaluate_value(allocator_source) if allocator_source else UnknownValue("allocator request unproven"),
            offset=evaluate_value(role_sources.get("offset", "0")),
            length=length,
            payload=payload,
            target=evaluate_value(role_sources.get("dst", role_sources.get("target", ""))) if role_sources.get("dst", role_sources.get("target", "")) else UnknownValue("target not bound"),
            source_binding=CanonicalSourceBinding(
                source_id=f"line:{getattr(node, 'lineno', 0)}",
                line=int(getattr(node, "lineno", 0)),
                source_text=source_text,
                fingerprint=hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()[:16],
            ),
            contract_id=contract.contract_id,
            confidence=_semantic_confidence(contract),
            provenance=tuple(item.source.name.lower() for item in contract.evidence),
        ))
    return tuple(sorted(operations, key=lambda item: (item.source_binding.line, item.operation_id)))


def function_fingerprint(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    stable = ast.Module(body=[node], type_ignores=[])
    return hashlib.sha256(ast.dump(stable, include_attributes=False).encode()).hexdigest()


def _signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> FunctionSignature:
    positional = [*node.args.posonlyargs, *node.args.args]
    names = [item.arg for item in positional]
    if names and names[0] in {"self", "cls"}:
        names = names[1:]
    defaults: list[tuple[str, str]] = []
    if node.args.defaults:
        for name, value in zip(names[-len(node.args.defaults):], node.args.defaults):
            defaults.append((name, _unparse(value)))
    defaults.extend(
        (arg.arg, _unparse(value))
        for arg, value in zip(node.args.kwonlyargs, node.args.kw_defaults)
        if value is not None
    )
    return FunctionSignature(
        tuple((*names, *(item.arg for item in node.args.kwonlyargs))),
        tuple(item.arg for item in node.args.posonlyargs if item.arg not in {"self", "cls"}),
        tuple(item.arg for item in node.args.kwonlyargs),
        tuple(defaults),
        node.args.vararg.arg if node.args.vararg else "",
        node.args.kwarg.arg if node.args.kwarg else "",
    )


def _inline_annotation(node: ast.FunctionDef | ast.AsyncFunctionDef, lines: list[str]) -> str:
    line = max(0, int(getattr(node, "lineno", 1)) - 2)
    collected: list[str] = []
    while line >= 0 and line >= int(getattr(node, "lineno", 1)) - 5:
        text = lines[line].strip() if line < len(lines) else ""
        if text.startswith("#"):
            if "pwnbao:" in text.lower():
                collected.append(text.split(":", 1)[1].strip())
            line -= 1
            continue
        if text:
            break
        line -= 1
    return " ".join(reversed(collected))


def _annotation_contract(node: ast.FunctionDef | ast.AsyncFunctionDef, receiver: str, fingerprint: str, annotation: str) -> HelperContract:
    pairs = dict(re.findall(r"([a-zA-Z_][\w]*)\s*=\s*([^\s,]+)", annotation))
    operation = _kind_from_text(pairs.pop("op", ""))
    roles = {
        role: ArgumentBinding(role, expression=expression, parameter=expression if expression in _signature(node).parameters else "")
        for role, expression in pairs.items()
        if role in {"index", "size", "data", "offset", "length", "src", "dst", "target"}
    }
    return HelperContract(
        _contract_id(receiver, node.name, fingerprint), node.name, receiver, operation, _signature(node), roles, (),
        (ContractEvidence(ContractEvidenceSource.INLINE_ANNOTATION, annotation, int(getattr(node, "lineno", 0)), 0.99),),
        ContractConfidence.CONFIRMED, fingerprint,
    )


def _structural_contract(node: ast.FunctionDef | ast.AsyncFunctionDef, receiver: str, fingerprint: str) -> HelperContract | None:
    signature = _signature(node)
    params = set(signature.parameters)
    sent: list[tuple[str, str]] = []
    recv = False
    literals: list[str] = []
    size_expression = ""
    # PROMPT_SYNC vs OUTPUT_DATA_FLOW (protocol v1.2 §H): a recv-family call
    # whose value is discarded (bare expression statement) carries no data
    # flow — an unused recvuntil only synchronizes a prompt, an unused recv
    # drops its value. Only consumed results (assigned / returned / printed /
    # flowing into a computation) are output data flow and may structurally
    # prove SHOW. FREE/DELETE never depends on this flag.
    discarded_calls = {
        id(parent.value)
        for parent in ast.walk(node)
        if isinstance(parent, ast.Expr) and isinstance(parent.value, ast.Call)
    }
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, (str, bytes, int)):
            text = child.value.decode(errors="ignore") if isinstance(child.value, bytes) else str(child.value)
            literals.append(text.lower())
        if not isinstance(child, ast.Call):
            continue
        short = _qualified_name(child.func).rsplit(".", 1)[-1].lower()
        if (short in _RECV or short.startswith("recv")) and id(child) not in discarded_calls:
            recv = True
        if short not in _SEND and "send" not in short:
            continue
        # send_size(...len(x)...) proves the allocator request size when the
        # helper first sends the byte length of a parameter (the common
        # pwntools addchunk(data) pattern: send_size(len(data)); send_data(data)).
        if "size" in short and child.args:
            first = child.args[0]
            if (
                isinstance(first, ast.Call)
                and isinstance(first.func, ast.Name)
                and first.func.id == "len"
                and first.args
                and isinstance(first.args[0], ast.Name)
            ):
                size_expression = f"len({first.args[0].id})"
            continue
        prompt = " ".join(
            str(item.value.decode(errors="ignore") if isinstance(item.value, bytes) else item.value).lower()
            for item in child.args
            if isinstance(item, ast.Constant) and isinstance(item.value, (str, bytes))
        )
        prompt_role = _prompt_role(prompt)
        for argument in child.args:
            for name in _names(argument) & params:
                sent.append((name, prompt_role))
    unique_sent = list(dict.fromkeys(sent))
    roles: dict[str, ArgumentBinding] = {}
    for position, parameter in enumerate(signature.parameters):
        role = _role_name(parameter)
        prompted = next((hint for name, hint in unique_sent if name == parameter and hint), "")
        role = prompted or role
        if role:
            roles.setdefault(role, ArgumentBinding(role, parameter, parameter, position))
    if size_expression:
        roles.setdefault("size", ArgumentBinding("size", expression=size_expression))

    literal_blob = " ".join(literals)
    candidate = _kind_from_text(name_candidate(node.name))
    operation = CanonicalOperationKind.UNKNOWN
    proof = ""
    # ``index + size + data`` is genuinely ambiguous in CTF wrappers: both
    # add(idx,size,data) and edit(idx,size,data) are common.  Structural body
    # shape proves the arguments but not the operation.  A helper-name verb may
    # DISAMBIGUATE an already-proven shape, but a name alone never proves one.
    if "offset" in roles and "data" in roles and ("index" in roles or len(roles) >= 2):
        operation, proof = CanonicalOperationKind.EDIT, "body sends offset and data"
    elif "index" in roles and "data" in roles and "size" in roles and unique_sent:
        if candidate is CanonicalOperationKind.EDIT:
            operation, proof = CanonicalOperationKind.EDIT, "index+size+data body; edit verb disambiguates"
        elif candidate is CanonicalOperationKind.ALLOC:
            operation, proof = CanonicalOperationKind.ALLOC, "index+size+data body; alloc verb disambiguates"
        else:
            # Keep UNKNOWN rather than silently turning an edit wrapper into an
            # allocation.  The candidate UI/user Contract can resolve it.
            return None
    elif "size" in roles and "data" in roles and (unique_sent or size_expression):
        operation, proof = CanonicalOperationKind.ALLOC, (
            "body sends len(data) size and data" if size_expression else "body sends size and data"
        )
    elif "data" in roles and "index" in roles and unique_sent:
        operation, proof = CanonicalOperationKind.EDIT, "body sends index and data"
    elif "index" in roles and recv:
        operation, proof = CanonicalOperationKind.SHOW, "body selects index then receives output"
    elif "index" in roles and unique_sent and any(word in literal_blob for word in ("delete", "free", "remove")):
        operation, proof = CanonicalOperationKind.DELETE, "body selects index with delete/free prompt"
    elif {"src", "dst"}.issubset(roles):
        operation, proof = CanonicalOperationKind.COPY, "body sends source and destination"
    elif candidate is CanonicalOperationKind.DELETE and "index" in roles and unique_sent and not recv:
        # Name is only disambiguating already-proven one-index outbound shape.
        operation, proof = candidate, "single index outbound body; delete verb disambiguates"
    if operation is CanonicalOperationKind.UNKNOWN:
        return None
    if operation is CanonicalOperationKind.EDIT:
        roles.setdefault("offset", ArgumentBinding("offset", expression="0", fixed=True))
        if "length" not in roles and "data" in roles:
            roles["length"] = ArgumentBinding("length", expression=f"len({roles['data'].expression})", fixed=True)
    return HelperContract(
        _contract_id(receiver, node.name, fingerprint), node.name, receiver, operation, signature, roles, (),
        (ContractEvidence(ContractEvidenceSource.STRUCTURAL_BODY, proof, int(getattr(node, "lineno", 0)), 0.94),),
        ContractConfidence.STRUCTURAL, fingerprint,
    )


def _candidate_contract(node: ast.FunctionDef | ast.AsyncFunctionDef, receiver: str, fingerprint: str, candidate: CanonicalOperationKind) -> HelperContract:
    return HelperContract(
        _contract_id(receiver, node.name, fingerprint), node.name, receiver, CanonicalOperationKind.UNKNOWN,
        _signature(node), {}, (),
        ((ContractEvidence(ContractEvidenceSource.NAME_CANDIDATE, f"name candidate: {candidate.value}", int(getattr(node, "lineno", 0)), 0.35),) if candidate is not CanonicalOperationKind.UNKNOWN else ()),
        ContractConfidence.CANDIDATE if candidate is not CanonicalOperationKind.UNKNOWN else ContractConfidence.UNKNOWN,
        fingerprint, candidate_operation=candidate,
    )


def _wrapper_contract(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    receiver: str,
    fingerprint: str,
    contracts: Mapping[str, HelperContract],
) -> HelperContract | None:
    proven_calls: list[tuple[ast.Call, HelperContract]] = []
    for call in (child for child in ast.walk(node) if isinstance(child, ast.Call)):
        callee_name, callee_receiver = _call_target(call.func)
        keys = [f"{callee_receiver}.{callee_name}" if callee_receiver else callee_name, callee_name]
        base = next((contracts[key] for key in keys if key in contracts and contracts[key].proven), None)
        if base is None:
            unique = [item for item in contracts.values() if item.function == callee_name and item.proven]
            base = unique[0] if len(unique) == 1 else None
        if base is None or base.function == node.name:
            continue
        proven_calls.append((call, base))
    # A wrapper denotes one transformed operation. Orchestration helpers such
    # as pwn()/main() contain many operations and must not collapse to the first.
    if len(proven_calls) != 1:
        return None
    for call, base in proven_calls:
        bound = _bind_call(base.signature, call)
        roles = {
            role: ArgumentBinding(role, expression=_substitute(binding.expression or binding.parameter, bound), fixed=True)
            for role, binding in base.roles.items()
        }
        return HelperContract(
            _contract_id(receiver, node.name, fingerprint), node.name, receiver, base.operation, _signature(node), roles,
            tuple(CanonicalEffect(item.kind, item.target, _substitute(item.expression, bound)) for item in base.effects),
            (ContractEvidence(ContractEvidenceSource.WRAPPER, f"wrapper propagates {base.key}", int(getattr(call, "lineno", 0)), 0.89),),
            ContractConfidence.INFERRED, fingerprint,
        )
    return None


def _partial_contract(alias: str, base: HelperContract, fixed_args: tuple[str, ...], fixed_keywords: dict[str, str]) -> HelperContract:
    bound = dict(zip(base.signature.parameters, fixed_args))
    bound.update(fixed_keywords)
    remaining = tuple(name for name in base.signature.parameters if name not in bound)
    roles = {
        role: replace(binding, expression=_substitute(binding.expression or binding.parameter, bound), fixed=binding.parameter in bound)
        for role, binding in base.roles.items()
    }
    fingerprint = hashlib.sha256(f"partial:{base.function_fingerprint}:{fixed_args}:{sorted(fixed_keywords.items())}".encode()).hexdigest()
    return HelperContract(
        _contract_id("", alias, fingerprint), alias, "", base.operation,
        FunctionSignature(remaining), roles, base.effects,
        (ContractEvidence(ContractEvidenceSource.SAFE_ALIAS, f"functools.partial of {base.key}", score=0.90),),
        ContractConfidence.INFERRED, fingerprint,
    )


def _bind_call(signature: FunctionSignature, call: ast.Call) -> dict[str, str]:
    bound = signature.default_map()
    for name, value in zip(signature.parameters, call.args):
        bound[name] = _unparse(value)
    for keyword in call.keywords:
        if keyword.arg:
            bound[keyword.arg] = _unparse(keyword.value)
    return bound


def _substitute(expression: str, values: Mapping[str, str]) -> str:
    if not expression:
        return ""
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError:
        return values.get(expression, expression)

    class Substitute(ast.NodeTransformer):
        def visit_Name(self, node: ast.Name) -> ast.AST:
            replacement = values.get(node.id)
            if replacement is None:
                return node
            try:
                return ast.copy_location(ast.parse(replacement, mode="eval").body, node)
            except SyntaxError:
                return node

    return _unparse(Substitute().visit(tree).body)


def _wrapper_cycles(definitions: Mapping[str, tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]) -> list[tuple[str, ...]]:
    graph: dict[str, set[str]] = {key: set() for key in definitions}
    short_to_key = {node.name: key for key, (_receiver, node) in definitions.items()}
    for key, (_receiver, node) in definitions.items():
        for call in (item for item in ast.walk(node) if isinstance(item, ast.Call)):
            name, _ = _call_target(call.func)
            target = short_to_key.get(name)
            if target:
                graph[key].add(target)
    result: list[tuple[str, ...]] = []
    visiting: list[str] = []
    seen: set[str] = set()

    def visit(name: str) -> None:
        if name in visiting:
            cycle = tuple(visiting[visiting.index(name):] + [name])
            if cycle not in result:
                result.append(cycle)
            return
        if name in seen:
            return
        visiting.append(name)
        for target in graph[name]:
            visit(target)
        visiting.pop()
        seen.add(name)

    for key in graph:
        visit(key)
    return result


def _enclosing_definition(
    node: ast.AST,
    parent: Mapping[ast.AST, ast.AST],
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    current = parent.get(node)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current
        current = parent.get(current)
    return None


def _role_name(parameter: str) -> str:
    lowered = parameter.lower().strip("_")
    for role, aliases in _ROLE_ALIASES.items():
        if lowered in aliases or any(lowered.endswith("_" + alias) for alias in aliases):
            return role
    return ""


def _prompt_role(prompt: str) -> str:
    normalized = re.sub(r"[^a-z0-9_]+", " ", prompt.lower())
    for role, words in _PROMPT_ROLES.items():
        if any(re.search(rf"\b{re.escape(word)}\b", normalized) for word in words):
            return role
    return ""


def _names(node: ast.AST) -> set[str]:
    return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}


def _call_target(node: ast.AST) -> tuple[str, str]:
    if isinstance(node, ast.Name):
        return node.id, ""
    if isinstance(node, ast.Attribute):
        return node.attr, _qualified_name(node.value)
    return "", ""


def _qualified_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _kind_from_text(value: str) -> CanonicalOperationKind:
    aliases = {"free": "delete", "remove": "delete", "alloc": "alloc", "edit": "edit", "show": "show", "copy": "copy", "delete": "delete"}
    try:
        return CanonicalOperationKind(aliases.get(str(value or "").lower(), "unknown"))
    except ValueError:
        return CanonicalOperationKind.UNKNOWN


def _contract_id(receiver: str, function: str, fingerprint: str) -> str:
    return "contract:" + hashlib.sha256(f"{receiver}:{function}:{fingerprint}".encode()).hexdigest()[:16]


def _evidence_rank(contract: HelperContract) -> int:
    return int(contract.strongest_evidence or 0)


def _semantic_confidence(contract: HelperContract) -> SemanticConfidence:
    return {
        ContractConfidence.CONFIRMED: SemanticConfidence.CONFIRMED,
        ContractConfidence.STRUCTURAL: SemanticConfidence.STRUCTURAL,
        ContractConfidence.INFERRED: SemanticConfidence.INFERRED,
        ContractConfidence.CANDIDATE: SemanticConfidence.CANDIDATE,
    }.get(contract.confidence, SemanticConfidence.UNKNOWN)


def _as_contract(item: HelperContract | Mapping[str, object]) -> HelperContract:
    return item if isinstance(item, HelperContract) else HelperContract.from_dict(item)


def _unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node).strip()
    except Exception:
        return ""
