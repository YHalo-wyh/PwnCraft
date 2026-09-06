from __future__ import annotations

import ast
import hashlib
import re
import textwrap
from dataclasses import dataclass, field, replace
from typing import Any, Iterable, Mapping

from pwncraft.features.heapviz.api_profile import infer_api_profile_from_source
from pwncraft.features.heapviz.contracts import HelperContract, HelperContractResolver, lower_source_calls
from pwncraft.features.heapviz.models import HeapApiProfile
from pwncraft.features.heapviz.operations import HeapOperation, HeapOperationKind
from pwncraft.features.heapviz.source_compat import parse_module_source

# 识别器行为修订号：进入训练样本 engine.recognizer_revision。任何影响
# 识别结果的改动（语义表/规则消费/报告结构）都必须递增 —— 三个月后旧
# 样本是哪个识别器生成的，靠它回答。
RECOGNIZER_REVISION = "recognizer-2026.09-r6"  # r6: cycle-4 generic size-only alloc promotion
from pwncraft.features.heapviz.semantics import (
    BehaviorEffectExpander,
    CallTarget,
    ChallengeBehaviorProfile,
    ProgramEvidence,
    ProgramEvent,
    CanonicalHeapOperation,
    canonicalize_operations,
    legacy_from_canonical,
    parse_semantic_expression,
)


@dataclass(frozen=True)
class SourceBinding:
    source_id: str
    start: int
    end: int
    line: int
    end_line: int
    source_text: str
    fingerprint: str
    loop_env: tuple[tuple[str, str], ...] = ()
    confidence: str = "confirmed"  # confirmed | inferred | manual | stale
    match_status: str = "matched"  # matched | rebound | stale


@dataclass(frozen=True)
class ParseDiagnostic:
    severity: str
    code: str
    message: str
    start: int = 0
    end: int = 0
    line: int = 0
    suggestion: str = ""


@dataclass(frozen=True)
class BranchGroup:
    branch_id: str
    condition: str
    choices: tuple[str, ...]
    selected: str = ""
    start: int = 0
    end: int = 0
    line: int = 0


@dataclass(frozen=True)
class TimelineOverride:
    override_id: str
    source_id: str
    action: str = "replace"  # replace | ignore | insert_before | insert_after
    operation: HeapOperation | None = None
    locked: bool = True
    anchor_text: str = ""
    fingerprint: str = ""
    status: str = "active"  # active | stale

    def to_dict(self) -> dict[str, object]:
        return {
            "override_id": self.override_id,
            "source_id": self.source_id,
            "action": self.action,
            "operation": self.operation.to_dict() if self.operation else None,
            "locked": self.locked,
            "anchor_text": self.anchor_text,
            "fingerprint": self.fingerprint,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "TimelineOverride":
        raw_operation = payload.get("operation")
        operation = HeapOperation.from_dict(dict(raw_operation)) if isinstance(raw_operation, Mapping) else None
        return cls(
            override_id=str(payload.get("override_id") or ""),
            source_id=str(payload.get("source_id") or ""),
            action=str(payload.get("action") or "replace"),
            operation=operation,
            locked=bool(payload.get("locked", True)),
            anchor_text=str(payload.get("anchor_text") or ""),
            fingerprint=str(payload.get("fingerprint") or ""),
            status=str(payload.get("status") or "active"),
        )


@dataclass(frozen=True)
class HeapAnalysisResult:
    operations: tuple[HeapOperation, ...] = ()
    bindings: tuple[SourceBinding, ...] = ()
    branch_groups: tuple[BranchGroup, ...] = ()
    diagnostics: tuple[ParseDiagnostic, ...] = ()
    symbols: dict[str, str] = field(default_factory=dict)
    valid: bool = True
    program_events: tuple[ProgramEvent, ...] = ()
    canonical_operations: tuple[CanonicalHeapOperation, ...] = ()
    helper_contracts: tuple[HelperContract, ...] = ()
    # RecognitionReport：识别失败是一等数据。候选调用数 / recognized /
    # ambiguous / unknown / ignored + 逐调用评分，让「识别错了」可见，
    # 而不是只能看到一份不知道缺了谁的 canonical 列表。
    recognition_report: dict[str, Any] = field(default_factory=dict)

    def operation_spans(self) -> list[tuple[HeapOperation, int, int]]:
        return [
            (operation, binding.start, binding.end)
            for operation, binding in zip(self.operations, self.bindings)
        ]


_UNKNOWN = object()
_RECV_NAMES = {"recv", "recvn", "recvline", "recvuntil", "clean", "read", "readline"}

_DEFAULT_NAMES: dict[str, HeapOperationKind] = {
    **{name: HeapOperationKind.ALLOC for name in (
        "add", "alloc", "allocate", "malloc", "new", "create", "insert", "buy",
        "add_note", "create_note",
        # 复合命名（chunk/note/item/node/data/message/ele 变体）
        "addchunk", "add_chunk", "addnode", "add_node", "addnote", "additem",
        "add_item", "addelem", "add_elem", "addelement", "add_element",
        "addmsg", "add_msg", "addmessage", "add_message", "add_data",
        "newchunk", "new_chunk", "newnode", "new_node", "newnote", "new_note",
        "newitem", "new_item", "newelem", "new_ele",
        "createchunk", "create_chunk", "createnode", "create_node",
        "createnote", "createitem", "create_item", "createelem", "create_ele",
        "create_data",
        "allocchunk", "alloc_chunk", "allocnote", "alloc_note", "allocnode",
        "alloc_node", "allocmem", "alloc_mem",
        "mallocchunk", "malloc_chunk", "mallocnote", "malloc_note",
        "push", "put", "apply_chunk", "new_ele",
    )},
    **{name: HeapOperationKind.FREE for name in (
        "delete", "free", "del", "remove", "rm", "drop", "destroy", "release", "erase", "wipe",
        "deletechunk", "delete_chunk", "deleteitem", "delete_item", "deletenote",
        "delete_note", "deletenode", "delete_node", "deledata", "delete_data",
        "delchunk", "del_chunk", "delnote", "del_note", "delnode", "del_node",
        "delelem", "del_elem", "delelement", "del_element", "delitem", "del_item",
        "freechunk", "free_chunk", "freenote", "free_note", "freenode", "free_node",
        "freemem", "free_mem", "removechunk", "remove_chunk", "removeitem", "remove_item",
        "removenote", "remove_note", "removenode", "remove_node",
        "rmchunk", "rm_chunk", "rmnote", "rm_note",
        "destroynote", "destroy_chunk", "destroynode", "destroy_node",
        "pop", "popchunk", "pop_chunk",
    )},
    **{name: HeapOperationKind.EDIT for name in (
        "edit", "update", "write", "change", "modify", "fill", "rename", "set",
        "edit_note", "change_note",
        "editchunk", "edit_chunk", "edititem", "edit_item", "editnode",
        "edit_node", "editnote", "edit_data",
        "modifychunk", "modify_chunk", "modifyitem", "modify_item",
        "modifynote", "modify_node", "modify_data",
        "changechunk", "change_chunk", "changenote", "change_data",
        "writechunk", "write_chunk", "writenote", "write_node", "write_data",
        "fillchunk", "fill_chunk", "fillnote", "fill_data",
        "setchunk", "set_chunk", "setnote", "setnode",
        "updatechunk", "update_chunk", "updatenote", "update_note",
        "updateitem", "update_item", "updatenode", "update_node",
    )},
    **{name: HeapOperationKind.SHOW for name in (
        "show", "view", "display", "leak", "dump", "read_note", "show_note", "view_note",
        "showchunk", "show_chunk", "showitem", "show_item", "shownote",
        "shown_node", "show_node", "showdata", "show_data",
        "printchunk", "print_chunk", "printnote", "print_note", "printnode",
        "print_node", "printitem", "print_item", "printdata", "print_data",
        "listchunk", "list_chunk", "listnote", "list_note", "listnode", "list_node",
        "dumpchunk", "dump_chunk", "dumpnote", "dump_node", "dumpitem", "dump_item",
        "viewchunk", "view_chunk", "viewitem", "view_item", "viewnode", "view_node",
        "leakchunk", "leak_chunk", "readchunk", "read_chunk",
        "see", "peek",
    )},
    **{name: HeapOperationKind.COPY for name in (
        "copy", "copy_chunk", "clone", "duplicate", "move", "memcpy", "memmove",
        "copychunk", "copyitem", "copy_item", "copynode", "copy_node",
        "copynote", "copy_note", "copydata", "copy_data",
        "dupchunk", "dup_chunk", "dupnode", "dup_node",
        "duplicate_chunk", "duplicate_note",
    )},
}


_AMBIGUOUS_HEURISTIC_NAMES = {
    "insert", "remove", "rm", "drop", "release", "erase", "wipe",
    "update", "write", "change", "modify", "fill", "rename", "set",
    "copy", "clone", "duplicate", "move",
}
_PYTHON_BUILTIN_CALLS = {
    "set", "dict", "list", "tuple", "bytes", "bytearray", "str", "int",
    "len", "range", "enumerate", "zip", "map", "filter", "print",
}
_NON_CHALLENGE_RECEIVERS = {
    "os", "sys", "path", "pathlib", "shutil", "config", "settings",
    "items", "values", "keys", "data", "result", "results", "mapping",
    "dict", "list", "set", "tuple", "str", "bytes", "bytearray",
}
_CHALLENGE_RECEIVERS = {
    "heap", "allocator", "arena", "client", "challenge", "target", "menu",
    "service", "svc", "note", "notes", "chunk", "chunks_api", "pwn",
}


class HeapSourceAnalyzer:
    """Safe, bounded Python source-to-heap-IR analyzer.

    It never imports or executes user code.  Unknown control flow is surfaced as
    a branch/diagnostic instead of being guessed.
    """

    def __init__(
        self,
        source: str,
        api_profile: HeapApiProfile | None = None,
        variables: Mapping[str, str | int] | None = None,
        branch_choices: Mapping[str, str] | None = None,
        overrides: Iterable[TimelineOverride] = (),
        learned_rules: Iterable[Mapping[str, object]] = (),
        max_loop_iterations: int = 256,
        max_events: int = 1024,
        behavior_profile: ChallengeBehaviorProfile | None = None,
        helper_contracts: Iterable[HelperContract] = (),
    ):
        self.source = source or ""
        self.api_profile = api_profile or HeapApiProfile()
        self.variables = dict(variables or {})
        self.branch_choices = dict(branch_choices or {})
        self.overrides = tuple(overrides)
        self.learned_rules = tuple(dict(item) for item in learned_rules if isinstance(item, Mapping))
        self.max_loop_iterations = max(1, int(max_loop_iterations))
        self.max_events = max(1, int(max_events))
        self.behavior_profile = behavior_profile or ChallengeBehaviorProfile()
        self.helper_contracts = tuple(helper_contracts)
        self._behavior_expander = BehaviorEffectExpander(self.behavior_profile)
        self._line_offsets = self._build_line_offsets(self.source)
        self._operations: list[HeapOperation] = []
        self._bindings: list[SourceBinding] = []
        self._diagnostics: list[ParseDiagnostic] = []
        self._branches: list[BranchGroup] = []
        self._env: dict[str, Any] = dict(self.variables)
        self._aliases: dict[str, str] = {}
        self._semantic_names: dict[str, HeapOperationKind] = dict(_DEFAULT_NAMES)
        self._explicit_profile_names = {
            self.api_profile.alloc_function,
            self.api_profile.free_function,
            self.api_profile.edit_function,
            self.api_profile.show_function,
            self.api_profile.copy_function,
        }
        self._defined_function_names: set[str] = set()
        self._templates: dict[HeapOperationKind, str] = {}
        self._function_roles: dict[str, tuple[str, ...]] = {}
        self._function_defaults: dict[str, dict[str, str]] = {}
        self._defined_function_parameters: dict[str, tuple[str, ...]] = {}
        self._index_to_chunk: dict[str, str] = {}
        self._known_values: dict[str, str] = {}
        self._last_show_value = ""
        self._payload_words: dict[str, tuple[str, list[str]]] = {}
        self._payload_sources: dict[str, str] = {}
        self._emitted_fake_names: set[str] = set()
        self._add_count = 0
        self._last_alloc_index = ""
        self._truncated = False
        self._uncertain_stop = False
        # A number of menu-driven challenges edit/show the object selected by
        # a preceding login()/select_*() call.  Keep that symbolic handle in
        # the analyzer instead of incorrectly treating edit(size, data)'s size
        # as a menu index.  This is static state only; no EXP code is executed.
        self._active_index = ""
        self._selector_names = {
            "login", "select_student", "choose_student", "use_student",
            "select_user", "choose_user", "use_user",
        }
        self._selector_clear_names = {"logout", "signout", "deselect", "close_student"}
        self._recv_value_helpers: set[str] = set()
        self._function_nodes: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self._method_names: set[str] = set()
        self._entry_call_stack: list[str] = []
        self._entry_call_count = 0
        self._entry_names = {"pwn", "exploit", "attack", "solve", "exp", "main"}
        self._helper_effect_cache: dict[str, bool] = {}
        self._program_events: list[ProgramEvent] = []
        self._program_events_by_id: dict[str, ProgramEvent] = {}
        # Recognition ledger：每一个被考虑过的调用点都有裁决（recognized /
        # ambiguous / unknown / ignored）与评分 —— 「没认出来」本身是结果。
        self._recognition_candidates: dict[tuple[int, int], dict[str, Any]] = {}
        # 用户显式标注「忽略」的函数名（RecognitionCorrection → ignore 规则）。
        self._recognition_ignore_names: set[str] = set()
        for rule in self.learned_rules:
            if str(rule.get("family") or "") != "recognition_ignore":
                continue
            if not bool(rule.get("enabled", True)):
                continue
            name = str((rule.get("matcher") or {}).get("function") or "")
            if name:
                self._recognition_ignore_names.add(name)

    def analyze(self) -> HeapAnalysisResult:
        try:
            tree, py2_parse_error = parse_module_source(self.source)
            if tree is None:
                raise py2_parse_error
        except SyntaxError as error:
            start = self._position(max(1, error.lineno or 1), max(0, (error.offset or 1) - 1))
            diagnostic = ParseDiagnostic(
                "error",
                "syntax_error",
                error.msg,
                start,
                min(len(self.source), start + 1),
                int(error.lineno or 0),
                "补全当前语句后会自动恢复；最后一次有效时间线应继续保留。",
            )
            partial = self._partial_syntax_diagnostics(int(error.lineno or 0))
            return HeapAnalysisResult(diagnostics=(diagnostic, *partial), valid=False)

        self._discover_helpers(tree)
        # Whole-file 预扫在执行路径之前：执行 walk 可能因 uncertain stop
        # 提前终止，但报告必须覆盖源码里的全部候选调用 —— 用户必须能
        # 看到「识别器漏了谁」。recognized 裁决只由真实绑定签发，预扫
        # 只填 ignored / ambiguous / unknown 的底账。
        self._prescan_recognition(tree)
        self._walk_statements(tree.body, self._env, {})
        if not self._operations:
            self._analyze_embedded_heap_scripts(tree)
        if not self._operations:
            self._preview_uninvoked_entrypoint(tree)
        operations, bindings, override_diagnostics = self._apply_overrides(self._operations, self._bindings)
        self._diagnostics.extend(override_diagnostics)
        operations = [replace(operation, op_id=f"op_{index:03d}") for index, operation in enumerate(operations, 1)]
        symbols = {name: self._display_value(value) for name, value in self._env.items() if value is not _UNKNOWN}
        contract_resolution = HelperContractResolver(user_contracts=self.helper_contracts).resolve(self.source)
        contract_operations = lower_source_calls(self.source, contract_resolution)
        # A user-confirmed contract is source semantics, not a one-row display
        # override. Re-lower every call carrying that contract and replace only
        # legacy operations bound to the same source lines.
        if self.helper_contracts and contract_operations:
            legacy_by_line = {
                binding.line: operation
                for operation, binding in zip(operations, bindings)
            }
            confirmed_lines = {item.source_binding.line for item in contract_operations}
            retained = [
                (operation, binding)
                for operation, binding in zip(operations, bindings)
                if binding.line not in confirmed_lines
            ]
            lowered_pairs = []
            for item in contract_operations:
                previous = legacy_by_line.get(item.source_binding.line)
                lowered = replace(
                    legacy_from_canonical(item),
                    chunk=previous.chunk if previous is not None else "",
                )
                lowered_pairs.append((lowered, self._binding_from_canonical(item)))
            combined = sorted((*retained, *lowered_pairs), key=lambda pair: (pair[1].start, pair[1].line))
            operations = [replace(item, op_id=f"op_{index:03d}") for index, (item, _binding) in enumerate(combined, 1)]
            bindings = [binding for _item, binding in combined]

        # Contract-lowered operations are authoritative only at their bound
        # call sites.  Earlier code used ``contract_operations or ...`` and
        # consequently dropped every ordinary add/delete call as soon as one
        # structurally proven helper existed in the same EXP.  Build a full,
        # position-aligned Canonical stream and replace just the matching
        # entries.  This is the stream executed by the v0.12 GUI/core.
        canonical_base = list(canonicalize_operations(operations, bindings))
        contract_by_line: dict[int, list[CanonicalHeapOperation]] = {}
        for item in contract_operations:
            contract_by_line.setdefault(item.source_binding.line, []).append(item)
        canonical_operations: list[CanonicalHeapOperation] = []
        for legacy, binding, base in zip(operations, bindings, canonical_base):
            candidates = contract_by_line.get(binding.line, [])
            selected = candidates.pop(0) if candidates else None
            canonical_operations.append(
                replace(
                    selected,
                    operation_id=legacy.op_id,
                    source_binding=base.source_binding,
                )
                if selected is not None
                else base
            )
        return HeapAnalysisResult(
            operations=tuple(operations),
            bindings=tuple(bindings),
            branch_groups=tuple(self._branches),
            diagnostics=tuple(self._diagnostics),
            symbols=symbols,
            valid=True,
            program_events=tuple(self._program_events),
            canonical_operations=tuple(canonical_operations),
            helper_contracts=contract_resolution.contracts,
            recognition_report=self._build_recognition_report(),
        )

    def _binding_from_canonical(self, operation: CanonicalHeapOperation) -> SourceBinding:
        raw = operation.source_binding
        line = max(1, raw.line)
        start = self._position(line, 0)
        source_text = raw.source_text or self.source[start : self.source.find("\n", start) if "\n" in self.source[start:] else len(self.source)]
        end = start + len(source_text)
        return SourceBinding(
            raw.source_id or f"line:{line}",
            start,
            end,
            line,
            line + source_text.count("\n"),
            source_text,
            raw.fingerprint,
            confidence=operation.confidence.value,
        )

    def _partial_syntax_diagnostics(self, error_line: int) -> tuple[ParseDiagnostic, ...]:
        lines = self.source.splitlines()
        candidates = [
            ("prefix", "\n".join(lines[: max(0, error_line - 1)])),
            ("suffix", textwrap.dedent("\n".join(lines[max(0, error_line):]))),
        ]
        diagnostics: list[ParseDiagnostic] = []
        for label, source in candidates:
            if not source.strip():
                continue
            if parse_module_source(source)[0] is None:
                continue
            partial = HeapSourceAnalyzer(
                source,
                self.api_profile,
                self.variables,
                self.branch_choices,
                (),
                self.learned_rules,
                self.max_loop_iterations,
                self.max_events,
                self.behavior_profile,
            ).analyze()
            if partial.valid and partial.operations:
                diagnostics.append(ParseDiagnostic(
                    "info",
                    f"partial_{label}",
                    f"语法错误{'前' if label == 'prefix' else '后'}仍有 {len(partial.operations)} 个完整语义步可识别；主画布继续保留上次有效结果。",
                    line=error_line,
                ))
        return tuple(diagnostics)

    def _analyze_embedded_heap_scripts(self, tree: ast.Module) -> None:
        """Extract a narrow object lifetime trace from embedded JS payloads."""

        patterns = (
            (HeapOperationKind.ALLOC, re.compile(r"(?:let|const|var)\s+(\w+)\s*=\s*new\s+\w+\s*\(([^)]*)\)")),
            (HeapOperationKind.SHOW, re.compile(r"(\w+)\.(?:view|show|read)\s*\(([^)]*)\)")),
            (HeapOperationKind.FREE, re.compile(r"(\w+)\.(?:recycle|free|delete|dispose)\s*\(([^)]*)\)")),
            (HeapOperationKind.EDIT, re.compile(r"(\w+)\.(?:resize|write|set|edit)\s*\(([^)]*)\)")),
        )
        events: list[tuple[int, HeapOperationKind, str, str, ast.Constant]] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            text = node.value
            if "new " not in text or not any(token in text for token in (".view(", ".recycle(", ".resize(", ".free(")):
                continue
            for kind, pattern in patterns:
                for match in pattern.finditer(text):
                    events.append((match.start(), kind, match.group(1), match.group(2).strip(), node))
        for _offset, kind, name, argument, node in sorted(events, key=lambda item: item[0]):
            if kind == HeapOperationKind.ALLOC:
                index = str(self._add_count)
                self._index_to_chunk[index] = name
                self._add_count += 1
                operation = HeapOperation(
                    "", kind, chunk=name, index=index, request_size=argument or "unknown",
                    meta={"parse_confidence": "embedded-script", "language": "javascript"},
                )
            else:
                index = next((key for key, value in self._index_to_chunk.items() if value == name), name)
                operation = HeapOperation(
                    "", kind, chunk=name, index=index,
                    request_size=argument if kind == HeapOperationKind.EDIT else "",
                    data=argument if kind == HeapOperationKind.EDIT else "",
                    meta={"parse_confidence": "embedded-script", "language": "javascript"},
                )
            self._append(operation, node, {}, "inferred")
        if events:
            self._diagnostics.append(ParseDiagnostic(
                "info", "embedded_heap_script",
                f"已从嵌入 JavaScript 静态提取 {len(events)} 个对象生命周期步骤。",
            ))

    def _discover_helpers(self, tree: ast.Module) -> None:
        inferred_dispatch_rules = self._infer_dispatcher_rules(tree)
        if inferred_dispatch_rules:
            self.learned_rules = (*self.learned_rules, *inferred_dispatch_rules)
            names = sorted({str(dict(item.get("matcher") or {}).get("function") or "") for item in inferred_dispatch_rules})
            self._diagnostics.append(ParseDiagnostic(
                "info",
                "inferred_dispatcher",
                f"已从字面量选择子推导通用菜单分发器: {', '.join(names)}。",
                suggestion="映射只在同一源码中同时出现 alloc/free/edit/show 完整证据时启用。",
            ))
        self._semantic_names.update(
            {
                self.api_profile.alloc_function: HeapOperationKind.ALLOC,
                self.api_profile.free_function: HeapOperationKind.FREE,
                self.api_profile.edit_function: HeapOperationKind.EDIT,
                self.api_profile.show_function: HeapOperationKind.SHOW,
                self.api_profile.copy_function: HeapOperationKind.COPY,
            }
        )
        self._templates = {
            HeapOperationKind.ALLOC: self.api_profile.alloc_template,
            HeapOperationKind.FREE: self.api_profile.free_template,
            HeapOperationKind.EDIT: self.api_profile.edit_template,
            HeapOperationKind.SHOW: self.api_profile.show_template,
            HeapOperationKind.COPY: self.api_profile.copy_template,
        }
        module_functions = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
        method_groups: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
        for class_node in (node for node in tree.body if isinstance(node, ast.ClassDef)):
            for method in class_node.body:
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    method_groups.setdefault(method.name, []).append(method)
        unique_methods = [nodes[0] for nodes in method_groups.values() if len(nodes) == 1]
        self._method_names = {node.name for node in unique_methods}
        function_nodes = [*module_functions, *unique_methods]
        self._function_nodes = {node.name: node for node in unique_methods}
        self._function_nodes.update({node.name: node for node in module_functions})
        self._defined_function_names = set(self._function_nodes)
        for node in function_nodes:
            parameters = [item.arg for item in (*node.args.posonlyargs, *node.args.args)]
            all_parameters = tuple(item.arg for item in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs))
            self._defined_function_parameters[node.name] = all_parameters
            # Empty roles are intentional placeholders.  Keeping the original
            # parameter name here made an unused password/flags parameter look
            # like a heap field and caused later positional fallbacks to shift.
            semantic_kind = self._semantic_names.get(node.name)
            roles = tuple(
                self._keyword_role(name, semantic_kind)
                if semantic_kind in {
                    HeapOperationKind.ALLOC, HeapOperationKind.FREE,
                    HeapOperationKind.EDIT, HeapOperationKind.SHOW,
                    HeapOperationKind.COPY,
                }
                else (
                    self._keyword_role(name, HeapOperationKind.ALLOC)
                    or self._keyword_role(name, HeapOperationKind.COPY)
                )
                for name in parameters
            )
            self._function_roles[node.name] = roles
            defaults: dict[str, str] = {}
            if node.args.defaults:
                for name, value in zip(parameters[-len(node.args.defaults):], node.args.defaults):
                    defaults[name] = self._source_segment(value)
            self._function_defaults[node.name] = defaults
        self._install_learned_rules(function_nodes)
        # Multiple passes let wrappers inherit a semantic kind from a function
        # discovered earlier/later in the module.
        for _pass in range(3):
            changed = False
            for node in function_nodes:
                if node.name in self._semantic_names:
                    continue
                if self._is_recv_value_helper(node):
                    self._recv_value_helpers.add(node.name)
                    continue
                segment = ast.get_source_segment(self.source, node) or ast.unparse(node)
                profile, found = infer_api_profile_from_source(segment, self.api_profile)
                if found:
                    kind_name, function_name = next(iter(found.items()))
                    kind = HeapOperationKind(kind_name if kind_name != "alloc" else "alloc")
                    self._semantic_names[function_name] = kind
                    template = getattr(profile, f"{kind_name}_template")
                    self._templates[kind] = template
                    inferred_roles = tuple(
                        role
                        for role in re.findall(r"\{(index|size|data|chunk|target|src|dst|length)\}", template)
                    )
                    if inferred_roles:
                        self._function_roles[function_name] = inferred_roles
                    changed = True
                    continue
                wrapped = self._wrapped_kind(node)
                if wrapped:
                    self._semantic_names[node.name] = wrapped
                    changed = True
            if not changed:
                break

        for node in function_nodes:
            inferred_roles = self._infer_wrapper_roles(node)
            if inferred_roles:
                self._function_roles[node.name] = inferred_roles

        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Name):
                self._aliases[node.targets[0].id] = node.value.id
                base = self._resolve_alias(node.value.id)
                if base in self._semantic_names:
                    self._semantic_names[node.targets[0].id] = self._semantic_names[base]

    def _infer_dispatcher_rules(self, tree: ast.Module) -> tuple[dict[str, object], ...]:
        """Infer ``cmd(choice, *values)`` mappings from a complete call family.

        This targets compact EXPs that encode every menu value and therefore do
        not define add/delete/edit/show wrappers.  The inference is deliberately
        all-or-nothing: it requires a local variadic dispatcher, literal choice
        values, and independent evidence for all four core actions.
        """

        candidates: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.args.vararg is None:
                continue
            if any(
                isinstance(child, ast.Call)
                and ("send" in self._call_name(child.func).lower() or self._call_name(child.func).lower() in {"sa", "sla", "sl", "s", "write", "writeline"})
                for child in ast.walk(node)
            ):
                candidates[node.name] = node
        if not candidates:
            return ()

        all_calls = sorted(
            (node for node in ast.walk(tree) if isinstance(node, ast.Call)),
            key=lambda item: (int(getattr(item, "lineno", 0)), int(getattr(item, "col_offset", 0))),
        )
        rules: list[dict[str, object]] = []
        source_lines = self.source.splitlines()
        for name in candidates:
            grouped: dict[str, list[ast.Call]] = {}
            for call in all_calls:
                if self._call_name(call.func) != name or len(call.args) < 2:
                    continue
                selector = self._literal_rule_value(call.args[0])
                if selector is _UNKNOWN:
                    continue
                grouped.setdefault(str(selector), []).append(call)
            semantics: dict[str, tuple[str, list[str]]] = {}
            for selector, calls in grouped.items():
                arities = {len(call.args) for call in calls}
                if len(arities) != 1:
                    continue
                arity = next(iter(arities))
                tail = [argument for call in calls for argument in call.args[1:]]
                has_data = any(self._looks_payload_expression(argument) or self._looks_like_data_expression(self._source_segment(argument)) for argument in tail)
                if arity >= 4:
                    semantics[selector] = ("copy", ["src", "dst", "length"])
                elif arity == 3 and has_data:
                    semantics[selector] = ("edit", ["index", "data"])
                elif arity == 3:
                    first_values = [self._literal_rule_value(call.args[1]) for call in calls]
                    second_values = [self._literal_rule_value(call.args[2]) for call in calls]
                    first_numbers = [int(value) for value in first_values if isinstance(value, (int, bool))]
                    second_numbers = [int(value) for value in second_values if isinstance(value, (int, bool))]
                    roles = ["index", "size"]
                    if first_numbers and second_numbers and max(first_numbers) > max(second_numbers):
                        roles = ["size", "index"]
                    semantics[selector] = ("alloc", roles)
                elif arity == 2:
                    has_following_recv = False
                    for call in calls:
                        line = int(getattr(call, "end_lineno", getattr(call, "lineno", 0)))
                        next_dispatch_line = min(
                            (
                                int(getattr(other, "lineno", len(source_lines) + 1))
                                for other in all_calls
                                if self._call_name(other.func) == name
                                and int(getattr(other, "lineno", 0)) > line
                            ),
                            default=min(len(source_lines) + 1, line + 4),
                        )
                        window = "\n".join(source_lines[line:max(line, next_dispatch_line - 1)]).lower()
                        if "recv" in window:
                            has_following_recv = True
                            break
                    semantics[selector] = ("show" if has_following_recv else "free", ["index"])

            core = {semantic for semantic, _roles in semantics.values()}
            if not {"alloc", "free", "edit", "show"}.issubset(core):
                continue
            for selector, (semantic, roles) in sorted(semantics.items()):
                call = grouped[selector][0]
                rules.append({
                    "rule_id": f"ast-dispatch:{name}:{selector}:{semantic}",
                    "semantic": semantic,
                    "matcher": {
                        "function": name,
                        "arity": len(call.args),
                        "argument_equals": {"0": selector},
                    },
                    "output": {"roles": roles, "arg_offset": 1},
                    "enabled": True,
                    "source": "same-source complete dispatcher family",
                })
        return tuple(rules)

    def _is_recv_value_helper(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """Identify wrappers that only parse bytes already printed by show()."""

        calls = [child for child in ast.walk(node) if isinstance(child, ast.Call)]
        has_recv = any(self._call_name(child.func) in _RECV_NAMES for child in calls)
        if not has_recv:
            return False
        for child in calls:
            name = self._resolve_alias(self._call_name(child.func))
            if name in _RECV_NAMES or name in {"u32", "u64", "int", "bytes", "str"}:
                continue
            # Menu helpers often alternate recvuntil() prompts and outbound
            # send calls.  Those functions mutate the target and must still
            # go through normal helper classification.
            if "send" in name.lower() or name.lower() in {"write", "writeline"}:
                return False
            if self._semantic_names.get(name) in {
                HeapOperationKind.ALLOC, HeapOperationKind.FREE,
                HeapOperationKind.EDIT, HeapOperationKind.SHOW,
                HeapOperationKind.COPY,
            }:
                return False
        return True

    def _wrapped_kind(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> HeapOperationKind | None:
        kinds = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                kind = self._semantic_kind(child)
                if kind is not None:
                    kinds.append(kind)
        unique = tuple(dict.fromkeys(kinds))
        return unique[0] if len(unique) == 1 else None

    def _infer_wrapper_roles(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...] | None:
        parameters = [item.arg for item in (*node.args.posonlyargs, *node.args.args)]
        if not parameters:
            return None
        mapping: dict[str, str] = {}
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            callee = self._resolve_alias(self._call_name(child.func))
            kind = self._semantic_kind(child)
            if kind is None or callee == node.name:
                continue
            learned_roles = self._learned_roles_for_call(child)
            roles = list(learned_roles) if learned_roles else [role for role in re.findall(r"\{(index|size|data|chunk|target|src|dst|length)\}", self._template_for_kind(kind))]
            if (
                kind == HeapOperationKind.ALLOC
                and len(child.args) >= 3
                and (
                    not any(role in {"index", "size", "data"} for role in roles)
                    or ("index" not in roles and callee not in self._defined_function_parameters)
                )
            ):
                roles = ["index", "size", "data"]
            positional_roles = roles
            if kind == HeapOperationKind.ALLOC and len(child.args) == 1:
                argument = child.args[0]
                # ``return add(data)`` is common when the wrapper chooses a
                # fixed/implicit size.  Do not blindly assign the first role
                # from the default ``add(size, data)`` template: use the
                # wrapper parameter name (and, for literals, its expression
                # shape) to distinguish data-only from size-only helpers.
                named_role = self._keyword_role(argument.id, kind) if isinstance(argument, ast.Name) else ""
                rendered = self._source_segment(argument)
                positional_roles = [
                    named_role
                    or ("data" if self._looks_like_data_expression(rendered) else "size")
                ]
            for role, argument in zip(positional_roles, child.args):
                if isinstance(argument, ast.Name) and argument.id in parameters:
                    mapping[argument.id] = role
            for keyword in child.keywords:
                if keyword.arg and isinstance(keyword.value, ast.Name) and keyword.value.id in parameters:
                    role = self._keyword_role(keyword.arg, kind)
                    if role:
                        mapping[keyword.value.id] = role
        if not mapping:
            return None
        current = self._function_roles.get(node.name, tuple(parameters))
        return tuple(mapping.get(name, current[index] if index < len(current) else name) for index, name in enumerate(parameters))

    def _walk_statements(self, statements: Iterable[ast.stmt], env: dict[str, Any], loop_env: dict[str, Any]) -> str:
        for statement in statements:
            if self._truncated:
                return "stop"
            signal = self._walk_statement(statement, env, loop_env)
            if signal in {"break", "continue", "return", "stop"}:
                return signal
        return ""

    def _walk_statement(self, statement: ast.stmt, env: dict[str, Any], loop_env: dict[str, Any]) -> str:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom)):
            return ""
        if isinstance(statement, ast.Assign):
            self._handle_assign(statement, env, loop_env)
            return "stop" if self._uncertain_stop else ""
        if isinstance(statement, ast.AnnAssign):
            if statement.value is not None:
                synthetic = ast.Assign(targets=[statement.target], value=statement.value)
                ast.copy_location(synthetic, statement)
                self._handle_assign(synthetic, env, loop_env)
            return "stop" if self._uncertain_stop else ""
        if isinstance(statement, ast.AugAssign):
            self._handle_augassign(statement, env, loop_env)
            return "stop" if self._uncertain_stop else ""
        if isinstance(statement, ast.Expr):
            self._analyze_expression(statement.value, "", statement, env, loop_env)
            self._apply_container_call(statement.value, env)
            return "stop" if self._uncertain_stop else ""
        if isinstance(statement, ast.For):
            return self._handle_for(statement, env, loop_env)
        if isinstance(statement, ast.If):
            return self._handle_if(statement, env, loop_env)
        if isinstance(statement, ast.While):
            value = self._safe_eval(statement.test, env)
            if value is False:
                return self._walk_statements(statement.orelse, env, loop_env)
            if value is True and self._contains_entry_call(statement.body):
                self._diagnose_node(
                    "info",
                    "bounded_entry_loop",
                    "持久重连循环只静态展开一次入口流程。",
                    statement,
                )
                self._walk_statements(statement.body, env, loop_env)
                return ""
            self._diagnose_node("warning", "dynamic_while", "while 执行次数无法静态证明，未推进堆状态。", statement, "将循环展开为 range，或在时间线中绑定人工步骤。")
            self._append_unresolved(statement, loop_env, "dynamic while: iteration count is unknown")
            return "stop"
        if isinstance(statement, ast.Break):
            return "break"
        if isinstance(statement, ast.Continue):
            return "continue"
        if isinstance(statement, ast.Return):
            if statement.value:
                self._analyze_expression(statement.value, "", statement, env, loop_env)
            return "return"
        if isinstance(statement, ast.Assert):
            value = self._safe_eval(statement.test, env)
            if value is False:
                self._diagnose_node(
                    "error",
                    "static_assertion_failed",
                    "assert 条件可静态证明为 False；真实 EXP 会在这里停止。",
                    statement,
                )
                return "stop"
            if value is not True:
                self._diagnose_node(
                    "info",
                    "runtime_assertion",
                    "assert 是运行时约束，静态分析保留后续路径但不假定条件成立。",
                    statement,
                )
            return ""
        if isinstance(statement, (ast.With, ast.AsyncWith)):
            return self._walk_statements(statement.body, env, loop_env)
        if isinstance(statement, ast.Try):
            self._diagnose_node("info", "try_path", "静态时间线采用 try 主路径；异常分支保留为诊断。", statement)
            return self._walk_statements(statement.body, env, loop_env)
        self._diagnose_node("info", "unsupported_statement", f"暂未识别语句 {type(statement).__name__}。", statement)
        return ""

    def _handle_assign(self, statement: ast.Assign, env: dict[str, Any], loop_env: dict[str, Any]) -> None:
        if not statement.targets:
            return
        target = statement.targets[0]
        target_name = self._assignment_target_name(target)
        if isinstance(target, ast.Name) and self._looks_payload_expression(statement.value):
            self._payload_sources[target.id] = self._source_segment(statement.value).strip() or ast.unparse(statement.value)
        if isinstance(statement.value, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            values = self._expand_comprehension(statement.value, env, loop_env)
            if isinstance(target, ast.Name):
                env[target.id] = values if values is not _UNKNOWN else _UNKNOWN
            return
        if target_name:
            packed = self._packed_values(statement.value, env)
            if packed:
                pack, values = packed
                self._payload_words[target_name] = (pack, list(values))
                if len(values) >= 4:
                    self._emit_fake_chunk(target_name, pack, values, statement, loop_env)
                env[target_name] = _UNKNOWN
                return
        if isinstance(target, ast.Name) and isinstance(statement.value, ast.Name):
            self._aliases[target.id] = statement.value.id
            base = self._resolve_alias(statement.value.id)
            if base in self._semantic_names:
                self._semantic_names[target.id] = self._semantic_names[base]

        operations_before = len(self._operations)
        self._analyze_expression(statement.value, target_name, statement, env, loop_env)
        self._apply_container_call(statement.value, env)
        value = self._safe_eval(statement.value, env)
        if isinstance(target, ast.Name):
            if len(self._operations) > operations_before and self._operations[-1].kind == HeapOperationKind.ALLOC:
                index = self._operations[-1].index
                env[target.id] = self._parse_scalar(index)
            else:
                env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)) and value is not _UNKNOWN:
            self._bind_target(target, value, env)
        elif isinstance(target, ast.Subscript):
            self._assign_subscript(target, value, env)

    def _assignment_target_name(self, target: ast.AST) -> str:
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, ast.Attribute):
            return self._source_segment(target).strip()
        return ""

    def _handle_augassign(self, statement: ast.AugAssign, env: dict[str, Any], loop_env: dict[str, Any]) -> None:
        if (
            isinstance(statement.target, ast.Name)
            and isinstance(statement.op, ast.Add)
            and statement.target.id in self._payload_sources
            and self._looks_payload_expression(statement.value)
        ):
            right = self._source_segment(statement.value).strip() or ast.unparse(statement.value)
            self._payload_sources[statement.target.id] = f"({self._payload_sources[statement.target.id]}) + ({right})"
        if isinstance(statement.target, ast.Name) and isinstance(statement.op, ast.Add):
            packed = self._packed_values(statement.value, env)
            existing = self._payload_words.get(statement.target.id)
            if packed and existing and packed[0] == existing[0]:
                values = list(existing[1]) + list(packed[1])
                self._payload_words[statement.target.id] = (existing[0], values)
                if len(values) >= 4 and statement.target.id not in self._emitted_fake_names:
                    self._emit_fake_chunk(statement.target.id, existing[0], values, statement, loop_env)
                env[statement.target.id] = _UNKNOWN
                return
        self._analyze_expression(statement.value, "", statement, env, loop_env)
        if not isinstance(statement.target, ast.Name):
            return
        current = env.get(statement.target.id, _UNKNOWN)
        right = self._safe_eval(statement.value, env)
        if current is _UNKNOWN or right is _UNKNOWN:
            env[statement.target.id] = _UNKNOWN
            return
        try:
            if isinstance(statement.op, ast.Add):
                env[statement.target.id] = current + right
            elif isinstance(statement.op, ast.Sub):
                env[statement.target.id] = current - right
            else:
                env[statement.target.id] = _UNKNOWN
        except (TypeError, ValueError, ArithmeticError):
            env[statement.target.id] = _UNKNOWN

    def _handle_for(self, statement: ast.For, env: dict[str, Any], loop_env: dict[str, Any]) -> str:
        iterable = self._safe_iterable(statement.iter, env)
        if iterable is _UNKNOWN:
            self._diagnose_node("warning", "dynamic_iterable", "for iterable 无法静态确定，未展开循环。", statement, "改用静态 range/list，或在时间线中人工绑定。")
            self._append_unresolved(statement, loop_env, "dynamic for: iterable is unknown")
            return "stop"
        values = list(iterable)
        if len(values) > self.max_loop_iterations:
            self._diagnose_node("warning", "loop_truncated", f"循环共有 {len(values)} 次，只展开前 {self.max_loop_iterations} 次。", statement)
            values = values[: self.max_loop_iterations]
        completed = True
        for value in values:
            self._bind_target(statement.target, value, env)
            next_loop = dict(loop_env)
            for name in self._target_names(statement.target):
                next_loop[name] = env.get(name, _UNKNOWN)
            signal = self._walk_statements(statement.body, env, next_loop)
            if signal == "break":
                completed = False
                break
            if signal in {"return", "stop"}:
                return signal
        if completed and statement.orelse:
            return self._walk_statements(statement.orelse, env, loop_env)
        return ""

    def _handle_if(self, statement: ast.If, env: dict[str, Any], loop_env: dict[str, Any]) -> str:
        condition = self._safe_eval(statement.test, env)
        if isinstance(condition, bool):
            return self._walk_statements(statement.body if condition else statement.orelse, env, loop_env)
        # Debug/logging guards are extremely common at the top of an EXP.  If
        # neither arm contains a heap-semantic call, both paths have the same
        # allocator state and the code after the if is a proven common suffix.
        # Do not discard an entire exploit merely because args.GDB is unknown.
        if self._branch_is_heap_neutral(statement):
            self._diagnose_node(
                "info",
                "heap_neutral_branch",
                f"条件 `{self._source_segment(statement.test)}` 只影响调试/辅助流程，已继续解析共同后缀。",
                statement,
            )
            return ""
        branch_id = self._node_id("branch", statement, loop_env)
        selected = self.branch_choices.get(branch_id, "")
        choices = ("true", "false")
        self._branches.append(
            BranchGroup(
                branch_id,
                self._source_segment(statement.test),
                choices,
                selected if selected in choices else "",
                *self._span(statement),
                int(getattr(statement, "lineno", 0)),
            )
        )
        if selected == "true":
            return self._walk_statements(statement.body, env, loop_env)
        if selected == "false":
            return self._walk_statements(statement.orelse, env, loop_env)
        self._diagnose_node("warning", "branch_unselected", f"条件 `{self._source_segment(statement.test)}` 无法静态确定，请在时间线选择 true/false。", statement)
        self._append(
            HeapOperation(
                "",
                HeapOperationKind.NOTE,
                note=f"branch candidate: {self._source_segment(statement.test)}",
                meta={"analysis_status": "branch_candidate", "branch_id": branch_id},
            ),
            statement,
            loop_env,
            "branch_candidate",
        )
        return "stop"

    def _branch_is_heap_neutral(self, statement: ast.If) -> bool:
        """Return True only when both arms provably contain no heap event."""

        harmless = {
            "attach", "pause", "log", "print", "success", "info", "warning",
            "debug", "sleep", "setLevel",
        }
        for node in ast.walk(statement):
            if not isinstance(node, ast.Call):
                continue
            name = self._resolve_alias(self._call_name(node.func))
            target = self._call_target(node)
            if self._semantic_kind(node) is not None:
                return False
            if (
                self._looks_heap_related(name)
                and name not in harmless
                and self._is_heap_candidate_target(target)
            ):
                return False
        return True

    def _analyze_expression(self, expression: ast.AST, result_var: str, statement: ast.AST, env: dict[str, Any], loop_env: dict[str, Any]) -> None:
        self._update_active_selector(expression, env)
        if isinstance(expression, ast.Call) and self._inline_entry_call(expression, env, loop_env):
            return
        if isinstance(expression, ast.Call) and self._inline_effect_helper_call(expression, env, loop_env):
            return
        if isinstance(expression, ast.Call):
            structured = self._structured_action_operation(expression, result_var, env)
            if structured is not None:
                self._note_recognition(
                    expression, "recognized", structured.kind,
                    "菜单 dispatcher / 结构化动作命中（structured action）",
                )
                self._append(structured, expression, loop_env, "confirmed")
                if structured.kind == HeapOperationKind.SHOW:
                    value_name = structured.meta.get("result_var") or self._unique_value_name("show_result")
                    self._known_values[value_name] = "show"
                    self._last_show_value = value_name
                return
        if isinstance(expression, ast.Call):
            self._record_program_event(expression, result_var, env, loop_env)

        behavior_calls = [
            node for node in ast.walk(expression)
            if isinstance(node, ast.Call)
            and self.behavior_profile.match(
                self._call_target(node).function_name,
                self._call_target(node).receiver,
            ) is not None
        ]
        behavior_calls.sort(key=lambda node: (getattr(node, "lineno", 0), getattr(node, "col_offset", 0)), reverse=True)
        behavior_node_ids = {id(node) for node in behavior_calls}
        for call in behavior_calls:
            event = self._record_program_event(call, result_var if call is expression else "", env, loop_env)
            for operation in self._behavior_expander.expand(event):
                self._append(operation, call, loop_env, "profile")

        semantic_calls: list[ast.Call] = []
        for node in ast.walk(expression):
            if not isinstance(node, ast.Call) or id(node) in behavior_node_ids:
                continue
            kind = self._semantic_kind(node)
            if kind is not None:
                semantic_calls.append(node)
                learned = self._matching_learned_rule(node)
                target = self._call_target(node)
                self._note_recognition(
                    node, "recognized", kind,
                    f"语义绑定 → {kind.value}"
                    + ("（learned rule 精确匹配调用形态）" if learned else f"（target origin: {target.origin}）"),
                )
            else:
                verdict, reason = self._classify_unrecognized_call(node)
                self._note_recognition(node, verdict, None, reason)
        semantic_calls.sort(key=lambda node: (getattr(node, "lineno", 0), getattr(node, "col_offset", 0)), reverse=True)
        replacements: list[tuple[str, str]] = []
        generated_dependencies: list[str] = []
        for call_index, call in enumerate(semantic_calls, 1):
            kind = self._semantic_kind(call)
            if kind is None:
                continue
            direct = call is expression
            call_result = result_var if direct and kind == HeapOperationKind.SHOW else ""
            if kind == HeapOperationKind.SHOW and not call_result:
                base = (result_var + "_raw") if result_var else ("leak" if direct else "show_result")
                call_result = self._unique_value_name(base)
            operation = self._operation_from_call(call, kind, call_result, result_var if direct else "", env)
            if operation is not None:
                learned = self._matching_learned_rule(call)
                event = self._record_program_event(call, call_result, env, loop_env)
                target = event.target
                confidence = "learned" if learned else (
                    "confirmed" if target.origin in {"profile", "user_helper", "challenge_receiver"} else "inferred"
                )
                operation = replace(
                    operation,
                    meta={
                        **operation.meta,
                        "program_event_id": event.event_id,
                        "call_target": target.qualified_name,
                        "call_origin": target.origin,
                        "evidence": "; ".join(item.detail for item in event.evidence),
                    },
                )
                if learned:
                    operation = replace(
                        operation,
                        meta={**operation.meta, "learned_rule_id": str(learned.get("rule_id") or ""), "parse_confidence": "learned"},
                    )
                self._append(operation, call, loop_env, confidence)
                if kind == HeapOperationKind.SHOW:
                    self._known_values[call_result] = "show"
                    self._last_show_value = call_result
                    generated_dependencies.append(call_result)
                    replacements.append((self._source_segment(call), call_result))
            else:
                self._note_recognition(
                    call, "unknown", None,
                    "语义名匹配但参数无法下降为操作（roles/arity 证据不足），拒绝猜测",
                )

        if (semantic_calls and semantic_calls[0] is expression) or (behavior_calls and behavior_calls[0] is expression):
            return

        has_recv = any(
            isinstance(node, ast.Call)
            and self._call_name(node.func) in (_RECV_NAMES | self._recv_value_helpers)
            for node in ast.walk(expression)
        )
        expression_text = self._render_node(expression, env)
        for old, new in replacements:
            if old:
                expression_text = expression_text.replace(old, new, 1)
        dependency_names = [name for name in self._names(expression) if name in self._known_values]
        if has_recv and self._last_show_value:
            dependency_names.append(self._last_show_value)
        dependencies = tuple(dict.fromkeys(generated_dependencies + dependency_names))
        if result_var and (dependencies or has_recv):
            meta = {
                "result_var": result_var,
                "expression": expression_text,
                "dependencies": ",".join(dependencies),
                "source_kind": "recv" if has_recv else "derived",
                "source": self._source_segment(statement),
                "provenance": "inferred" if has_recv else "derived",
            }
            meta.update(self._value_flow_metadata(expression))
            operation = HeapOperation("", HeapOperationKind.DERIVE_VALUE, chunk=result_var, value=expression_text, meta=meta)
            self._append(operation, statement, loop_env, "inferred" if has_recv else "confirmed")
            self._known_values[result_var] = "recv" if has_recv else "derived"

        # Semantic-looking unknown calls should be visible rather than silently
        # disappearing from the model.
        if not semantic_calls and isinstance(expression, ast.Call):
            active_edit = self._active_object_edit_operation(expression, env)
            if active_edit is not None:
                self._note_recognition(
                    expression, "recognized", active_edit.kind,
                    "active-object edit：跟随前置 login/select 的当前对象",
                )
                self._append(active_edit, expression, loop_env, "inferred")
                return
            name = self._call_name(expression.func)
            target = self._call_target(expression)
            if name and self._looks_heap_related(name) and self._is_heap_candidate_target(target):
                self._diagnose_node("warning", "unmapped_call", f"调用 `{name}` 看起来像堆操作，但参数角色不明确。", statement, "在函数适配或时间线校正中映射它。")
                self._append_unresolved(statement, loop_env, f"unmapped heap-like call: {name}")
                self._uncertain_stop = True

    def _update_active_selector(self, expression: ast.AST, env: Mapping[str, Any]) -> None:
        if not isinstance(expression, ast.Call):
            return
        name = self._resolve_alias(self._call_name(expression.func)).lower()
        if name in self._selector_clear_names:
            self._active_index = ""
            return
        if name not in self._selector_names or not expression.args:
            return
        self._active_index = self._render_node(expression.args[0], env)

    def _structured_action_operation(
        self,
        call: ast.Call,
        result_var: str,
        env: Mapping[str, Any],
    ) -> HeapOperation | None:
        """Map literal JSON/dict actions used by non-menu heap services."""

        mapping_node = next((item for item in call.args if isinstance(item, ast.Dict)), None)
        if mapping_node is None:
            mapping_node = next((item.value for item in call.keywords if isinstance(item.value, ast.Dict)), None)
        if mapping_node is None:
            return None
        fields: dict[str, ast.AST] = {}
        for key, value in zip(mapping_node.keys, mapping_node.values):
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                fields[key.value.lower()] = value
        action_node = fields.get("op") or fields.get("action") or fields.get("cmd") or fields.get("type")
        if not isinstance(action_node, ast.Constant) or not isinstance(action_node.value, str):
            return None
        action = action_node.value.lower().strip()
        kinds = {
            "capture": HeapOperationKind.ALLOC,
            "create": HeapOperationKind.ALLOC,
            "add": HeapOperationKind.ALLOC,
            "forget": HeapOperationKind.FREE,
            "delete": HeapOperationKind.FREE,
            "remove": HeapOperationKind.FREE,
            "rewrite": HeapOperationKind.EDIT,
            "edit": HeapOperationKind.EDIT,
            "update": HeapOperationKind.EDIT,
            "recall": HeapOperationKind.SHOW,
            "show": HeapOperationKind.SHOW,
            "view": HeapOperationKind.SHOW,
        }
        kind = kinds.get(action)
        if kind is None:
            return None

        def rendered(*names: str) -> str:
            node = next((fields.get(name) for name in names if fields.get(name) is not None), None)
            return self._render_node(node, env) if node is not None else ""

        tag = rendered("tag", "name", "id", "idx", "index", "slot")
        day = rendered("day", "day_from", "key")
        index = ":".join(item for item in (tag, day) if item) or str(self._add_count)
        if kind == HeapOperationKind.ALLOC:
            chunk = self._auto_chunk_name(self._add_count)
            self._index_to_chunk[index] = chunk
            self._last_alloc_index = index
            self._add_count += 1
            return HeapOperation(
                "", kind, chunk=chunk, index=index,
                request_size=rendered("size", "length", "len") or "unknown",
                data=rendered("content", "content_hex", "data", "payload"),
                meta={"structured_action": action, "function": self._call_name(call.func)},
            )
        chunk = self._index_to_chunk.get(index, "")
        if kind == HeapOperationKind.FREE:
            return HeapOperation("", kind, chunk=chunk, index=index, meta={"structured_action": action})
        if kind == HeapOperationKind.EDIT:
            return HeapOperation(
                "", kind, chunk=chunk, index=index,
                request_size=rendered("size", "length", "len"),
                data=rendered("content", "content_hex", "data", "payload"),
                meta={"structured_action": action},
            )
        meta = {"structured_action": action, "function": self._call_name(call.func)}
        if result_var:
            meta["result_var"] = result_var
        return HeapOperation("", kind, chunk=chunk, index=index, meta=meta)

    def _active_object_edit_operation(self, call: ast.Call, env: dict[str, Any]) -> HeapOperation | None:
        """Recognize selected-object field edits such as login(id); edit_bio(size, data)."""

        if not self._active_index:
            return None
        function_name = self._resolve_alias(self._call_name(call.func))
        if not self._looks_active_object_edit_name(function_name):
            return None
        positional, keywords = self._call_arguments(call, env)
        size = keywords.get("size") or keywords.get("length") or (positional[0] if positional else "")
        data = (
            keywords.get("data")
            or keywords.get("content")
            or keywords.get("payload")
            or (positional[1] if len(positional) > 1 else "")
        )
        if not data:
            return None
        index = self._active_index
        return HeapOperation(
            "",
            HeapOperationKind.EDIT,
            chunk=self._index_to_chunk.get(index, ""),
            index=index,
            request_size=size,
            data=data,
            meta={
                "function": function_name,
                "active_selector": index,
                "parse_confidence": "active-object-edit",
            },
        )

    def _operation_from_call(
        self,
        call: ast.Call,
        kind: HeapOperationKind,
        show_result: str,
        assignment_target: str,
        env: dict[str, Any],
    ) -> HeapOperation | None:
        positional, keywords = self._call_arguments(call, env)
        function_name = self._resolve_alias(self._call_name(call.func))
        template = self._template_for_kind(kind)
        roles = [role for role in re.findall(r"\{(index|size|data|chunk|target|src|dst|length)\}", template)]
        learned_roles = self._learned_roles_for_call(call)
        function_roles = learned_roles or self._function_roles.get(function_name, ())
        has_known_signature = function_name in self._defined_function_parameters
        if function_roles:
            roles = list(function_roles)
        values: dict[str, str] = {}
        for role, value in zip(roles, positional):
            values.setdefault(role, value)
        for key, value in keywords.items():
            role = self._keyword_role(key, kind) or self._learned_keyword_role(call, key)
            if role:
                values[role] = value
        defaults = self._function_defaults.get(function_name, {})
        for name, value in defaults.items():
            role = self._keyword_role(name, kind)
            if role:
                values.setdefault(role, value)

        if (
            kind == HeapOperationKind.ALLOC
            and len(positional) >= 3
            and not any(role in values for role in {"index", "size", "data"})
        ):
            # Most three-argument menu helpers are add(index, size, data).  A
            # partially or fully discovered signature wins over this fallback.
            values.update(index=positional[0], size=positional[1], data=positional[2])
        elif (
            kind == HeapOperationKind.ALLOC
            and len(positional) >= 3
            and not has_known_signature
            and "index" not in values
        ):
            # With no helper definition there is no signature evidence to
            # distinguish add(size,data,flags) from the common
            # add(index,size,data) form. Preserve the established call-only
            # fallback; defined helpers use their proven roles above.
            values.update(index=positional[0], size=positional[1], data=positional[2])

        if kind == HeapOperationKind.ALLOC:
            single_positional_is_data = bool(
                len(positional) == 1
                and (
                    (function_roles and function_roles[0] == "data")
                    or (not function_roles and self._looks_like_data_expression(positional[0]))
                )
            )
            data_position = 1 if len(positional) > 1 else -1
            data = values.get("data") or (
                positional[data_position]
                if data_position >= 0 and not has_known_signature
                else ""
            )
            if single_positional_is_data:
                data = positional[0]
            if single_positional_is_data:
                size = "unknown"
            elif values.get("size"):
                size = values["size"]
            elif has_known_signature:
                # A helper such as reg(id, name, password) allocates, but the
                # requested size is not present in Python.  Unknown is more
                # truthful than reusing id as malloc size.
                size = "unknown"
            else:
                size = "unknown" if data and len(positional) == 1 else (positional[0] if positional else "unknown")
            index = values.get("index") or str(self._add_count)
            name = assignment_target if assignment_target and assignment_target.lower() not in {"idx", "index", "id", "slot"} else self._auto_chunk_name(self._add_count)
            chunk = self._sanitize_chunk_name(name) or self._auto_chunk_name(self._add_count)
            self._index_to_chunk[index] = chunk
            self._last_alloc_index = index
            self._add_count += 1
            return HeapOperation("", kind, chunk=chunk, index=index, request_size=size, data=data, meta={"parse_confidence": "confirmed"})
        if kind in {HeapOperationKind.FREE, HeapOperationKind.EDIT, HeapOperationKind.SHOW}:
            defined_parameters = self._defined_function_parameters.get(function_name, ())
            implicit_index = (
                self._active_index or self._last_alloc_index
                if has_known_signature and not defined_parameters
                else self._active_index
            )
            active_object_edit = bool(
                kind == HeapOperationKind.EDIT
                and self._active_index
                and "index" not in values
                and ("data" in values or "size" in values)
            )
            if values.get("index"):
                index = values["index"]
            elif active_object_edit:
                index = self._active_index
            elif has_known_signature:
                index = implicit_index
            else:
                index = positional[0] if positional else self._active_index
            chunk = self._index_to_chunk.get(index, "")
            if kind == HeapOperationKind.FREE:
                return HeapOperation("", kind, chunk=chunk, index=index)
            if kind == HeapOperationKind.EDIT:
                data = values.get("data") or (
                    positional[1] if len(positional) > 1 and not has_known_signature else "payload"
                )
                meta = {"offset": values.get("offset", "0")}
                if values.get("size"):
                    meta["length"] = values["size"]
                return HeapOperation(
                    "", kind, chunk=chunk, index=index,
                    request_size=values.get("size", ""), data=data, meta=meta,
                )
            meta = {
                "function": self._call_name(call.func),
                "expression": self._source_segment(call),
            }
            if values.get("offset"):
                meta["offset"] = values["offset"]
            if values.get("size"):
                meta["length"] = values["size"]
            if show_result:
                meta["result_var"] = show_result
            return HeapOperation("", kind, chunk=chunk, index=index, meta=meta)
        if kind == HeapOperationKind.COPY:
            src = values.get("src") or (positional[0] if positional else "")
            dst = values.get("dst") or (positional[1] if len(positional) > 1 else "")
            length = values.get("length") or values.get("size") or (positional[2] if len(positional) > 2 else "")
            return HeapOperation(
                "",
                kind,
                chunk=self._index_to_chunk.get(dst, ""),
                index=dst,
                request_size=length,
                target=self._index_to_chunk.get(src, src),
                meta={"src": src, "dst": dst, "length": length, "src_chunk": self._index_to_chunk.get(src, ""), "dst_chunk": self._index_to_chunk.get(dst, "")},
            )
        return None

    def _value_flow_metadata(self, expression: ast.AST) -> dict[str, str]:
        metadata: dict[str, str] = {}
        for node in ast.walk(expression):
            if not isinstance(node, ast.Call):
                continue
            name = self._call_name(node.func)
            if name in {"u32", "p32"}:
                metadata.update(byte_width="4", endian="little")
            elif name in {"u64", "p64"}:
                metadata.update(byte_width="8", endian="little")
            elif isinstance(node.func, ast.Attribute) and node.func.attr == "from_bytes":
                endian = "little"
                if len(node.args) > 1:
                    value = self._safe_eval(node.args[1], self._env)
                    if isinstance(value, str):
                        endian = value
                metadata["endian"] = endian
        for node in ast.walk(expression):
            if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice) and isinstance(node.slice.upper, ast.Constant) and isinstance(node.slice.upper.value, int):
                metadata.setdefault("observed_bytes", str(node.slice.upper.value))
                break
        return metadata

    def _append(self, operation: HeapOperation, node: ast.AST, loop_env: Mapping[str, Any], confidence: str) -> None:
        if len(self._operations) >= self.max_events:
            if not self._truncated:
                self._diagnose_node("warning", "events_truncated", f"语义事件超过 {self.max_events} 条，停止继续展开。", node)
            self._truncated = True
            return
        start, end = self._span(node)
        source_text = self.source[start:end] or self._source_segment(node)
        fingerprint = hashlib.sha1(ast.dump(node, include_attributes=False).encode("utf-8")).hexdigest()[:16]
        source_id = self._node_id("source", node, loop_env)
        binding = SourceBinding(
            source_id,
            start,
            end,
            int(getattr(node, "lineno", 0)),
            int(getattr(node, "end_lineno", getattr(node, "lineno", 0))),
            source_text,
            fingerprint,
            tuple((name, self._display_value(value)) for name, value in sorted(loop_env.items())),
            confidence,
        )
        note = f"from EXP: {source_text.strip()}"
        if loop_env:
            note += " [" + ", ".join(f"{key}={self._display_value(value)}" for key, value in loop_env.items()) + "]"
        operation_meta = dict(operation.meta)
        operation_meta.setdefault("source_line", str(binding.line))
        operation_meta.setdefault("source_end_line", str(binding.end_line))
        operation_meta.setdefault("source_id", binding.source_id)
        operation_meta.setdefault("ast_fingerprint", binding.fingerprint)
        self._operations.append(replace(operation, note=operation.note or note, meta=operation_meta))
        self._bindings.append(binding)

    def _append_unresolved(self, node: ast.AST, loop_env: Mapping[str, Any], reason: str) -> None:
        """Expose an uncertain execution boundary without mutating allocator state."""
        self._append(
            HeapOperation(
                "",
                HeapOperationKind.NOTE,
                note=reason,
                meta={"analysis_status": "unresolved"},
            ),
            node,
            loop_env,
            "unresolved",
        )

    def _emit_fake_chunk(self, name: str, pack: str, values: list[str], node: ast.AST, loop_env: Mapping[str, Any]) -> None:
        if len(values) < 4 or not self._looks_like_fake_chunk(name, values):
            return
        operation = HeapOperation(
            "",
            HeapOperationKind.FAKE_CHUNK,
            chunk=self._sanitize_chunk_name(name) or "fake_chunk",
            request_size=values[1],
            data=f"{name} = " + " + ".join(f"{pack}({value})" for value in values),
            target=name,
            fd_storage=values[2],
            meta={
                "prev_size": values[0],
                "size": values[1],
                "fd": values[2],
                "bk": values[3],
                "address": name,
                "pack": pack,
                "source": "ast-fake-chunk-builder",
                "role": "fake",
                "evidence_level": "candidate",
            },
        )
        self._append(operation, node, loop_env, "inferred")
        self._emitted_fake_names.add(name)

    @staticmethod
    def _looks_like_fake_chunk(name: str, values: list[str]) -> bool:
        """Separate chunk metadata builders from ordinary packed ROP chains."""

        # Structure, not the variable name, creates a *candidate*.  Requiring
        # a small aligned malloc size in word 1 sharply separates the common
        # ``prev_size,size,fd,bk`` layout from packed ROP addresses.  Allocator
        # use is still required before the engine upgrades it to confirmed.
        try:
            prev_size = int(str(values[0]).strip(), 0)
            raw_size = int(str(values[1]).strip(), 0)
        except (TypeError, ValueError):
            return False
        chunk_size = raw_size & ~0x7
        if not (0x20 <= chunk_size <= 0x10000 and chunk_size % 0x10 == 0):
            return False
        if prev_size < 0 or (prev_size and prev_size % 0x10):
            return False
        pointer_words = " ".join(str(value).lower() for value in values[2:4])
        rop_markers = ("pop_", "system", "bin_sh", "setcontext", "syscall", "leave_ret")
        return not any(marker in pointer_words for marker in rop_markers)

    def _packed_values(self, node: ast.AST, env: Mapping[str, Any]) -> tuple[str, list[str]] | None:
        if isinstance(node, ast.Call):
            name = self._call_name(node.func)
            if name == "flat":
                args = list(node.args)
                if len(args) == 1 and isinstance(args[0], (ast.List, ast.Tuple)):
                    args = list(args[0].elts)
                if len(args) >= 4:
                    pack = "p32" if "32" in self.api_profile.alloc_template else "p64"
                    return pack, [self._render_packed_word(item, env) for item in args]
            if name in {"p32", "p64"} and node.args:
                return name, [self._render_packed_word(node.args[0], env)]
            return None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._packed_values(node.left, env)
            right = self._packed_values(node.right, env)
            if left and right and left[0] == right[0]:
                return left[0], left[1] + right[1]
        return None

    def _render_packed_word(self, node: ast.AST, env: Mapping[str, Any]) -> str:
        """Render one packed machine word without expanding a payload name.

        In ``fake_chunk += p64(fake_chunk)`` the inner name is a pointer value,
        not a request to splice the whole previously-built payload expression
        into the fd field.
        """
        if isinstance(node, ast.Name) and (node.id not in env or env.get(node.id) is _UNKNOWN):
            return node.id
        return self._render_node(node, env)

    def _apply_container_call(self, expression: ast.AST, env: dict[str, Any]) -> None:
        if not isinstance(expression, ast.Call) or not isinstance(expression.func, ast.Attribute):
            return
        if not isinstance(expression.func.value, ast.Name):
            return
        name = expression.func.value.id
        method = expression.func.attr
        container = env.get(name, _UNKNOWN)
        if not isinstance(container, (list, dict)):
            return
        if method == "append" and isinstance(container, list) and expression.args:
            value = self._safe_eval(expression.args[0], env)
            if value is _UNKNOWN and self._operations and self._operations[-1].kind == HeapOperationKind.ALLOC:
                value = self._parse_scalar(self._operations[-1].index)
            if value is not _UNKNOWN:
                container.append(value)
        elif method == "extend" and isinstance(container, list) and expression.args:
            value = self._safe_eval(expression.args[0], env)
            if isinstance(value, (list, tuple)):
                container.extend(value)
        elif method == "update" and isinstance(container, dict) and expression.args:
            value = self._safe_eval(expression.args[0], env)
            if isinstance(value, dict):
                container.update(value)

    def _expand_comprehension(self, expression: ast.ListComp | ast.SetComp | ast.GeneratorExp, env: dict[str, Any], loop_env: dict[str, Any]) -> Any:
        results: list[Any] = []
        iterations = 0

        def walk(generator_index: int, local_loop: dict[str, Any]) -> bool:
            nonlocal iterations
            if generator_index >= len(expression.generators):
                iterations += 1
                if iterations > self.max_loop_iterations:
                    self._diagnose_node("warning", "comprehension_truncated", f"列表推导式只展开前 {self.max_loop_iterations} 次。", expression)
                    return False
                before = len(self._operations)
                self._analyze_expression(expression.elt, "", expression.elt, env, local_loop)
                value = self._safe_eval(expression.elt, env)
                if value is _UNKNOWN and len(self._operations) > before and self._operations[-1].kind == HeapOperationKind.ALLOC:
                    value = self._parse_scalar(self._operations[-1].index)
                results.append(value)
                return True
            generator = expression.generators[generator_index]
            iterable = self._safe_iterable(generator.iter, env)
            if iterable is _UNKNOWN:
                self._diagnose_node("warning", "dynamic_comprehension", "列表推导式 iterable 无法静态确定。", generator.iter)
                return False
            for value in iterable:
                self._bind_target(generator.target, value, env)
                next_loop = dict(local_loop)
                for name in self._target_names(generator.target):
                    next_loop[name] = env.get(name, _UNKNOWN)
                include = True
                for condition in generator.ifs:
                    result = self._safe_eval(condition, env)
                    if result is False:
                        include = False
                        break
                    if not isinstance(result, bool):
                        self._diagnose_node("warning", "dynamic_comprehension_if", "推导式条件无法确定，未猜测该迭代。", condition)
                        include = False
                        break
                if include and not walk(generator_index + 1, next_loop):
                    return False
            return True

        completed = walk(0, dict(loop_env))
        return results if completed else (results if results else _UNKNOWN)

    def _apply_overrides(
        self,
        operations: list[HeapOperation],
        bindings: list[SourceBinding],
    ) -> tuple[list[HeapOperation], list[SourceBinding], list[ParseDiagnostic]]:
        active_by_source: dict[str, list[TimelineOverride]] = {}
        diagnostics: list[ParseDiagnostic] = []
        rebound_sources: set[str] = set()
        known_ids = {binding.source_id for binding in bindings}
        for override in self.overrides:
            if override.source_id.startswith("manual_range_"):
                continue
            target_id = override.source_id
            if target_id not in known_ids and override.fingerprint:
                matches = [binding for binding in bindings if binding.fingerprint == override.fingerprint and (not override.anchor_text or override.anchor_text.strip() == binding.source_text.strip())]
                if len(matches) == 1:
                    target_id = matches[0].source_id
                    rebound_sources.add(target_id)
            if target_id not in known_ids:
                diagnostics.append(ParseDiagnostic("warning", "stale_override", f"人工校正 {override.override_id} 已无法绑定到当前源码。", suggestion="重新选择源码范围并绑定。"))
                continue
            active_by_source.setdefault(target_id, []).append(replace(override, source_id=target_id, status="active"))

        result_ops: list[HeapOperation] = []
        result_bindings: list[SourceBinding] = []
        inserted: set[str] = set()
        for operation, binding in zip(operations, bindings):
            if binding.source_id in rebound_sources:
                binding = replace(binding, match_status="rebound")
            overrides = active_by_source.get(binding.source_id, [])
            for override in overrides:
                if override.action == "insert_before" and override.operation and override.override_id not in inserted:
                    result_ops.append(override.operation)
                    result_bindings.append(replace(binding, confidence="manual"))
                    inserted.add(override.override_id)
            ignored = any(override.action == "ignore" for override in overrides)
            replacement = next((override.operation for override in reversed(overrides) if override.action == "replace" and override.operation), None)
            if not ignored:
                result_ops.append(replacement or operation)
                result_bindings.append(replace(binding, confidence="manual" if replacement else binding.confidence))
            for override in overrides:
                if override.action == "insert_after" and override.operation and override.override_id not in inserted:
                    result_ops.append(override.operation)
                    result_bindings.append(replace(binding, confidence="manual"))
                    inserted.add(override.override_id)
        manual_ranges: list[tuple[int, HeapOperation, SourceBinding, str]] = []
        for override in self.overrides:
            if not override.source_id.startswith("manual_range_") or not override.operation:
                continue
            anchor = override.anchor_text
            start = self.source.find(anchor) if anchor else -1
            if start < 0 or (anchor and self.source.find(anchor, start + 1) >= 0):
                diagnostics.append(ParseDiagnostic("warning", "stale_override", f"人工选区 {override.override_id} 已无法唯一绑定。", suggestion="重新选择代码范围。"))
                continue
            end = start + len(anchor)
            line = self.source.count("\n", 0, start) + 1
            end_line = line + anchor.count("\n")
            binding = SourceBinding(
                override.source_id,
                start,
                end,
                line,
                end_line,
                anchor,
                override.fingerprint or hashlib.sha1(anchor.encode("utf-8")).hexdigest()[:16],
                (),
                "manual",
            )
            manual_ranges.append((start, override.operation, binding, override.action))
        for start, operation, binding, action in sorted(manual_ranges, key=lambda item: item[0]):
            insert_at = len(result_bindings)
            for index, current in enumerate(result_bindings):
                if current.start >= start:
                    insert_at = index
                    break
                if current.start < start < current.end:
                    insert_at = index + (1 if action == "insert_after" else 0)
                    break
            result_ops.insert(insert_at, operation)
            result_bindings.insert(insert_at, binding)
        # ``result_ops`` already follows Python evaluation order.  Sorting by
        # source start used to move an outer derive expression before the
        # nested ``show()`` that must execute first (for example
        # ``u64(show(7)[:5].ljust(...))``).  Keep deterministic AST order and
        # only splice free-standing manual ranges near their source anchor.
        return result_ops, result_bindings, diagnostics

    def _call_arguments(self, call: ast.Call, env: Mapping[str, Any]) -> tuple[list[str], dict[str, str]]:
        positional: list[str] = []
        keywords: dict[str, str] = {}
        for argument in call.args:
            if isinstance(argument, ast.Starred):
                value = self._safe_eval(argument.value, env)
                if isinstance(value, (tuple, list)):
                    positional.extend(self._display_value(item) for item in value)
                else:
                    positional.append("*" + self._render_node(argument.value, env))
            else:
                positional.append(self._render_node(argument, env))
        for keyword in call.keywords:
            if keyword.arg is None:
                value = self._safe_eval(keyword.value, env)
                if isinstance(value, dict):
                    keywords.update({str(key): self._display_value(item) for key, item in value.items()})
                continue
            keywords[keyword.arg] = self._render_node(keyword.value, env)
        return positional, keywords

    def _safe_iterable(self, node: ast.AST, env: Mapping[str, Any]) -> Any:
        value = self._safe_eval(node, env)
        if isinstance(value, (list, tuple, range)):
            return value
        return _UNKNOWN

    def _safe_eval(self, node: ast.AST, env: Mapping[str, Any]) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id == "__name__":
                return "__main__"
            return env.get(node.id, _UNKNOWN)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            values = [self._safe_eval(item, env) for item in node.elts]
            if any(value is _UNKNOWN for value in values):
                return _UNKNOWN
            return tuple(values) if isinstance(node, ast.Tuple) else list(values)
        if isinstance(node, ast.Dict):
            keys = [self._safe_eval(item, env) for item in node.keys]
            values = [self._safe_eval(item, env) for item in node.values]
            if any(item is _UNKNOWN for item in keys + values):
                return _UNKNOWN
            return dict(zip(keys, values))
        if isinstance(node, ast.UnaryOp):
            value = self._safe_eval(node.operand, env)
            if value is _UNKNOWN:
                return _UNKNOWN
            try:
                if isinstance(node.op, ast.USub): return -value
                if isinstance(node.op, ast.UAdd): return +value
                if isinstance(node.op, ast.Invert): return ~value
                if isinstance(node.op, ast.Not): return not value
            except (TypeError, ArithmeticError):
                return _UNKNOWN
        if isinstance(node, ast.BinOp):
            left = self._safe_eval(node.left, env)
            right = self._safe_eval(node.right, env)
            if left is _UNKNOWN or right is _UNKNOWN:
                return _UNKNOWN
            try:
                if isinstance(node.op, ast.Add): return left + right
                if isinstance(node.op, ast.Sub): return left - right
                if isinstance(node.op, ast.Mult): return left * right
                if isinstance(node.op, ast.FloorDiv): return left // right
                if isinstance(node.op, ast.Mod): return left % right
                if isinstance(node.op, ast.LShift): return left << right
                if isinstance(node.op, ast.RShift): return left >> right
                if isinstance(node.op, ast.BitAnd): return left & right
                if isinstance(node.op, ast.BitOr): return left | right
                if isinstance(node.op, ast.BitXor): return left ^ right
            except (TypeError, ArithmeticError, ValueError, OverflowError):
                return _UNKNOWN
        if isinstance(node, ast.BoolOp):
            values = [self._safe_eval(item, env) for item in node.values]
            if any(value is _UNKNOWN for value in values): return _UNKNOWN
            return all(values) if isinstance(node.op, ast.And) else any(values)
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
            left = self._safe_eval(node.left, env)
            right = self._safe_eval(node.comparators[0], env)
            if left is _UNKNOWN or right is _UNKNOWN: return _UNKNOWN
            op = node.ops[0]
            try:
                if isinstance(op, ast.Eq): return left == right
                if isinstance(op, ast.NotEq): return left != right
                if isinstance(op, ast.Lt): return left < right
                if isinstance(op, ast.LtE): return left <= right
                if isinstance(op, ast.Gt): return left > right
                if isinstance(op, ast.GtE): return left >= right
                if isinstance(op, ast.In): return left in right
                if isinstance(op, ast.NotIn): return left not in right
            except TypeError:
                return _UNKNOWN
        if isinstance(node, ast.IfExp):
            condition = self._safe_eval(node.test, env)
            if isinstance(condition, bool):
                return self._safe_eval(node.body if condition else node.orelse, env)
        if isinstance(node, ast.Subscript):
            container = self._safe_eval(node.value, env)
            index = self._safe_eval(node.slice, env)
            if container is _UNKNOWN or index is _UNKNOWN:
                return _UNKNOWN
            try: return container[index]
            except (KeyError, IndexError, TypeError): return _UNKNOWN
        if isinstance(node, ast.Slice):
            lower = None if node.lower is None else self._safe_eval(node.lower, env)
            upper = None if node.upper is None else self._safe_eval(node.upper, env)
            step = None if node.step is None else self._safe_eval(node.step, env)
            if _UNKNOWN in {lower, upper, step}: return _UNKNOWN
            return slice(lower, upper, step)
        if isinstance(node, ast.Call):
            name = self._call_name(node.func)
            args = [self._safe_eval(item, env) for item in node.args]
            if any(item is _UNKNOWN for item in args):
                return _UNKNOWN
            try:
                if name == "range" and 1 <= len(args) <= 3: return range(*args)
                if name == "enumerate" and 1 <= len(args) <= 2: return list(enumerate(*args))
                if name == "zip" and args: return list(zip(*args))
                if name in {"list", "tuple", "bytes", "str", "int"} and len(args) <= 1:
                    return {"list": list, "tuple": tuple, "bytes": bytes, "str": str, "int": int}[name](*args)
            except (TypeError, ValueError, OverflowError):
                return _UNKNOWN
        return _UNKNOWN

    def _contains_entry_call(self, statements: Iterable[ast.stmt]) -> bool:
        return any(
            isinstance(node, ast.Call)
            and self._resolve_alias(self._call_name(node.func)).lower() in self._entry_names
            for statement in statements
            for node in ast.walk(statement)
        )

    def _preview_uninvoked_entrypoint(self, tree: ast.Module) -> None:
        """Preview one obvious definition-only exploit body as inferred IR.

        PDF snippets and partially pasted EXPs often end after ``exploit`` is
        defined.  This path is deliberately narrower than normal inlining: it
        requires exactly one no-argument entrypoint and at least one already
        classified heap call.  The emitted operations remain inferred rather
        than pretending the missing call executed.
        """

        candidates = [
            node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.lower() in self._entry_names
        ]
        if len(candidates) != 1:
            effect_candidates = [node for node in candidates if self._function_has_heap_effect(node.name, set())]
            preferred = [node for node in effect_candidates if node.name.lower() != "main"]
            if len(preferred) == 1:
                candidates = preferred
            elif len(effect_candidates) == 1:
                candidates = effect_candidates
            else:
                return
        definition = candidates[0]
        parameters = [item.arg for item in (*definition.args.posonlyargs, *definition.args.args)]
        required = max(0, len(parameters) - len(definition.args.defaults))
        if definition.args.vararg or definition.args.kwarg:
            return
        has_heap_call = self._function_has_heap_effect(definition.name, set()) or any(
            isinstance(node, ast.Call) and self._semantic_kind(node) is not None
            for statement in definition.body
            for node in ast.walk(statement)
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
        )
        if not has_heap_call:
            return

        start_ops = len(self._operations)
        start_bindings = len(self._bindings)
        local_env = dict(self._env)
        for parameter in parameters[:required]:
            local_env[parameter] = _UNKNOWN
        if definition.args.defaults:
            for parameter, default in zip(parameters[-len(definition.args.defaults):], definition.args.defaults):
                local_env[parameter] = self._safe_eval(default, self._env)
        self._entry_call_stack.append(definition.name)
        self._entry_call_count += 1
        try:
            self._walk_statements(definition.body, local_env, {})
        finally:
            self._entry_call_stack.pop()
        if len(self._operations) == start_ops:
            return
        for index in range(start_ops, len(self._operations)):
            operation = self._operations[index]
            self._operations[index] = replace(
                operation,
                meta={
                    **operation.meta,
                    "parse_confidence": operation.meta.get("parse_confidence", "inferred"),
                    "entrypoint_preview": "uninvoked",
                },
            )
        for index in range(start_bindings, len(self._bindings)):
            self._bindings[index] = replace(self._bindings[index], confidence="inferred")
        self._diagnose_node(
            "info",
            "previewed_uninvoked_entrypoint",
            f"源码只定义了入口 `{definition.name}`；已按未调用预览展开，步骤不代表真实执行。",
            definition,
        )

    def _inline_entry_call(self, call: ast.Call, env: dict[str, Any], loop_env: dict[str, Any]) -> bool:
        name = self._resolve_alias(self._call_name(call.func))
        definition = self._function_nodes.get(name)
        if definition is None or name.lower() not in self._entry_names:
            return False
        if name in self._entry_call_stack or len(self._entry_call_stack) >= 8 or self._entry_call_count >= 32:
            self._diagnose_node("warning", "entry_inline_limit", f"入口函数 `{name}` 达到有界内联限制。", call)
            return True
        parameters = [item.arg for item in (*definition.args.posonlyargs, *definition.args.args)]
        required = max(0, len(parameters) - len(definition.args.defaults))
        supplied = len(call.args) + len([item for item in call.keywords if item.arg])
        if not required <= supplied <= len(parameters) or any(item.arg is None for item in call.keywords):
            self._diagnose_node("warning", "entry_args_unknown", f"入口函数 `{name}` 参数无法静态绑定。", call)
            return True
        local_env = dict(env)
        for parameter, argument in zip(parameters, call.args):
            local_env[parameter] = self._safe_eval(argument, env)
        for keyword in call.keywords:
            if keyword.arg:
                local_env[keyword.arg] = self._safe_eval(keyword.value, env)
        if definition.args.defaults:
            for parameter, default in zip(parameters[-len(definition.args.defaults):], definition.args.defaults):
                local_env.setdefault(parameter, self._safe_eval(default, env))
        self._entry_call_stack.append(name)
        self._entry_call_count += 1
        self._diagnose_node("info", "inlined_entrypoint", f"已静态内联入口函数 `{name}`。", call)
        try:
            self._walk_statements(definition.body, local_env, loop_env)
        finally:
            self._entry_call_stack.pop()
        return True

    def _inline_effect_helper_call(self, call: ast.Call, env: dict[str, Any], loop_env: dict[str, Any]) -> bool:
        """Inline a local phase/wrapper that transitively performs heap calls.

        Competition EXPs rarely keep all add/free/edit/show calls directly in
        ``main``.  They use helpers such as ``setup()``, ``poison()`` and
        ``set_layout()``.  Previously only specially named entrypoints were
        expanded, so the canvas silently lost most of an otherwise static
        exploit.  This bounded interpreter expands only a proven local helper
        whose body contains a semantic call (possibly through another local
        helper); arbitrary Python calls are never executed.
        """

        if not isinstance(call.func, (ast.Name, ast.Attribute)):
            return False
        name = self._resolve_alias(self._call_name(call.func))
        definition = self._function_nodes.get(name)
        if definition is None or self._semantic_kind(call) is not None:
            return False
        if not self._function_has_heap_effect(name, set()):
            return False
        if name in self._entry_call_stack or len(self._entry_call_stack) >= 12 or self._entry_call_count >= 128:
            self._diagnose_node("warning", "helper_inline_limit", f"局部堆 helper `{name}` 达到有界内联限制。", call)
            return True

        parameters = [item.arg for item in (*definition.args.posonlyargs, *definition.args.args)]
        implicit_receiver = bool(parameters and parameters[0] in {"self", "cls"} and isinstance(call.func, ast.Attribute))
        bind_parameters = parameters[1:] if implicit_receiver else parameters
        required = max(0, len(parameters) - len(definition.args.defaults))
        if implicit_receiver:
            required = max(0, required - 1)
        supplied = len(call.args) + len([item for item in call.keywords if item.arg])
        if not required <= supplied <= len(bind_parameters) or any(item.arg is None for item in call.keywords):
            self._diagnose_node("warning", "helper_args_unknown", f"局部堆 helper `{name}` 参数无法静态绑定。", call)
            return True

        local_env = dict(env)
        if implicit_receiver:
            local_env[parameters[0]] = _UNKNOWN
        for parameter, argument in zip(bind_parameters, call.args):
            local_env[parameter] = self._safe_eval(argument, env)
        for keyword in call.keywords:
            if keyword.arg:
                local_env[keyword.arg] = self._safe_eval(keyword.value, env)
        if definition.args.defaults:
            for parameter, default in zip(bind_parameters[-len(definition.args.defaults):], definition.args.defaults):
                local_env.setdefault(parameter, self._safe_eval(default, env))

        self._entry_call_stack.append(name)
        self._entry_call_count += 1
        self._diagnose_node("info", "inlined_heap_helper", f"已静态内联局部堆 helper `{name}`。", call)
        try:
            self._walk_statements(definition.body, local_env, loop_env)
        finally:
            self._entry_call_stack.pop()
        return True

    def _function_has_heap_effect(self, name: str, visiting: set[str]) -> bool:
        cached = self._helper_effect_cache.get(name)
        if cached is not None:
            return cached
        if name in visiting:
            return False
        definition = self._function_nodes.get(name)
        if definition is None:
            return False
        visiting = {*visiting, name}
        for node in ast.walk(definition):
            if not isinstance(node, ast.Call):
                continue
            callee = self._resolve_alias(self._call_name(node.func))
            if callee == name:
                continue
            if self._semantic_kind(node) is not None:
                self._helper_effect_cache[name] = True
                return True
            if isinstance(node.func, (ast.Name, ast.Attribute)) and self._function_has_heap_effect(callee, visiting):
                self._helper_effect_cache[name] = True
                return True
            if any(
                isinstance(argument, ast.Dict)
                and any(
                    isinstance(key, ast.Constant) and key.value in {"op", "action", "cmd", "type"}
                    and isinstance(value, ast.Constant) and isinstance(value.value, str)
                    and value.value.lower() in {"capture", "create", "add", "forget", "delete", "remove", "rewrite", "edit", "update", "recall", "show", "view"}
                    for key, value in zip(argument.keys, argument.values)
                )
                for argument in node.args
            ):
                self._helper_effect_cache[name] = True
                return True
        self._helper_effect_cache[name] = False
        return False

    def _render_node(self, node: ast.AST, env: Mapping[str, Any]) -> str:
        if isinstance(node, ast.Name) and node.id in self._payload_sources:
            return self._payload_sources[node.id]
        if isinstance(node, (ast.Name, ast.Subscript)):
            value = self._safe_eval(node, env)
            if value is not _UNKNOWN:
                return self._display_value(value)
        # Fold expressions that actually depend on statically-bound loop or
        # container variables (100+i, sizes[i], base_idx+j).  Literal-only
        # expressions such as 0x80|14 stay verbatim because their source form
        # can carry exploit meaning even though Python can evaluate them.
        if self._names(node):
            value = self._safe_eval(node, env)
            if value is not _UNKNOWN and isinstance(value, (bool, int, float, bytes, str)):
                return self._display_value(value)
        text = self._source_segment(node)
        names = sorted(self._names(node), key=len, reverse=True)
        for name in names:
            value = env.get(name, _UNKNOWN)
            if value is _UNKNOWN or isinstance(value, str) and not self._is_literal_string(value):
                continue
            text = re.sub(rf"\b{re.escape(name)}\b", self._display_value(value), text)
        return text.strip()

    def _semantic_kind(self, call: ast.Call) -> HeapOperationKind | None:
        learned = self._matching_learned_rule(call)
        if learned:
            try:
                return HeapOperationKind(str(learned.get("semantic") or ""))
            except ValueError:
                pass
        target = self._call_target(call)
        name = target.function_name
        if name.lower() in self._recognition_ignore_names:
            return None   # 用户显式标注忽略：永远不猜这个函数的语义
        kind = self._semantic_names.get(name) or _DEFAULT_NAMES.get(name.lower())
        if kind is None or self._is_excluded_call_target(target):
            return None
        if target.is_method:
            return kind if target.origin in {"challenge_receiver", "user_method"} else None
        if name.lower() in _AMBIGUOUS_HEURISTIC_NAMES and target.origin not in {
            "profile", "user_helper", "learned", "challenge_receiver",
        }:
            return None
        return kind

    # -----------------------------------------------------------------
    # RecognitionReport ledger —— 识别能力的自观测数据。
    #
    # 绝不「没认出来就猜一个最像的」：每个被考虑过的调用点都拿到明确
    # 裁决 —— recognized（已绑定语义）/ ambiguous（名字/形态无法唯一
    # 定语义）/ unknown（像堆操作但无证据）/ ignored（非堆调用，说明
    # 忽略原因）。UNKNOWN 与 AMBIGUOUS 是正式结果，不是错误。

    _KIND_FAMILIES: dict[str, frozenset[str]] = {
        kind_enum.value: frozenset(
            name for name, mapped in _DEFAULT_NAMES.items() if mapped == kind_enum
        )
        for kind_enum in (
            HeapOperationKind.ALLOC,
            HeapOperationKind.FREE,
            HeapOperationKind.EDIT,
            HeapOperationKind.SHOW,
            HeapOperationKind.COPY,
        )
    }

    @classmethod
    def _semantic_scores(cls, name: str) -> dict[str, float]:
        """名字家族启发式评分：只作展示提示，永不直接当语义用。"""
        lowered = name.lower()
        hits = [kind for kind, family in cls._KIND_FAMILIES.items() if lowered in family]
        if not hits:
            return {}
        share = round(1.0 / len(hits), 2)
        return {kind: share for kind in sorted(hits)}

    def _note_recognition(
        self,
        call: ast.Call,
        verdict: str,
        kind: HeapOperationKind | None,
        reason: str,
    ) -> None:
        key = (int(getattr(call, "lineno", 0)), int(getattr(call, "col_offset", 0)))
        target = self._call_target(call)
        entry = self._recognition_candidates.get(key)
        if entry is None:
            self._recognition_candidates[key] = {
                "line": key[0],
                "source_text": (self._source_segment(call) or "").strip(),
                "function": target.function_name,
                "receiver": target.receiver,
                "origin": target.origin,
                "verdict": verdict,
                "kind": kind.value if kind else "",
                "confidence": self._target_confidence(target),
                "scores": self._semantic_scores(target.function_name),
                # 实参数量：标注 UI 的参数位由此动态生成（训练样本的
                # 角色槽位必须对齐真实调用形态）。
                "argument_count": len(call.args),
                "reason": reason,
            }
            return
        # 循环体多次走过同一调用点：已绑定语义的裁决优先于此前的占位。
        if verdict == "recognized" and entry["verdict"] != "recognized":
            entry.update({
                "verdict": verdict,
                "kind": kind.value if kind else "",
                "confidence": self._target_confidence(target),
                "reason": reason,
            })

    def _classify_unrecognized_call(self, call: ast.Call) -> tuple[str, str]:
        """semantic_kind=None 时的裁决：为什么没认出来（不猜）。"""
        target = self._call_target(call)
        name = target.function_name
        lowered = name.lower()
        if lowered in self._recognition_ignore_names:
            return "ignored", "用户标注忽略（recognition_ignore 规则），识别器不再猜测该函数"
        if self._is_excluded_call_target(target):
            return "ignored", "Python 内置/标准库调用，与堆语义无关"
        if lowered in _RECV_NAMES or lowered in {item.lower() for item in self._recv_value_helpers}:
            return "ignored", "IO 接收调用（leak 通道），不是堆操作"
        if lowered in self._selector_names or lowered in self._selector_clear_names:
            return "ignored", "菜单选择器调用（login/select 之类），只影响 active index"
        if lowered in _AMBIGUOUS_HEURISTIC_NAMES and target.origin not in {
            "profile", "user_helper", "learned", "challenge_receiver",
        }:
            return (
                "ambiguous",
                "通用动词名（insert/remove/edit…）单凭名字无法唯一确定语义；"
                "需要 helper 函数体、别名映射或 HelperContract 佐证",
            )
        if target.is_method and target.origin == "python_builtin":
            return "ignored", "容器/字符串方法调用，与堆语义无关"
        if self._looks_heap_related(name):
            return "unknown", "名字像堆操作，但没有函数体/映射/契约证据，拒绝猜测语义"
        if target.origin in {"challenge_receiver", "user_method", "user_helper", "default_helper", "heuristic"} and not target.is_method:
            if target.origin == "user_helper":
                return "unknown", "EXP 自定义函数调用，但函数体没有可证明的堆语义（可能需要 dispatcher 规则）"
            if target.origin == "challenge_receiver":
                return "unknown", "challenge 对象的方法调用未映射到任何堆语义（可能需要 dispatcher 规则/映射）"
        return "ignored", "非堆调用"

    def _prescan_recognition(self, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            key = (int(getattr(node, "lineno", 0)), int(getattr(node, "col_offset", 0)))
            if key in self._recognition_candidates:
                continue
            if self._semantic_kind(node) is not None:
                continue   # recognized 只能来自执行路径的真实绑定
            verdict, reason = self._classify_unrecognized_call(node)
            self._note_recognition(node, verdict, None, reason)

    def _build_recognition_report(self) -> dict[str, Any]:
        entries = sorted(
            self._recognition_candidates.values(),
            key=lambda item: (item["line"], item["function"]),
        )
        counts: dict[str, int] = {"recognized": 0, "ambiguous": 0, "unknown": 0, "ignored": 0}
        for entry in entries:
            counts[entry["verdict"]] = counts.get(entry["verdict"], 0) + 1
        return {
            "candidate_calls": len(entries),
            "recognized": counts["recognized"],
            "ambiguous": counts["ambiguous"],
            "unknown": counts["unknown"],
            "ignored": counts["ignored"],
            "truncated": self._truncated or self._uncertain_stop,
            "recognizer_revision": RECOGNIZER_REVISION,
            "candidates": entries,
        }

    def _record_program_event(
        self,
        call: ast.Call,
        result: str,
        env: Mapping[str, Any],
        loop_env: Mapping[str, Any],
    ) -> ProgramEvent:
        event_id = self._node_id("event", call, loop_env)
        existing = self._program_events_by_id.get(event_id)
        if existing is not None:
            return existing
        target = self._call_target(call)
        kind = self._program_event_kind(call, target)
        start, end = self._span(call)
        evidence: list[ProgramEvidence] = []
        behavior = self.behavior_profile.match(target.function_name, target.receiver)
        learned = self._matching_learned_rule(call)
        if behavior:
            evidence.append(ProgramEvidence(
                "challenge_profile",
                behavior.evidence,
                int(getattr(call, "lineno", 0)),
                1.0,
            ))
            target = replace(target, origin="profile")
        elif learned:
            evidence.append(ProgramEvidence(
                "learned_rule",
                f"rule {learned.get('rule_id') or '<scene>'} matched exact call shape",
                int(getattr(call, "lineno", 0)),
                0.98,
            ))
            target = replace(target, origin="learned")
        elif target.origin == "user_helper":
            definition = self._function_nodes.get(target.function_name)
            evidence.append(ProgramEvidence(
                "helper_definition",
                f"helper body `{target.function_name}` is defined in this EXP",
                int(getattr(definition, "lineno", 0)),
                0.96,
            ))
        else:
            evidence.append(ProgramEvidence(
                "call_target",
                f"{target.qualified_name} resolved as {target.origin}",
                int(getattr(call, "lineno", 0)),
                self._target_confidence(target),
            ))
        positional = tuple(
            parse_semantic_expression(self._render_node(item, env))
            for item in call.args
        )
        keywords = tuple(
            (str(item.arg or "**"), parse_semantic_expression(self._render_node(item.value, env)))
            for item in call.keywords
        )
        event = ProgramEvent(
            event_id,
            kind,
            target,
            positional,
            keywords,
            self._source_segment(call),
            int(getattr(call, "lineno", 0)),
            start,
            end,
            result,
            max((item.confidence for item in evidence), default=0.0),
            tuple(evidence),
        )
        self._program_events.append(event)
        self._program_events_by_id[event_id] = event
        return event

    def _program_event_kind(self, call: ast.Call, target: CallTarget) -> str:
        name = target.function_name.lower()
        if name in self._selector_names or name in self._selector_clear_names:
            return "selector"
        if self.behavior_profile.match(target.function_name, target.receiver) is not None:
            return "call"
        semantic = self._semantic_kind(call)
        if semantic in {HeapOperationKind.EDIT, HeapOperationKind.COPY}:
            return "write"
        if semantic == HeapOperationKind.SHOW or name in _RECV_NAMES or name in self._recv_value_helpers:
            return "read"
        return "call"

    def _call_target(self, call: ast.Call) -> CallTarget:
        qualified = self._qualified_call_name(call.func)
        raw_name = self._call_name(call.func)
        name = self._resolve_alias(raw_name)
        receiver = qualified.rsplit(".", 1)[0] if isinstance(call.func, ast.Attribute) and "." in qualified else ""
        receiver_root = receiver.split(".", 1)[0].lower() if receiver else ""
        receiver_type = "unknown"
        if receiver_root:
            value = self._env.get(receiver.split(".", 1)[0], _UNKNOWN)
            if value is not _UNKNOWN:
                receiver_type = type(value).__name__.lower()
            elif receiver_root in _NON_CHALLENGE_RECEIVERS:
                receiver_type = "known_non_challenge"

        if receiver:
            if name in self._method_names and (receiver_root == "self" or receiver_type != "known_non_challenge"):
                origin = "user_method"
            elif receiver_type in {"dict", "list", "set", "tuple", "str", "bytes", "bytearray", "known_non_challenge"}:
                origin = "python_builtin"
            elif receiver_root in _CHALLENGE_RECEIVERS:
                origin = "challenge_receiver"
            else:
                origin = "heuristic"
        elif name in self._defined_function_names or raw_name in self._defined_function_names:
            origin = "user_helper"
        elif name in self._explicit_profile_names or raw_name in self._explicit_profile_names:
            origin = "profile"
        elif name.lower() in _PYTHON_BUILTIN_CALLS:
            origin = "python_builtin"
        elif name.lower() in _DEFAULT_NAMES and name.lower() not in _AMBIGUOUS_HEURISTIC_NAMES:
            origin = "default_helper"
        else:
            origin = "heuristic"
        return CallTarget(qualified or name, name, receiver, receiver_type, origin)

    @staticmethod
    def _target_confidence(target: CallTarget) -> float:
        return {
            "profile": 1.0,
            "learned": 0.98,
            "user_helper": 0.96,
            "user_method": 0.94,
            "challenge_receiver": 0.80,
            "default_helper": 0.72,
            "heuristic": 0.35,
            "python_builtin": 0.0,
        }.get(target.origin, 0.0)

    @staticmethod
    def _is_excluded_call_target(target: CallTarget) -> bool:
        return target.origin == "python_builtin"

    def _is_heap_candidate_target(self, target: CallTarget) -> bool:
        if self._is_excluded_call_target(target):
            return False
        if self.behavior_profile.match(target.function_name, target.receiver) is not None:
            return True
        if not target.is_method:
            return True
        return target.origin in {"profile", "user_helper", "user_method", "learned", "challenge_receiver"}

    def _install_learned_rules(self, function_nodes: Iterable[ast.FunctionDef | ast.AsyncFunctionDef]) -> None:
        definitions = {node.name: node for node in function_nodes}
        for rule in self.learned_rules:
            if not bool(rule.get("enabled", True)):
                continue
            matcher = dict(rule.get("matcher") or {})
            output = dict(rule.get("output") or {})
            function = str(matcher.get("function") or "")
            semantic = str(rule.get("semantic") or output.get("semantic") or "")
            if not function or semantic not in {"alloc", "free", "edit", "show", "copy"}:
                continue
            # A dispatcher rule such as cmd(1,...)=alloc is call-specific and
            # must never turn every cmd(...) invocation into one global kind.
            if matcher.get("argument_equals"):
                continue
            node = definitions.get(function)
            if node is None:
                continue
            parameters = [item.arg for item in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)]
            try:
                arity = int(matcher.get("arity") or 0)
            except (TypeError, ValueError):
                continue
            expected_names = [str(item) for item in list(matcher.get("parameter_names") or [])]
            # A call learned from one site can omit default arguments.  Exact
            # parameter names are therefore stronger than the observed call
            # arity and must win when both are available.
            if arity and not expected_names and arity != len(parameters):
                continue
            if expected_names and expected_names != parameters:
                continue
            self._semantic_names[function] = HeapOperationKind(semantic)
            roles = tuple(str(item) for item in list(output.get("roles") or []))
            if roles:
                self._function_roles[function] = roles

    def _matching_learned_rule(self, call: ast.Call) -> dict[str, object] | None:
        name = self._resolve_alias(self._call_name(call.func))
        keyword_names = sorted(str(item.arg) for item in call.keywords if item.arg)
        for rule in self.learned_rules:
            if not bool(rule.get("enabled", True)):
                continue
            matcher = dict(rule.get("matcher") or {})
            if str(matcher.get("function") or "") != name:
                continue
            try:
                arity = int(matcher.get("arity") or 0)
            except (TypeError, ValueError):
                continue
            expected_keywords = sorted(str(item) for item in list(matcher.get("keywords") or []))
            if expected_keywords and expected_keywords != keyword_names:
                continue
            expected_parameters = tuple(str(item) for item in list(matcher.get("parameter_names") or []))
            call_arity = len(call.args) + len([item for item in call.keywords if item.arg])
            if arity and not expected_parameters and arity != call_arity:
                continue
            if expected_parameters:
                defined_parameters = self._defined_function_parameters.get(name)
                if defined_parameters is not None:
                    if defined_parameters != expected_parameters:
                        continue
                    required = max(0, len(defined_parameters) - len(self._function_defaults.get(name, {})))
                    if not required <= call_arity <= len(defined_parameters):
                        continue
                else:
                    # Positional calls alone cannot prove the helper signature
                    # learned in another challenge. A keyword-only call that
                    # names every parameter is self-describing and remains a
                    # safe exact match.
                    if len(call.args) or set(keyword_names) != set(expected_parameters):
                        continue
            expected_shape = matcher.get("call_shape")
            if expected_shape and expected_shape != self.learned_call_shape(call):
                continue
            argument_equals = matcher.get("argument_equals") or {}
            if isinstance(argument_equals, Mapping):
                matched = True
                for raw_position, expected in argument_equals.items():
                    try:
                        position = int(raw_position)
                    except (TypeError, ValueError):
                        matched = False
                        break
                    if position < 0 or position >= len(call.args):
                        matched = False
                        break
                    actual = self._literal_rule_value(call.args[position])
                    if actual is _UNKNOWN or str(actual) != str(expected):
                        matched = False
                        break
                if not matched:
                    continue
            semantic = str(rule.get("semantic") or dict(rule.get("output") or {}).get("semantic") or "")
            if semantic not in {"alloc", "free", "edit", "show", "copy"}:
                continue
            return rule
        return None

    def _learned_roles_for_call(self, call: ast.Call) -> tuple[str, ...]:
        rule = self._matching_learned_rule(call)
        if not rule:
            return ()
        output = dict(rule.get("output") or {})
        try:
            offset = max(0, min(31, int(output.get("arg_offset") or 0)))
        except (TypeError, ValueError):
            offset = 0
        # 位置敏感：None/空槽表示「该位置角色未知」，必须保留占位让
        # zip 对齐实参下标，绝不能压缩列表（否则 arg1 会错位成 arg0）。
        roles = list(output.get("roles") or [])
        placeholders = tuple("" for _ in range(offset))
        return placeholders + tuple(
            str(item) if item not in (None, "") else "" for item in roles
        )

    @staticmethod
    def _literal_rule_value(node: ast.AST) -> object:
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, float, bool)):
            return node.value
        if (
            isinstance(node, ast.UnaryOp)
            and isinstance(node.op, (ast.USub, ast.UAdd))
            and isinstance(node.operand, ast.Constant)
            and isinstance(node.operand.value, (int, float))
        ):
            return -node.operand.value if isinstance(node.op, ast.USub) else node.operand.value
        return _UNKNOWN

    def _learned_keyword_role(self, call: ast.Call, keyword: str) -> str:
        rule = self._matching_learned_rule(call)
        if not rule:
            return ""
        matcher = dict(rule.get("matcher") or {})
        roles = [str(item) for item in list(dict(rule.get("output") or {}).get("roles") or [])]
        parameters = [str(item) for item in list(matcher.get("parameter_names") or [])]
        if parameters and len(parameters) == len(roles):
            return dict(zip(parameters, roles)).get(keyword, "")
        # A call-only learned rule has no function definition to supply the
        # signature.  It can still safely map a fully-keyword call because its
        # exact call_shape and ordered role list are stored together.
        named_keywords = [str(item.arg) for item in call.keywords if item.arg]
        if not call.args and len(named_keywords) == len(roles):
            return dict(zip(named_keywords, roles)).get(keyword, "")
        return ""

    @staticmethod
    def learned_call_shape(call: ast.Call) -> dict[str, object]:
        """Return a literal-free, deterministic AST shape for exact rules.

        Values deliberately do not participate in the matcher, so a rule
        learned from ``take(0, 0x40, b'A')`` also matches the same helper with
        another index/size/content.  Expression classes still participate;
        an unrelated same-name helper with a different signature is not
        silently mapped.
        """

        def node_shape(node: ast.AST) -> str:
            if isinstance(node, ast.Starred):
                return "star:" + node_shape(node.value)
            if isinstance(node, ast.Constant):
                value = node.value
                if value is None:
                    return "const:none"
                if isinstance(value, bool):
                    return "const:bool"
                if isinstance(value, bytes):
                    return "const:bytes"
                if isinstance(value, str):
                    return "const:str"
                if isinstance(value, int):
                    return "const:int"
                if isinstance(value, float):
                    return "const:float"
                return "const:" + type(value).__name__.lower()
            if isinstance(node, ast.Name):
                return "name"
            if isinstance(node, ast.Attribute):
                return "attribute"
            if isinstance(node, ast.Subscript):
                return "subscript"
            if isinstance(node, ast.Call):
                return "call:" + HeapSourceAnalyzer._call_name(node.func)
            if isinstance(node, ast.BinOp):
                return "binop:" + type(node.op).__name__
            if isinstance(node, ast.UnaryOp):
                return "unary:" + type(node.op).__name__
            if isinstance(node, (ast.List, ast.Tuple, ast.Dict, ast.Set)):
                return type(node).__name__.lower()
            return type(node).__name__.lower()

        return {
            "callee": "method" if isinstance(call.func, ast.Attribute) else "name",
            "positional": [node_shape(item) for item in call.args],
            "keywords": sorted(
                [
                    {"name": str(item.arg or "**"), "shape": node_shape(item.value)}
                    for item in call.keywords
                ],
                key=lambda item: (item["name"], item["shape"]),
            ),
        }

    def _template_for_kind(self, kind: HeapOperationKind) -> str:
        defaults = {
            HeapOperationKind.ALLOC: "{func}({size}, {data})",
            HeapOperationKind.FREE: "{func}({index})",
            HeapOperationKind.EDIT: "{func}({index}, {data})",
            HeapOperationKind.SHOW: "{func}({index})",
            HeapOperationKind.COPY: "{func}({src}, {dst}, {length})",
        }
        return self._templates.get(kind) or defaults[kind]

    @staticmethod
    def _keyword_role(name: str, kind: HeapOperationKind) -> str:
        key = name.lower().strip("_")
        if kind == HeapOperationKind.COPY:
            if key in {"src", "source", "from_idx", "src_idx"}: return "src"
            if key in {"dst", "dest", "destination", "to_idx", "dst_idx"}: return "dst"
            if key in {"length", "len", "n", "size", "count"}: return "length"
        if key in {"idx", "index", "i", "id", "sid", "uid", "no", "num", "slot", "pos", "key"}: return "index"
        if key in {"size", "sz", "length", "len", "n", "request", "request_size", "chunk_size"}: return "size"
        if key in {"data", "content", "contents", "payload", "text", "msg", "buf", "blob", "body", "buffer", "name", "value"}: return "data"
        return ""

    @staticmethod
    def _looks_active_object_edit_name(name: str) -> bool:
        key = name.lower()
        return bool(re.fullmatch(r"(?:edit|update|write|change|modify|fill)_[a-z0-9_]+", key))

    def _bind_target(self, target: ast.AST, value: Any, env: dict[str, Any]) -> None:
        if isinstance(target, ast.Name):
            env[target.id] = value
            return
        if isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (tuple, list)) and len(target.elts) == len(value):
            for child, item in zip(target.elts, value):
                self._bind_target(child, item, env)

    def _assign_subscript(self, target: ast.Subscript, value: Any, env: dict[str, Any]) -> None:
        if not isinstance(target.value, ast.Name): return
        container = env.get(target.value.id, _UNKNOWN)
        index = self._safe_eval(target.slice, env)
        if container is _UNKNOWN or index is _UNKNOWN: return
        try:
            container[index] = value
        except (TypeError, KeyError, IndexError):
            return

    @staticmethod
    def _target_names(target: ast.AST) -> tuple[str, ...]:
        return tuple(node.id for node in ast.walk(target) if isinstance(node, ast.Name))

    @staticmethod
    def _call_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name): return node.id
        if isinstance(node, ast.Attribute): return node.attr
        return ""

    @staticmethod
    def _qualified_call_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = HeapSourceAnalyzer._qualified_call_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    def _resolve_alias(self, name: str) -> str:
        seen: set[str] = set()
        while name in self._aliases and name not in seen:
            seen.add(name)
            name = self._aliases[name]
        return name

    @staticmethod
    def _names(node: ast.AST) -> tuple[str, ...]:
        return tuple(dict.fromkeys(item.id for item in ast.walk(node) if isinstance(item, ast.Name)))

    def _source_segment(self, node: ast.AST) -> str:
        try:
            return (ast.get_source_segment(self.source, node) or ast.unparse(node)).strip()
        except Exception:
            return ""

    def _span(self, node: ast.AST) -> tuple[int, int]:
        start = self._position(int(getattr(node, "lineno", 1)), int(getattr(node, "col_offset", 0)))
        end = self._position(int(getattr(node, "end_lineno", getattr(node, "lineno", 1))), int(getattr(node, "end_col_offset", getattr(node, "col_offset", 0))))
        return start, max(start, end)

    def _position(self, line: int, column: int) -> int:
        index = max(0, min(line - 1, len(self._line_offsets) - 1))
        return min(len(self.source), self._line_offsets[index] + max(0, column))

    @staticmethod
    def _build_line_offsets(source: str) -> list[int]:
        offsets = [0]
        for match in re.finditer("\n", source):
            offsets.append(match.end())
        return offsets

    def _node_id(self, prefix: str, node: ast.AST, loop_env: Mapping[str, Any]) -> str:
        payload = ast.dump(node, include_attributes=False) + "|" + repr(sorted((key, self._display_value(value)) for key, value in loop_env.items()))
        return prefix + "_" + hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]

    def _diagnose_node(self, severity: str, code: str, message: str, node: ast.AST, suggestion: str = "") -> None:
        start, end = self._span(node)
        self._diagnostics.append(ParseDiagnostic(severity, code, message, start, end, int(getattr(node, "lineno", 0)), suggestion))

    def _unique_value_name(self, base: str) -> str:
        base = self._sanitize_chunk_name(base) or "value"
        if base not in self._known_values:
            return base
        index = 2
        while f"{base}_{index}" in self._known_values:
            index += 1
        return f"{base}_{index}"

    @staticmethod
    def _auto_chunk_name(index: int) -> str:
        value = max(0, index)
        result = ""
        while True:
            value, remainder = divmod(value, 26)
            result = chr(ord("A") + remainder) + result
            if value == 0: return result
            value -= 1

    @staticmethod
    def _sanitize_chunk_name(name: str) -> str:
        clean = re.sub(r"\W+", "_", str(name or "")).strip("_")
        if clean and clean[0].isdigit(): clean = "chunk_" + clean
        return clean

    @staticmethod
    def _looks_heap_related(name: str) -> bool:
        lowered = name.lower()
        return any(token in lowered for token in ("alloc", "chunk", "note", "heap", "free", "delete", "edit", "show", "view", "create", "remove"))

    @staticmethod
    def _looks_like_data_expression(value: str) -> bool:
        text = str(value or "").strip()
        return bool(
            text.startswith(("b'", 'b"', "bytearray(", "bytes(", "p32(", "p64(", "flat(", "payload", "content", "data", "buf", "blob", "body", "name"))
            or "ljust(" in text
            or "rjust(" in text
        )

    @staticmethod
    def _looks_payload_expression(node: ast.AST) -> bool:
        for item in ast.walk(node):
            if isinstance(item, ast.Constant) and isinstance(item.value, bytes):
                return True
            if isinstance(item, ast.Call):
                name = HeapSourceAnalyzer._call_name(item.func)
                if name in {"p8", "p16", "p32", "p64", "flat", "fit", "bytes", "bytearray", "struct.pack"}:
                    return True
        return False

    @staticmethod
    def _display_value(value: Any) -> str:
        if value is _UNKNOWN: return "unknown"
        if isinstance(value, bytes): return repr(value)
        if isinstance(value, str): return value if HeapSourceAnalyzer._is_literal_string(value) else repr(value)
        return repr(value) if isinstance(value, (list, tuple, dict)) else str(value)

    @staticmethod
    def _is_literal_string(value: str) -> bool:
        text = value.strip()
        return bool(re.fullmatch(r"(?:0x[0-9a-fA-F]+|\d+|[A-Za-z_]\w*(?:\s*[+\-*/<>&|^]\s*(?:0x[0-9a-fA-F]+|\d+|[A-Za-z_]\w*))*)", text))

    @staticmethod
    def _parse_scalar(text: str) -> Any:
        stripped = str(text).strip()
        try: return int(stripped, 0)
        except ValueError: return stripped


def analyze_heap_source(
    source: str,
    api_profile: HeapApiProfile | None = None,
    variables: Mapping[str, str | int] | None = None,
    branch_choices: Mapping[str, str] | None = None,
    overrides: Iterable[TimelineOverride] = (),
    *,
    learned_rules: Iterable[Mapping[str, object]] = (),
    max_loop_iterations: int = 256,
    max_events: int = 1024,
    behavior_profile: ChallengeBehaviorProfile | None = None,
    helper_contracts: Iterable[HelperContract] = (),
) -> HeapAnalysisResult:
    return HeapSourceAnalyzer(
        source,
        api_profile,
        variables,
        branch_choices,
        overrides,
        learned_rules,
        max_loop_iterations,
        max_events,
        behavior_profile,
        helper_contracts,
    ).analyze()
