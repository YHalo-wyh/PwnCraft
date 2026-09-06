from __future__ import annotations

import ast
import re

from pwncraft.features.heapviz.expressions import evaluate_int_expr
from pwncraft.features.heapviz.operations import HeapOperation, HeapOperationKind
from pwncraft.features.heapviz.semantics.challenge_profile import ChallengeBehaviorProfile, ChallengeCallBehavior
from pwncraft.features.heapviz.semantics.program_ir import ProgramEvent


_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


class BehaviorEffectExpander:
    """Expand ProgramEvents into deterministic allocator operations."""

    def __init__(self, profile: ChallengeBehaviorProfile):
        self.profile = profile

    def behavior_for(self, event: ProgramEvent) -> ChallengeCallBehavior | None:
        return self.profile.match(event.target.function_name, event.target.receiver)

    def expand(self, event: ProgramEvent) -> tuple[HeapOperation, ...]:
        behavior = self.behavior_for(event)
        if behavior is None:
            return ()
        positional, keywords = event.argument_sources()
        bindings = dict(behavior.defaults)
        bindings.update({name: value for name, value in zip(behavior.parameters, positional)})
        bindings.update(keywords)
        evidence = f"{behavior.evidence}; source line {event.line}; call {event.target.qualified_name}"
        operations: list[HeapOperation] = []
        for effect_index, effect in enumerate(behavior.effects, 1):
            try:
                kind = HeapOperationKind(effect.kind)
            except ValueError:
                kind = HeapOperationKind.NOTE
            meta = {
                **{key: self._substitute(value, bindings) for key, value in effect.meta.items()},
                "behavior_profile": self.profile.name or "scene",
                "behavior_helper": behavior.function,
                "behavior_effect": str(effect_index),
                "bind_handle": "true" if effect.bind_handle else "false",
                "parse_confidence": "challenge-profile",
                "evidence": evidence,
                "program_event_id": event.event_id,
            }
            operations.append(
                HeapOperation(
                    "",
                    kind,
                    chunk=self._substitute(effect.chunk, bindings),
                    index=self._substitute(effect.index, bindings),
                    request_size=self._substitute_expression(effect.request_size, bindings),
                    data=self._substitute_expression(effect.data, bindings),
                    field=self._substitute(effect.field, bindings),
                    value=self._substitute_expression(effect.value, bindings),
                    target=self._substitute_expression(effect.target, bindings),
                    fd_storage=self._substitute_expression(effect.fd_storage, bindings),
                    count=effect.count,
                    note=self._substitute(effect.note, bindings),
                    meta=meta,
                )
            )
        return tuple(operations)

    @staticmethod
    def _substitute(template: str, bindings: dict[str, str]) -> str:
        text = str(template or "")
        return _PLACEHOLDER_RE.sub(lambda match: bindings.get(match.group(1), match.group(0)), text)

    def _substitute_expression(self, template: str, bindings: dict[str, str]) -> str:
        text = self._substitute(template, bindings).strip()
        if not text:
            return ""
        try:
            tree = ast.parse(text, mode="eval")
        except SyntaxError:
            return text

        class Binder(ast.NodeTransformer):
            def visit_Name(self, node: ast.Name):  # noqa: N802 - ast visitor API
                replacement = bindings.get(node.id)
                if replacement is None:
                    return node
                try:
                    return ast.copy_location(ast.parse(replacement, mode="eval").body, node)
                except SyntaxError:
                    return node

            def visit_Call(self, node: ast.Call):  # noqa: N802 - ast visitor API
                node = self.generic_visit(node)
                if isinstance(node.func, ast.Name) and node.func.id == "len" and len(node.args) == 1:
                    try:
                        value = ast.literal_eval(node.args[0])
                    except (ValueError, SyntaxError):
                        return node
                    if isinstance(value, (str, bytes, list, tuple, dict, set)):
                        return ast.copy_location(ast.Constant(len(value)), node)
                return node

        bound = ast.fix_missing_locations(Binder().visit(tree))
        try:
            rendered = ast.unparse(bound.body).strip()
        except Exception:
            return text
        evaluated = evaluate_int_expr(rendered)
        return hex(evaluated.value) if evaluated.value is not None else rendered
