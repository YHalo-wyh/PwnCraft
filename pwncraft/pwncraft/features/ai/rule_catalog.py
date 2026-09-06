from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from pwncraft.features.heapviz.operations import HeapOperation, HeapOperationKind


@dataclass(frozen=True)
class HeapRuleSpec:
    rule_id: str
    kind: HeapOperationKind
    required_any: tuple[tuple[str, ...], ...]
    arguments: tuple[str, ...]
    description: str
    default_placement: str = "replace_operation"

    def prompt_dict(self) -> dict[str, object]:
        args: object
        if self.arguments[:len(_COMMON_ARGUMENTS)] == _COMMON_ARGUMENTS:
            extras = self.arguments[len(_COMMON_ARGUMENTS):]
            args = "common" + (("+" + ",".join(extras)) if extras else "")
        else:
            args = ",".join(self.arguments)
        return {
            "id": self.rule_id,
            "args": args,
            "need": ["|".join(group) for group in self.required_any],
            "place": "after" if self.default_placement == "insert_after" else "replace",
        }


_COMMON_ARGUMENTS = (
    "chunk",
    "index",
    "request_size",
    "data",
    "field",
    "value",
    "target",
    "fd_storage",
    "count",
)


class HeapRuleCatalog:
    """Whitelisted semantic constructors available to the local model."""

    _SPECS = {
        spec.rule_id: spec
        for spec in (
            HeapRuleSpec("op.alloc", HeapOperationKind.ALLOC, (("request_size",),), _COMMON_ARGUMENTS, "malloc/add allocation"),
            HeapRuleSpec("op.free", HeapOperationKind.FREE, (("chunk", "index"),), _COMMON_ARGUMENTS, "free/delete by chunk or index"),
            HeapRuleSpec("op.edit", HeapOperationKind.EDIT, (("chunk", "index"),), _COMMON_ARGUMENTS, "edit/write chunk data"),
            HeapRuleSpec("op.show", HeapOperationKind.SHOW, (("chunk", "index"),), _COMMON_ARGUMENTS, "show/read chunk data"),
            HeapRuleSpec(
                "op.copy",
                HeapOperationKind.COPY,
                (("src",), ("dst",), ("length",)),
                ("src", "dst", "length", "src_chunk", "dst_chunk"),
                "copy bytes from src to dst",
            ),
            HeapRuleSpec(
                "corruption.safe_link_fd",
                HeapOperationKind.SAFE_LINK_FD,
                (("chunk", "index"), ("target",)),
                _COMMON_ARGUMENTS,
                "encode a freelist next pointer with safe-linking",
                "insert_after",
            ),
            HeapRuleSpec(
                "corruption.overflow_header",
                HeapOperationKind.OVERFLOW_HEADER,
                (("chunk", "index"),),
                _COMMON_ARGUMENTS + ("prev_size", "size"),
                "overwrite neighboring chunk metadata",
                "insert_after",
            ),
            HeapRuleSpec(
                "corruption.poison_fd",
                HeapOperationKind.POISON_FD,
                (("chunk", "index"), ("target",)),
                _COMMON_ARGUMENTS,
                "poison a tcache or fastbin forward pointer",
                "insert_after",
            ),
            HeapRuleSpec(
                "corruption.fake_chunk",
                HeapOperationKind.FAKE_CHUNK,
                (("chunk", "target"),),
                _COMMON_ARGUMENTS + ("prev_size", "size", "fd", "bk"),
                "materialize a source-proven fake chunk header",
                "insert_after",
            ),
            HeapRuleSpec(
                "allocator.consolidate",
                HeapOperationKind.CONSOLIDATE,
                (),
                ("chunk", "index", "request_size", "count"),
                "request strict fastbin/adjacent free consolidation replay",
                "insert_after",
            ),
        )
    }

    @classmethod
    def prompt_catalog(cls) -> list[dict[str, object]]:
        return [{"common": ",".join(_COMMON_ARGUMENTS)}, *[cls._SPECS[key].prompt_dict() for key in sorted(cls._SPECS)]]

    @classmethod
    def materialize(cls, payload: Mapping[str, object]) -> tuple[HeapOperation, dict[str, object]]:
        unknown = set(payload) - {"rule_id", "arguments", "placement"}
        if unknown:
            raise ValueError(f"heap_rule_call 包含未知字段: {', '.join(sorted(unknown))}")
        rule_id = str(payload.get("rule_id") or "").strip()
        spec = cls._SPECS.get(rule_id)
        if spec is None:
            raise ValueError(f"未知 heap rule `{rule_id}`")
        placement = str(payload.get("placement") or spec.default_placement)
        if placement not in {"replace_operation", "insert_before", "insert_after"}:
            raise ValueError(f"{rule_id}.placement 不受支持")
        raw_arguments = payload.get("arguments") or {}
        if isinstance(raw_arguments, (list, tuple)):
            if len(raw_arguments) > len(spec.arguments):
                raise ValueError(f"{rule_id}.arguments 位置参数过多")
            arguments = {
                name: value
                for name, value in zip(spec.arguments, raw_arguments)
                if value is not None and value != ""
            }
        elif isinstance(raw_arguments, Mapping):
            arguments = {str(key): value for key, value in raw_arguments.items()}
        else:
            raise ValueError("heap_rule_call.arguments 必须是 object 或按 catalog 顺序的数组")
        unexpected = set(arguments) - set(spec.arguments)
        if unexpected:
            raise ValueError(f"{rule_id} 不接受参数: {', '.join(sorted(unexpected))}")
        for group in spec.required_any:
            if not any(_argument_present(arguments.get(name)) for name in group):
                raise ValueError(f"{rule_id} 缺少参数之一: {'/'.join(group)}")
        if any(isinstance(value, (dict, list, tuple, set)) for value in arguments.values()):
            raise ValueError("heap rule 参数只能是标量")
        if any(len(str(value)) > 12000 for value in arguments.values()):
            raise ValueError("heap rule 参数过长")

        if spec.kind == HeapOperationKind.COPY:
            src = _argument_text(arguments.get("src"))
            dst = _argument_text(arguments.get("dst"))
            length = _argument_text(arguments.get("length"))
            operation = HeapOperation(
                "",
                spec.kind,
                chunk=_argument_text(arguments.get("dst_chunk")),
                index=dst,
                request_size=length,
                target=_argument_text(arguments.get("src_chunk")) or src,
                meta={
                    "src": src,
                    "dst": dst,
                    "length": length,
                    "src_chunk": _argument_text(arguments.get("src_chunk")),
                    "dst_chunk": _argument_text(arguments.get("dst_chunk")),
                    "source": f"heap_rule:{rule_id}",
                },
            )
        else:
            meta = {"source": f"heap_rule:{rule_id}"}
            for name in ("prev_size", "size", "fd", "bk"):
                if name in arguments:
                    meta[name] = _argument_text(arguments[name])
            try:
                count = int(arguments.get("count") or 1)
            except (TypeError, ValueError) as error:
                raise ValueError(f"{rule_id}.count 必须是整数") from error
            operation = HeapOperation(
                "",
                spec.kind,
                chunk=_argument_text(arguments.get("chunk")),
                index=_argument_text(arguments.get("index")),
                request_size=_argument_text(arguments.get("request_size")),
                data=_argument_text(arguments.get("data")),
                field=_argument_text(arguments.get("field")),
                value=_argument_text(arguments.get("value")),
                target=_argument_text(arguments.get("target")),
                fd_storage=_argument_text(arguments.get("fd_storage")),
                count=count,
                meta=meta,
            )
        return operation, {
            "rule_id": rule_id,
            "arguments": dict(arguments),
            "placement": placement,
        }


def _argument_present(value: object) -> bool:
    return value is not None and str(value).strip() != ""


def _argument_text(value: object) -> str:
    return "" if value is None else str(value)
