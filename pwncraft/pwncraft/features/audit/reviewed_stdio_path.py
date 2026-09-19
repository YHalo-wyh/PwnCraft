"""Reviewed FILE/stdout path composition.

This module begins only after an exact pointer write has already rebound a stdio
stream pointer to a reviewed object address.  It then checks explicit reviewed
FILE-field geometry plus one reviewed stream trigger.  Technique names such as
FSOP/House-of-* are intentionally irrelevant here, and reaching stdio is never
promoted to control transfer or exploit success.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ReviewedFileFieldWrite:
    role: str
    offset: int
    value: int
    width: int = 8
    provenance: str = "REVIEWED_FILE_FIELD"

    def validate(self) -> None:
        if not self.role.strip():
            raise ValueError("reviewed FILE field role must be non-empty")
        if self.offset < 0 or self.value < 0:
            raise ValueError("reviewed FILE field offset/value must be non-negative")
        if self.width <= 0:
            raise ValueError("reviewed FILE field width must be positive")


@dataclass(frozen=True)
class ReviewedStdioTrigger:
    call_kind: str
    stream: str
    site_label: str
    reaches_stream_reviewed: bool = False
    provenance: str = "REVIEWED_STDIO_TRIGGER"

    def validate(self) -> None:
        if not self.call_kind.strip() or not self.stream.strip() or not self.site_label.strip():
            raise ValueError("reviewed stdio trigger identity must be complete")


@dataclass(frozen=True)
class ReviewedStdioPathPolicy:
    name: str
    allocator_family: str
    allocator_version: str
    stream_pointer_address: int
    file_object_address: int
    payload_write_address: int
    payload_start_offset: int
    field_writes: tuple[ReviewedFileFieldWrite, ...]
    trigger: ReviewedStdioTrigger
    pointer_width: int = 8
    file_layout_reviewed: bool = False
    required_field_roles: tuple[str, ...] = (
        "write_base",
        "write_ptr",
        "lock",
        "wide_data",
        "vtable",
    )
    provenance: str = "REVIEWED_STDIO_FILE_PATH_POLICY"

    def validate(self) -> None:
        if not self.name.strip() or not self.allocator_family.strip() or not self.allocator_version.strip():
            raise ValueError("stdio policy identity must be complete")
        if min(
            self.stream_pointer_address,
            self.file_object_address,
            self.payload_write_address,
            self.payload_start_offset,
        ) < 0:
            raise ValueError("stdio addresses/offsets must be non-negative")
        if self.pointer_width <= 0:
            raise ValueError("stdio pointer width must be positive")
        if not self.required_field_roles:
            raise ValueError("stdio path must require explicit reviewed FILE roles")
        if len(set(self.required_field_roles)) != len(self.required_field_roles):
            raise ValueError("required FILE roles must be unique")
        roles: set[str] = set()
        offsets: set[int] = set()
        for field in self.field_writes:
            field.validate()
            if field.role in roles:
                raise ValueError("reviewed FILE field roles must be unique")
            if field.offset in offsets:
                raise ValueError("reviewed FILE field offsets must be unique")
            roles.add(field.role)
            offsets.add(field.offset)
        self.trigger.validate()


def _exact_stream_binding(upstream: dict[str, Any], stream_pointer: int, file_object: int, width: int) -> bool:
    if "reviewed_largebin_pointer_write" not in (upstream.get("capabilities") or []):
        return False
    for fact in upstream.get("facts") or []:
        if not isinstance(fact, dict) or fact.get("kind") != "largebin_insertion_pointer_write":
            continue
        return (
            fact.get("address") == stream_pointer
            and fact.get("value") == file_object
            and fact.get("width") == width
        )
    return False


def derive_reviewed_stdio_path(
    upstream: dict[str, Any],
    policy: ReviewedStdioPathPolicy,
) -> dict[str, Any] | None:
    """Derive a reviewed stream->FILE->stdio-path fact without claiming FSOP.

    The function requires an exact upstream pointer write, reviewed payload/object
    geometry, a minimally useful FILE write window, reviewed structural pointers,
    and a reviewed trigger that reaches the same stream.  What the vtable/wide
    data eventually dispatches to is deliberately outside this layer.
    """
    policy.validate()
    if not _exact_stream_binding(
        upstream,
        policy.stream_pointer_address,
        policy.file_object_address,
        policy.pointer_width,
    ):
        return None
    if not policy.file_layout_reviewed:
        return None
    if policy.payload_write_address != policy.file_object_address + policy.payload_start_offset:
        return None

    fields = {field.role: field for field in policy.field_writes}
    if any(role not in fields for role in policy.required_field_roles):
        return None

    write_base = fields["write_base"].value
    write_ptr = fields["write_ptr"].value
    if write_ptr <= write_base:
        return None
    if any(fields[role].value == 0 for role in ("lock", "wide_data", "vtable")):
        return None

    trigger = policy.trigger
    if not trigger.reaches_stream_reviewed or trigger.stream != "stdout":
        return None

    return {
        "kind": "reviewed_stdio_path",
        "state": "derived_static",
        "runtime_observed": False,
        "allocator": {"family": policy.allocator_family, "version": policy.allocator_version},
        "policy": {
            **asdict(policy),
            "field_writes": [asdict(field) for field in policy.field_writes],
            "trigger": asdict(policy.trigger),
        },
        "facts": [
            {
                "kind": "stdout_pointer_binds_reviewed_file_object",
                "stream_pointer_address": policy.stream_pointer_address,
                "file_object_address": policy.file_object_address,
                "pointer_width": policy.pointer_width,
            },
            {
                "kind": "reviewed_file_field_state",
                "file_object_address": policy.file_object_address,
                "payload_write_address": policy.payload_write_address,
                "payload_start_offset": policy.payload_start_offset,
                "fields": [asdict(field) for field in policy.field_writes],
            },
            {
                "kind": "reviewed_stdout_write_window",
                "write_base": write_base,
                "write_ptr": write_ptr,
            },
            {
                "kind": "reviewed_stdio_trigger_reaches_stream",
                "call_kind": trigger.call_kind,
                "stream": trigger.stream,
                "site_label": trigger.site_label,
                "provenance": trigger.provenance,
            },
        ],
        "capabilities": [
            "stdout_rebound_to_reviewed_file_object",
            "reviewed_stdio_path_reachable",
        ],
        "provenance": policy.provenance,
        "limitations": [
            "reviewed FILE field state plus a stdout trigger proves only entry into the reviewed stdio path",
            "vtable/wide-data dispatch target semantics are not proven by this layer",
            "no control transfer, stack pivot, ROP/ORW execution, shell or flag retrieval is inferred here",
        ],
    }
