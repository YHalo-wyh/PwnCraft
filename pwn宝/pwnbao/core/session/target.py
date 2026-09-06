"""TargetContext — the single workspace truth for the analyzed binary (v0.20 §1).

The original ELF is immutable evidence: it is copied into the project's
``original/`` area and never patched.  Everything that needs a patched
binary (patchelf interpreter/rpath, debug runs) uses the ``runtime/``
working copy.  Every tool in the workspace derives its target from this
object instead of asking the user again.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import shutil
from pathlib import Path

from ..elf_runtime import is_elf_file


_WORK_DIRNAME = ".pwnbao"
_ORIGINAL_DIRNAME = "work" + "/original"
_RUNTIME_DIRNAME = "work" + "/runtime"


def _refresh_copy(source: Path, destination: Path) -> None:
    """Re-copy a target file over its workspace copy (re-import must be idempotent).

    The original copy is chmod'd read-only after import; on Windows a plain
    ``copy2`` over it raises PermissionError, so clear the write-protect bit
    first.  When the bytes already match, skip the copy entirely.
    """
    if destination.exists():
        try:
            if destination.read_bytes() == source.read_bytes():
                return
        except OSError:
            pass
        try:
            destination.chmod(destination.stat().st_mode | 0o200)
        except OSError:
            pass
    shutil.copy2(source, destination)


@dataclass
class TargetContext:
    target_id: str = ""
    original_binary: str = ""
    working_binary: str = ""
    sha256: str = ""
    file_name: str = ""
    project_root: str = ""
    architecture: str = ""
    bits: int = 0
    endian: str = ""
    osabi: str = ""
    entry: int = 0
    pie: str = "UNKNOWN"
    nx: str = "UNKNOWN"
    canary: str = "UNKNOWN"
    relro: str = "UNKNOWN"
    interpreter: str = ""
    libc: str = ""
    ld: str = ""
    libc_version: str = ""
    build_id: str = ""
    source_files: list[str] = field(default_factory=list)
    exp_file: str = ""
    static_revision: int = 0
    runtime_revision: int = 0
    ida_facts: str = ""  # path to the BinaryIR JSON produced by ida_bridge

    # ------------------------------------------------------------------
    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "TargetContext":
        known = {name for name in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        clean = {key: value for key, value in dict(payload or {}).items() if key in known}
        context = cls()
        for key, value in clean.items():
            current_type = type(getattr(context, key))
            if current_type is int:
                value = int(value)
            elif current_type is str:
                value = str(value)
            elif current_type is list:
                value = [str(item) for item in (value or [])]
            setattr(context, key, value)
        return context

    # ------------------------------------------------------------------
    @property
    def primary_path(self) -> str:
        """The path tools should use by default: the runtime working copy
        when one exists, otherwise the untouched original."""
        return self.working_binary or self.original_binary


def discover_artifacts(binary_path: str | Path) -> tuple[str, str]:
    """Same-directory libc/ld auto-discovery (§94). Returns (libc, ld)."""
    folder = Path(binary_path).resolve().parent
    libc = ld = ""
    for entry in sorted(folder.iterdir()):
        name = entry.name.lower()
        if not entry.is_file():
            continue
        if not libc and (name.startswith("libc.so") or name.startswith("libc-")):
            libc = str(entry)
        elif not ld and (name.startswith("ld-linux") or name.startswith("ld-")):
            ld = str(entry)
    return libc, ld


def import_target(
    binary_path: str | Path,
    *,
    project_root: str | Path | None = None,
    libc: str | Path | None = None,
    ld: str | Path | None = None,
    elf_inspector=None,
) -> TargetContext:
    """Bind one binary as the workspace target.

    Copies (never moves) the original into ``<project>/.pwnbao/original/``
    and creates a mutable runtime copy under ``.pwnbao/runtime/``.  The
    original is marked read-only; every patch operation must target the
    runtime copy.
    """
    source = Path(binary_path).resolve()
    if not source.is_file() or not is_elf_file(str(source)):
        raise ValueError(f"不是有效 ELF: {source}")

    root = Path(project_root).resolve() if project_root else source.parent
    original_dir = root / _WORK_DIRNAME / "original"
    runtime_dir = root / _WORK_DIRNAME / "runtime"
    original_dir.mkdir(parents=True, exist_ok=True)
    runtime_dir.mkdir(parents=True, exist_ok=True)

    original_copy = original_dir / source.name
    if original_copy.resolve() != source:
        _refresh_copy(source, original_copy)
    working_copy = runtime_dir / source.name
    if working_copy.resolve() != source:
        _refresh_copy(source, working_copy)

    digest = hashlib.sha256(original_copy.read_bytes()).hexdigest()
    context = TargetContext(
        target_id=digest[:16],
        original_binary=str(original_copy),
        working_binary=str(working_copy),
        sha256=digest,
        file_name=source.name,
        project_root=str(root),
    )
    try:
        original_copy.chmod(original_copy.stat().st_mode & 0o555)  # read-only
    except OSError:
        pass

    auto_libc, auto_ld = discover_artifacts(source)
    context.libc = str(Path(libc).resolve()) if libc else auto_libc
    context.ld = str(Path(ld).resolve()) if ld else auto_ld

    if elf_inspector is None:
        from ..workbench import BinaryInspector

        elf_inspector = BinaryInspector()
    facts = elf_inspector.inspect(str(source))
    context.architecture = facts.architecture
    context.bits = facts.bits
    context.endian = facts.endian
    context.entry = facts.entry
    security = facts.security or {}
    context.nx = security.get("NX", "UNKNOWN")
    context.pie = security.get("PIE", "UNKNOWN")
    context.canary = security.get("CANARY", "UNKNOWN")
    context.relro = security.get("RELRO", "UNKNOWN")
    return context
