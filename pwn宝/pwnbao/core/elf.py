from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ElfCandidate:
    path: Path
    role: str


class ElfWorkspace:
    def __init__(self, directory: str | Path):
        self.directory = Path(directory)
        self.candidates: list[ElfCandidate] = []

    def scan(self) -> list[ElfCandidate]:
        if not self.directory.exists() or not self.directory.is_dir():
            raise ValueError("请选择有效目录")

        candidates: list[ElfCandidate] = []
        for path in sorted(self.directory.iterdir()):
            if not path.is_file():
                continue
            if not self._is_elf(path):
                continue
            candidates.append(ElfCandidate(path=path, role=self._guess_role(path)))

        self.candidates = candidates
        return candidates

    @staticmethod
    def _is_elf(path: Path) -> bool:
        try:
            with path.open("rb") as handle:
                return handle.read(4) == b"\x7fELF"
        except OSError:
            return False

    @staticmethod
    def _guess_role(path: Path) -> str:
        name = path.name.lower()
        if name.startswith("ld-") or name.startswith("ld-linux") or "ld-linux" in name:
            return "ld"
        if "libc.so" in name or name.startswith("libc-"):
            return "libc"
        return "binary"

    def primary_binary(self) -> Path | None:
        for item in self.candidates:
            if item.role == "binary":
                return item.path
        return self.candidates[0].path if self.candidates else None

    def interpreter(self) -> Path | None:
        for item in self.candidates:
            if item.role == "ld":
                return item.path
        return None

    def libc(self) -> Path | None:
        for item in self.candidates:
            if item.role == "libc":
                return item.path
        return None

