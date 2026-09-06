from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TcachePolicy:
    enabled: bool
    count_limit: int
    max_chunk_size_64: int = 0x410
    max_chunk_size_32: int = 0x208
    key_check: bool = False
    safe_linking: bool = False


@dataclass(frozen=True)
class FastbinPolicy:
    max_chunk_size_64: int = 0x80
    max_chunk_size_32: int = 0x40
    safe_linking: bool = False


@dataclass(frozen=True)
class UnsortedPolicy:
    first_fit_scan: bool = True
    insert_at_head: bool = True


@dataclass(frozen=True)
class LargebinPolicy:
    nextsize_links: bool = True
    best_fit: bool = True


@dataclass(frozen=True)
class IntegrityCheckPolicy:
    tcache_duplicate: bool = False
    top_size: bool = False
    io_vtable: bool = False


@dataclass(frozen=True)
class HookPolicy:
    malloc_free_hooks: bool = True


@dataclass(frozen=True)
class GlibcPolicy:
    version: tuple[int, int]
    tcache: TcachePolicy
    fastbin: FastbinPolicy
    unsorted: UnsortedPolicy
    largebin: LargebinPolicy
    integrity: IntegrityCheckPolicy
    hooks: HookPolicy

    @classmethod
    def for_version(cls, version: tuple[int, int]) -> GlibcPolicy:
        safe_linking = version >= (2, 32)
        key_check = version >= (2, 29)
        return cls(
            version,
            TcachePolicy(version >= (2, 26), 7, key_check=key_check, safe_linking=safe_linking),
            FastbinPolicy(safe_linking=safe_linking),
            UnsortedPolicy(),
            LargebinPolicy(),
            IntegrityCheckPolicy(key_check, version >= (2, 29), version >= (2, 24)),
            HookPolicy(version < (2, 34)),
        )

    def tcache_max(self, bits: int) -> int:
        return self.tcache.max_chunk_size_64 if bits == 64 else self.tcache.max_chunk_size_32

    def max_fast(self, bits: int) -> int:
        return self.fastbin.max_chunk_size_64 if bits == 64 else self.fastbin.max_chunk_size_32
