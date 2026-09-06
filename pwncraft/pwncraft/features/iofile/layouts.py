from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FileFieldLayout:
    name: str
    offset: int
    width: int
    kind: str = "pointer"
    description: str = ""


@dataclass(frozen=True)
class GlibcFileLayout:
    version: tuple[int, int]
    bits: int
    file_size: int
    plus_size: int
    wide_size: int
    fields: tuple[FileFieldLayout, ...]
    wide_fields: tuple[FileFieldLayout, ...]
    provenance: str = "bundled glibc layout database"

    def field(self, name: str) -> FileFieldLayout:
        return next(item for item in (*self.fields, *self.wide_fields) if item.name == name)


_FILE64 = (
    FileFieldLayout("_flags", 0x00, 4, "flags"),
    FileFieldLayout("_IO_read_ptr", 0x08, 8), FileFieldLayout("_IO_read_end", 0x10, 8),
    FileFieldLayout("_IO_read_base", 0x18, 8), FileFieldLayout("_IO_write_base", 0x20, 8),
    FileFieldLayout("_IO_write_ptr", 0x28, 8), FileFieldLayout("_IO_write_end", 0x30, 8),
    FileFieldLayout("_IO_buf_base", 0x38, 8), FileFieldLayout("_IO_buf_end", 0x40, 8),
    FileFieldLayout("_IO_save_base", 0x48, 8), FileFieldLayout("_IO_backup_base", 0x50, 8),
    FileFieldLayout("_IO_save_end", 0x58, 8), FileFieldLayout("_markers", 0x60, 8),
    FileFieldLayout("_chain", 0x68, 8, "structural_pointer"),
    FileFieldLayout("_fileno", 0x70, 4, "signed"), FileFieldLayout("_flags2", 0x74, 4, "flags"),
    FileFieldLayout("_old_offset", 0x78, 8, "signed"), FileFieldLayout("_cur_column", 0x80, 2, "integer"),
    FileFieldLayout("_vtable_offset", 0x82, 1, "signed"), FileFieldLayout("_shortbuf", 0x83, 1, "bytes"),
    FileFieldLayout("_lock", 0x88, 8, "structural_pointer"), FileFieldLayout("_offset", 0x90, 8, "signed"),
    FileFieldLayout("_codecvt", 0x98, 8), FileFieldLayout("_wide_data", 0xA0, 8, "structural_pointer"),
    FileFieldLayout("_freeres_list", 0xA8, 8), FileFieldLayout("_freeres_buf", 0xB0, 8),
    FileFieldLayout("__pad5", 0xB8, 8, "integer"), FileFieldLayout("_mode", 0xC0, 4, "signed"),
    FileFieldLayout("vtable", 0xD8, 8, "structural_pointer", "_IO_FILE_plus vtable pointer"),
)

_WIDE64 = (
    FileFieldLayout("wide._IO_read_ptr", 0x00, 8), FileFieldLayout("wide._IO_read_end", 0x08, 8),
    FileFieldLayout("wide._IO_read_base", 0x10, 8), FileFieldLayout("wide._IO_write_base", 0x18, 8),
    FileFieldLayout("wide._IO_write_ptr", 0x20, 8), FileFieldLayout("wide._IO_write_end", 0x28, 8),
    FileFieldLayout("wide._IO_buf_base", 0x30, 8), FileFieldLayout("wide._IO_buf_end", 0x38, 8),
    FileFieldLayout("wide._IO_save_base", 0x40, 8), FileFieldLayout("wide._IO_backup_base", 0x48, 8),
    FileFieldLayout("wide._IO_save_end", 0x50, 8),
    FileFieldLayout("wide._wide_vtable", 0xE0, 8, "structural_pointer"),
)


class GlibcFileLayoutDatabase:
    SUPPORTED = ((2, 23), (2, 27), (2, 31), (2, 32), (2, 34), (2, 35), (2, 36), (2, 37), (2, 38), (2, 39), (2, 40))

    @classmethod
    def get(cls, version: tuple[int, int], bits: int = 64) -> GlibcFileLayout:
        if bits != 64:
            raise ValueError("当前离线 IO FILE 数据库只提供已核对的 x86-64 布局")
        normalized = tuple(version[:2])
        if normalized >= (2, 40):
            normalized = (2, 40)
        if normalized not in cls.SUPPORTED:
            raise ValueError(f"不支持的 glibc IO FILE 布局：{version[0]}.{version[1]}")
        return GlibcFileLayout(
            normalized,
            bits,
            file_size=0xD8,
            plus_size=0xE0,
            wide_size=0xE8,
            fields=_FILE64,
            wide_fields=_WIDE64,
            provenance=f"bundled glibc {normalized[0]}.{normalized[1]} x86-64 layout",
        )
