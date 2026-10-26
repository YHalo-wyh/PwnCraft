#!/usr/bin/env python3
"""Inject an x86-64 Linux AWD guard into a new executable PT_LOAD segment."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable

import lief


MAGIC = b"AWDGUARD64-V1"
ANCHOR_MARKER = 0xA17C0A17C0A17C0A
SOURCE_MARKER = 0x51A7CE51A7CE51A7
TARGET_MARKER = 0x0E0F0E0F0E0F0E0F

# Linux x86-64 syscall numbers.  The default profile deliberately leaves
# normal file opening to Landlock, which can enforce paths without TOCTOU.
BASE_DENIED_SYSCALLS = {
    42,   # connect
    57,   # fork
    58,   # vfork
    59,   # execve
    90,   # chmod
    91,   # fchmod
    92,   # chown
    93,   # fchown
    94,   # lchown
    101,  # ptrace
    155,  # pivot_root
    161,  # chroot
    165,  # mount
    166,  # umount2
    169,  # reboot
    175,  # init_module
    176,  # delete_module
    246,  # kexec_load
    248,  # add_key
    249,  # request_key
    250,  # keyctl
    260,  # fchownat
    268,  # fchmodat
    272,  # unshare
    298,  # perf_event_open
    303,  # name_to_handle_at
    304,  # open_by_handle_at
    308,  # setns
    310,  # process_vm_readv
    311,  # process_vm_writev
    313,  # finit_module
    319,  # memfd_create
    320,  # kexec_file_load
    321,  # bpf
    322,  # execveat
    323,  # userfaultfd
    425,  # io_uring_setup
    426,  # io_uring_enter
    427,  # io_uring_register
    428,  # open_tree
    429,  # move_mount
    430,  # fsopen
    431,  # fsconfig
    432,  # fsmount
    433,  # fspick
    442,  # mount_setattr
    452,  # fchmodat2
}

PROCESS_CREATION_SYSCALLS = {56, 435}  # clone, clone3
OPEN_SYSCALLS = {2, 85, 257, 437}  # open, creat, openat, openat2

# classic BPF and seccomp constants
BPF_LD_W_ABS = 0x20
BPF_JMP_JEQ = 0x15
BPF_JMP_JGE = 0x35
BPF_RET = 0x06
AUDIT_ARCH_X86_64 = 0xC000003E
X32_SYSCALL_BIT = 0x40000000
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_KILL_PROCESS = 0x80000000


class PatchError(RuntimeError):
    pass


def bpf_stmt(code: int, value: int) -> int:
    return ((value & 0xFFFFFFFF) << 32) | (code & 0xFFFF)


def bpf_jump(code: int, value: int, jump_true: int, jump_false: int) -> int:
    if not 0 <= jump_true <= 0xFF or not 0 <= jump_false <= 0xFF:
        raise PatchError("seccomp BPF jump is outside the 8-bit range")
    return (
        ((value & 0xFFFFFFFF) << 32)
        | ((jump_false & 0xFF) << 24)
        | ((jump_true & 0xFF) << 16)
        | (code & 0xFFFF)
    )


def build_seccomp_filter(denied_syscalls: Iterable[int]) -> list[int]:
    denied = sorted(set(denied_syscalls))
    if len(denied) > 250:
        raise PatchError("too many denied syscalls for the linear cBPF filter")

    instructions = [
        bpf_stmt(BPF_LD_W_ABS, 4),
        0,  # architecture check, filled below
        bpf_stmt(BPF_LD_W_ABS, 0),
        0,  # x32 check, filled below
    ]
    instructions.extend(bpf_jump(BPF_JMP_JEQ, number, 0, 0) for number in denied)
    instructions.append(bpf_stmt(BPF_RET, SECCOMP_RET_ALLOW))
    kill_index = len(instructions)
    instructions.append(bpf_stmt(BPF_RET, SECCOMP_RET_KILL_PROCESS))

    instructions[1] = bpf_jump(
        BPF_JMP_JEQ, AUDIT_ARCH_X86_64, 0, kill_index - 2
    )
    instructions[3] = bpf_jump(
        BPF_JMP_JGE, X32_SYSCALL_BIT, kill_index - 4, 0
    )
    for index, number in enumerate(denied):
        instruction_index = 4 + index
        instructions[instruction_index] = bpf_jump(
            BPF_JMP_JEQ,
            number,
            kill_index - instruction_index - 1,
            0,
        )
    return instructions


def _byte_directive(value: bytes) -> str:
    return ".byte " + ", ".join(str(byte) for byte in value)


def _path_rule_assembly(index: int, writable: bool) -> str:
    rights = "rbx" if writable else "0xd"  # execute, read-file, read-dir
    return f"""
    # Open an allow-listed directory with O_PATH | O_CLOEXEC.  A missing
    # optional path is skipped, making the resulting policy stricter.
    mov eax, 257
    mov edi, -100
    lea rsi, [rip + guard_path_{index}]
    mov edx, 0x280000
    xor r10d, r10d
    syscall
    test rax, rax
    js guard_path_{index}_done
    mov r14, rax

    sub rsp, 16
    mov qword ptr [rsp], {rights}
    mov dword ptr [rsp + 8], r14d
    mov eax, 445
    mov edi, r13d
    mov esi, 1
    mov rdx, rsp
    xor r10d, r10d
    syscall
    add rsp, 16
    test rax, rax
    js guard_path_{index}_add_failed

    mov eax, 3
    mov edi, r14d
    syscall
    jmp guard_path_{index}_done

guard_path_{index}_add_failed:
    mov eax, 3
    mov edi, r14d
    syscall
    mov edi, 123
    jmp guard_fail

guard_path_{index}_done:
"""


def build_guard_assembly(
    read_only_paths: list[str],
    read_write_paths: list[str],
    seccomp_filter: list[int],
) -> str:
    path_entries = [(path, False) for path in read_only_paths]
    path_entries.extend((path, True) for path in read_write_paths)
    path_rules = "\n".join(
        _path_rule_assembly(index, writable)
        for index, (_, writable) in enumerate(path_entries)
    )

    filter_pushes = "\n".join(
        f"    movabs rax, 0x{instruction:016x}\n    push rax"
        for instruction in reversed(seccomp_filter)
    )
    filter_stack_size = len(seccomp_filter) * 8 + 16

    path_data = "\n".join(
        f"guard_path_{index}:\n    {_byte_directive(os.fsencode(path) + bytes([0]))}"
        for index, (path, _) in enumerate(path_entries)
    )

    return f"""
.intel_syntax noprefix
.section .text
.global _start
_start:
    # CET-compatible indirect entry.  Save process-entry state; r11 is later
    # reused as the direct jump target (r11 is unspecified by the ELF ABI).
    .byte 0xf3, 0x0f, 0x1e, 0xfa
    pushfq
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    # Make ptrace-style inspection harder; failure is non-fatal because this
    # flag is supplementary rather than the filesystem security boundary.
    mov eax, 157
    mov edi, 4
    xor esi, esi
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall

    # no_new_privs is required for both unprivileged Landlock and seccomp.
    mov eax, 157
    mov edi, 38
    mov esi, 1
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    js guard_fail_no_new_privs

    # Drop effective, permitted and inheritable Linux capabilities.  Landlock
    # remains the path boundary even when the original service starts as UID 0.
    sub rsp, 32
    mov dword ptr [rsp], 0x20080522
    mov dword ptr [rsp + 4], 0
    mov qword ptr [rsp + 8], 0
    mov qword ptr [rsp + 16], 0
    mov qword ptr [rsp + 24], 0
    mov eax, 126
    mov rdi, rsp
    lea rsi, [rsp + 8]
    syscall
    add rsp, 32
    test rax, rax
    js guard_fail_capabilities

    # Query Landlock ABI.  Protection is fail-closed when unavailable.
    mov eax, 444
    xor edi, edi
    xor esi, esi
    mov edx, 1
    syscall
    cmp rax, 1
    jl guard_fail_landlock_abi
    mov r12, rax

    # Filesystem access bits supported by the detected ABI.
    mov rbx, 0x1fff
    cmp r12, 2
    jb guard_landlock_mask_ready
    or rbx, 0x2000
    cmp r12, 3
    jb guard_landlock_mask_ready
    or rbx, 0x4000
    cmp r12, 5
    jb guard_landlock_mask_ready
    or rbx, 0x8000
guard_landlock_mask_ready:

    push rbx
    mov eax, 444
    mov rdi, rsp
    mov esi, 8
    xor edx, edx
    syscall
    add rsp, 8
    test rax, rax
    js guard_fail_landlock_create
    mov r13, rax

{path_rules}

    mov eax, 446
    mov edi, r13d
    xor esi, esi
    syscall
    test rax, rax
    js guard_fail_landlock_restrict

    mov eax, 3
    mov edi, r13d
    syscall

    # Materialize struct sock_filter[] and struct sock_fprog on the stack.
{filter_pushes}
    mov rdi, rsp
    push rdi
    mov rax, {len(seccomp_filter)}
    push rax
    mov rdx, rsp
    mov edi, 22
    mov esi, 2
    mov eax, 157
    syscall
    test rax, rax
    js guard_fail_seccomp
    add rsp, {filter_stack_size}

    # Compute load-bias + relocated original e_entry while registers are still
    # saved.  Put the target in the saved-r11 slot so all other registers are
    # restored before the CET-safe direct jump.
    lea rax, [rip + guard_runtime_anchor]
    movabs r10, 0x{SOURCE_MARKER:016x}
    sub rax, r10
    movabs r10, 0x{TARGET_MARKER:016x}
    add rax, r10
    mov qword ptr [rsp + 32], rax

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq
    jmp r11

guard_fail_no_new_privs:
    mov edi, 120
    jmp guard_fail
guard_fail_capabilities:
    mov edi, 126
    jmp guard_fail
guard_fail_landlock_abi:
    mov edi, 121
    jmp guard_fail
guard_fail_landlock_create:
    mov edi, 122
    jmp guard_fail
guard_fail_landlock_restrict:
    mov edi, 124
    jmp guard_fail
guard_fail_seccomp:
    mov edi, 125
guard_fail:
    mov eax, 60
    syscall
    ud2

guard_runtime_anchor:
    .quad 0x{ANCHOR_MARKER:016x}
guard_magic:
    {_byte_directive(MAGIC)}
{path_data}
"""


def assemble_guard(source: str) -> bytearray:
    gcc = shutil.which("gcc")
    objcopy = shutil.which("objcopy")
    if gcc is None or objcopy is None:
        raise PatchError("gcc and GNU objcopy are required to build the x86-64 guard")

    with tempfile.TemporaryDirectory(prefix="awd-guard-") as directory:
        directory_path = Path(directory)
        source_path = directory_path / "guard.S"
        object_path = directory_path / "guard.o"
        binary_path = directory_path / "guard.bin"
        source_path.write_text(source, encoding="utf-8")
        try:
            subprocess.run(
                [gcc, "-c", "-nostdlib", "-o", object_path, source_path],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [objcopy, "-O", "binary", "-j", ".text", object_path, binary_path],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as error:
            detail = error.stderr.strip() or error.stdout.strip()
            raise PatchError(f"failed to assemble guard: {detail}") from error
        return bytearray(binary_path.read_bytes())


def _replace_unique(payload: bytearray, marker: int, value: int) -> None:
    encoded_marker = struct.pack("<Q", marker)
    encoded_value = struct.pack("<Q", value)
    count = payload.count(encoded_marker)
    if count != 1:
        raise PatchError(f"internal guard marker occurs {count} times instead of once")
    offset = payload.index(encoded_marker)
    payload[offset : offset + 8] = encoded_value


def _normalise_paths(paths: Iterable[str]) -> list[str]:
    result: list[str] = []
    for path in paths:
        resolved = str(Path(path).expanduser().resolve(strict=False))
        if resolved not in result:
            result.append(resolved)
    return result


def _is_ancestor(parent: str, child: str) -> bool:
    try:
        return os.path.commonpath([parent, child]) == parent
    except ValueError:
        return False


def validate_policy(
    read_only_paths: list[str],
    read_write_paths: list[str],
    protected_paths: list[str],
) -> None:
    for allowed in [*read_only_paths, *read_write_paths]:
        for protected in protected_paths:
            if _is_ancestor(allowed, protected):
                raise PatchError(
                    f"allow-listed path {allowed!r} contains protected path "
                    f"{protected!r}; Landlock cannot express a deny exception"
                )


def validate_input(binary: lief.ELF.Binary, input_path: Path) -> None:
    header = binary.header
    if header.identity_class != lief.ELF.Header.CLASS.ELF64:
        raise PatchError("only ELF64 inputs are supported")
    if header.identity_data != lief.ELF.Header.ELF_DATA.LSB:
        raise PatchError("only little-endian ELF inputs are supported")
    if header.machine_type != lief.ELF.ARCH.X86_64:
        raise PatchError("only Linux x86-64 ELF inputs are supported")
    if header.entrypoint == 0:
        raise PatchError("input ELF has no executable entry point")
    if any(MAGIC in bytes(segment.content) for segment in binary.segments):
        raise PatchError("input ELF is already protected by AWDGUARD64")
    if not any(
        segment.type == lief.ELF.Segment.TYPE.LOAD
        and segment.has(lief.ELF.Segment.FLAGS.X)
        and segment.virtual_address <= header.entrypoint
        < segment.virtual_address + segment.virtual_size
        for segment in binary.segments
    ):
        raise PatchError(f"entry point of {input_path} is not in an executable PT_LOAD")


def verify_output(output_path: Path) -> None:
    binary = lief.ELF.parse(str(output_path))
    if binary is None:
        raise PatchError("LIEF could not parse the generated ELF")
    entrypoint = binary.header.entrypoint
    candidates = [
        segment
        for segment in binary.segments
        if segment.type == lief.ELF.Segment.TYPE.LOAD
        and segment.has(lief.ELF.Segment.FLAGS.R)
        and segment.has(lief.ELF.Segment.FLAGS.X)
        and not segment.has(lief.ELF.Segment.FLAGS.W)
        and segment.virtual_address <= entrypoint
        < segment.virtual_address + segment.virtual_size
    ]
    if not candidates or not any(MAGIC in bytes(segment.content) for segment in candidates):
        raise PatchError("generated entry point is not inside the AWD guard RX PT_LOAD")
    for segment in binary.segments:
        if segment.type == lief.ELF.Segment.TYPE.LOAD and segment.alignment > 1:
            if segment.virtual_address % segment.alignment != segment.file_offset % segment.alignment:
                raise PatchError("generated ELF contains a misaligned PT_LOAD")


def patch_binary(
    input_path: Path,
    output_path: Path,
    read_only_paths: list[str],
    read_write_paths: list[str],
    protected_paths: list[str],
    denied_syscalls: set[int],
) -> None:
    binary = lief.ELF.parse(str(input_path))
    if binary is None:
        raise PatchError(f"unable to parse {input_path} as ELF")
    validate_input(binary, input_path)
    validate_policy(read_only_paths, read_write_paths, protected_paths)

    input_entrypoint = binary.header.entrypoint
    seccomp_filter = build_seccomp_filter(denied_syscalls)
    assembly = build_guard_assembly(read_only_paths, read_write_paths, seccomp_filter)
    payload = assemble_guard(assembly)

    segment = lief.ELF.Segment()
    segment.type = lief.ELF.Segment.TYPE.LOAD
    segment.flags = lief.ELF.Segment.FLAGS.R | lief.ELF.Segment.FLAGS.X
    segment.alignment = 0x1000
    segment.content = list(payload)
    injected_segment = binary.add(segment)
    if injected_segment is None:
        raise PatchError("LIEF failed to add the guard PT_LOAD")
    # LIEF may relocate the original LOAD segments to make room for a larger
    # program-header table.  It updates e_entry as part of that relocation, so
    # this post-add value—not the input file's value—is the correct jump target.
    relocated_entrypoint = binary.header.entrypoint

    anchor_bytes = struct.pack("<Q", ANCHOR_MARKER)
    if payload.count(anchor_bytes) != 1:
        raise PatchError("internal runtime anchor is not unique")
    anchor_offset = payload.index(anchor_bytes)
    _replace_unique(
        payload,
        SOURCE_MARKER,
        injected_segment.virtual_address + anchor_offset,
    )
    _replace_unique(payload, TARGET_MARKER, relocated_entrypoint)
    injected_segment.content = list(payload)
    binary.header.entrypoint = injected_segment.virtual_address

    output_path.parent.mkdir(parents=True, exist_ok=True)
    binary.write(str(output_path))
    source_mode = stat.S_IMODE(input_path.stat().st_mode)
    output_path.chmod(source_mode | stat.S_IXUSR)
    try:
        verify_output(output_path)
    except Exception:
        output_path.unlink(missing_ok=True)
        raise

    print(f"[+] input OEP : 0x{input_entrypoint:x}")
    if relocated_entrypoint != input_entrypoint:
        print(f"[+] moved OEP : 0x{relocated_entrypoint:x}")
    print(f"[+] guard OEP : 0x{injected_segment.virtual_address:x}")
    print(f"[+] guard size: {len(payload)} bytes")
    print(f"[+] output    : {output_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inject Landlock + seccomp AWD protection into an x86-64 ELF"
    )
    parser.add_argument("input", type=Path, help="input x86-64 ELF")
    parser.add_argument("-o", "--output", type=Path, help="output ELF")
    parser.add_argument(
        "--protected-path",
        action="append",
        default=[],
        help="path that must not be covered by an allow rule (default: /flag)",
    )
    parser.add_argument("--allow-ro", action="append", default=[], help="add a read-only directory")
    parser.add_argument("--allow-rw", action="append", default=[], help="add a read-write directory")
    parser.add_argument(
        "--no-default-paths",
        action="store_true",
        help="do not allow the standard runtime directories automatically",
    )
    parser.add_argument("--allow-connect", action="store_true", help="allow outbound connect(2)")
    parser.add_argument(
        "--single-threaded",
        action="store_true",
        help="also block clone and clone3; only safe for single-threaded services",
    )
    parser.add_argument(
        "--deny-open",
        action="store_true",
        help="block every open family syscall in addition to Landlock",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_path = args.input.resolve()
    output_path = args.output or input_path.with_name(input_path.name + ".protected")
    output_path = output_path.resolve()

    default_ro = []
    default_rw = []
    if not args.no_default_paths:
        default_ro = ["/lib", "/lib64", "/usr", "/etc", "/dev", str(input_path.parent)]
        default_rw = ["/tmp"]

    read_only_paths = _normalise_paths([*default_ro, *args.allow_ro])
    read_write_paths = _normalise_paths([*default_rw, *args.allow_rw])
    # RW wins if a path was supplied in both categories.
    read_only_paths = [path for path in read_only_paths if path not in read_write_paths]
    protected_paths = _normalise_paths(args.protected_path or ["/flag"])

    denied_syscalls = set(BASE_DENIED_SYSCALLS)
    if args.allow_connect:
        denied_syscalls.discard(42)
    if args.single_threaded:
        denied_syscalls.update(PROCESS_CREATION_SYSCALLS)
    if args.deny_open:
        denied_syscalls.update(OPEN_SYSCALLS)

    try:
        patch_binary(
            input_path,
            output_path,
            read_only_paths,
            read_write_paths,
            protected_paths,
            denied_syscalls,
        )
    except (PatchError, OSError, RuntimeError, ValueError) as error:
        print(f"[-] {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
