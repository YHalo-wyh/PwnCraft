from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping
import re


@dataclass(frozen=True)
class SyscallSpec:
    name: str
    number: int
    registers: tuple[str, ...]
    prototype: str = ""
    return_register: str = "rax"
    architecture: str = "amd64"

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "number": self.number, "registers": list(self.registers), "prototype": self.prototype, "return_register": self.return_register, "architecture": self.architecture}

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "SyscallSpec":
        return cls(str(payload.get("name", "")), int(payload.get("number", 0)), tuple(str(x) for x in payload.get("registers", ())), str(payload.get("prototype", "")), str(payload.get("return_register", "rax")), str(payload.get("architecture", "amd64")))


_TABLES: dict[str, dict[str, SyscallSpec]] = {
    "amd64": {
        "read": SyscallSpec("read", 0, ("rdi", "rsi", "rdx"), "ssize_t read(int fd, void *buf, size_t count)"),
        "write": SyscallSpec("write", 1, ("rdi", "rsi", "rdx"), "ssize_t write(int fd, const void *buf, size_t count)"),
        "open": SyscallSpec("open", 2, ("rdi", "rsi", "rdx"), "int open(const char *path, int flags, mode_t mode)"),
        "openat": SyscallSpec("openat", 257, ("rdi", "rsi", "rdx", "r10"), "int openat(int dirfd, const char *path, int flags, mode_t mode)"),
        "execve": SyscallSpec("execve", 59, ("rdi", "rsi", "rdx"), "int execve(const char *filename, char *const argv[], char *const envp[])"),
        "close": SyscallSpec("close", 3, ("rdi",), "int close(int fd)"),
        "exit": SyscallSpec("exit", 60, ("rdi",), "void _exit(int status)"),
        "mmap": SyscallSpec("mmap", 9, ("rdi", "rsi", "rdx", "r10", "r8", "r9"), "void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)"),
        "mprotect": SyscallSpec("mprotect", 10, ("rdi", "rsi", "rdx"), "int mprotect(void *addr, size_t len, int prot)"),
        "dup2": SyscallSpec("dup2", 33, ("rdi", "rsi"), "int dup2(int oldfd, int newfd)"),
    },
    "i386": {
        "read": SyscallSpec("read", 3, ("ebx", "ecx", "edx"), "ssize_t read(int fd, void *buf, size_t count)", return_register="eax", architecture="i386"),
        "write": SyscallSpec("write", 4, ("ebx", "ecx", "edx"), "ssize_t write(int fd, void *buf, size_t count)", return_register="eax", architecture="i386"),
        "open": SyscallSpec("open", 5, ("ebx", "ecx", "edx"), "int open(const char *path, int flags, mode_t mode)", return_register="eax", architecture="i386"),
        "execve": SyscallSpec("execve", 11, ("ebx", "ecx", "edx"), "int execve(const char *filename, char *const argv[], char *const envp[])", return_register="eax", architecture="i386"),
        "close": SyscallSpec("close", 6, ("ebx",), "int close(int fd)", return_register="eax", architecture="i386"),
        "exit": SyscallSpec("exit", 1, ("ebx",), "void _exit(int status)", return_register="eax", architecture="i386"),
        "mmap": SyscallSpec("mmap2", 192, ("ebx", "ecx", "edx", "esi", "edi", "ebp"), "void *mmap2(void *addr, size_t length, int prot, int flags, int fd, off_t pgoff)", return_register="eax", architecture="i386"),
        "mprotect": SyscallSpec("mprotect", 125, ("ebx", "ecx", "edx"), "int mprotect(void *addr, size_t len, int prot)", return_register="eax", architecture="i386"),
        "dup2": SyscallSpec("dup2", 63, ("ebx", "ecx"), "int dup2(int oldfd, int newfd)", return_register="eax", architecture="i386"),
    },
    "aarch64": {
        "read": SyscallSpec("read", 63, ("x0", "x1", "x2"), "ssize_t read(unsigned int fd, const char *buf, size_t count)", return_register="x0", architecture="aarch64"),
        "write": SyscallSpec("write", 64, ("x0", "x1", "x2"), "ssize_t write(unsigned int fd, const char *buf, size_t count)", return_register="x0", architecture="aarch64"),
        "openat": SyscallSpec("openat", 56, ("x0", "x1", "x2", "x3"), "int openat(int dirfd, const char *path, int flags, mode_t mode)", return_register="x0", architecture="aarch64"),
        "execve": SyscallSpec("execve", 221, ("x0", "x1", "x2"), "int execve(const char *filename, char *const argv[], char *const envp[])", return_register="x0", architecture="aarch64"),
        "close": SyscallSpec("close", 57, ("x0",), "int close(int fd)", return_register="x0", architecture="aarch64"),
        "exit": SyscallSpec("exit", 93, ("x0",), "void _exit(int status)", return_register="x0", architecture="aarch64"),
        "mmap": SyscallSpec("mmap", 222, ("x0", "x1", "x2", "x3", "x4", "x5"), "void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)", return_register="x0", architecture="aarch64"),
        "mprotect": SyscallSpec("mprotect", 226, ("x0", "x1", "x2"), "int mprotect(void *addr, size_t len, int prot)", return_register="x0", architecture="aarch64"),
        # aarch64 无 dup2（只有 dup3）：保持缺席即 unknown，不伪造。
    },
}


def normalize_architecture(arch: str | None, *, strict: bool = False) -> str:
    """Normalize architecture names.

    ``strict=True`` raises instead of silently falling back to amd64; the
    default keeps compatibility with pre-v0.17 callers.
    """
    text = str(arch or "amd64").casefold().strip().replace("x86_64", "amd64").replace("x86-64", "amd64").replace("arm64", "aarch64")
    if text in _TABLES:
        return text
    if strict:
        raise ValueError(f"不支持的架构: {arch}")
    return "amd64"


def syscall_table(architecture: str = "amd64") -> dict[str, SyscallSpec]:
    return dict(_TABLES[normalize_architecture(architecture)])


def lookup_syscall(name: str, architecture: str = "amd64") -> SyscallSpec | None:
    return syscall_table(architecture).get(str(name).strip().lower())


def parse_seccomp_policy(text: str) -> dict[str, str]:
    """Parse common seccomp-tools/readable policy lines without guessing."""
    policy: dict[str, str] = {}
    for raw_line in str(text).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Supports ``allow: read``, ``allow read``, ``read ALLOW`` and
        # seccomp-tools tables such as ``read  ALLOW``.
        match = re.search(r"^(?:[+|\-]\s*)?(?:allow|deny|block|trap|kill)\s*[:=]?\s*([a-zA-Z0-9_]+)\b", line, re.IGNORECASE)
        if match:
            name = match.group(1).lower()
            action = "ALLOWED" if line.lstrip("+|- ").casefold().startswith("allow") else "BLOCKED"
            policy[name] = action
            continue
        match = re.search(r"^([a-zA-Z0-9_]+)(?:\s+\d+)?\s+(ALLOWED|BLOCKED|DENY|ALLOW|TRAP|KILL)\b", line, re.IGNORECASE)
        if match:
            name = match.group(1).lower()
            policy[name] = "ALLOWED" if match.group(2).upper() in {"ALLOWED", "ALLOW"} else "BLOCKED"
    return policy


_DEFAULT_ACTION_RE = re.compile(r"\bdefault\s+(?:action\s*)?[:=]?\s*(allow|kill|trap|errno|trace|log|notify)\b", re.IGNORECASE)


def parse_seccomp_policy_structured(text: str) -> dict[str, object]:
    """Structured seccomp view: flat verdicts plus provable metadata only.

    Complex BPF argument filters cannot be proven from plain text, so they
    stay recorded as source lines with ``unknown`` constraints; the model
    never turns them into an allowed/blocked claim.
    """
    flat = parse_seccomp_policy(text)
    default_action = ""
    source_lines: list[str] = []
    constraints: dict[str, str] = {}
    for raw_line in str(text).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        source_lines.append(line)
        match = _DEFAULT_ACTION_RE.search(line)
        if match and not default_action:
            default_action = match.group(1).lower()
        # Argument filters such as ``if (arg0 == 0x0) allow`` are recorded
        # verbatim: the verdict stays unknown rather than being guessed.
        if re.search(r"\bif\s*\(\s*arg\d", line, re.IGNORECASE):
            name_match = re.search(r"\b(allow|deny|block|trap|kill)\s*[:=]?\s*([a-zA-Z0-9_]+)\b", line, re.IGNORECASE)
            if name_match:
                constraints[name_match.group(2).lower()] = line
    return {
        "policy": flat,
        "default_action": default_action,
        "constraints": constraints,
        "source_lines": source_lines,
    }


def seccomp_verdict(policy: Mapping[str, str], name: str) -> str:
    """Return ALLOWED/BLOCKED/UNKNOWN for one syscall under a flat policy.

    A default-allow policy without an explicit entry is UNKNOWN: the model
    cannot prove either verdict from absence alone.
    """
    key = str(name).strip().lower()
    value = policy.get(key)
    if value:
        return "ALLOWED" if str(value).upper() == "ALLOWED" else "BLOCKED"
    return "UNKNOWN"


# ---------------------------------------------------------------------------
# seccomp-tools dump table (real BPF disassembly, observed facts only)

_SECCOMP_DUMP_ROW_RE = re.compile(
    r"^\s*\d+:\s+[0-9a-fA-Fx]+\s+[0-9a-fA-Fx]+\s+[0-9a-fA-Fx]+\s+[0-9a-fA-Fx]+\s*(.*)$"
)
# seccomp-tools prints ``A = arch`` and ``if (arch != 0xc000003e)``; the
# constant lives on the comparison row, not on the load row.
_SECCOMP_ARCH_EQ_RE = re.compile(r"\bA\s*=\s*(0x[0-9a-fA-F]+)\b")
_SECCOMP_ARCH_NE_RE = re.compile(r"\barch\s*!=\s*(0x[0-9a-fA-F]+)\b")
_SECCOMP_NR_CMP_RE = re.compile(r"\bA\s*(?:==|!=)\s*(0x[0-9a-fA-F]+|[a-zA-Z_][a-zA-Z0-9_]*)\b")
_SECCOMP_RET_RE = re.compile(r"\breturn\s+(KILL_PROCESS|KILL|TRAP|ERRNO|USER_NOTIF|TRACE|LOG|ALLOW)\b", re.IGNORECASE)
_AUDIT_ARCH = {
    0x40000003: "i386",
    0xC000003E: "amd64",
    0xC00000B7: "aarch64",
}


def parse_seccomp_tools_dump(text: str) -> dict[str, object]:
    """Parse ``seccomp-tools dump`` output into observed facts.

    Only what the BPF disassembly literally shows is reported: the audit
    arch constant, every ``A == 0xNN`` syscall-number comparison, the final
    return action (the default action) and the raw rows.  Whether a compared
    syscall ends up allowed or killed depends on the jump targets, so the
    model records them as "compared" — never as an allow/deny claim.
    """
    rows: list[str] = []
    arch = ""
    return_actions: list[str] = []
    compared: list[str] = []
    for raw_line in str(text).splitlines():
        if not _SECCOMP_DUMP_ROW_RE.match(raw_line):
            continue
        rows.append(raw_line.rstrip())
        line = raw_line.strip()
        arch_match = _SECCOMP_ARCH_EQ_RE.search(line) or _SECCOMP_ARCH_NE_RE.search(line)
        if arch_match and not arch:
            arch = _AUDIT_ARCH.get(int(arch_match.group(1), 16), arch_match.group(1))
        nr_match = _SECCOMP_NR_CMP_RE.search(line)
        if nr_match:
            number = nr_match.group(1).lower()
            if number not in compared:
                compared.append(number)
        ret_match = _SECCOMP_RET_RE.search(line)
        if ret_match:
            return_actions.append(ret_match.group(1).upper())
    named: list[dict[str, str]] = []
    if compared and arch in ("amd64", "i386", "aarch64"):
        try:
            table = syscall_table(arch)
            by_number = {int(spec.number): spec.name for spec in table.values()}
        except Exception:
            table = {}
            by_number = {}
        for number in compared:
            if number.startswith("0x"):
                named.append({"nr": number, "name": by_number.get(int(number, 16), "")})
            else:
                named.append({"nr": number, "name": number})
    else:
        named = [{"nr": number, "name": "" if number.startswith("0x") else number} for number in compared]
    return {
        "tool": "seccomp-tools dump",
        "rows": len(rows),
        "arch": arch,
        "default_action": return_actions[-1].lower() if return_actions else "",
        "return_actions": return_actions,
        "compared": named,
        "raw": str(text).rstrip(),
    }
