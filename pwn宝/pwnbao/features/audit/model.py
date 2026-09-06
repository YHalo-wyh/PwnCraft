"""ExploitIR + Diagnostic models for the EXP Live Auditor (VNext.3)."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITY_ERROR = "error"
SEVERITY_WARNING = "warning"
SEVERITY_SUGGESTION = "suggestion"

# 来源系统 (VNext.3.1 #6): 每条结论/状态标注从哪里来。
#   OBSERVED          直接观测 (审计器从 EXP/目标行为实际读到)
#   DERIVED           由规则/数据流推导 (推导链可复核)
#   MANUAL_ASSUMPTION 用户手工断言 (画布手改/手写假设, 显式标记, 不冒充真值)
PROVENANCE_OBSERVED = "OBSERVED"
PROVENANCE_DERIVED = "DERIVED"
PROVENANCE_MANUAL_ASSUMPTION = "MANUAL_ASSUMPTION"


@dataclass(frozen=True)
class SourceSpan:
    """精确来源定位 (VNext.3.1 #1): 复盘/裁判时可证明结论出处。"""
    file: str = "exp.py"
    line: int = 0
    col: int = 0
    end_line: int = 0
    end_col: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Diagnostic:
    code: str
    severity: str            # error | warning | suggestion
    confidence: float
    message: str
    line: int
    evidence: list[dict] = field(default_factory=list)
    suggested_fix: str = ""  # replacement expression/statements; never auto-applied
    impact: str = ""
    scope: str = "main"
    span: dict = field(default_factory=dict)          # SourceSpan dict
    provenance: str = PROVENANCE_DERIVED              # 结论来源
    fix_target: str = ""                              # quick-fix 定位文本

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Interaction:
    """One tube interaction, expanded through helper bodies."""
    action: str          # SEND | SENDLINE | RECV | RECVUNTIL | RECVLINE | RECVN
    wait_for: str = ""   # delimiter argument text (until/after family)
    value: str = ""      # sent value expression text
    length: int | None = None  # concrete recv(n) length
    line: int = 0
    scope: str = "main"


@dataclass
class PackOp:
    fn: str              # p64 | p32 | u64 | u32
    arg: str             # argument expression text
    line: int = 0
    scope: str = "main"


@dataclass
class Hardcode:
    var: str
    value: int
    line: int = 0
    scope: str = "main"


@dataclass
class HelperCall:
    """A call to a user-defined helper, expanded with argument bindings."""
    function: str
    args: list[str] = field(default_factory=list)   # argument expr texts
    line: int = 0
    scope: str = "main"


@dataclass
class ExploitIR:
    interactions: list[Interaction] = field(default_factory=list)
    packs: list[PackOp] = field(default_factory=list)
    unpacks: list[PackOp] = field(default_factory=list)
    helper_calls: list[HelperCall] = field(default_factory=list)
    hardcodes: list[Hardcode] = field(default_factory=list)
    # var -> concrete recv length (leak dataflow seeds)
    var_recv_length: dict[str, int] = field(default_factory=dict)
    # var -> recvline/unknown-length marker
    var_recv_unknown: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "interactions": [asdict(i) for i in self.interactions],
            "packs": [asdict(p) for p in self.packs],
            "unpacks": [asdict(p) for p in self.unpacks],
            "helper_calls": [asdict(c) for c in self.helper_calls],
            "hardcodes": [asdict(h) for h in self.hardcodes],
            "var_recv_length": dict(self.var_recv_length),
            "var_recv_unknown": list(self.var_recv_unknown),
        }
