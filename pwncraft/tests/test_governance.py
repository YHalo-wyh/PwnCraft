"""阶段 2-4 治理与指标验收测试 (确定性, 无网络)。"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "autocorrect"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pwncraft"))

from pwncraft.features.audit.address_derivation import verify_address_derivations
from pwncraft.features.audit.cross_view import cross_view_check
from governance import compute_metrics, course_status, material_governance


def test_addr_derivation_short_recv_detected() -> None:
    src = '''
def pwn():
    leak = io.recv(6)
    libc_base = u64(leak) - libc.sym["puts"]
'''
    checks = verify_address_derivations(src)
    align = [c for c in checks if c.code == "ADDR_ALIGN_002"]
    assert align, "短 recv → libc_base 页对齐检查应报错"
    assert align[0].severity == "error"


def test_addr_derivation_clean_passes() -> None:
    src = '''
def pwn():
    leak = io.recv(8)
    libc_base = u64(leak) - libc.sym["puts"]
'''
    checks = verify_address_derivations(src)
    errors = [c for c in checks if c.severity == "error"]
    assert not errors


def test_cross_view_no_ghost_helpers() -> None:
    binary_ir = {"functions": [{"name": "create"}, {"name": "delete"}]}
    exploit_ir = {"helper_calls": [{"function": "create"}, {"function": "delete"}]}
    issues = cross_view_check(binary_ir, exploit_ir)
    ghost = [i for i in issues if i["check"] == "C1_ghost_helpers"]
    assert not ghost


def test_cross_view_ghost_detected() -> None:
    binary_ir = {"functions": [{"name": "create"}]}
    exploit_ir = {"helper_calls": [{"function": "create"}, {"function": "phantom"}]}
    issues = cross_view_check(binary_ir, exploit_ir)
    ghost = [i for i in issues if i["check"] == "C1_ghost_helpers"]
    assert ghost


def test_course_status_structure() -> None:
    status = course_status()
    assert status["partial"] >= 3  # 课程 1/2/4 至少 PARTIAL
    assert "4" in status["courses"]  # 堆缺口
    assert "5" in status["courses"]  # fmt 语义
    c4 = status["courses"]["4"]
    assert "1:N allocator events" in str(c4["done"])


def test_material_governance() -> None:
    inv = {"cases": [
        {"case_id": "c1", "domain": "heap", "material_readiness": True,
         "entry_status": "ok", "gaps": []},
        {"case_id": "c2", "domain": "stack", "material_readiness": False,
         "entry_status": "missing", "gaps": ["exp entry missing"]},
    ]}
    gov = material_governance(inv)
    assert gov["total"] == 2
    assert gov["by_annotation_status"]["LOCKED"] == 1
    assert gov["by_annotation_status"]["GAP"] == 1


def test_metrics_computation() -> None:
    results = [
        {"verdict": "MATCH", "assertions": {"planned": 10, "executed": 10}},
        {"verdict": "DIVERGED", "assertions": {"planned": 8, "executed": 3}},
        {"verdict": "MATCH", "assertions": {"planned": 6, "executed": 6}},
    ]
    metrics = compute_metrics(results)
    assert metrics["total_cases"] == 3
    assert metrics["match"] == 2
    assert metrics["diverged"] == 1
    assert metrics["pass_rate"] == "2/3"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"PASS {name}")
    print("all governance tests passed")
