"""M1 跨域接入验收 — CaseManifest 归一 / 领域适配器 / 适用层契约。

Deterministic-First: 全部合成材料, 无网络, 无推断。
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "autocorrect"))

import case_manifest as CM  # noqa: E402
import domain_adapters as DA  # noqa: E402


def _write_case(root: Path, case_id: str, manifest: dict) -> Path:
    d = root / case_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False),
                                     encoding="utf-8")
    return d


HEAP_MANIFEST = {
    "case_id": "heap-x",
    "technique": "heap",
    "target": {"arch": "amd64", "binary_sha256": "a" * 64, "libc_sha256": "b" * 64},
    "exp_analysis": {"entry_file": "pwn/x/exp.py"},
    "quality": {"tier": "GOLD"},
}

STACK_MANIFEST = {
    "case_id": "stack-x",
    "technique": "stack_rop",
    "target": {"arch": "amd64", "binary_sha256": "c" * 64, "libc_sha256": None},
    "exp_analysis": {"entry_file": {"rel": "x/exp.py", "role": "python",
                                    "size": 100}},
    "quality": {"tier": "SILVER"},
}

STACK_NO_ENTRY = {"case_id": "stack-empty", "technique": "stack_rop",
                  "target": {"arch": "amd64", "binary_sha256": "d" * 64},
                  "exp_analysis": {"entry_file": None},
                  "quality": {"tier": "SILVER"}}


def test_n1_heap_string_entry_normalizes() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        d = _write_case(Path(tmp), "heap-x", HEAP_MANIFEST)
        material = CM.load_case_material(d)
        assert material.domain == "heap" and material.entry_status == "ok"
        assert material.entry_candidates[0]["rel"] == "pwn/x/exp.py"
        assert material.material_readiness is True


def test_n2_stack_dict_entry_normalizes() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        d = _write_case(Path(tmp), "stack-x", STACK_MANIFEST)
        material = CM.load_case_material(d)
        assert material.domain == "stack"
        assert material.entry_status == "ok"
        assert material.entry_candidates[0]["rel"] == "x/exp.py"
        # 缺 libc: SILVER 领域内不阻塞纯解析评测 (owner 阶段 3 修订)
        assert material.libc_present is False
        assert material.material_readiness is True


def test_n3_missing_entry_enters_gap_queue() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        d = _write_case(Path(tmp), "stack-empty", STACK_NO_ENTRY)
        material = CM.load_case_material(d)
        assert material.entry_status == "missing"
        assert material.material_readiness is False
        assert any("exp entry" in g for g in material.gaps)


STACK_EXP_BUGGY = '''
def pwn():
    leak = io.recv(6)
    libc_base = u64(leak) - libc.sym["puts"]
    io.send(p32(libc_base + 16))
'''

STACK_EXP_CLEAN = '''
def pwn():
    leak = io.recv(8)
    libc_base = u64(leak) - libc.sym["puts"]
    io.send(p64(libc_base + 16))
'''


def _stack_material():
    return CM.CaseMaterial(case_id="stack-synth", technique="stack_rop",
                           domain="stack", tier="SILVER", arch="amd64",
                           entry_status="ok", binary_sha256="e" * 64,
                           material_readiness=True)


def test_s1_stack_adapter_flags_leak_and_arch() -> None:
    report = DA.run_domain("stack", _stack_material(), STACK_EXP_BUGGY,
                           bits=64, pie=False)
    assert report["verdict"] == "DIVERGED"
    rules = next(r for r in report["layer_results"]
                 if r["layer"] == "EXP_SEMANTIC_RULES")
    codes = [d["code"] for d in rules["diagnostics"]]
    assert "EXP_LEAK_001" in codes and "EXP_ARCH_001" in codes


def test_s2_stack_adapter_clean_exp_matches() -> None:
    report = DA.run_domain("stack", _stack_material(), STACK_EXP_CLEAN,
                           bits=64, pie=False)
    assert report["verdict"] == "MATCH"


def test_s3_stack_applicable_layers_declared() -> None:
    applicable = DA.default_applicable_layers("stack")
    assert applicable["required_layers"] == ["EXP_SEMANTIC_RULES"]
    assert "ALLOCATOR" in applicable["not_applicable_layers"]
    assert "BINS" in applicable["not_applicable_layers"]


FMT_EXP_OK = '''
def pwn():
    io.sendline(b"%7$s")
'''

FMT_EXP_BROKEN = '''
def pwn():
    io.sendline(b"%7$s"
'''


def test_f1_fmt_adapter_smoke_ok() -> None:
    material = CM.CaseMaterial(case_id="fmt-synth", technique="fmtstr",
                               domain="fmt", tier="SILVER", arch="amd64",
                               entry_status="ok")
    report = DA.run_domain("fmt", material, FMT_EXP_OK)
    assert report["verdict"] == "MATCH"
    statuses = {r["layer"]: r["status"] for r in report["layer_results"]}
    assert statuses["EXP_PARSE"] == "MATCH"
    # M4 fmt 深化: 语义检查层已实现 (无 %n 的干净 EXP → MATCH 含 facts)
    assert statuses["FMT_SEMANTIC_CHECKS"] == "MATCH"


def test_f2_fmt_adapter_syntax_error_diverged() -> None:
    material = CM.CaseMaterial(case_id="fmt-synth", technique="fmtstr",
                               domain="fmt", tier="SILVER", arch="amd64",
                               entry_status="ok")
    report = DA.run_domain("fmt", material, FMT_EXP_BROKEN)
    assert report["verdict"] == "DIVERGED"


def test_f3_unsupported_domain_rejected() -> None:
    try:
        DA.run_domain("future", _stack_material(), "x = 1")
        raise SystemExit("should reject")
    except ValueError:
        pass


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"PASS {name}")
    print("all m1 domain tests passed")
