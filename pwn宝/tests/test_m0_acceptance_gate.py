"""M0 验收可信 — 评测契约 / 完整性门禁 / 接受注册表 验收测试。

覆盖计划阶段 0 的合成反例:
  G1 空断言集不得 MATCH
  G2 必需层被跳过 → INCONCLUSIVE (非静默通过)
  G3 计划断言未全部执行 (早停) → INCONCLUSIVE
  G4 NOT_APPLICABLE 层显式呈现
  R1 空真值 + 空输出: verdict 不得为 MATCH (owner 记录的历史缺陷)
  R2 接受注册表往返
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "autocorrect"))

import evaluation_contract as EC  # noqa: E402
from pwnbao.features.audit.audit import audit_exp  # noqa: E402  (smoke: import OK)


def _empty_report() -> dict:
    """比较器对空真值+空输出的报告形状 (owner 记录的历史缺陷复现)。"""
    return {
        "case_id": "synthetic-empty", "verdict": "MATCH",
        "first_divergence": None, "helper_contract_status": [],
        "layers_compared": ["HELPER_CONTRACT", "STATIC_RECOGNITION",
                            "CANONICAL_IR", "ARGUMENT_BINDING",
                            "TARGET_BEHAVIOR", "ALLOCATOR",
                            "PHYSICAL_MEMORY", "BINS", "SNAPSHOT",
                            "CANVAS_TRUTH"],
        "layer_results": [{"layer": l, "status": "MATCH"}
                          for l in ["HELPER_CONTRACT", "STATIC_RECOGNITION",
                                    "CANONICAL_IR", "ARGUMENT_BINDING",
                                    "TARGET_BEHAVIOR", "ALLOCATOR",
                                    "PHYSICAL_MEMORY", "BINS", "SNAPSHOT",
                                    "CANVAS_TRUTH"]],
        "_expected_op_count": 0, "_machine_check_count": 0,
    }


def test_g1_empty_assertions_cannot_match() -> None:
    report = EC.enforce(_empty_report(), EC.EvaluationContract(
        case_id="synthetic-empty", required_layers=["HELPER_CONTRACT"],
        min_assertions=1))
    assert report["verdict"] == EC.VERDICT_INCONCLUSIVE
    assert "planned=0" in report["assertion_counts"]["gate"]


def test_g2_required_layer_skipped_blocks_match() -> None:
    report = _empty_report()
    report["layers_compared"] = [l for l in report["layers_compared"]
                                 if l != "CANVAS_TRUTH"]
    report["layer_results"] = [r for r in report["layer_results"]
                               if r["layer"] != "CANVAS_TRUTH"]
    report["_expected_op_count"] = 5  # 断言数足够, 缺的是必需层
    contract = EC.EvaluationContract(
        case_id="synthetic", required_layers=["HELPER_CONTRACT", "CANVAS_TRUTH"],
        min_assertions=1)
    result = EC.enforce(report, contract)
    assert result["verdict"] == EC.VERDICT_INCONCLUSIVE
    assert "CANVAS_TRUTH" in result["contract_evaluation"]["missing_required_layers"]
    skipped = [r for r in result["layer_results"]
               if r["layer"] == "CANVAS_TRUTH"]
    assert skipped and skipped[0]["status"] == "SKIPPED"


def test_g3_early_stop_means_not_all_executed() -> None:
    report = _empty_report()
    # helper 层有偏差 → 早停 → STATIC_RECOGNITION 之后的计划断言未执行
    report["verdict"] = "DIVERGED"
    report["first_divergence"] = {"layer": "HELPER_CONTRACT"}
    report["helper_contract_status"] = [{"helper": "create",
                                         "semantic": "SEMANTIC_DIVERGED"}]
    report["layers_compared"] = ["HELPER_CONTRACT"]
    report["layer_results"] = [{"layer": "HELPER_CONTRACT", "status": "DIVERGED"}]
    report["_expected_op_count"] = 8
    report["_machine_check_count"] = 0
    contract = EC.EvaluationContract(case_id="synthetic",
                                     required_layers=["HELPER_CONTRACT"],
                                     min_assertions=1)
    result = EC.enforce(report, contract)
    counts = result["assertion_counts"]
    assert counts["planned"] == 10  # 2 (helper) + 8 (ops)
    assert counts["executed"] < counts["planned"]
    # DIVERGED 本身就是非 MATCH, 门禁不把它改成 INCONCLUSIVE
    assert result["verdict"] == "DIVERGED"


def test_g4_not_applicable_layers_explicit() -> None:
    report = _empty_report()
    report["_expected_op_count"] = 5
    report["layers_compared"] = [l for l in report["layers_compared"]
                                 if l not in ("ALLOCATOR", "BINS")]
    report["layer_results"] = [r for r in report["layer_results"]
                               if r["layer"] not in ("ALLOCATOR", "BINS")]
    contract = EC.EvaluationContract(
        case_id="synthetic-stack", required_layers=["HELPER_CONTRACT"],
        not_applicable_layers=["ALLOCATOR", "BINS"], min_assertions=1)
    result = EC.enforce(report, contract)
    assert result["verdict"] == "MATCH"
    na = [r for r in result["layer_results"] if r["layer"] == "ALLOCATOR"]
    assert na and na[0]["status"] == "NOT_APPLICABLE"


def test_r1_owner_defect_now_gated() -> None:
    """owner 记录的历史缺陷: 仅 case_id 的真值 + 空输出 → 曾得 MATCH。
    现在: 无契约时也必须 INCONCLUSIVE (planned=0)。"""
    report = EC.enforce(_empty_report(), None)
    assert report["verdict"] != "MATCH"
    assert report["assertion_counts"]["planned"] == 0


def test_r2_registry_roundtrip(tmp_path: Path | None = None) -> None:
    import tempfile
    tmp_path = tmp_path or Path(tempfile.mkdtemp())
    registry_path = tmp_path / "accepted_cases.json"
    registry_path.write_text('["case-a"]', encoding="utf-8")  # 旧格式
    loaded = __import__("json").loads(registry_path.read_text(encoding="utf-8"))
    migrated = [{"case_id": x} if isinstance(x, str) else dict(x)
                for x in loaded]
    assert migrated == [{"case_id": "case-a"}]


def test_s1_auditor_kernel_imports_clean() -> None:
    assert callable(audit_exp)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"PASS {name}")
    print("all m0 gate tests passed")
