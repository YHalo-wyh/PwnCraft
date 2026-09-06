#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Assemble the PwnCraft training review bundle (read-only copies; originals
are never modified). Layout per owner request 2026-09-05."""
from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]          # .../pwn宝
AC = ROOT / "autocorrect"
PROJ = ROOT / "pwn宝"                                # recognizer sources
CORPUS = ROOT / "heap-corpus"
STAGE = ROOT / "PwnCraft_training_review"
LAB13 = "heap-ctf-wiki-hitcontraning-lab13-bae716d5"
NOTE2 = "heap-ctf-wiki-2016-zctf-note2-a85b75f2"
BABY = "heap-ctf-wiki-2017-0ctf-babyheap-9527e180"


def cp(src, dst):
    src, dst = Path(src), Path(dst)
    if not src.exists():
        print(f"  [skip-missing] {src}")
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)


def wjson(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, default=str),
                    encoding="utf-8")


def main():
    if STAGE.exists():
        shutil.rmtree(STAGE)
    print("== staging", STAGE.name)

    # ---------------- top level
    cp(AC / "TRAINING_PROTOCOL.md", STAGE / "TRAINING_PROTOCOL.md")
    cp(AC / "README.md", STAGE / "autocorrect_README.md")

    # ---------------- autocorrect framework
    for f in ("loop.py", "pwncraft_adapter.py", "comparator.py",
              "comparator_v2.py", "comparator_v3.py", "regression.py",
              "curriculum_state.json", "reviewer_protocol.md"):
        cp(AC / f, STAGE / "autocorrect" / f)
    for f in (AC / "schemas").glob("*.json"):
        cp(f, STAGE / "autocorrect" / "schemas" / f.name)

    # patches (full history, immutable)
    for cyc in ("cycle-0-bootstrap-invalidated", "cycle-1", "cycle-2"):
        src = AC / "patches" / cyc
        if src.exists():
            for f in src.rglob("*"):
                if f.is_file():
                    cp(f, STAGE / "autocorrect" / "patches" / cyc / f.relative_to(src))

    # case workdirs: expected_truth + divergence reports + curated generated
    for case in (LAB13, NOTE2, BABY):
        src = AC / "cases" / case
        dst = STAGE / "autocorrect" / "cases" / case
        cp(src / "expected_truth.json", dst / "expected_truth.json") if case != BABY else \
            cp(src / "expected_analysis.json", dst / "expected_analysis.json")
        for f in src.glob("divergence_report*.json"):
            cp(f, dst / f.name)

    # regression baselines + probes + validation
    for f in (AC / "regression" / "baselines").rglob("*.json"):
        cp(f, STAGE / "autocorrect" / "regression" / "baselines" /
           f.relative_to(AC / "regression" / "baselines"))
    cp(AC / "regression" / "last_run.json", STAGE / "autocorrect" / "regression" / "last_run.json")
    cp(AC / "regression" / "probes_cycle-2.json", STAGE / "autocorrect" / "regression" / "probes_cycle-2.json")
    cp(AC / "regression" / "canvas_export_validation.json",
       STAGE / "autocorrect" / "regression" / "canvas_export_validation.json")

    # ---------------- recognizer core (recently trained modules only)
    rc = STAGE / "recognizer"
    cp(PROJ / "pwnbao/features/heapviz/contracts/resolver.py", rc / "contracts/resolver.py")
    cp(PROJ / "pwnbao/features/heapviz/contracts/model.py", rc / "contracts/model.py")
    cp(PROJ / "pwnbao/features/heapviz/contracts/aliases.py", rc / "contracts/aliases.py")
    cp(PROJ / "pwnbao/features/heapviz/analyzer.py", rc / "analyzer.py")
    cp(PROJ / "pwnbao/features/heapviz/api_profile.py", rc / "api_profile.py")
    cp(PROJ / "pwnbao/features/heapviz/source_compat.py", rc / "source_compat.py")
    cp(PROJ / "pwnbao/features/heapviz/semantics/canonical_ir.py", rc / "semantics/canonical_ir.py")
    cp(PROJ / "pwnbao/features/heapviz/semantics/challenge_profile.py",
       rc / "semantics/challenge_profile.py")
    cp(PROJ / "pwnbao/features/heapviz/canvas_model.py", rc / "canvas_model.py")
    cp(PROJ / "pwnbao/features/heapviz/grid/physical_grid.py", rc / "grid/physical_grid.py")
    cp(PROJ / "pwnbao/features/heapviz/presentation/scene_model.py",
       rc / "presentation/scene_model.py")
    # synthetic tests proving one-cycle discipline
    cp(PROJ / "tests/test_contract_output_dataflow_evidence.py",
       rc / "tests/test_contract_output_dataflow_evidence.py")
    cp(PROJ / "tests/test_source_compat_py2_print.py",
       rc / "tests/test_source_compat_py2_print.py")

    # ---------------- corpus
    cb = STAGE / "corpus"
    cp(CORPUS / "collection_report.json", cb / "collection_report.json")
    cp(AC / "curriculum_state.json", cb / "curriculum_state.json")
    cp(CORPUS / "repos_meta.json", cb / "repos_meta.json")
    cp(CORPUS / "batch_summary.json", cb / "batch_summary.json")
    for f in (CORPUS / "index").glob("*.json*"):
        cp(f, cb / "index" / f.name)
    for d in sorted((CORPUS / "corpus").iterdir()):
        if d.is_dir():
            cp(d / "manifest.json", cb / "gold" / d.name / "manifest.json")

    # ---------------- sample cases (real, complete)
    def sample(case, out):
        src = CORPUS / "corpus" / case
        sc = STAGE / "sample_cases" / out
        for f in (src / "original/challenge").glob("*"):
            cp(f, sc / "challenge" / f.name)
        for f in (src / "original/solution").glob("*"):
            cp(f, sc / "solution" / f.name)
        for f in (src / "original/docs").glob("*"):
            cp(f, sc / "docs" / f.name)
        ac_src = AC / "cases" / case
        if (ac_src / "expected_truth.json").exists():
            cp(ac_src / "expected_truth.json", sc / "expected_truth.json")
        # divergence reports (latest cycle emphasized)
        for f in sorted(ac_src.glob("divergence_report*.json")):
            cp(f, sc / f.name)
        # curated generated artifacts from the LATEST run (canvas-export label)
        gen = ac_src / "generated" / "canvas-export" / "pwncraft_output.json"
        out_gen = sc / "generated"
        if gen.exists():
            data = json.loads(gen.read_text(encoding="utf-8"))
            a = data["analyzer"]
            wjson(out_gen / "recognition.json", a["recognition"])
            wjson(out_gen / "helper_contracts.json", a["helper_contracts"])
            wjson(out_gen / "canonical_ir.json", a["canonical_ops"])
            wjson(out_gen / "diagnostics.json", a["diagnostics"])
            steps = data["replay"]["steps"]
            wjson(out_gen / "allocator_events.json",
                  [{"step": s.get("step"),
                    "alloc_events": s.get("alloc_events"),
                    "free_events": s.get("free_events"),
                    "bins": {"tcache": s.get("tcache"), "fastbins": s.get("fastbins"),
                             "unsorted": s.get("unsorted")}} for s in steps])
            wjson(out_gen / "physical_memory.json",
                  [{"step": s.get("step"),
                    "note": "renderer-input physical view (bridge payload): "
                            "physical_chunks + overwrite_edges + paint_spans",
                    "physical_chunks": s.get("chunks"),
                    "overwrite_edges": s.get("overwrite_edges"),
                    "paint_spans_raw": s.get("paint_spans")} for s in steps])
            wjson(out_gen / "snapshots.json",
                  [{"step": s.get("step"), "op_id": s.get("op_id"),
                    "n_chunks": s.get("n_chunks"), "handles": s.get("handles"),
                    "top": s.get("top"), "aborted": s.get("aborted"),
                    "warnings": s.get("warnings")} for s in steps])
            wjson(out_gen / "target_behavior.json", {
                "status": "NOT_IMPLEMENTED_IN_RECOGNIZER",
                "protocol": "TRAINING_PROTOCOL v1.2 §I: target_behavior 层真值目前在 "
                            "expected_truth.json (Analyst 侧); 识别器侧该层尚未建模 "
                            "(lab13 1:N 缺口 = 已知 first-divergence 队列)",
                "expected_side_ref": "../expected_truth.json#target_behavior"})
            cm = data["canvas_semantic_model"]["steps"]
            wjson(out_gen / "canvas_model.json",
                  {"note": "FULL per-step model (disk artifact); representative "
                           "single-step files exported alongside",
                   "n_steps": len(cm),
                   "invariants": data["canvas_invariants"],
                   "steps": cm})
            # representative single steps + matching raw snapshots
            picks = sorted({1, len(cm) // 2, len(cm) - 1})
            raw_steps = None
            sess_gen = ac_src / "generated" / "canvas-export"
            for i in picks:
                if i < len(cm):
                    wjson(out_gen / f"canvas_model.step{cm[i]['step']}.json", cm[i])
            # raw serialized step for those picks (full renderer payload)
            full = json.loads((sess_gen / "pwncraft_output.json").read_text(encoding="utf-8"))
            for i in picks:
                if i < len(cm):
                    wjson(out_gen / f"snapshot.step{cm[i]['step']}.json",
                          full["replay"]["steps"][i])
        # regression result for this case
        base_dir = AC / "regression" / "baselines" / case
        if base_dir.exists():
            idx = json.loads((base_dir / "index.json").read_text(encoding="utf-8"))
            exps = []
            ep = base_dir / "explanations.json"
            if ep.exists():
                exps = json.loads(ep.read_text(encoding="utf-8"))
            lr = json.loads((AC / "regression" / "last_run.json").read_text(encoding="utf-8"))
            mine = next((r for r in lr if r["case_id"] == case), None)
            wjson(sc / "regression_result.json",
                  {"baseline_versions": idx, "explanations": exps,
                   "latest_regress": mine})

    sample(LAB13, "lab13_hitcontraning_heapcreator_glibc2.23")
    sample(NOTE2, "zctf2016_note2_glibc2.19_py2dialect")

    # ---------------- README_current_status.md
    st = json.loads((AC / "curriculum_state.json").read_text(encoding="utf-8"))
    readme = f"""# PwnCraft Training — Current Status (2026-09-05)

## 训练管线位置
- 识别器源码: pwnbao/features/heapviz (本包 recognizer/ 为近两 cycle 实改模块副本)
- 训练框架: autocorrect/ (loop.py = run/generate/diverge/baseline/regress/explain)
- 语料: heap-corpus/corpus (8 GOLD; provenance 见 corpus/)

## Cycle 历史
| cycle | case | 目标 first divergence | patch | 结果 |
|---|---|---|---|---|
| cycle-0 | babyheap(bootstrap) | — | prompt-sync 负向判断(硬编码式) | **INVALIDATED** (Analyst 污染 + comparator 无证据比对); 归档于 autocorrect/patches/cycle-0-bootstrap-invalidated |
| cycle-1 | lab13 | HELPER_CONTRACT@show SEMANTIC_MATCH/**EVIDENCE_DIVERGED** | PROMPT_SYNC≠OUTPUT_DATA_FLOW 证据分类 (r3) | ACCEPTED (371 tests) |
| cycle-2 | note2 | **EXP_PARSE** (py2 print 方言) | source_compat tokenize 引导改写 (r4) | ACCEPTED (390 tests) |

## 当前识别器修订: recognizer-2026.09-r4

## 已接受规则 (accepted_rules in curriculum_state.json)
1. R-EVIDENCE-PROMPTSYNC-VS-OUTPUT (cycle-1)
2. R-EXP-PY2-PRINT-TOLERANCE (cycle-2)

## 打开的 first divergences (队首优先)
1. lab13 `show` / note2 `shownote`: 调用点级 OUTPUT_DATA_FLOW 缺失 (双 case 共同动机) — cycle-3 目标
2. lab13 TARGET_BEHAVIOR 1:N (create=malloc(0x10)+malloc(size); delete=two free calls)
   ↳ 几何层下游投影已被 CANVAS inv7 结构化捕获 (fastbin 复用块与 top 双重声索, 见 lab13/generated/canvas_model.json invariants)
3. size-only alloc 契约 (babyheap allocate[有提示词] / stkof alloc[无提示词] 两种形状)

## CANVAS_SEMANTIC_MODEL (v1.3 §J, 2026-09-05 新增)
- 导出: recognizer/canvas_model.py; 验证: 3 case, note2/babyheap 全绿, lab13 8×inv7=真实发现(见上)
- 单步模型 ~0.8k tokens, invariant 摘要 ~0.5k/case, 截图路径 ~20-44k/case → 降幅 ~95%

## Generalization 证据
- cycle-1: babyheap free show→delete 自动修复 (不同函数名同数据流)
- cycle-2 probes: wheelofrobots/hacklu 从 SyntaxError→完整识别; stkof(py3) 不变
- probes 详细: autocorrect/regression/probes_cycle-2.json

## 审查要点建议 (给你)
- loop.py cmd_diverge: 确认"一 cycle 一偏差"是否代码化 (layers 顺序 + _halt 即停)
- comparator_v3.py: 六元组 + SEMANTIC_MATCH/EVIDENCE_DIVERGED + EXP_PARSE/TARGET_BEHAVIOR/CANVAS 层
- regression.py: 版本化基线不可覆盖 + explanations sidecar + check_all_versions
- patches/cycle-*/: 每 cycle 的 .pre checkpoint + diff + PATCH.md (revert 路径完整)
"""
    (STAGE / "README_current_status.md").write_text(readme, encoding="utf-8")

    # coverage matrix flat view
    wjson(STAGE / "corpus" / "coverage_matrix.json", {
        "generated": "2026-09-05, from autocorrect/curriculum_state.json",
        "completed_cases": st["completed_cases"],
        "accepted_rules": st["accepted_rules"],
        "coverage": st["coverage"],
        "capability_queue": st["capability_queue"],
    })

    # ---------------- zip
    zip_path = ROOT / "PwnCraft_training_review_2026-09-05.zip"
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(STAGE.rglob("*")):
            if f.is_file():
                z.write(f, f.relative_to(STAGE.parent))
    n = sum(1 for f in STAGE.rglob("*") if f.is_file())
    size_mb = zip_path.stat().st_size / 1024 / 1024
    print(f"== bundle: {n} files, zip {size_mb:.1f} MB -> {zip_path}")


if __name__ == "__main__":
    main()
