"""Deposit generated artifacts into ``review_queue`` (协议：生成物先进评审区).

Nothing here is trainable by default: the manifest carries
``training.trainable=false`` until a reviewer promotes the case through the
existing intake/splits gates.  The layout mirrors the corpus review queue:
``<root>/<case_id>/{manifest.json, ...}``.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Mapping, Sequence

from pwncraft import APP_VERSION

from .facts import TargetFacts
from .graph import PrimitiveGraph
from .render import RenderedExp
from .strategy import ExploitStrategy

REVIEW_SCHEMA_VERSION = "1.0"
GENERATOR = "pwncraft.features.synth"


def _sha256_text(text: str) -> str:
    return hashlib.sha256(str(text or "").encode("utf-8")).hexdigest()


def synth_case_id(binary_sha256: str, strategy_id: str, exp_source: str) -> str:
    """确定性 case_id：同二进制 + 同策略 + 同源码 = 同一题（重复导出可对齐）。"""
    digest = _sha256_text(f"{binary_sha256}|{strategy_id}|{exp_source}")
    return "synth-" + digest[:20]


def _plan_markdown(facts: TargetFacts, strategy: ExploitStrategy, rendered: RenderedExp | None,
                   verdict: Mapping[str, object],
                   verification: Mapping[str, object] | None = None) -> str:
    lines = [f"# 合成计划 · {strategy.id}", "",
             f"- 策略：{strategy.name}（status={strategy.status}）",
             f"- 目标：`{facts.path}`  sha256=`{facts.sha256}`",
             f"- 保护：PIE={facts.security.get('PIE')} NX={facts.security.get('NX')} "
             f"CANARY={facts.security.get('CANARY')} RELRO={facts.security.get('RELRO')}",
             f"- 往返自检：{verdict.get('verdict')}（ERROR {verdict.get('error_count')} 条）",
             f"- 运行时验证：{(verification or {}).get('status') or 'NOT_RUN'}"
             f"（{(verification or {}).get('summary') or '未执行'}）",
             "", "## 步骤"]
    lines.extend(f"{index}. {step}" for index, step in enumerate(strategy.steps, 1))
    if strategy.missing:
        lines.extend(["", "## 缺口"] + [f"- {item}" for item in strategy.missing])
    if strategy.evidence:
        lines.extend(["", "## 证据"] + [f"- {item}" for item in strategy.evidence])
    if rendered is not None and rendered.unresolved:
        lines.extend(["", "## 未解析常量"] + [f"- {item}" for item in rendered.unresolved])
    if rendered is None:
        lines.extend(["", "## 说明",
                      "- 未产生候选策略：静态事实不足（见 gap 节点），本 case 作为负样本沉淀。"])
    lines.extend(["", "## 纪律",
                  "- 生成物为 DERIVED 级别：只能作为骨架，必须人工复核。",
                  "- 未通过运行时验证前，`trainable=false`，不得进入训练/评测 split。"])
    return "\n".join(lines) + "\n"


def deposit_case(
    dest_root: str | Path,
    *,
    facts: TargetFacts,
    graph: PrimitiveGraph,
    strategies: Sequence[ExploitStrategy],
    rendered: RenderedExp | None,
    verdict: Mapping[str, object],
    verification: Mapping[str, object] | None = None,
) -> dict:
    root = Path(dest_root)
    source = rendered.source if rendered is not None else ""
    strategy_id = rendered.strategy if rendered is not None else "none"
    case_id = synth_case_id(facts.sha256, strategy_id, source)
    case_dir = root / case_id
    case_dir.mkdir(parents=True, exist_ok=True)

    exp_sha = _sha256_text(source)
    manifest = {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "case_id": case_id,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "generator": {"module": GENERATOR, "app_version": APP_VERSION},
        "target": {"path": facts.path, "sha256": facts.sha256,
                   "arch": facts.architecture, "bits": facts.bits,
                   "security": dict(facts.security)},
        "strategy": {"id": strategy_id, "status": next(
            (item.status for item in strategies if item.id == strategy_id),
            "none" if rendered is None else "unknown")},
        "exp": None if rendered is None else
        {"sha256": exp_sha, "unresolved": list(rendered.unresolved)},
        "audit": {"verdict": verdict.get("verdict"),
                  "error_count": verdict.get("error_count"),
                  "diagnostic_count": verdict.get("diagnostic_count")},
        "verification": dict(verification) if verification is not None else None,
        "provenance": "DERIVED",
        "training": {"trainable": False,
                     "runtime_verified": bool((verification or {}).get("status") == "VERIFIED_SHELL"),
                     "gate": "review_queue → 人工评审 → autocorrect intake/splits 注册"},
    }
    if rendered is None:
        exp_text = ("# NO_STRATEGY: 静态事实不足，未产生候选策略。\n"
                    "# 检测结果（facts/graph/strategies）已随本 case 沉淀；\n"
                    "# 补齐运行时候选证据后可重新运行合成。\n")
    else:
        exp_text = rendered.source if rendered.source.endswith("\n") else rendered.source + "\n"
    payloads: dict[str, str] = {
        "manifest.json": json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        "facts.json": json.dumps(facts.to_dict(), ensure_ascii=False, indent=2) + "\n",
        "graph.json": json.dumps(graph.to_dict(), ensure_ascii=False, indent=2) + "\n",
        "strategies.json": json.dumps([item.to_dict() for item in strategies],
                                      ensure_ascii=False, indent=2) + "\n",
        "audit.json": json.dumps(dict(verdict), ensure_ascii=False, indent=2) + "\n",
        "exp.py": exp_text,
        "plan.md": _plan_markdown(facts, next(
            (item for item in strategies if item.id == strategy_id),
            ExploitStrategy(id=strategy_id, name=strategy_id,
                            status="none" if rendered is None else "unknown")), rendered, verdict,
            verification),
    }
    written: list[str] = []
    for name, text in payloads.items():
        (case_dir / name).write_text(text, encoding="utf-8")
        written.append(str(case_dir / name))
    return {"case_id": case_id, "dir": str(case_dir), "files": written,
            "exp_sha256": exp_sha, "trainable": False}
