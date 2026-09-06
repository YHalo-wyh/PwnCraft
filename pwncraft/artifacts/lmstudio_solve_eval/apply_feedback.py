from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwncraft.features.ai import AIKnowledgeStore, AIProposal, FeedbackRecord, LearnedRule
from pwncraft.features.heapviz import analyze_heap_source

SOURCE_PATH = Path(r"C:/Users/WYH/Desktop/软安决赛/traditional/solve.py")
OUT = Path("artifacts/lmstudio_solve_eval")
MODEL = "qwen3.6-27b"


def rule_id(semantic: str, matcher: dict, output: dict) -> str:
    identity = json.dumps({"semantic": semantic, "matcher": matcher, "output": output}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "rule_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]


def main() -> None:
    source = SOURCE_PATH.read_text(encoding="utf-8")
    source_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
    definitions = [
        {
            "proposal_id": "helper_mapping_add_reviewed",
            "semantic": "alloc",
            "function": "add",
            "roles": ["size", "index"],
            "parameter_names": ["size", "idx"],
            "anchor": "add(size,idx)",
            "decision": "modified",
            "reason": "LM Studio 正确识别 add(size,idx)，人工将 keywords 从形参名校正为空的调用关键字集合。",
        },
        {
            "proposal_id": "helper_mapping_copy_reviewed",
            "semantic": "copy",
            "function": "copy",
            "roles": ["src", "dst", "length"],
            "parameter_names": ["src", "dst", "len"],
            "anchor": "copy(src,dst,len)",
            "decision": "modified",
            "reason": "LM Studio 第二候选因 len 角色不合法被校验器拒绝；按 helper send 顺序校正为 length。",
        },
    ]
    store = AIKnowledgeStore()
    existing = {item.rule_id for item in store.list_rules(include_disabled=True)}
    saved = []
    dataset_rows = []
    for item in definitions:
        start = source.index(item["anchor"])
        end = start + len(item["anchor"])
        helper_mapping = {
            "semantic": item["semantic"],
            "function": item["function"],
            "roles": item["roles"],
            "arity": len(item["roles"]),
            "keywords": [],
            "parameter_names": item["parameter_names"],
        }
        proposal = AIProposal(
            item["proposal_id"],
            "helper_mapping",
            start,
            end,
            item["anchor"],
            confidence=0.98,
            rationale=item["reason"],
            helper_mapping=helper_mapping,
        )
        feedback = FeedbackRecord(
            feedback_id="fb_" + hashlib.sha256((source_hash + item["proposal_id"]).encode()).hexdigest()[:24],
            source_hash=source_hash,
            source_fragment=item["anchor"],
            decision=item["decision"],
            proposal=proposal.to_dict(),
            final_value=proposal.to_dict(),
            model=MODEL,
        )
        stored_feedback = store.add_feedback(feedback, proposal.signature())
        matcher = {
            "function": item["function"],
            "arity": len(item["roles"]),
            "keywords": [],
            "parameter_names": item["parameter_names"],
        }
        output = {"roles": item["roles"]}
        rid = rule_id(item["semantic"], matcher, output)
        learned = LearnedRule(rid, item["semantic"], matcher, output, source="ai-feedback-reviewed")
        if rid not in existing:
            learned = store.save_rule(learned)
            existing.add(rid)
        saved.append({
            "feedback_id": stored_feedback.feedback_id,
            "rule_id": rid,
            "semantic": item["semantic"],
            "function": item["function"],
            "roles": item["roles"],
        })
        dataset_rows.append({
            "input": item["anchor"],
            "decision": item["decision"],
            "proposal": proposal.to_dict(),
            "expected": proposal.to_dict(),
            "model": MODEL,
        })

    learned_rules = [rule.to_dict() for rule in store.list_rules() if rule.rule_id in {item["rule_id"] for item in saved}]
    replay = analyze_heap_source(source, learned_rules=learned_rules)
    learned_add = sum(op.meta.get("learned_rule_id") == saved[0]["rule_id"] for op in replay.operations)
    learned_copy = sum(op.meta.get("learned_rule_id") == saved[1]["rule_id"] for op in replay.operations)
    verification = {
        "knowledge_path": str(store.path),
        "persistent": store.persistent,
        "saved": saved,
        "replay_valid": replay.valid,
        "replay_operations": len(replay.operations),
        "learned_add_operations": learned_add,
        "learned_copy_operations": learned_copy,
    }
    (OUT / "feedback_verification.json").write_text(json.dumps(verification, ensure_ascii=False, indent=2), encoding="utf-8")
    with (OUT / "reviewed_feedback.jsonl").open("w", encoding="utf-8", newline="\n") as stream:
        for row in dataset_rows:
            stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    print(json.dumps(verification, ensure_ascii=False, indent=2))
    if not replay.valid or learned_add < 1 or learned_copy < 1:
        raise SystemExit("learned rules did not replay")


if __name__ == "__main__":
    main()
