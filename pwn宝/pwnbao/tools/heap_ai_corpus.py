from __future__ import annotations

import argparse
import json
from pathlib import Path

from pwnbao.features.ai import (
    AIKnowledgeStore,
    AIProviderConfig,
    CorpusEvaluator,
    CorpusManifest,
    OpenAICompatibleProvider,
    ProviderError,
)


DEFAULT_MODEL = "qwen3-coder-30b-a3b-instruct"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the auditable pwnbao Heap AI corpus")
    parser.add_argument("manifest", type=Path, help="corpus manifest JSON")
    parser.add_argument("--output", type=Path, default=Path("artifacts/heap_ai_corpus/latest"))
    parser.add_argument("--knowledge", type=Path, default=None)
    parser.add_argument("--split", action="append", choices=("train", "dev", "holdout"))
    parser.add_argument("--case", dest="case_ids", action="append", help="evaluate only this case_id; repeatable")
    parser.add_argument("--allow-network", action="store_true", help="download hash-locked public sources")
    parser.add_argument("--with-ai", action="store_true", help="call the configured Qwen Coder service")
    parser.add_argument(
        "--auto-review-proven",
        action="store_true",
        help="compile only strict-replay accepted candidates into fixtures/rule evidence",
    )
    parser.add_argument(
        "--promotion-mode",
        choices=("strict", "aggressive", "global-now"),
        default="strict",
        help=(
            "rule promotion policy: strict keeps 2 independent cases + holdout; "
            "aggressive enables strict-replay proven helper rules after one case; "
            "global-now is an explicit one-case global promotion mode"
        ),
    )
    parser.add_argument(
        "--promote-threshold",
        type=int,
        default=None,
        help="override required positive cases for rule promotion",
    )
    parser.add_argument(
        "--promote-without-holdout",
        action="store_true",
        help="do not require holdout evidence before enabling a proven rule",
    )
    parser.add_argument(
        "--promotion-confidence",
        type=float,
        default=None,
        help="override minimum AI confidence after strict replay accepts a candidate",
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:1234/v1")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--context-budget", type=int, default=4096, help="model context budget used for prompt fitting")
    parser.add_argument("--max-input-tokens", type=int, default=3584, help="maximum input tokens allowed per case")
    parser.add_argument("--max-output-tokens", type=int, default=512, help="maximum output tokens requested from the model")
    parser.add_argument("--timeout", type=float, default=180.0, help="per-case model timeout in seconds")
    parser.add_argument("--no-resume", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = CorpusManifest.load(args.manifest)
    knowledge = AIKnowledgeStore(args.knowledge)
    config = AIProviderConfig(
        base_url=args.base_url,
        model=args.model,
        timeout=args.timeout,
        temperature=0.1,
        max_tokens=args.max_output_tokens,
        context_budget_tokens=args.context_budget,
        max_input_tokens=args.max_input_tokens,
        analysis_mode="manual",
        json_prefill=True,
    )
    provider = None
    if args.with_ai:
        provider = OpenAICompatibleProvider(config)
        try:
            models = provider.list_models()
        except ProviderError as error:
            print(json.dumps({"status": "offline", "error": str(error)}, ensure_ascii=False, indent=2))
            return 2
        if config.model not in models:
            print(json.dumps({
                "status": "model_mismatch",
                "expected": config.model,
                "available": list(models),
            }, ensure_ascii=False, indent=2))
            return 2
    evaluator = CorpusEvaluator(knowledge, config, provider)
    summary = evaluator.run(
        manifest,
        args.output,
        allow_network=args.allow_network,
        use_ai=args.with_ai,
        resume=not args.no_resume,
        splits=args.split or ("train", "dev", "holdout"),
        case_ids=args.case_ids,
        auto_review_proven=args.auto_review_proven,
        promotion_mode=args.promotion_mode,
        promote_threshold=args.promote_threshold,
        promote_without_holdout=args.promote_without_holdout,
        promotion_confidence=args.promotion_confidence,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 1 if summary["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
