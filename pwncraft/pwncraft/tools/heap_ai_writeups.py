from __future__ import annotations

import argparse
import json
from pathlib import Path

from pwncraft.features.ai import LocalSourceCorpusScanner, PdfWriteupCorpusScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a local Heap AI corpus from user-owned writeups/sources")
    parser.add_argument("root", type=Path, help="directory containing user-owned PDF writeups or local source tree")
    parser.add_argument("--output", type=Path, default=Path("artifacts/heap_ai_writeups/latest"))
    parser.add_argument("--kind", choices=("auto", "pdf", "local"), default="auto")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    kind = args.kind
    if kind == "auto":
        top_level_pdfs = list(args.root.glob("*.pdf")) if args.root.exists() else []
        source_files = [
            path for path in args.root.rglob("*")
            if path.is_file() and path.suffix.lower() in {".py", ".md", ".txt"}
        ] if args.root.exists() else []
        kind = "pdf" if top_level_pdfs and not source_files else "local"
    scanner = PdfWriteupCorpusScanner() if kind == "pdf" else LocalSourceCorpusScanner()
    result = scanner.scan(args.root, args.output)
    print(json.dumps(result["summary"], ensure_ascii=False, indent=2))
    extra = {"manifest": result["manifest"]}
    if "prompt_guidance" in result:
        extra["prompt_guidance"] = result["prompt_guidance"]
    print(json.dumps(extra, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
