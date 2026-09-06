from __future__ import annotations

import argparse
import json

from pwnbao.features.heapviz.benchmark import SemanticBenchmarkRunner, default_benchmark_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run deterministic HeapViz semantic ground truth benchmark")
    parser.add_argument("dataset", nargs="?", default=str(default_benchmark_path()))
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()
    report = SemanticBenchmarkRunner().run_file(args.dataset)
    payload = report.to_dict()
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"cases: {payload['case_count']}")
        for name, value in payload["metrics"].items():
            print(f"{name:34} {value:.2%}")
        for case in payload["cases"]:
            print(f"{'PASS' if case['passed'] else 'FAIL'}  {case['id']}")
            for failure in case["failures"]:
                print(f"      {failure}")
    return 0 if report.whole_case_pass_rate == 1.0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
