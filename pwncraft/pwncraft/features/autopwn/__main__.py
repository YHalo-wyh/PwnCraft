"""CLI for offline AutoPwn MVP. Run execution commands only in a disposable Linux VM."""
import argparse
import json
import sys
from .engine import inspect_target, fuzz_stdin, verify_candidates


def main(argv=None):
    parser = argparse.ArgumentParser(description="PwnCraft offline AutoPwn MVP")
    sub = parser.add_subparsers(dest="mode", required=True)
    p = sub.add_parser("inspect", help="Read ELF header without executing")
    p.add_argument("elf")
    p = sub.add_parser("probe", help="Bounded stdin crash smoke probe (not AFL++)")
    p.add_argument("elf")
    p.add_argument("--out", required=True)
    p.add_argument("--runs", type=int, default=100)
    p.add_argument("--timeout", type=float, default=.6)
    p.add_argument("--execute-untrusted", action="store_true")
    p = sub.add_parser("verify", help="Parallel local EXP script condition checks")
    p.add_argument("elf")
    p.add_argument("--manifest", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--expected-regex", required=True)
    p.add_argument("--workers", type=int, default=3)
    p.add_argument("--replays", type=int, default=2)
    p.add_argument("--timeout", type=float, default=3)
    p.add_argument("--execute-untrusted", action="store_true")
    args = parser.parse_args(argv)
    if args.mode != "inspect" and not args.execute_untrusted:
        parser.error("Execution requires --execute-untrusted in a disposable Linux VM")
    try:
        if args.mode == "inspect":
            report = inspect_target(args.elf)
        elif args.mode == "probe":
            report = fuzz_stdin(args.elf, args.out, count=args.runs, timeout=args.timeout)
        else:
            report = verify_candidates(args.elf, args.manifest, args.out,
                                       expected_regex=args.expected_regex, workers=args.workers,
                                       replays=args.replays, timeout=args.timeout)
    except (ValueError, RuntimeError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
