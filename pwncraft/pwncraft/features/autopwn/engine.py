"""Offline AutoPwn MVP: ELF inspection, bounded stdin probes, EXP candidate checking.

No cloud/LLM required. Execution is intentionally OPT-IN. Process limits and
temporary working directories are NOT a sandbox; use a disposable Linux VM.
"""
from __future__ import annotations

from concurrent.futures import CancelledError, ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import random
import re
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time


@dataclass(frozen=True)
class TargetInfo:
    path: str
    sha256: str
    architecture: str
    bits: int
    endian: str
    kind: str
    executable: bool


def inspect_target(target: str | Path) -> dict:
    """Read-only ELF recognition: never invoke an unknown executable."""
    path = Path(target).expanduser().resolve(strict=True)
    if not path.is_file():
        raise ValueError("Target must be a regular file")
    with path.open("rb") as stream:
        header = stream.read(64)
    if len(header) < 20 or header[:4] != b"\x7fELF":
        raise ValueError("Not an ELF file")
    if header[4] not in (1, 2) or header[5] not in (1, 2):
        raise ValueError("Malformed ELF header")
    endian = "little" if header[5] == 1 else "big"
    elf_type, machine = struct.unpack_from(("<" if endian == "little" else ">") + "HH", header, 16)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return asdict(TargetInfo(
        str(path), digest.hexdigest(),
        {3: "i386", 8: "mips", 40: "arm", 62: "amd64", 183: "aarch64"}.get(machine, f"machine-{machine}"),
        32 if header[4] == 1 else 64, endian,
        {1: "relocatable", 2: "executable", 3: "shared/PIE", 4: "core"}.get(elf_type, str(elf_type)),
        os.access(path, os.X_OK)))


def _kill_group(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass


def run_process(argv: list[str], *, cwd: Path, input_data: bytes = b"",
                timeout: float = 1.0, cancel: threading.Event | None = None) -> dict:
    """Bound execution and capture output; this is not a security boundary."""
    if not argv or not (0.05 <= timeout <= 120):
        raise ValueError("Invalid process command or timeout")
    started = time.monotonic()
    process = subprocess.Popen(
        argv, cwd=str(cwd), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, start_new_session=True)
    output: dict = {}
    done = threading.Event()

    def collect() -> None:
        try:
            output["stdout"], output["stderr"] = process.communicate(input_data)
        except Exception as exc:
            output["error"] = str(exc)
        finally:
            done.set()

    threading.Thread(target=collect, daemon=True).start()
    timed_out = cancelled = False
    try:
        while not done.wait(0.05):
            if cancel is not None and cancel.is_set():
                cancelled = True
                break
            if time.monotonic() - started >= timeout:
                timed_out = True
                break
        if timed_out or cancelled:
            _kill_group(process)
            done.wait(1.0)
    finally:
        _kill_group(process)
    if output.get("error"):
        raise OSError(output["error"])
    return {
        "returncode": process.poll(),
        "stdout": output.get("stdout", b"")[:32768].decode("utf-8", "replace"),
        "stderr": output.get("stderr", b"")[:32768].decode("utf-8", "replace"),
        "timed_out": timed_out,
        "cancelled": cancelled,
        "duration_seconds": round(time.monotonic() - started, 4),
    }


def fuzz_cases(count: int, *, max_input: int = 4096, seed: int = 1337):
    """Small deterministic stdin smoke corpus, NOT AFL++ coverage-guided fuzzing."""
    if not (1 <= count <= 10000 and 1 <= max_input <= 65536):
        raise ValueError("Probe budget out of range")
    rng = random.Random(seed)
    basic = [b"", b"0\n", b"1\n", b"-1\n", b"%p." * 64,
             b"1\n" + b"A" * 128 + b"\n", b"2\n" + b"B" * 1024 + b"\n"]
    sizes = [0, 1, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096]
    for i in range(count):
        if i < len(basic):
            sample = basic[i]
        else:
            size = min(sizes[i % len(sizes)], max_input)
            sample = (rng.choice([b"A", b"\x00", b"\xff", b"\n", b"01234567"]) * (size + 1))[:size]
            if i % 5 == 0:
                sample = bytes(rng.randrange(256) for _ in range(size))
        yield sample[:max_input]


def fuzz_stdin(target: str | Path, output: str | Path, *, count: int = 100,
               timeout: float = 0.6, max_input: int = 4096) -> dict:
    if os.name != "posix":
        raise RuntimeError("Local ELF execution requires an isolated Linux environment")
    info = inspect_target(target)
    if not info["executable"]:
        raise ValueError("ELF is not executable")
    folder = Path(output).resolve()
    folder.mkdir(parents=True, exist_ok=True)
    crashes, seen, timeouts, errors = [], set(), 0, 0
    with tempfile.TemporaryDirectory(prefix="pwncraft-probe-") as work:
        for index, sample in enumerate(fuzz_cases(count, max_input=max_input)):
            try:
                first = run_process([info["path"]], cwd=Path(work), input_data=sample, timeout=timeout)
            except OSError:
                errors += 1
                continue
            timeouts += int(first["timed_out"])
            code = first["returncode"]
            if code is None or code >= 0 or first["timed_out"]:
                continue
            signature = f"signal:{-code}"
            if signature in seen:
                continue
            seen.add(signature)
            try:
                second = run_process([info["path"]], cwd=Path(work), input_data=sample, timeout=timeout)
                reproduced = second["returncode"] == code and not second["timed_out"]
            except OSError:
                reproduced = False
            name = f"crash_{index:05d}_signal{-code}.bin"
            (folder / name).write_bytes(sample)
            crashes.append({"input_file": name, "signal": -code, "reproduced": reproduced,
                            "input_sha256": hashlib.sha256(sample).hexdigest()})
    result = {"target": info, "mode": "bounded-stdin-smoke-probe", "tested": count,
              "timeouts": timeouts, "launch_errors": errors, "crashes": crashes,
              "limitations": ["NOT coverage-guided AFL++", "stdin only",
                              "Crash does not prove control flow or exploitability",
                              "No operating-system sandbox"]}
    (folder / "fuzz-report.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), "utf-8")
    return result


def read_candidates(manifest: str | Path) -> list[dict]:
    path = Path(manifest).resolve(strict=True)
    document = json.loads(path.read_text("utf-8"))
    items = document.get("candidates")
    if not isinstance(items, list) or not items or len(items) > 256:
        raise ValueError("Manifest must contain 1-256 candidates")
    candidates = []
    for item in items:
        script = (path.parent / str(item["script"])).resolve(strict=True)
        if script.suffix != ".py" or not script.is_file():
            raise ValueError("Candidate must be an existing Python script")
        candidates.append({"name": str(item["name"]), "script": str(script),
                           "priority": int(item.get("priority", 0))})
    if len({item["name"] for item in candidates}) != len(candidates):
        raise ValueError("Duplicate candidate names")
    return sorted(candidates, key=lambda item: (-item["priority"], item["name"]))


def _check_candidate(candidate: dict, target: str, expression: re.Pattern,
                     cancel: threading.Event, timeout: float) -> dict:
    try:
        with tempfile.TemporaryDirectory(prefix="pwncraft-exp-") as work:
            run = run_process([sys.executable, candidate["script"], target],
                              cwd=Path(work), timeout=timeout, cancel=cancel)
        matched = (run["returncode"] == 0 and not run["timed_out"]
                   and not run["cancelled"] and bool(expression.search(run["stdout"])))
        return {"candidate": candidate["name"], "script": candidate["script"],
                "condition_met": matched, "run": run}
    except OSError as exc:
        return {"candidate": candidate["name"], "script": candidate["script"],
                "condition_met": False, "error": str(exc)}


def verify_candidates(target: str | Path, manifest: str | Path, output: str | Path, *,
                      expected_regex: str, workers: int = 3, timeout: float = 3.0,
                      replays: int = 2) -> dict:
    """First matching script wins; matching stdout is NOT independent exploit proof."""
    if os.name != "posix":
        raise RuntimeError("EXP execution requires an isolated Linux environment")
    info = inspect_target(target)
    candidates = read_candidates(manifest)
    if not (1 <= workers <= 16 and 0 <= replays <= 10):
        raise ValueError("Workers/replays out of range")
    if not expected_regex or len(expected_regex) > 1024:
        raise ValueError("A bounded expected-regex is required")
    expression = re.compile(expected_regex)
    cancel = threading.Event()
    results, winner, repeat = [], None, []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_check_candidate, item, info["path"], expression, cancel, timeout): item
                   for item in candidates}
        for future in as_completed(futures):
            try:
                outcome = future.result()
            except CancelledError:
                item = futures[future]
                outcome = {"candidate": item["name"], "script": item["script"],
                           "condition_met": False, "cancelled": True}
            results.append(outcome)
            if outcome["condition_met"] and winner is None:
                winner = outcome["candidate"]
                cancel.set()
                for pending in futures:
                    pending.cancel()
    if winner:
        chosen = next(item for item in candidates if item["name"] == winner)
        for _ in range(replays):
            repeat.append(_check_candidate(chosen, info["path"], expression, threading.Event(), timeout))
    report = {"target": info, "checker": "caller-supplied-stdout-regex",
              "warning": "A script can print a matching string without exploiting the ELF.",
              "winner": winner, "replay_condition_met": bool(winner) and all(x["condition_met"] for x in repeat),
              "checks": results, "replays": repeat}
    folder = Path(output).resolve()
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "candidate-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), "utf-8")
    return report
