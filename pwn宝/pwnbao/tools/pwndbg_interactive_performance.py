from __future__ import annotations

import json
import math
import os
from pathlib import Path
import select
import signal
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "artifacts/ui_audit_v013/pwndbg_interactive_performance.json"
PROMPT = b"pwndbg> "


def _stats(name: str, values: list[float]) -> dict[str, object]:
    ordered = sorted(values)
    p95 = ordered[max(0, math.ceil(len(ordered) * 0.95) - 1)]
    return {
        "name": name,
        "count": len(ordered),
        "average_ms": round(sum(ordered) / len(ordered), 3),
        "p95_ms": round(p95, 3),
        "maximum_ms": round(ordered[-1], 3),
    }


class _PromptSession:
    def __init__(self, target: Path, *, relay: bool):
        import pty

        launcher = ROOT / "third_party/pwndbg-mogai/launcher.sh"
        base = [
            "sh", str(launcher), "--quiet", "-nx", str(target),
            "-ex", "set debuginfod enabled off",
            "-ex", "set pagination off",
            "-ex", "set confirm off",
            "-ex", "start",
        ]
        environment = os.environ.copy()
        environment.update(TERM="xterm-256color", COLORTERM="truecolor", PWNBAO_BRIDGE="0")
        environment.pop("NO_COLOR", None)
        self.relay = relay
        self.buffer = bytearray()
        self.transcript = bytearray()
        self.process = None
        self.pid = 0
        if relay:
            command = [
                "python3", str(ROOT / "pwnbao/core/terminal/pty_relay.py"),
                "--rows", "55", "--cols", "150", "--", *base,
            ]
            self.process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=environment,
                bufsize=0,
            )
            assert self.process.stdin is not None and self.process.stdout is not None
            self.read_fd = self.process.stdout.fileno()
            self.write_fd = self.process.stdin.fileno()
        else:
            self.pid, descriptor = pty.fork()
            if self.pid == 0:
                os.execvpe(base[0], base, environment)
            self.read_fd = self.write_fd = descriptor
        self.wait_prompt(35.0)

    def _read_once(self, deadline: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(bytes(self.transcript[-1200:]))
        readable, _, _ = select.select([self.read_fd], [], [], min(0.1, remaining))
        if not readable:
            return
        try:
            payload = os.read(self.read_fd, 65536)
        except OSError as error:
            raise EOFError(bytes(self.transcript[-1200:])) from error
        if not payload:
            raise EOFError(bytes(self.transcript[-1200:]))
        self.buffer.extend(payload)
        self.transcript.extend(payload)

    def wait_prompt(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while PROMPT not in self.buffer:
            self._read_once(deadline)
        end = self.buffer.rfind(PROMPT) + len(PROMPT)
        del self.buffer[:end]

    def command(self, command: str, timeout: float = 20.0) -> float:
        self.buffer.clear()
        started = time.perf_counter()
        os.write(self.write_fd, command.encode("utf-8") + b"\r")
        self.wait_prompt(timeout)
        return (time.perf_counter() - started) * 1000.0

    def close(self) -> None:
        try:
            os.write(self.write_fd, b"quit\r")
        except OSError:
            pass
        if self.process is not None:
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        elif self.pid:
            try:
                os.kill(self.pid, signal.SIGHUP)
            except OSError:
                pass


def _compile_probe(directory: Path) -> Path:
    source = directory / "pwnbao_perf.c"
    target = directory / "pwnbao_perf"
    source.write_text(
        "#include <stdlib.h>\n"
        "volatile unsigned long sink;\n"
        "__attribute__((noinline)) static unsigned long work(unsigned long x){return x*33+7;}\n"
        "int main(void){void*p=malloc(0x40);for(unsigned long i=0;i<10000;i++)sink+=work(i);free(p);return 0;}\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["cc", "-g", "-O0", "-fno-omit-frame-pointer", str(source), "-o", str(target)],
        check=True,
        capture_output=True,
    )
    return target


def _run_mode(target: Path, name: str, *, relay: bool) -> list[dict[str, object]]:
    session = _PromptSession(target, relay=relay)
    reports = []
    try:
        for command, count in (
            ("ni", 100),
            ("si", 50),
            ("telescope $rsp 8", 3),
            ("vmmap", 3),
            ("bins", 3),
        ):
            values = [session.command(command) for _ in range(count)]
            reports.append(_stats(f"{name}_{command.split()[0]}_{count}", values))
        (OUTPUT.parent / f"{name}.ansi").write_bytes(session.transcript)
    finally:
        session.close()
    return reports


def run() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="pwnbao-pwndbg-perf-") as temporary:
        target = _compile_probe(Path(temporary))
        results = _run_mode(target, "standalone_pty", relay=False)
        results.extend(_run_mode(target, "embedded_relay_pty", relay=True))
    report = {"version": "2026.07.29-pwndbg-mogai.16", "results": results}
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


def main() -> int:
    print(json.dumps(run(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
