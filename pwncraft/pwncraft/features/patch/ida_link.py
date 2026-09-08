"""IDA 联动 — 通过本机 IDA-CLI（idalib, IDA Pro 9.0+）驱动真实 IDA 数据库。

架构：桥进程（python310）零 import 依赖；按需 spawn 一个安装了 ida_cli +
idalib 的解释器（默认探测 IDA_CLI_PYTHON / D:\\python\\python.exe 等 3.11+），
驱动脚本持有 AgentSession 常驻复用，行 JSON 协议交互。驱动脚本按 ze-mu-zhou
IDACLI 的 AgentSession 语义调用 ai helpers（pwn_overview / functions /
decompile / disasm / patch_bytes）。

Keypatch 式双向联动：文件侧补丁应用后可把字节同步 patch 进 IDA 数据库，
IDA 视图与磁盘补丁保持一致。
"""
from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
from pathlib import Path

_DRIVER_SOURCE = r'''
import json, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')
from ida_cli.agent_bridge import AgentSession

session = None
target = None

def ensure(target_path):
    global session, target
    if session is not None and target == target_path:
        return
    if session is not None:
        try:
            session.__exit__(None, None, None)
        except Exception:
            pass
        session = None
    session = AgentSession.start(target_path, require_ida=True)
    session.__enter__()
    target = target_path

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        req = json.loads(line)
        op = req.get('op')
        if op == 'probe':
            ensure(req['target'])
            backend = session.probe_backend(require_ida=True)
            out = {'ok': True, 'result': backend}
        elif op == 'exec':
            ensure(req['target'])
            result = session.result(req['code'], request_id=str(req.get('rid') or 'r'),
                                    timeout_s=float(req.get('timeout') or 180))
            out = {'ok': True, 'result': result}
        elif op == 'close':
            break
        else:
            out = {'ok': False, 'error': f'未知 op: {op}'}
    except Exception as error:
        out = {'ok': False, 'error': f'{type(error).__name__}: {error}'}
    print(json.dumps(out, ensure_ascii=False, default=str), flush=True)
if session is not None:
    try:
        session.__exit__(None, None, None)
    except Exception:
        pass
'''

_CANDIDATE_PYTHONS = (
    r"D:\python\python.exe",
    r"C:\Python311\python.exe",
    r"C:\Python312\python.exe",
    r"C:\Python313\python.exe",
)


class IdaLinkError(RuntimeError):
    """IDA 联动不可用或调用失败。"""


class IdaCliLink:
    """一个常驻驱动进程 + 按 target 复用的 AgentSession。"""

    def __init__(self) -> None:
        self._proc: subprocess.Popen | None = None
        self._lines: "queue.Queue[str]" = queue.Queue()
        self._lock = threading.Lock()
        self._python: str | None = None
        self._target: str | None = None

    # -- 解释器探测 ----------------------------------------------------
    def python_exe(self, *, refresh: bool = False) -> str | None:
        if self._python and not refresh:
            return self._python
        candidates = []
        env_python = os.environ.get("IDA_CLI_PYTHON")
        if env_python:
            candidates.append(env_python)
        candidates.extend(_CANDIDATE_PYTHONS)
        for exe in candidates:
            if not Path(exe).is_file():
                continue
            try:
                probe = subprocess.run(
                    [exe, "-B", "-c", "import ida_cli, idapro"],
                    capture_output=True, timeout=30,
                    stdin=subprocess.DEVNULL)
                if probe.returncode == 0:
                    self._python = exe
                    return exe
            except (OSError, subprocess.TimeoutExpired):
                continue
        return None

    # -- 驱动进程 ------------------------------------------------------
    def _ensure_proc(self) -> subprocess.Popen:
        if self._proc is not None and self._proc.poll() is None:
            return self._proc
        python = self.python_exe()
        if not python:
            raise IdaLinkError(
                "未找到安装了 IDA-CLI 的 Python（需要 3.11+ 且已装 ida_cli 与 "
                "idapro/idalib）。安装：IDA9.4 目录 idalib\\python 下 "
                "py-activate-idalib.py -d <IDA目录>，再 pip install -e "
                "<IDACLI 仓库>；或设置 IDA_CLI_PYTHON 指向该解释器")
        self._proc = subprocess.Popen(
            [python, "-B", "-c", _DRIVER_SOURCE],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, encoding="utf-8",
            errors="replace", bufsize=1)
        self._lines = queue.Queue()

        def pump(stream, sink):
            try:
                for line in stream:
                    sink.put(line)
            except Exception:
                pass

        threading.Thread(target=pump, args=(self._proc.stdout, self._lines), daemon=True).start()
        threading.Thread(target=pump, args=(self._proc.stderr, queue.Queue()), daemon=True).start()
        return self._proc

    def _request(self, payload: dict, timeout: float = 200.0) -> dict:
        with self._lock:
            proc = self._ensure_proc()
            assert proc.stdin is not None
            proc.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
            proc.stdin.flush()
            try:
                line = self._lines.get(timeout=timeout)
            except queue.Empty as error:
                raise IdaLinkError(f"IDA 驱动响应超时（{timeout:.0f}s）") from error
        try:
            reply = json.loads(line)
        except (TypeError, ValueError) as error:
            raise IdaLinkError(f"IDA 驱动返回异常：{line[:200]!r}") from error
        if not reply.get("ok"):
            raise IdaLinkError(str(reply.get("error") or "IDA 驱动调用失败"))
        return reply.get("result")

    # -- 业务操作 ------------------------------------------------------
    def status(self, target: str | Path) -> dict:
        python = self.python_exe()
        if not python:
            return {"available": False, "python": "",
                    "hint": "未找到 IDA-CLI Python（3.11+，含 ida_cli + idapro）"}
        backend = self._request({"op": "probe", "target": str(target)}, timeout=200)
        self._target = str(target)
        return {"available": True, "python": python, "backend": backend}

    def _exec(self, target: str | Path, code: str, *, timeout: float = 200.0):
        return self._request({"op": "exec", "target": str(target), "code": code,
                              "timeout": timeout, "rid": "pwncraft"}, timeout=timeout + 20)

    def overview(self, target: str | Path) -> dict:
        return self._exec(target, "__result__ = ai.pwn_overview()")

    def functions(self, target: str | Path) -> list:
        return self._exec(target, "__result__ = ai.functions()", timeout=120)

    def disasm(self, target: str | Path, function: str, limit: int = 64) -> list:
        call = f"__result__ = ai.disasm({json.dumps(function, ensure_ascii=False)}, {int(limit)})"
        return self._exec(target, call, timeout=120)

    def decompile(self, target: str | Path, function: str) -> dict:
        call = f"__result__ = ai.decompile({json.dumps(function, ensure_ascii=False)})"
        return self._exec(target, call, timeout=300)

    def patch_bytes(self, target: str | Path, ea_or_name, hex_bytes: str) -> dict:
        locator = json.dumps(ea_or_name) if isinstance(ea_or_name, str) else int(ea_or_name)
        call = (f"__result__ = ai.patch_bytes({locator}, "
                f"bytes.fromhex({json.dumps(hex_bytes.replace(' ', ''))}))")
        return self._exec(target, call, timeout=120)

    def close(self) -> None:
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        try:
            proc.stdin.write(json.dumps({"op": "close"}) + "\n")
            proc.stdin.flush()
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
