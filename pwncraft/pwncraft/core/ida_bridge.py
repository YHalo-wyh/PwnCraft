"""IDA Bridge — stdlib MCP client for ida-pro-mcp / idalib-mcp.

Connects PwnCraft to IDA Pro through the standard MCP JSON-RPC protocol
without any SDK dependency (the project is stdlib-only). Two transports:

  * ``IdalibStdioTransport`` — spawns ``idalib-mcp --stdio [binary]``
    (headless; the recommended mode for batch analysis and training).
  * ``IdaGuiHttpTransport``  — POSTs to the GUI plugin endpoint
    (default ``http://127.0.0.1:13337/mcp``).

Protocol notes (MCP spec): stdio = newline-delimited JSON-RPC over the
child's stdin/stdout; the client performs the ``initialize`` handshake,
sends ``notifications/initialized``, then uses ``tools/list`` and
``tools/call``.  Tool results arrive as ``{content: [{type: text, ...}],
isError?}``.

Nothing here mutates the analyzed binary: all calls are QUERY tools
(decompile/disasm/imports/xrefs/...).  ``analyze_binary`` is the one-shot
convenience used by the bridge RPCs and the binary-evidence extractor.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import tempfile
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MCP_PROTOCOL_VERSION = "2025-03-26"
_DEFAULT_HTTP_HOST = "127.0.0.1"
_DEFAULT_HTTP_PORT = 13337
_REQUEST_TIMEOUT = 120.0


class McpError(RuntimeError):
    """Raised for transport, protocol, or tool errors."""


# ---------------------------------------------------------------- transports

class _StdioTransport:
    """Newline-delimited JSON-RPC over a child process (idalib-mcp --stdio)."""

    name = "stdio"

    def __init__(self, argv: list[str], cwd: str | None = None):
        self._argv = [str(a) for a in argv]
        self._cwd = cwd
        self._proc: subprocess.Popen | None = None
        self._lock = threading.Lock()
        self._pending: dict[int | str, dict] = {}
        self._reader: threading.Thread | None = None

    def start(self) -> None:
        if self._proc is not None:
            return
        try:
            self._proc = subprocess.Popen(
                self._argv,
                cwd=self._cwd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except OSError as error:
            raise McpError(f"无法启动 {self._argv[0]}: {error}") from error
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()

    def _pump(self) -> None:
        proc = self._proc
        assert proc is not None and proc.stdout is not None
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except ValueError:
                continue  # server chatter that is not JSON-RPC
            if not isinstance(message, dict):
                continue
            if message.get("id") is None:
                continue  # notification (e.g. server progress)
            with self._lock:
                waiter = self._pending.pop(message["id"], None)
            if waiter is not None:
                waiter.append(message)

    def send(self, payload: dict, timeout: float) -> dict:
        if self._proc is None or self._proc.stdin is None:
            raise McpError("stdio transport 未启动")
        request_id = uuid.uuid4().hex[:12]
        payload = dict(payload, id=request_id)
        waiter: list[dict] = []
        with self._lock:
            self._pending[request_id] = waiter
            try:
                self._proc.stdin.write(json.dumps(payload) + "\n")
                self._proc.stdin.flush()
            except OSError as error:
                self._pending.pop(request_id, None)
                raise McpError(f"stdio 写入失败: {error}") from error
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if waiter:
                response = waiter[0]
                if "error" in response:
                    raise McpError(f"MCP error: {response['error']}")
                return response.get("result") or {}
            if self._proc.poll() is not None:
                stderr = ""
                if self._proc.stderr is not None:
                    try:
                        stderr = self._proc.stderr.read()[:400]
                    except Exception:
                        pass
                raise McpError(f"idalib-mcp 进程退出 (code={self._proc.returncode}) {stderr}")
            time.sleep(0.02)
        with self._lock:
            self._pending.pop(request_id, None)
        raise McpError(f"MCP 请求超时 ({timeout:.0f}s): {payload.get('method')}")

    def notify(self, payload: dict) -> None:
        """MCP notification: no id, no response expected."""
        if self._proc is None or self._proc.stdin is None:
            return
        try:
            self._proc.stdin.write(json.dumps(payload) + "\n")
            self._proc.stdin.flush()
        except OSError:
            pass

    def stop(self) -> None:
        if self._proc is None:
            return
        try:
            if self._proc.stdin is not None:
                self._proc.stdin.close()
        except OSError:
            pass
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
        self._proc = None


class _HttpTransport:
    """POST JSON-RPC to the ida-pro-mcp GUI plugin endpoint."""

    name = "http"

    def __init__(self, host: str = _DEFAULT_HTTP_HOST, port: int = _DEFAULT_HTTP_PORT,
                 path: str = "/mcp"):
        self._host, self._port, self._path = host, int(port), path

    def start(self) -> None:
        self.ping()  # fail fast when the GUI plugin is not listening

    def stop(self) -> None:
        pass

    def send(self, payload: dict, timeout: float) -> dict:
        request_id = payload.get("id", 1)
        try:
            connection = http.client.HTTPConnection(self._host, self._port,
                                                    timeout=timeout)
            body = json.dumps(payload)
            connection.request("POST", self._path, body=body,
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            raw = response.read().decode("utf-8", "replace")
            status = response.status
            connection.close()
        except OSError as error:
            raise McpError(f"HTTP 传输失败 ({self._host}:{self._port}): {error}") from error
        if status != 200:
            raise McpError(f"HTTP {status}: {raw[:200]}")
        # Some servers answer with SSE frames; accept both plain JSON and
        # `data:` lines, preferring the message whose id matches.
        candidates: list[dict] = []
        if raw.lstrip().startswith("{"):
            try:
                candidates.append(json.loads(raw))
            except ValueError:
                pass
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                try:
                    candidates.append(json.loads(line[5:].strip()))
                except ValueError:
                    pass
        for message in candidates:
            if isinstance(message, dict) and message.get("id") == request_id:
                if "error" in message:
                    raise McpError(f"MCP error: {message['error']}")
                return message.get("result") or {}
        raise McpError("HTTP 响应中没有匹配 id 的 JSON-RPC 结果")

    def ping(self) -> None:
        self.send({"jsonrpc": "2.0", "id": 0, "method": "ping"}, timeout=5.0)


# ---------------------------------------------------------------- client

@dataclass
class IdaToolResult:
    tool: str
    text: str = ""
    structured: Any = None
    is_error: bool = False


class IdaMcpClient:
    """Session over one transport: handshake + typed tool-call helpers.

    All helpers are QUERY-side; nothing here patches the analyzed binary.
    """

    def __init__(self, transport):
        self._transport = transport
        self._server_info: dict = {}
        self._tools: list[dict] = []
        self._initialized = False

    # -- lifecycle
    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.close()

    def start(self) -> None:
        self._transport.start()
        result = self._transport.send({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "pwncraft-ida-bridge", "version": "1.0"},
            },
        }, timeout=_REQUEST_TIMEOUT)
        self._server_info = result if isinstance(result, dict) else {}
        notifier = getattr(self._transport, "notify", None)
        if notifier is not None:
            notifier({"jsonrpc": "2.0", "method": "notifications/initialized"})
        else:
            self._transport.send({"jsonrpc": "2.0",
                                  "method": "notifications/initialized"},
                                 timeout=15.0)
        listing = self._transport.send({
            "jsonrpc": "2.0", "method": "tools/list", "params": {},
        }, timeout=_REQUEST_TIMEOUT)
        tools = (listing or {}).get("tools") or []
        self._tools = [t.get("name", "") for t in tools if isinstance(t, dict)]
        self._initialized = True

    def close(self) -> None:
        self._transport.stop()
        self._initialized = False

    # -- introspection
    @property
    def server_info(self) -> dict:
        return dict(self._server_info)

    @property
    def tool_names(self) -> list[str]:
        return list(self._tools)

    def has_tool(self, name: str) -> bool:
        return name in self._tools

    # -- raw call
    def call(self, tool: str, arguments: dict | None = None,
             timeout: float = _REQUEST_TIMEOUT) -> IdaToolResult:
        if not self._initialized:
            raise McpError("client 未完成 initialize")
        if self._tools and tool not in self._tools:
            raise McpError(f"IDA server 无工具 {tool} (可用: {', '.join(self._tools[:12])}...)")
        result = self._transport.send({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": tool, "arguments": dict(arguments or {})},
        }, timeout=timeout)
        text_parts: list[str] = []
        structured: Any = None
        is_error = bool((result or {}).get("isError"))
        for item in (result or {}).get("content") or []:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "text":
                text_parts.append(str(item.get("text") or ""))
            elif item.get("type") == "resource":
                text_parts.append(str(item.get("text") or ""))
        raw_structured = (result or {}).get("structuredContent")
        if raw_structured is not None:
            structured = raw_structured
        return IdaToolResult(tool=tool, text="\n".join(text_parts),
                             structured=structured, is_error=is_error)

    def call_json(self, tool: str, arguments: dict | None = None,
                  timeout: float = _REQUEST_TIMEOUT) -> Any:
        """Call a tool and parse its text payload as JSON (falls back to raw)."""
        result = self.call(tool, arguments, timeout=timeout)
        if result.structured is not None:
            return result.structured
        try:
            return json.loads(result.text)
        except ValueError:
            return result.text

    # -- domain helpers (query-only; tolerant to naming across releases)
    def _resolve(self, function: str, timeout: float = 15.0) -> str:
        """Function name or address -> canonical address string."""
        if _looks_addr(function):
            return function.strip()
        try:
            payload = self.call_json("get_function_by_name", {"name": function},
                                     timeout=timeout)
        except McpError:
            return function
        if isinstance(payload, dict):
            return str(payload.get("address") or payload.get("start") or function)
        text = str(payload)
        for token in text.replace(",", " ").split():
            if _looks_addr(token):
                return token
        return function

    def decompile(self, function: str) -> str:
        address = self._resolve(function)
        tool = "decompile_function" if self.has_tool("decompile_function") else "decompile"
        result = self.call(tool, {"address": address})
        return result.text

    def disasm(self, function: str) -> str:
        address = self._resolve(function)
        tool = "disassemble_function" if self.has_tool("disassemble_function") else "disasm"
        key = "start_address" if tool == "disassemble_function" else "address"
        return self.call(tool, {key: address}).text

    def list_funcs(self, page: int = 256) -> list[dict]:
        """Paged function listing (v1.7.x uses offset/count)."""
        tool = "list_functions" if self.has_tool("list_functions") else "list_funcs"
        functions: list[dict] = []
        offset = 0
        while offset < 8192:  # hard safety bound
            payload = self.call_json(tool, {"offset": offset, "count": page},
                                     timeout=60.0)
            batch = _normalize_function_list(payload)
            if not batch:
                break
            functions.extend(batch)
            if len(batch) < page:
                break
            offset += len(batch)
        # de-duplicate by (address, name)
        seen = set()
        unique = []
        for item in functions:
            key = (item.get("address"), item.get("name"))
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)
        return unique

    def imports(self) -> Any:
        if self.has_tool("imports"):
            return self.call_json("imports")
        return None  # v1.7.x has no imports tool; use xrefs_to(plt_name)

    def xrefs_to(self, function: str, timeout: float = 30.0) -> Any:
        tool = "get_xrefs_to" if self.has_tool("get_xrefs_to") else "xrefs_to"
        address = self._resolve(function)
        return self.call_json(tool, {"address": address}, timeout=timeout)

    def callees(self, address: str) -> Any:
        if self.has_tool("callees"):
            return self.call_json("callees", {"address": address})
        return None


def _looks_addr(value: str) -> bool:
    text = str(value).strip().lower()
    return text.startswith("0x") and all(c in "0123456789abcdef" for c in text[2:])


# ---------------------------------------------------------------- doctor

@dataclass
class IdaDoctorReport:
    idalib_mcp: str = ""          # resolved executable path or ""
    ida_install: str = ""         # best-effort IDA install dir
    idalib_python: bool = False   # `import idalib` succeeded in some python
    gui_plugin_port_open: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "idalib_mcp": self.idalib_mcp,
            "ida_install": self.ida_install,
            "idalib_python": self.idalib_python,
            "gui_plugin_port_open": self.gui_plugin_port_open,
            "notes": list(self.notes),
            "ready_headless": bool(self.idalib_mcp),
            "ready_gui": self.gui_plugin_port_open,
        }


def detect_environment(port: int = _DEFAULT_HTTP_PORT) -> IdaDoctorReport:
    """Best-effort environment probe (no IDA startup, fast)."""
    report = IdaDoctorReport()
    exe = shutil.which("idalib-mcp")
    if not exe:
        # uv tool installs land in user scripts
        for candidate in ("idalib-mcp.exe", "idalib-mcp"):
            for base in (Path(os.environ.get("APPDATA", "")) / "Python" / "Scripts",
                         Path.home() / ".local" / "bin",
                         Path(os.environ.get("USERPROFILE", "")) / ".local" / "bin"):
                guess = base / candidate
                if guess.is_file():
                    exe = str(guess)
                    break
            if exe:
                break
    report.idalib_mcp = exe or ""
    if not exe:
        report.notes.append("idalib-mcp 未找到: pip install ida-pro-mcp 后可用 (headless 模式)")

    for base in (Path("C:/Program Files"), Path("C:/Program Files (x86)"),
                 Path.home() / "AppData" / "Local" / "Programs"):
        if not base.is_dir():
            continue
        try:
            entries = [p for p in base.iterdir() if "ida" in p.name.lower()]
        except OSError:
            entries = []
        if entries:
            report.ida_install = str(sorted(entries)[-1])
            break
    if not report.ida_install:
        report.notes.append("未在默认路径找到 IDA 安装目录 (仅影响提示, 不阻塞 idalib-mcp)")

    # idalib activation probe: a python that can import idalib
    for python in ("python", "python3"):
        try:
            probe = subprocess.run(
                [python, "-c", "import idalib"],
                capture_output=True, text=True, timeout=15,
            )
            if probe.returncode == 0:
                report.idalib_python = True
                break
        except (OSError, subprocess.TimeoutExpired):
            continue
    if not report.idalib_python:
        report.notes.append(
            "idalib 未激活: 运行 IDA 目录下的 py-activate-idalib.py "
            "(idalib-mcp 需要)")

    try:
        probe_transport = _HttpTransport(port=port)
        probe_transport.ping()
        report.gui_plugin_port_open = True
    except McpError:
        report.gui_plugin_port_open = False
    return report


# ---------------------------------------------------------------- one-shot analysis

def _idalib_stdio_supported(exe: str) -> bool:
    """Older idalib-mcp releases only expose --host/--port HTTP servers;
    newer ones add --stdio. Probe once via --help."""
    try:
        probe = subprocess.run([exe, "--help"], capture_output=True, text=True,
                               timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return "--stdio" in (probe.stdout + probe.stderr)


class _SseTransport:
    """Legacy MCP HTTP+SSE transport (older ida-pro-mcp releases):
    GET /sse keeps a server→client event stream (carries the POST endpoint
    with a session id AND async tool responses); requests are POSTed to the
    announced endpoint and answered on the stream by matching id."""

    name = "sse"

    def __init__(self, host: str, port: int, sse_path: str = "/sse"):
        self._host, self._port = host, int(port)
        self._sse_path = sse_path
        self._endpoint: str | None = None
        self._pending: dict[Any, dict] = {}
        self._lock = threading.Lock()
        self._reader: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline and self._endpoint is None:
            if self._stop.is_set():
                raise McpError("SSE 读取线程已停止")
            time.sleep(0.1)
        if self._endpoint is None:
            raise McpError(f"SSE 未公布 endpoint ({self._host}:{self._port}{self._sse_path})")

    def stop(self) -> None:
        self._stop.set()

    def _pump(self) -> None:
        try:
            connection = http.client.HTTPConnection(self._host, self._port,
                                                    timeout=300.0)
            connection.request("GET", self._sse_path,
                               headers={"Accept": "text/event-stream"})
            response = connection.getresponse()
            event: dict = {}
            while not self._stop.is_set():
                line = response.fp.readline()
                if not line:
                    break
                text = line.decode("utf-8", "replace").strip()
                if not text:
                    event = {}
                    continue
                if text.startswith("event:"):
                    event["event"] = text[6:].strip()
                elif text.startswith("data:"):
                    event.setdefault("data", []).append(text[5:].strip())
                    if event.get("event") == "endpoint" or text.startswith("data: /"):
                        payload = "".join(event.get("data", []))
                        with self._lock:
                            self._endpoint = payload
                    elif event.get("event") in ("message", ""):
                        payload = "".join(event.get("data", []))
                        try:
                            message = json.loads(payload)
                        except ValueError:
                            continue
                        if isinstance(message, dict) and message.get("id") is not None:
                            with self._lock:
                                self._pending.pop(message["id"], None)
                                self._pending[message["id"]] = message
        except Exception:
            pass  # transport closed or server stopped

    def send(self, payload: dict, timeout: float) -> dict:
        endpoint = self._endpoint
        if not endpoint:
            raise McpError("SSE endpoint 未就绪")
        request_id = payload.get("id", uuid.uuid4().hex[:12])
        body = json.dumps(dict(payload, id=request_id))
        try:
            connection = http.client.HTTPConnection(self._host, self._port,
                                                    timeout=30.0)
            connection.request("POST", endpoint, body=body,
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            response.read()
            connection.close()
            if response.status not in (200, 202):
                raise McpError(f"SSE POST {response.status}")
        except OSError as error:
            raise McpError(f"SSE POST 失败: {error}") from error
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                message = self._pending.pop(request_id, None)
            if message is not None:
                if "error" in message:
                    raise McpError(f"MCP error: {message['error']}")
                return message.get("result") or {}
            time.sleep(0.05)
        raise McpError(f"SSE 响应超时 ({timeout:.0f}s): {payload.get('method')}")

    def notify(self, payload: dict) -> None:
        """MCP notification over SSE: POST without waiting for a response."""
        endpoint = self._endpoint
        if not endpoint:
            return
        try:
            connection = http.client.HTTPConnection(self._host, self._port,
                                                    timeout=10.0)
            body = json.dumps(payload)
            connection.request("POST", endpoint, body=body,
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            response.read()
            connection.close()
        except OSError:
            pass


def _free_port() -> int:
    import socket
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def analyze_binary(binary_path: str | Path, *,
                   idalib_mcp: str | None = None,
                   extra_args: list[str] | None = None,
                   timeout: float = 300.0) -> dict:
    """Headless one-shot: run idalib-mcp against the binary, run the standard
    query battery, return structured facts.

    Transport auto-detection: streamable HTTP (POST /mcp) first, legacy
    HTTP+SSE (/sse) fallback, stdio only for builds advertising --stdio.
    idalib fails on non-ASCII paths, so the binary is staged into an
    ASCII-safe temp dir when needed (copy only; the original is untouched).
    """
    binary = Path(binary_path).resolve()
    if not binary.is_file():
        raise McpError(f"binary 不存在: {binary}")
    exe = idalib_mcp or shutil.which("idalib-mcp")
    if not exe:
        raise McpError("idalib-mcp 不可用 — 见 ida_bridge.detect_environment()")
    extra = [str(a) for a in (extra_args or [])]

    # idalib leaves an unpacked database (id0/id1/id2/nam/til) next to the
    # input; snapshot the directory before/after so we can clean up exactly
    # what THIS run created (the original binary is never touched).
    _IDA_DB_SUFFIXES = (".id0", ".id1", ".id2", ".nam", ".til", ".i64", ".idb")

    def _snapshot_dir() -> set:
        try:
            return {p.name for p in binary.parent.iterdir() if p.is_file()}
        except OSError:
            return set()

    before_files = _snapshot_dir()
    # PROLOGUE GUARD: a crashed/killed idalib run corrupts the unpacked
    # database (id0/id1/...) left next to the input; every later run then
    # hangs or fatals on the stale database. Delete stale unpacked DBs
    # BEFORE spawning so each analysis starts fresh (binary untouched).
    for stale_name in list(before_files):
        if stale_name.lower().endswith(_IDA_DB_SUFFIXES):
            try:
                (binary.parent / stale_name).unlink()
                before_files.discard(stale_name)
            except OSError:
                pass
    server_proc: subprocess.Popen | None = None
    started = time.monotonic()

    if _idalib_stdio_supported(exe):
        argv = [exe, "--stdio", str(binary)] + extra
        transport = _StdioTransport(argv)
    else:
        port = _free_port()
        argv = [exe, str(binary), "--host", "127.0.0.1", "--port", str(port)] + extra
        server_log_path = Path(tempfile.gettempdir()) / "pwncraft-idalib-server.log"
        server_log = open(server_log_path, "wb")
        server_proc = subprocess.Popen(
            argv, stdout=server_log, stderr=server_log,
            # NEVER leave stdout/stderr as unread PIPEs: uvicorn logging
            # fills the Windows pipe buffer (a few KB) and the server then
            # blocks mid-request. Log to a file instead (readable for
            # failure diagnostics).
            # idalib is also picky about the process cwd (hangs when spawned
            # from a non-ASCII directory); anchor it to an ASCII path.
            cwd=tempfile.gettempdir())
        try:
            transport = _wait_http_ready(server_proc=server_proc, port=port,
                                         timeout=min(timeout, 180.0))
        except Exception:
            # never leave an orphan idalib instance behind: it holds the
            # unpacked database AND the license, poisoning every later run
            try:
                server_proc.terminate()
                server_proc.wait(timeout=10)
            except Exception:
                try:
                    server_proc.kill()
                except Exception:
                    pass
            server_log.close()
            raise

    facts: dict[str, Any] = {
        "binary": str(binary),
        "server_log": str(server_log_path),
        "transport": getattr(transport, "name", "http"),
        "decompilations": {},
        "disassemblies": {},
        "imports": None,
        "functions": None,
        "callgraphs": {},
    }
    try:
        with IdaMcpClient(transport) as client:
            facts["server"] = client.server_info.get("serverInfo") or {}
            if client.has_tool("get_metadata"):
                try:
                    facts["metadata"] = client.call_json("get_metadata")
                except McpError as error:
                    facts["metadata"] = f"<error: {error}>"
            if client.has_tool("list_functions") or client.has_tool("list_funcs"):
                facts["functions"] = client.list_funcs()
            # allocation entry points: callers of the malloc/free PLT
            # functions. Resolve PLT addresses from the function table first
            # (get_function_by_name("malloc") can return the GOT data entry,
            # whose xrefs are useless).
            alloc_xrefs: dict[str, Any] = {}
            fn_index = {f.get("name"): f for f in (facts.get("functions") or [])
                        if isinstance(f, dict)}
            if client.has_tool("get_xrefs_to") or client.has_tool("xrefs_to"):
                for symbol in ("malloc", "free", "calloc", "realloc"):
                    plt = None
                    for candidate in (f".{symbol}", symbol, f"{symbol}@plt",
                                      f"__{symbol}"):
                        entry = fn_index.get(candidate)
                        if entry and entry.get("address"):
                            plt = entry["address"]
                            break
                    if not plt:
                        alloc_xrefs[symbol] = "<not present>"
                        continue
                    try:
                        alloc_xrefs[symbol] = {"plt": plt,
                                               "xrefs": client.xrefs_to(plt,
                                                                        timeout=30.0)}
                    except McpError as error:
                        alloc_xrefs[symbol] = f"<error: {error}>"
            facts["alloc_xrefs"] = alloc_xrefs
            targets = _heap_interesting_functions(facts.get("functions"))
            decompiler_ok: bool | None = None
            for name in targets:
                try:
                    text = client.decompile(name)
                    if "Can't import PySide6" in text or "Error executing tool" in text:
                        raise McpError(text[:120])
                    decompiler_ok = True
                    facts["decompilations"][name] = text
                except McpError as error:
                    if decompiler_ok is None:
                        decompiler_ok = False
                    # headless without a working Hex-Rays/Qt stack: fall back
                    # to the disassembly (the assembly-level evidence the
                    # training loop actually consumes)
                    try:
                        facts["disassemblies"][name] = client.disasm(name)
                        facts.setdefault("degrade_notes", []).append(
                            f"{name}: decompile unavailable -> disassembly "
                            f"({str(error)[:80]})")
                    except McpError as error2:
                        facts.setdefault("degrade_notes", []).append(
                            f"{name}: both decompile and disasm failed "
                            f"({str(error2)[:80]})")
    finally:
        transport.stop()
        if server_proc is not None:
            try:
                server_proc.terminate()
                server_proc.wait(timeout=10)
            except Exception:
                server_proc.kill()
        try:
            server_log.close()
        except Exception:
            pass
        # clean up only the unpacked-database files THIS run produced
        for name in _snapshot_dir() - before_files:
            if name.lower().endswith(_IDA_DB_SUFFIXES):
                try:
                    (binary.parent / name).unlink()
                except OSError:
                    pass
    facts["elapsed_seconds"] = round(time.monotonic() - started, 1)
    return facts


def _wait_http_ready(*, transport_factory=None, server_proc: subprocess.Popen,
                     port: int, timeout: float):
    """Wait for the spawned idalib-mcp HTTP server and return a working
    transport. Tries streamable HTTP (/mcp) then legacy SSE (/sse); IDA's
    initial auto-analysis may delay readiness substantially."""
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    sse: _SseTransport | None = None
    while time.monotonic() < deadline:
        if server_proc.poll() is not None:
            stderr = ""
            if server_proc.stderr is not None:
                try:
                    stderr = server_proc.stderr.read()[:400]
                except Exception:
                    pass
            raise McpError(f"idalib-mcp 启动失败 (code={server_proc.returncode}) {stderr}")
        if sse is None:
            try:
                probe = _HttpTransport(port=port)
                probe.ping()
                return probe
            except McpError as error:
                last_error = error
            # legacy server: start the SSE pump once and wait for endpoint.
            # NOTE: do NOT initialize here — an SSE session accepts exactly
            # one initialize, which belongs to the caller's client.
            sse = _SseTransport("127.0.0.1", port)
            try:
                sse.start()
                return sse
            except McpError as error:
                last_error = error
                sse = None
                time.sleep(1.0)
        else:
            time.sleep(1.0)
    raise McpError(f"idalib-mcp HTTP 就绪超时 ({timeout:.0f}s): {last_error}")


def _normalize_function_list(payload: Any) -> list[dict]:
    """ida-pro-mcp returns either JSON blobs or formatted text; normalize to
    [{name, address}] best-effort."""
    if isinstance(payload, dict):
        payload = (payload.get("functions") or payload.get("result")
                   or payload.get("data") or payload.get("content") or [])
    if not isinstance(payload, list):
        text = str(payload)
        functions = []
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                functions.append({"address": parts[0], "name": parts[-1].strip()})
        return functions
    functions = []
    for item in payload:
        if isinstance(item, dict):
            functions.append({
                "name": str(item.get("name") or ""),
                "address": str(item.get("address") or item.get("start") or ""),
            })
        elif isinstance(item, str):
            parts = item.split()
            if len(parts) >= 2:
                functions.append({"address": parts[0], "name": parts[-1].strip()})
    return functions


def _heap_interesting_functions(functions) -> list[str]:
    """Pick the analysis targets for the extraction battery: main + anything
    whose name hints at menu handlers / allocation activity."""
    if not functions:
        return []
    names = [f.get("name") or "" for f in functions if isinstance(f, dict)]
    picked: list[str] = []
    for hint in ("main",):
        picked.extend(n for n in names if n == hint)
    keywords = ("menu", "create", "delete", "edit", "show", "add", "remove",
                "alloc", "free", "heap", "note", "list")
    picked.extend(n for n in names
                  if n and n not in picked
                  and any(k in n.lower() for k in keywords))
    # nothing hinted: fall back to every non-library-looking function
    if not picked:
        picked = [n for n in names
                  if n and not n.startswith((".", "_", "sub_"))][:24]
    return picked[:32]
