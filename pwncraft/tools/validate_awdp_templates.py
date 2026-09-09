"""Compile a real ELF and verify every AWDP patch template end to end.

Run from the repository root on Windows with WSL + gcc available:
    python tools/validate_awdp_templates.py
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable
import hashlib
import json
import shutil
import subprocess
import sys
from zipfile import ZipFile

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from pwncraft.electron_bridge import ElectronBridge
from pwncraft.features.patch.patch_core import parse_instruction_lines
from pwncraft.core.wsl import WslToolRunner, decode_wsl_output


FIXTURE_SOURCE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline)) void dangerous(const char *command) {
    system(command);
}

__attribute__((noinline)) ssize_t vulnerable_read(void) {
    char buffer[64];
    ssize_t count = read(STDIN_FILENO, buffer, 300);
    printf("READ=%zd\n", count);
    return count;
}

__attribute__((noinline)) void marker(void) {
    puts("MARKER");
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "danger") == 0) {
        dangerous("/bin/true");
    } else if (argc > 1 && strcmp(argv[1], "read") == 0) {
        vulnerable_read();
    } else if (argc > 1 && strcmp(argv[1], "marker") == 0) {
        marker();
    }
    puts("READY");
    return 0;
}
"""


@dataclass(frozen=True)
class TemplateCase:
    name: str
    request: dict
    verify_runtime: Callable[[WslToolRunner, Path], None] | None = None


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _compile_fixture(root: Path, runner: WslToolRunner, *, bits: int) -> Path:
    source = root / "awdp_fixture.c"
    binary = root / f"awdp_fixture_{bits}"
    source.write_text(FIXTURE_SOURCE, encoding="utf-8")
    command = [
        runner.wsl_exe, "--exec", "gcc", f"-m{bits}", "-O0", "-fno-stack-protector",
        "-no-pie", "-Wl,-z,lazy", "-o", runner.to_wsl_path(binary),
        runner.to_wsl_path(source),
    ]
    completed = subprocess.run(command, capture_output=True, timeout=30)
    if completed.returncode != 0:
        detail = decode_wsl_output(completed.stderr) or decode_wsl_output(completed.stdout)
        raise RuntimeError(f"gcc 编译真实 AWDP fixture 失败：\n{detail}")
    _require(binary.is_file() and binary.read_bytes().startswith(b"\x7fELF"), "gcc 未生成有效 ELF")
    return binary


def _run(runner: WslToolRunner, binary: Path, *args: str, stdin: bytes = b"") -> tuple[int, str]:
    result, timed_out = runner.run_target_capture(
        [runner.to_wsl_path(binary), *args], stdin_data=stdin, timeout=5)
    _require(not timed_out, f"目标运行超时：{binary.name} {' '.join(args)}")
    return result.returncode, result.stdout + result.stderr


def _verify_seccomp(runner: WslToolRunner, binary: Path) -> None:
    code, output = _run(runner, binary)
    _require(code == 0 and "READY" in output, f"seccomp 补丁误伤正常启动：rc={code}, {output!r}")


def _verify_plt_redirect(runner: WslToolRunner, binary: Path) -> None:
    code, output = _run(runner, binary, "danger")
    _require(code == 0 and "/bin/true" in output and "READY" in output,
             f"system→puts 重定向未产生真实行为：rc={code}, {output!r}")


def _verify_read_length(runner: WslToolRunner, binary: Path) -> None:
    code, output = _run(runner, binary, "read", stdin=b"A" * 64)
    _require(code == 0 and "READ=16" in output and "READY" in output,
             f"read 长度没有收紧到 16：rc={code}, {output!r}")


def _verify_ret(runner: WslToolRunner, binary: Path) -> None:
    code, output = _run(runner, binary, "marker")
    _require(code == 0 and "MARKER" not in output and "READY" in output,
             f"ret 模板没有跳过 marker：rc={code}, {output!r}")


def _case_catalog(binary: Path) -> list[TemplateCase]:
    bridge = ElectronBridge()
    functions, error = bridge._disassemble_functions(binary)
    _require(not error, f"真实 ELF 反汇编失败：{error}")
    marker = next((fn for fn in functions if fn.get("name") == "marker"), None)
    _require(marker is not None, "真实 ELF 中没有 marker 函数")
    marker_insns = parse_instruction_lines(str(marker.get("assembly") or ""))
    _require(bool(marker_insns), "marker 函数没有可解析指令")
    first = marker_insns[0]
    start = int(first["address"])
    end = start + int(first["size"])
    custom = " ".join("90" for _ in range(int(first["size"])))
    return [
        TemplateCase("seccomp", {"kind": "seccomp", "preset": "blacklist_min"}, _verify_seccomp),
        TemplateCase("plt_call", {"kind": "plt_call", "source": "system", "target": "puts"},
                     _verify_plt_redirect),
        TemplateCase("plt_stub", {"kind": "plt_stub", "source": "system", "target": "puts"},
                     _verify_plt_redirect),
        TemplateCase("readlen", {"kind": "readlen", "function": "vulnerable_read",
                                  "callee": "read", "size": "0x10"}, _verify_read_length),
        TemplateCase("nop_function", {"kind": "nop_function", "function": "marker"}),
        TemplateCase("ret_function", {"kind": "ret_function", "function": "marker"}, _verify_ret),
        TemplateCase("nop_range", {"kind": "nop_range", "start": hex(start), "end": hex(end)}),
        TemplateCase("custom", {"kind": "custom", "vaddr": hex(start), "hex": custom,
                                 "expected_size": int(first["size"])}),
    ]


def _validate_case(root: Path, pristine: Path, case: TemplateCase, runner: WslToolRunner) -> dict:
    case_root = root / case.name
    case_root.mkdir()
    working = case_root / "target"
    exported = case_root / "target_patched"
    shutil.copy2(pristine, working)
    before = working.read_bytes()

    bridge = ElectronBridge()
    bridge.workspace.target = {
        "original_binary": str(pristine),
        "working_binary": str(working),
        "project_root": str(case_root),
    }
    params = {"path": str(working), "request": case.request}
    preview = bridge.rpc_patch_preview(params)
    _require(bool(preview["ops"]), f"{case.name}: 预览没有生成补丁")
    _require(working.read_bytes() == before, f"{case.name}: 预览阶段修改了 ELF")

    applied = bridge.rpc_patch_apply(params)
    _require(len(applied["applied"]) == len(preview["ops"]), f"{case.name}: 应用条数与预览不一致")
    _require(working.read_bytes() != before, f"{case.name}: 应用后 ELF 没有变化")
    listed = bridge.rpc_patch_list({"path": str(working)})
    _require(listed["summary"]["healthy"], f"{case.name}: 应用后完整性检查失败")
    _require(listed["summary"]["applied"] == len(applied["applied"]),
             f"{case.name}: 生效补丁计数错误")
    probe = bridge.rpc_patch_probe(
        {"path": str(working), "args": "", "input": "", "timeout": 5, "compare": True})
    _require(probe["patched"]["ok"], f"{case.name}: 补丁后存活探测失败")
    _require(probe["comparison"] and probe["comparison"]["same_returncode"]
             and probe["comparison"]["same_stdout"],
             f"{case.name}: 无参基线行为与原始副本不一致")

    export = bridge.rpc_patch_export({"path": str(working), "kind": "patched", "dest": str(exported)})
    _require(exported.read_bytes() == working.read_bytes(), f"{case.name}: 导出 ELF 与工作副本不一致")
    _require(export["sha256"] == hashlib.sha256(exported.read_bytes()).hexdigest(),
             f"{case.name}: 导出 sha256 不一致")
    bundle_path = case_root / "submission.zip"
    bundle = bridge.rpc_patch_export(
        {"path": str(working), "kind": "bundle", "dest": str(bundle_path)})
    with ZipFile(bundle_path) as archive:
        _require(set(archive.namelist()) == set(bundle["files"]),
                 f"{case.name}: 比赛包文件清单不一致")
        manifest = json.loads(archive.read("manifest.json"))
        bundled_elf = archive.read(f"{pristine.name}_patched")
        _require(bundled_elf == exported.read_bytes(), f"{case.name}: 比赛包 ELF 与导出 ELF 不一致")
        _require(manifest["patched"]["sha256"] == export["sha256"],
                 f"{case.name}: 比赛包 manifest 哈希不一致")
        _require(manifest["operation_count"] == len(applied["applied"]),
                 f"{case.name}: 比赛包补丁计数错误")
    if case.verify_runtime:
        case.verify_runtime(runner, exported)

    undone = bridge.rpc_patch_undo({"path": str(working), "op_id": listed["ops"][0]["op_id"]})
    _require(undone["count"] == len(applied["applied"]), f"{case.name}: 没有完整撤销补丁组")
    _require(working.read_bytes() == before, f"{case.name}: 撤销后未恢复原始 ELF")
    _require(not bridge.rpc_patch_list({"path": str(working)})["ops"], f"{case.name}: 撤销后日志未清空")
    return {"template": case.name, "ops": len(applied["applied"]),
            "runtime": "passed" if case.verify_runtime else "byte-verified"}


def main() -> int:
    runner = WslToolRunner()
    with TemporaryDirectory(prefix="pwncraft-awdp-real-") as folder:
        root = Path(folder)
        results = []
        for arch, bits in (("amd64", 64), ("i386", 32)):
            arch_root = root / arch
            arch_root.mkdir()
            pristine = _compile_fixture(arch_root, runner, bits=bits)
            baseline_code, baseline_output = _run(runner, pristine)
            _require(baseline_code == 0 and "READY" in baseline_output,
                     f"{arch}: 真实 ELF 基线运行失败")
            audit_bridge = ElectronBridge()
            audit = audit_bridge.rpc_patch_audit({"path": str(pristine)})
            audit_ids = {item["id"] for item in audit["findings"]}
            _require("import:system" in audit_ids, f"{arch}: 风险扫描未发现 system 调用")
            _require(any(item.startswith("length:read:vulnerable_read") for item in audit_ids),
                     f"{arch}: 风险扫描未发现过大 read 长度")
            arch_results = [_validate_case(arch_root, pristine, case, runner)
                            for case in _case_catalog(pristine)]
            results.extend({**item, "arch": arch} for item in arch_results)
    for result in results:
        print(f"PASS {result['arch']}/{result['template']}: {result['ops']} op(s), {result['runtime']}")
    print(f"PASS all: audit + {len(results)} AWDP architecture/template cases applied, bundled and undone")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
