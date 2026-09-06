from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch
import subprocess

from pwncraft.core.code_analysis import parse_disassembly
from pwncraft.core.wsl import ToolResult, WslToolRunner, decode_wsl_output
from pwncraft.electron_bridge import ElectronBridge


DISASSEMBLY = """Disassembly of section .text:
0000000000000000 <main>:
   0:\t55                   \tpush %rbp
   1:\tc3                   \tret
0000000000000010 <helper<int>>:
  10:\tc3                   \tret
Disassembly of section .plt:
0000000000000020 <puts@plt>:
  20:\tff 25 00 00 00 00    \tjmp *0x0(%rip)
"""


class WslOutputTests(TestCase):
    def test_utf8_and_wide_startup_diagnostics(self):
        notice = "wsl: 检测到 localhost 代理配置，但未镜像到 WSL。\r\n"
        linux = "ldd: /mnt/c/中文目录/文件: No such file or directory\n"
        for encoding in ("utf-16-le", "utf-16-be", "utf-16"):
            with self.subTest(encoding=encoding):
                self.assertEqual(decode_wsl_output(notice.encode(encoding)), notice)
                self.assertEqual(decode_wsl_output(notice.encode(encoding) + linux.encode()), notice + linux)
                self.assertEqual(decode_wsl_output(linux.encode() + notice.encode(encoding)), linux + notice)
        self.assertEqual(decode_wsl_output(linux.encode()), linux)
        self.assertEqual(decode_wsl_output(linux), linux)
        self.assertEqual(decode_wsl_output(b""), "")

    @patch("pwncraft.core.wsl.subprocess.run")
    def test_run_tool_decodes_each_stream(self, run):
        notice = "wsl: 中文提示\r\n"
        run.return_value = subprocess.CompletedProcess([], 0, b"libc.so.6 => /lib/libc.so.6\n", notice.encode("utf-16-le"))
        result = WslToolRunner().run_tool("ldd", ["/bin/true"])
        self.assertEqual(result.stderr, notice)
        self.assertNotIn("\x00", result.combined_output())
        self.assertEqual(run.call_args.args[0], ["wsl.exe", "--exec", "ldd", "/bin/true"])


class CodeAnalysisTests(TestCase):
    def test_function_boundaries_and_display_limits(self):
        result = parse_disassembly(DISASSEMBLY, max_functions=2, max_lines=1)
        self.assertEqual(result["function_count"], 3)
        self.assertTrue(result["truncated"])
        main, helper = result["functions"]
        self.assertEqual(main["address"], "0x0")
        self.assertEqual(main["instruction_count"], 2)
        self.assertTrue(main["truncated"])
        self.assertEqual(helper["name"], "helper<int>")
        self.assertNotIn("puts", helper["assembly"])
        self.assertEqual(parse_disassembly("unsupported file format")["functions"], [])

    def test_ldd_notice_is_separate_and_failure_is_preserved(self):
        bridge = ElectronBridge()
        bridge._runner = Mock()
        ok = ToolResult([], 0, "libc.so.6 => /lib/libc.so.6", "wsl: 中文提示")
        bridge._runner.run_tool.return_value = ok
        bridge._runner.file.return_value = ok
        bridge._runner.checksec.return_value = ok
        result = bridge.rpc_binary_reports({"path": "example"})
        self.assertEqual(result["reports"]["ldd"], ok.stdout)
        self.assertEqual(result["diagnostics"]["ldd"]["notice"], ok.stderr)
        bridge._runner.run_tool.return_value = ToolResult([], 1, "", "not a dynamic executable")
        result = bridge.rpc_binary_reports({"path": "example"})
        self.assertIn("not a dynamic executable", result["reports"]["ldd"])
        self.assertEqual(result["diagnostics"]["ldd"]["returncode"], 1)

    def test_analysis_uses_selected_file_and_never_executes_source(self):
        with TemporaryDirectory() as folder:
            target = Path(folder) / "中文 ELF"
            header = bytearray(64)
            header[:6] = b"\x7fELF\x02\x01"
            header[18:20] = (0x3e).to_bytes(2, "little")
            target.write_bytes(header)
            bridge = ElectronBridge()
            bridge._runner = Mock()
            bridge._runner.to_wsl_path.return_value = "/mnt/c/中文 ELF"
            bridge._runner.run_tool.return_value = ToolResult([], 0, DISASSEMBLY, "")
            result = bridge.rpc_code_analysis({"path": str(target), "source": "def incomplete("})
            self.assertEqual(result["function_count"], 3)
            self.assertEqual(result["diagnostics"][0]["code"], "EXP_PARSE_001")
            bridge._runner.run_tool.assert_called_once_with("objdump", ["-d", "--", "/mnt/c/中文 ELF"])
            bridge._runner.run_tool.reset_mock()
            result = bridge.rpc_code_analysis({"path": str(target), "source": "raise RuntimeError('must not run')", "include_assembly": False})
            bridge._runner.run_tool.assert_not_called()
            self.assertEqual(target.read_bytes(), header)

    @patch("pwncraft.electron_bridge.BinaryInspector")
    def test_missing_disassembler_keeps_audit_results(self, inspector):
        inspector.return_value.inspect.return_value = SimpleNamespace(bits=64, security={})
        bridge = ElectronBridge()
        bridge._runner = Mock()
        bridge._runner.run_tool.side_effect = FileNotFoundError("objdump missing")
        result = bridge.rpc_code_analysis({"path": "example", "source": "def incomplete("})
        self.assertIn("objdump missing", result["assembly_error"])
        self.assertEqual(result["diagnostics"][0]["code"], "EXP_PARSE_001")
