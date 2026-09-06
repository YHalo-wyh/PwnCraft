from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).parents[1]
FORK = ROOT / "third_party" / "pwndbg-mogai"


class PwndbgForkV013Tests(unittest.TestCase):
    def test_fork_is_pinned_source_tree_and_versioned(self) -> None:
        self.assertEqual((FORK / "UPSTREAM_RELEASE").read_text().strip(), "2026.07.29")
        self.assertEqual(
            (FORK / "UPSTREAM_COMMIT").read_text().strip(),
            "f4de22244b7e9f0aeda26a92208c42edaca2f8d8",
        )
        self.assertTrue((FORK / "pwndbg" / "commands" / "context.py").is_file())
        version = (FORK / "pwndbg" / "lib" / "version.py").read_text(encoding="utf-8")
        self.assertIn("2026.07.29-pwndbg-mogai.16", version)

    def test_mogai_forces_colors_without_touching_official_theme(self) -> None:
        source = (FORK / "pwndbg/pwncraft/theme.py").read_text(encoding="utf-8")
        self.assertIn("disable_colors.value = False", source)
        self.assertIn("_disable_colors_trigger()", source)
        self.assertIn("parameter.update_color_function()", source)
        self.assertIn("enhance-integer", (FORK / "pwndbg/color/enhance.py").read_text(encoding="utf-8"))
        self.assertIn('"blue,bold"', source)
        self.assertNotIn(".gdbinit", source)

    def test_gui_has_no_tutor_renderer_or_command_catalog(self) -> None:
        debugger = ROOT / "pwncraft" / "gui" / "debugger"
        self.assertFalse((debugger / "command_palette.py").exists())
        self.assertFalse((debugger / "tutor_renderer.py").exists())
        source = "\n".join(path.read_text(encoding="utf-8") for path in debugger.glob("*.py"))
        self.assertNotIn("CommandPalette", source)
        self.assertNotIn("TutorRenderer", source)

    def test_localization_and_tutor_use_native_pwndbg_apis(self) -> None:
        context_zh = (FORK / "pwndbg/pwncraft/localization/context_zh_CN.py").read_text(encoding="utf-8")
        native = (FORK / "pwndbg/pwncraft/tutor/native.py").read_text(encoding="utf-8")
        context = (FORK / "pwndbg/pwncraft/tutor/context.py").read_text(encoding="utf-8")
        for title in ("寄存器 REGISTERS", "反汇编 DISASM", "栈 STACK", "调用栈 BACKTRACE"):
            self.assertIn(title, context_zh)
        self.assertIn("@pwndbg.commands.Command", native)
        for command in ("frame-explain", "return-info", "rbp-info", "stackof", "safe-link", "cyclic-find"):
            self.assertIn(command, native)
        self.assertIn("GDB unwinder", native)
        self.assertIn("pwndbg.color.context", context)
        self.assertIn("context.context_sections", context)

    def test_slash_projects_live_registry_and_real_argparse(self) -> None:
        registry = (FORK / "pwndbg/pwncraft/slash/registry.py").read_text(encoding="utf-8")
        command = (FORK / "pwndbg/pwncraft/slash/command.py").read_text(encoding="utf-8")
        proxy = (FORK / "input_proxy.py").read_text(encoding="utf-8")
        self.assertIn("for command in pwndbg.commands.commands", registry)
        self.assertIn('getattr(item.parser, "_actions"', registry)
        self.assertIn("slash-native", command)
        self.assertIn("_partial_prefix_length", proxy)
        self.assertIn("MENU_ROWS = 8", proxy)
        self.assertIn("PgUp/PgDn", proxy)
        self.assertIn("_reserve_menu_rows", proxy)
        self.assertIn("move_selection", proxy)
        self.assertNotIn("len(_OSC_PREFIX) - 1", proxy)

    def test_stop_callback_is_lightweight_and_snapshot_is_explicit(self) -> None:
        source = (FORK / "pwndbg/pwncraft/bridge/runtime.py").read_text(encoding="utf-8")
        stop = source[source.index("    def _on_stop"):source.index("    def _on_before_prompt")]
        self.assertNotIn("gdb.execute", stop)
        self.assertNotIn("tcachebins", stop)
        self.assertNotIn("fastbins", stop)
        snapshot = source[source.index("    def snapshot"):source.index("    def file_snapshot")]
        self.assertRegex(snapshot, re.compile(r"tcachebins.*fastbins.*bins.*heap --count", re.S))

    def test_upstream_hooks_are_narrow(self) -> None:
        commands = (FORK / "pwndbg/commands/__init__.py").read_text(encoding="utf-8")
        ui = (FORK / "pwndbg/ui.py").read_text(encoding="utf-8")
        self.assertIn("pwndbg.pwncraft.install()", commands)
        self.assertIn("section_title", ui)

    def test_mogai_launcher_isolated_from_official_pwndbg_state(self) -> None:
        launcher = (FORK / "launcher.sh").read_text(encoding="utf-8")
        self.assertIn("pwndbg-mogai", launcher)
        self.assertIn("XDG_CONFIG_HOME", launcher)
        self.assertIn("XDG_CACHE_HOME", launcher)
        self.assertIn("XDG_DATA_HOME", launcher)
        self.assertIn("unset NO_COLOR", launcher)
        self.assertNotIn("~/.gdbinit", launcher)
        self.assertNotIn(".config/pwndbg\"", launcher)


if __name__ == "__main__":
    unittest.main()
