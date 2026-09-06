from __future__ import annotations

import base64
import json
import os
import shlex

from pwndbg.pwnbao.slash.registry import NativeCommand, by_name, commands, option_hints, search
from pwndbg.pwnbao.localization.commands_zh_CN import search_keywords

_installed = False
_handles: list[object] = []


def _render_matches(query: str) -> None:
    import pwndbg.color.context as context_color
    from pwndbg.color import message

    matches = search(query)
    print(message.notice(f"/  pwndbg-mogai 原生命令面板  query={query or '*'}"))
    if not matches:
        print(message.warn("未找到匹配命令。"))
        return
    for item in matches:
        description = item.description_zh or item.description
        print(f"{context_color.register('/' + item.name):<34} {message.info(description)}")
    print(message.hint("键盘：Tab 补全，↑/↓ 使用 GDB readline 历史，Enter 执行，Esc 取消当前输入。"))


def _show_options(item: NativeCommand) -> None:
    from pwndbg.color import message

    hints = option_hints(item)
    print(message.notice(f"/{item.name}  参数提示（来自当前 argparse parser）"))
    if not hints:
        print(message.info("该命令没有可选 flags。"))
    for hint in hints:
        print(message.info(hint))


def _invoke(item: NativeCommand, argument: str) -> None:
    import gdb

    text = str(argument or "").strip()
    if text == "-":
        _show_options(item)
        return
    # Delegation goes straight back to the registered Pwndbg command.  Its
    # real CommandObj/argparse parser performs parsing and validation.
    gdb.execute(" ".join(part for part in (item.name, text) if part), from_tty=True)


def install() -> None:
    global _installed
    if _installed:
        return
    import gdb

    class SlashCommand(gdb.Command):
        def __init__(self, name: str, target: NativeCommand | None = None, query: str = ""):
            super().__init__(name, gdb.COMMAND_USER)
            self.target = target
            self.query = query

        def invoke(self, argument: str, _from_tty: bool) -> None:
            self.dont_repeat()
            if self.target is not None:
                _invoke(self.target, argument)
            else:
                _render_matches(argument.strip() or self.query)

        def complete(self, text: str, _word: str):
            needle = str(text).lstrip("/")
            return ["/" + item.name for item in search(needle, limit=64)]

    # Exact slash aliases are generated from the real live registry.  No GUI
    # command map exists and new upstream commands automatically participate.
    registrations: list[tuple[str, NativeCommand | None, str]] = [("/", None, "")]
    registrations.extend(("/" + item.name, item, "") for item in commands())
    registrations.extend(("/" + query, None, query) for query in ("栈", "堆", "内存映射", "内存", "寄存器", "返回"))
    seen = set()
    for name, target, query in registrations:
        if name in seen:
            continue
        seen.add(name)
        try:
            _handles.append(SlashCommand(name, target, query))
        except (RuntimeError, gdb.error):
            # Some older GDB builds reject a bare '/'.  Exact /command aliases
            # still remain native and `slash QUERY` is registered below.
            continue

    class SlashFallback(gdb.Command):
        def __init__(self):
            super().__init__("slash", gdb.COMMAND_USER)

        def invoke(self, argument: str, _from_tty: bool) -> None:
            self.dont_repeat()
            _render_matches(argument)

        def complete(self, text: str, _word: str):
            return [item.name for item in search(text, limit=64)]

    _handles.append(SlashFallback())

    class SlashNative(gdb.Command):
        """Execution endpoint used by the fork's PTY input framework."""

        def __init__(self):
            super().__init__("slash-native", gdb.COMMAND_USER)

        def invoke(self, argument: str, _from_tty: bool) -> None:
            self.dont_repeat()
            try:
                parts = shlex.split(argument)
            except ValueError:
                parts = argument.split()
            if not parts:
                _render_matches("")
                return
            item = by_name(parts[0])
            if item is None:
                _render_matches(parts[0])
                return
            _invoke(item, " ".join(parts[1:]))

    _handles.append(SlashNative())

    # The independent launcher/input layer receives a one-time projection of
    # the *live* registry.  It is not maintained by the GUI or checked in as a
    # second catalog.  Descriptions and option hints come from current Pwndbg
    # CommandObj/argparse objects.
    if os.environ.get("PWNBAO_SLASH_PROXY", "").casefold() in {"1", "true", "yes"}:
        payload = [
            {
                "name": item.name,
                "aliases": item.aliases,
                "category": item.category,
                "description": " ".join((item.description_zh or item.description).split())[:100],
                "keywords": search_keywords(item.name),
                "options": option_hints(item),
            }
            for item in commands()
        ]
        encoded = base64.b64encode(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        os.write(1, ("\x1b]PWNDBG_SLASH;1;" + encoded + "\x07").encode("ascii"))
    _installed = True
