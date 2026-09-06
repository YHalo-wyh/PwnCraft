from __future__ import annotations

from dataclasses import dataclass

from pwndbg.pwncraft.localization.commands_zh_CN import chinese_matches, command_description


@dataclass(frozen=True)
class NativeCommand:
    name: str
    aliases: tuple[str, ...]
    category: str
    description: str
    description_zh: str
    parser: object


def commands() -> tuple[NativeCommand, ...]:
    """Project the live upstream registry; never cache a second catalog."""
    import pwndbg.commands

    result = []
    for command in pwndbg.commands.commands:
        name = str(command.command_name)
        description = str(getattr(command, "description", "") or "")
        category = getattr(command.category, "value", str(command.category))
        result.append(
            NativeCommand(
                name=name,
                aliases=tuple(str(alias) for alias in command.aliases),
                category=str(category),
                description=description,
                description_zh=command_description(name, description),
                parser=command.parser,
            )
        )
    return tuple(sorted(result, key=lambda item: item.name))


def by_name(name: str) -> NativeCommand | None:
    needle = str(name).strip().lstrip("/")
    for item in commands():
        if needle == item.name or needle in item.aliases:
            return item
    return None


def search(query: str, limit: int = 16) -> tuple[NativeCommand, ...]:
    needle = str(query).strip().lstrip("/").casefold()
    preferred = set(chinese_matches(needle)) if needle else set()
    scored: list[tuple[int, str, NativeCommand]] = []
    for item in commands():
        haystack = " ".join(
            (item.name, *item.aliases, item.category, item.description, item.description_zh)
        ).casefold()
        if needle and needle not in haystack and item.name not in preferred:
            continue
        if item.name in preferred:
            score = -2
        elif item.name.casefold().startswith(needle):
            score = 0
        else:
            score = 1
        scored.append((score, item.name, item))
    scored.sort(key=lambda value: (value[0], value[1]))
    return tuple(value[2] for value in scored[: max(1, int(limit))])


def option_hints(item: NativeCommand) -> tuple[str, ...]:
    result = []
    for action in getattr(item.parser, "_actions", ()):
        options = tuple(str(value) for value in getattr(action, "option_strings", ()))
        if not options:
            continue
        help_text = str(getattr(action, "help", "") or "")
        result.append(f"{' / '.join(options):<28} {help_text}")
    return tuple(result)

