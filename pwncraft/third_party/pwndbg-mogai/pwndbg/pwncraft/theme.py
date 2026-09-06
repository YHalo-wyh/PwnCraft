from __future__ import annotations


def ensure_classic_colors() -> None:
    """Re-enable ANSI color functions after user/GDB config is loaded.

    Pwndbg creates color callables while importing commands.  If ``NO_COLOR``
    or a persisted GDB setting was active at that moment, simply changing the
    parameter later leaves already-created callables returning plain text.
    Rebuilding every ColorParameter is cheap at a prompt boundary and keeps
    the embedded GUI and a standalone terminal consistent.
    """
    import pwndbg
    import pwndbg.color

    pwndbg.color.disable_colors.value = False
    pwndbg.color._disable_colors_trigger()
    for parameter in pwndbg.config.params.values():
        updater = getattr(parameter, "update_color_function", None)
        if callable(updater):
            updater()


def install_classic_theme() -> None:
    """Force a deterministic high-contrast theme for the isolated fork.

    This changes only pwndbg-mogai's in-process parameters.  It does not read
    or write the user's official Pwndbg theme/configuration.
    """
    import pwndbg.color
    import pwndbg.color.context as context_color
    import pwndbg.color.disasm as disasm_color
    import pwndbg.color.enhance as enhance_color
    import pwndbg.color.hexdump as hexdump_color
    import pwndbg.color.memory as memory_color
    import pwndbg.color.message as message_color
    import pwndbg.color.telescope as telescope_color

    ensure_classic_colors()
    # Assigning Parameter.value alone does not execute the GDB parameter
    # trigger.  If NO_COLOR was inherited during early import, colorize may
    # still contain the no-color implementation even though `show
    # disable-colors` says off.  Restore it explicitly inside this isolated
    # fork.
    pwndbg.color._disable_colors_trigger()
    settings = (
        (context_color.config_banner_color, "blue,bold"),
        (context_color.config_banner_title, "light_blue,bold"),
        (context_color.config_prefix_color, "red,bold"),
        (context_color.config_highlight_color, "green,bold"),
        (context_color.config_register_color, "cyan,bold"),
        (context_color.config_register_changed_color, "red,bold"),
        (context_color.config_flag_set_color, "green,bold"),
        (context_color.config_flag_unset_color, "red"),
        (context_color.config_comment, "gray"),
        (context_color.config_flag_value_color, "light_yellow"),
        (context_color.config_flag_bracket_color, "blue"),
        (context_color.config_flag_changed_color, "light_red,bold"),
        (enhance_color.config_integer_color, "light_cyan"),
        (enhance_color.config_string_color, "light_green"),
        (enhance_color.config_comment_color, "gray"),
        (enhance_color.config_unknown_color, "light_red"),
        (hexdump_color.config_normal, "light_blue"),
        (hexdump_color.config_printable, "light_green,bold"),
        (hexdump_color.config_zero, "red"),
        (hexdump_color.config_special, "light_yellow"),
        (hexdump_color.config_offset, "yellow"),
        (hexdump_color.config_address, "light_cyan"),
        (hexdump_color.config_separator, "gray"),
        (message_color.config_info_color, "light_gray"),
        (message_color.config_notice_color, "light_purple,bold"),
        (message_color.config_hint_color, "light_yellow"),
        (message_color.config_prompt_color, "light_red,bold"),
        (message_color.config_prompt_alive_color, "light_green,bold"),
        (telescope_color.offset_color, "yellow"),
        (telescope_color.register_color, "light_cyan,bold"),
        (telescope_color.offset_separator_color, "gray"),
        (telescope_color.offset_delimiter_color, "gray"),
        (telescope_color.repeating_marker_color, "light_purple"),
    )
    for parameter, value in settings:
        parameter.value = value
        # ColorParameter caches a generated callable; direct value assignment
        # intentionally bypasses the normal GDB trigger path, so refresh it.
        parameter.update_color_function()

    # ColorConfig keeps its parameters private but they are still the live
    # upstream configuration objects.  Reassert the classic address legend
    # rather than maintaining a second renderer-side color map.
    for name, value in {
        "stack": "light_yellow",
        "heap": "light_blue",
        "code": "light_red",
        "data": "light_purple",
        "rodata": "light_gray",
        "wx": "underline",
        "guard": "light_cyan",
    }.items():
        parameter = memory_color.c._params[name]
        parameter.value = value
        parameter.update_color_function()
    branch = disasm_color.c._params["branch"]
    branch.value = "light_green,bold"
    branch.update_color_function()
    try:
        import gdb
        # Keep the runtime knob aligned too; some user gdbinit files set this
        # after Pwndbg imports have completed.
        gdb.execute("set disable-colors off", from_tty=False)
    except Exception:
        pass
