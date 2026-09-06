from __future__ import annotations

_installed = False


def install() -> None:
    """Install native fork features after upstream registered its commands."""
    global _installed
    if _installed:
        return

    from pwndbg.pwncraft.slash.command import install as install_slash
    from pwndbg.pwncraft.theme import install_classic_theme
    from pwndbg.pwncraft.tutor.commands import install as install_tutor
    from pwndbg.pwncraft.tutor.context import install as install_context

    install_classic_theme()
    install_tutor()
    install_context()
    install_slash()

    # The bridge is intentionally optional.  A standalone terminal gets the
    # same localized Context, slash commands and tutor helpers without any GUI.
    from pwndbg.pwncraft.bridge.runtime import install_if_enabled

    install_if_enabled()
    _installed = True


__all__ = ["install"]
