from __future__ import annotations

_installed = False


def install() -> None:
    global _installed
    if _installed:
        return
    # Importing the module registers real Pwndbg Command objects and exposes
    # their argparse parsers through the upstream registry.
    import pwndbg.pwnbao.tutor.native  # noqa: F401

    _installed = True

