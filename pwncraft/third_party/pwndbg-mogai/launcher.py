from __future__ import annotations

from pathlib import Path
import sys

# Running this file with the pinned portable Python makes the fork root the
# first import location.  pwndbginit remains upstream; only `pwndbg` resolves
# to this source tree.  The installed portable directory is never modified.
ROOT = str(Path(__file__).resolve().parent)
if ROOT in sys.path:
    sys.path.remove(ROOT)
sys.path.insert(0, ROOT)

from pwndbginit.pwndbg_gdb import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())

