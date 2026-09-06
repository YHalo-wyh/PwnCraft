#!/bin/sh
set -eu

FORK_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
MOGAI_VERSION="${PWNDBG_MOGAI_VERSION:-2026.07.29-pwndbg-mogai.16}"
MOGAI_BASE="${PWNDBG_MOGAI_HOME:-$HOME/.local/share/pwnbao/pwndbg-mogai}"
PORTABLE_ROOT="${PWNDBG_PWNBAO_PORTABLE:-$MOGAI_BASE/$MOGAI_VERSION/runtime}"

test -x "$PORTABLE_ROOT/exe/python3"
test -x "$PORTABLE_ROOT/lib/ld-linux-x86-64.so.2"

export TERMINFO_DIRS="/etc/terminfo:/lib/terminfo:/usr/share/terminfo:$PORTABLE_ROOT/share/terminfo"
export TERM="${TERM:-xterm-256color}"
if [ "$TERM" = dumb ]; then export TERM=xterm-256color; fi
export COLORTERM="${COLORTERM:-truecolor}"
export FORCE_COLOR=1
export PY_COLORS=1
unset NO_COLOR
export PYTHONNOUSERSITE=1
export PYTHONHOME="$PORTABLE_ROOT"
export PATH="$PORTABLE_ROOT/bin:$PATH"
export XDG_CONFIG_HOME="${PWNDBG_MOGAI_CONFIG_HOME:-$HOME/.config/pwnbao/pwndbg-mogai}"
export XDG_CACHE_HOME="${PWNDBG_MOGAI_CACHE_HOME:-$HOME/.cache/pwnbao/pwndbg-mogai}"
export XDG_DATA_HOME="${PWNDBG_MOGAI_DATA_HOME:-$HOME/.local/share/pwnbao/pwndbg-mogai/data}"
export GDBHISTFILE="${PWNDBG_MOGAI_GDBHISTFILE:-$XDG_DATA_HOME/gdb_history}"
mkdir -p "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_DATA_HOME"
export PWNDBG_PWNBAO_LD="$PORTABLE_ROOT/lib/ld-linux-x86-64.so.2"
export PWNDBG_PWNBAO_PYTHON="$PORTABLE_ROOT/exe/python3"

exec "$PORTABLE_ROOT/lib/ld-linux-x86-64.so.2" \
    "$PORTABLE_ROOT/exe/python3" "$FORK_ROOT/input_proxy.py" "$@"
