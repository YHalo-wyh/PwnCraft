"""AWDP patch lab: byte-level ELF patching truth for the Electron surface.

All address↔offset math, instruction bytes and patch recipes live here in
pure Python; the renderer only displays what these builders produce.  Patches
always target the mutable ``.pwncraft/runtime`` working copy — the original
stays read-only by construction.
"""
