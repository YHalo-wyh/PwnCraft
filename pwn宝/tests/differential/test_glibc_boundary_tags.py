from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from pwnbao.features.heapviz.allocators.profiles import build_allocator_config
from pwnbao.features.heapviz.analyzer import analyze_heap_source
from pwnbao.features.heapviz.engine import GlibcHeapEngine


@unittest.skipUnless(
    os.environ.get("PWNBAO_RUN_GLIBC_DIFFERENTIAL") == "1" and shutil.which("gcc"),
    "set PWNBAO_RUN_GLIBC_DIFFERENTIAL=1 on a glibc host with gcc",
)
class GlibcBoundaryTagDifferentialTests(unittest.TestCase):
    """Optional runtime oracle; never replaced by simulator-generated truth."""

    def test_regular_free_publishes_prev_size_and_clears_prev_inuse(self) -> None:
        source = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    void *a = malloc(0x500), *b = malloc(0x500), *guard = malloc(0x20);
    (void)guard;
    free(a);
    uintptr_t *h = (uintptr_t *)b - 2;
    printf("%#lx %#lx\n", (unsigned long)h[0], (unsigned long)h[1]);
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            c_path, binary = root / "tag.c", root / "tag"
            c_path.write_text(source, encoding="utf-8")
            subprocess.run(["gcc", "-O0", "-o", str(binary), str(c_path)], check=True)
            output = subprocess.check_output([str(binary)], text=True).strip().split()
        observed_prev, observed_size = (int(item, 0) for item in output)
        snapshot = GlibcHeapEngine(build_allocator_config()).replay(
            analyze_heap_source(
                "add(0x500,b'A')\nadd(0x500,b'B')\nadd(0x20,b'G')\ndelete(0)\n"
            ).operations
        )[-1]
        b = snapshot.chunks["B"]
        self.assertEqual(observed_prev, int(b.fields[0].value, 0))
        self.assertEqual(observed_size & 1, 0)
        self.assertIn("PREV_INUSE=0", b.fields[1].value)


if __name__ == "__main__":
    unittest.main()
