"""Check AMD64 memory CMPXCHG using angr's VEX execution engine.

Build PyVEX from source with its vex submodule at the VEX revision under
test. Install angr in the Python environment and expose the built PyVEX
package on PYTHONPATH. From this repository, run for example:

    PYTHONPATH=/path/to/pyvex python tests/amd64_cmpxchg.py /path/to/build/pyvex/lib/libpyvex.so

Pass the native library from that build so a different installed PyVEX
cannot silently supply the instruction lifter.
"""

import argparse
import filecmp
import sys
import unittest
from importlib.resources import files
from pathlib import Path

import angr


class TestMemoryCmpxchg(unittest.TestCase):
    def test_dword(self):
        initial_rax = 0x1234567811223344
        replacement = 0x76543210
        address = 0x1000
        for prefix in (b"", b"\xf0"):
            # [lock] cmpxchg dword ptr [rdi], ecx
            project = angr.load_shellcode(prefix + b"\x0f\xb1\x0f", arch="amd64")
            for old, want_rax, want_memory, want_zf in (
                (0x11223344, initial_rax, replacement, 1),
                (0xFEDCBA98, 0x00000000FEDCBA98, 0xFEDCBA98, 0),
            ):
                with self.subTest(locked=bool(prefix), old=hex(old)):
                    state = project.factory.blank_state(addr=0)
                    state.options.discard(angr.options.UNICORN)
                    state.regs.rax = initial_rax
                    state.regs.rcx = replacement
                    state.regs.rdi = address
                    state.memory.store(address, old, size=4, endness="Iend_LE")

                    (after,) = project.factory.successors(state, num_inst=1).flat_successors
                    memory = after.memory.load(address, 4, endness="Iend_LE")
                    self.assertEqual(after.solver.eval_one(after.regs.rax), want_rax)
                    self.assertEqual(after.solver.eval_one(memory), want_memory)
                    self.assertEqual(after.solver.eval_one(after.regs.eflags[6]), want_zf)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library", type=Path, help="native PyVEX library from the VEX build under test")
    args = parser.parse_args()
    name = {"win32": "pyvex.dll", "cygwin": "pyvex.dll", "darwin": "libpyvex.dylib"}.get(sys.platform, "libpyvex.so")
    loaded = files("pyvex") / "lib" / name
    if not args.library.is_file() or not filecmp.cmp(loaded, args.library, shallow=False):
        parser.error(f"PyVEX library {loaded} does not match {args.library}")
    unittest.main(argv=[__file__])
