from __future__ import annotations

import unittest

import capstone

from spaghetti_extractor.relational.preflight import instruction_supported


class StageASemanticPreflightTests(unittest.TestCase):
    def test_leave_matches_the_reviewed_decoder_surface(self) -> None:
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        instructions = list(disassembler.disasm(b"\xc9", 0x401000))

        self.assertEqual(len(instructions), 1)
        self.assertTrue(instruction_supported(instructions[0]))


if __name__ == "__main__":
    unittest.main()
