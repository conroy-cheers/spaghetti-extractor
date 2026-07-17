from __future__ import annotations

import unittest

import capstone

from spaghetti_extractor.relational.preflight import instruction_supported


class StageASemanticPreflightTests(unittest.TestCase):
    def _instruction(self, encoded: bytes):
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        instructions = list(disassembler.disasm(encoded, 0x401000))
        self.assertEqual(len(instructions), 1)
        self.assertEqual(instructions[0].bytes, encoded)
        return instructions[0]

    def test_leave_matches_the_reviewed_decoder_surface(self) -> None:
        self.assertTrue(instruction_supported(self._instruction(b"\xc9")))

    def test_gnu_hello_forms_match_the_reviewed_decoder_surface(self) -> None:
        encodings = (
            bytes.fromhex("08c1"),
            bytes.fromhex("20c8"),
            bytes.fromhex("30c1"),
            bytes.fromhex("32c1"),
            bytes.fromhex("3401"),
            bytes.fromhex("c0ea05"),
            bytes.fromhex("a200104000"),
            bytes.fromhex("660fbe16"),
            bytes.fromhex("0fa3c2"),
            bytes.fromhex("f77c2440"),
        )

        for encoded in encodings:
            with self.subTest(encoded=encoded.hex()):
                self.assertTrue(instruction_supported(self._instruction(encoded)))

    def test_unreviewed_neighboring_forms_remain_fail_closed(self) -> None:
        for encoded in (bytes.fromhex("0fa300"), bytes.fromhex("660f57c0")):
            with self.subTest(encoded=encoded.hex()):
                self.assertFalse(instruction_supported(self._instruction(encoded)))


if __name__ == "__main__":
    unittest.main()
