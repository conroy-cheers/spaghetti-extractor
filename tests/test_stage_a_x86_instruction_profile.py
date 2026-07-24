from __future__ import annotations

import unittest

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

from spaghetti_extractor.relational.x86_instruction_profile import (
    is_reviewed_x87_frame_instruction,
)


class X86InstructionProfileTests(unittest.TestCase):
    @staticmethod
    def _decode(encoded: bytes):
        decoder = Cs(CS_ARCH_X86, CS_MODE_32)
        decoder.detail = True
        return next(decoder.disasm(encoded, 0x401000, count=1))

    def test_accepts_reviewed_32_bit_frame_forms(self) -> None:
        for encoded in (b"\xdd\x60\x20", b"\xdd\xb0\x8c\x00\x00\x00"):
            with self.subTest(encoded=encoded.hex()):
                self.assertTrue(
                    is_reviewed_x87_frame_instruction(self._decode(encoded))
                )

    def test_rejects_other_x87_and_segment_override_forms(self) -> None:
        for encoded in (b"\xd9\xe8", b"\x64\xdd\x60\x20"):
            with self.subTest(encoded=encoded.hex()):
                self.assertFalse(
                    is_reviewed_x87_frame_instruction(self._decode(encoded))
                )


if __name__ == "__main__":
    unittest.main()
