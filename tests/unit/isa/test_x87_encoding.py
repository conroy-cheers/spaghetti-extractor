from __future__ import annotations

import unittest

from spaghetti_extractor.isa.x87_encoding import is_x87_instruction_encoding


class X87EncodingTests(unittest.TestCase):
    def test_classifies_wait_and_primary_x87_opcode_space(self) -> None:
        for encoded in (
            b"\x9b",       # wait
            b"\xd9\xfc",  # frndint
            b"\xda\xc9",  # fcmove st(0), st(1)
            b"\x67\xd9\x00",  # address-size-prefixed fld
        ):
            with self.subTest(encoded=encoded.hex()):
                self.assertTrue(is_x87_instruction_encoding(encoded))

    def test_does_not_treat_other_or_malformed_encodings_as_x87(self) -> None:
        for encoded in (b"", b"\x66", b"\x90", b"\x0f\xaf\xc1"):
            with self.subTest(encoded=encoded.hex()):
                self.assertFalse(is_x87_instruction_encoding(encoded))


if __name__ == "__main__":
    unittest.main()
