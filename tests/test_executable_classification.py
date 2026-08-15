from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.extraction.executable_classification import (
    _is_padding_bytes,
)
from spaghetti_extractor.pe32.image import (
    parse_pe_image,
)

from tests.pe_fixtures import pe32_image


class ExecutableClassificationTests(unittest.TestCase):
    def test_alignment_jump_remains_executable_code(self) -> None:
        code = bytes.fromhex("e90b000000") + b"\x90" * 11 + b"\xc3"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "alignment-thunk.exe"
            path.write_bytes(pe32_image(code))
            binary = parse_pe_image(path)

            self.assertFalse(_is_padding_bytes(binary, 0x1000, code[:16]))
            self.assertTrue(_is_padding_bytes(binary, 0x1005, code[5:16]))


if __name__ == "__main__":
    unittest.main()
