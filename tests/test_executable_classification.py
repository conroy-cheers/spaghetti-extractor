from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor._contract_tools.map_generation import (
    _is_padding_bytes as contract_is_padding_bytes,
)
from spaghetti_extractor.stage_binary import (
    _is_padding_bytes as binary_is_padding_bytes,
    _parse_stage_a_pe,
)

from tests.pe_fixtures import pe32_image


class ExecutableClassificationTests(unittest.TestCase):
    def test_alignment_jump_remains_executable_code(self) -> None:
        code = bytes.fromhex("e90b000000") + b"\x90" * 11 + b"\xc3"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "alignment-thunk.exe"
            path.write_bytes(pe32_image(code))
            binary = _parse_stage_a_pe(path)

            for classify in (binary_is_padding_bytes, contract_is_padding_bytes):
                with self.subTest(classifier=classify.__module__):
                    self.assertFalse(classify(binary, 0x1000, code[:16]))
                    self.assertTrue(classify(binary, 0x1005, code[5:16]))


if __name__ == "__main__":
    unittest.main()
