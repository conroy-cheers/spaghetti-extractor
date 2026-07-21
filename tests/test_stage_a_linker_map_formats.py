from types import SimpleNamespace
import unittest

from spaghetti_extractor.relational.contract import _padding_bytes
from spaghetti_extractor.stage_binary import _parse_linker_map_symbol_line


class StageALinkerMapFormatTests(unittest.TestCase):
    def test_parses_lld_link_public_symbol(self) -> None:
        binary = SimpleNamespace(image_base=0x400000)

        self.assertEqual(
            _parse_linker_map_symbol_line(
                " 0001:0000000a       _rt_branch_check           "
                "000000000040100a     original.obj",
                binary,
            ),
            (0x100A, "_rt_branch_check"),
        )

    def test_ignores_lld_link_section_labels(self) -> None:
        binary = SimpleNamespace(image_base=0x400000)

        self.assertIsNone(_parse_linker_map_symbol_line(
            " 0001:00000060       .text                      "
            "0000000000401060     kernel32.o",
            binary,
        ))

    def test_accepts_lld_link_int3_alignment_padding(self) -> None:
        self.assertTrue(_padding_bytes(
            b"\xcc\xcc\x90",
            SimpleNamespace(),
            0x1000,
        ))
