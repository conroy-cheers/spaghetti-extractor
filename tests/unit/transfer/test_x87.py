from __future__ import annotations

import unittest

from spaghetti_extractor.errors import ToolkitInputError
from spaghetti_extractor.transfer.x87 import extract_typed_x87_operation


class TypedX87OperationTests(unittest.TestCase):
    def test_register_conditional_move_has_one_canonical_typed_form(self) -> None:
        operation = extract_typed_x87_operation(
            encoded=b"\xda\xc9",  # fcmove st(0), st(1)
            instruction={"mnemonic": "fcmove", "op_str": "st(0), st(1)"},
            image_base=0x400000,
        )

        self.assertEqual(operation.mnemonic, "fcmove")
        self.assertEqual(operation.operand.kind, "stack")
        self.assertEqual(operation.operand.registers, (0, 1))

    def test_operand_free_stack_transform_has_one_canonical_typed_form(self) -> None:
        operation = extract_typed_x87_operation(
            encoded=b"\xd9\xf4",  # fxtract
            instruction={"mnemonic": "fxtract", "op_str": ""},
            image_base=0x400000,
        )

        self.assertEqual(operation.mnemonic, "fxtract")
        self.assertEqual(operation.operand.kind, "none")

    def test_non_x87_bytes_cannot_enter_typed_x87_replay(self) -> None:
        with self.assertRaisesRegex(ToolkitInputError, "outside the x87 opcode space"):
            extract_typed_x87_operation(
                encoded=b"\x90",
                instruction={"mnemonic": "nop", "op_str": ""},
                image_base=0x400000,
            )


if __name__ == "__main__":
    unittest.main()
