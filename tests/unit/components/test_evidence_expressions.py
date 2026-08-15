"""Normalized machine-expression evaluation tests."""

from __future__ import annotations

import unittest

from spaghetti_extractor.components.evidence import (
    _MachineMemory,
    _UnsupportedSemantics,
    _eval_expr,
)


class ComponentEvidenceExpressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.memory = _MachineMemory()

    def test_sign_extend_preserves_positive_byte(self) -> None:
        expression = {
            "op": "sign_extend",
            "args": [8, {"op": "const", "value": 0x7F, "width": 32}],
        }

        self.assertEqual(_eval_expr(expression, {}, self.memory), 0x0000007F)

    def test_sign_extend_extends_negative_byte(self) -> None:
        expression = {
            "op": "sign_extend",
            "args": [8, {"op": "const", "value": 0x80, "width": 32}],
        }

        self.assertEqual(_eval_expr(expression, {}, self.memory), 0xFFFFFF80)

    def test_sign_extend_masks_input_to_source_width(self) -> None:
        expression = {
            "op": "sign_extend",
            "args": [16, {"op": "const", "value": 0x12348001, "width": 32}],
        }

        self.assertEqual(_eval_expr(expression, {}, self.memory), 0xFFFF8001)

    def test_sign_extend_rejects_invalid_arity(self) -> None:
        with self.assertRaisesRegex(_UnsupportedSemantics, "two arguments"):
            _eval_expr({"op": "sign_extend", "args": [8]}, {}, self.memory)

    def test_sign_extend_rejects_invalid_width(self) -> None:
        with self.assertRaisesRegex(_UnsupportedSemantics, "between 1 and 32"):
            _eval_expr(
                {
                    "op": "sign_extend",
                    "args": [0, {"op": "const", "value": 0, "width": 32}],
                },
                {},
                self.memory,
            )


if __name__ == "__main__":
    unittest.main()
