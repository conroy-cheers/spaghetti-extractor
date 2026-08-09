from __future__ import annotations

import unittest

from spaghetti_extractor._contract_tools.reference_contract import (
    _semantic_stack_delta_expr,
)


class ReferenceContractStackTests(unittest.TestCase):
    def test_nested_push_arithmetic_is_affine(self) -> None:
        expression = (
            "sub",
            ("sub", ("sub", ("reg", "esp"), ("const", 4)), ("const", 4)),
            ("const", 4),
        )

        self.assertEqual(_semantic_stack_delta_expr(expression), -12)

    def test_unsigned_wrapped_negative_constant_is_signed_delta(self) -> None:
        expression = (
            "sub",
            ("add", ("const", 0xFFFF_FFA8), ("reg", "esp")),
            ("const", 12),
        )

        self.assertEqual(_semantic_stack_delta_expr(expression), -100)

    def test_non_affine_or_multiple_esp_expression_is_unknown(self) -> None:
        self.assertIsNone(
            _semantic_stack_delta_expr(
                ("add", ("reg", "esp"), ("reg", "eax"))
            )
        )
        self.assertIsNone(
            _semantic_stack_delta_expr(
                ("add", ("reg", "esp"), ("reg", "esp"))
            )
        )


if __name__ == "__main__":
    unittest.main()
