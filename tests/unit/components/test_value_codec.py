from __future__ import annotations

import unittest

from spaghetti_extractor.components.value_codec import (
    parse_value_codec_expression,
    value_codec_expression_references,
)


class ValueCodecTests(unittest.TestCase):
    def test_resource_identity_is_a_typed_word_reference(self) -> None:
        expression, sort = parse_value_codec_expression(
            {"op": "resource_identity", "name": "window"},
            "test resource identity",
        )

        self.assertEqual(sort, "word")
        self.assertEqual(
            value_codec_expression_references(expression)["resource_identity"],
            {"window"},
        )


if __name__ == "__main__":
    unittest.main()
