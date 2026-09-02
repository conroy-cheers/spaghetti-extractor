from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.semantic_providers.intrinsic import (
    IntrinsicProviderError,
    _load_object,
)


class IntrinsicProviderTests(unittest.TestCase):
    def test_json_input_must_be_an_object(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(
                IntrinsicProviderError, "must be a JSON object"
            ):
                _load_object(path, "fixture")

if __name__ == "__main__":
    unittest.main()
