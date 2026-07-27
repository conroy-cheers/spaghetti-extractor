from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from spaghetti_extractor.util import utc_now


class UtilTests(unittest.TestCase):
    def test_utc_now_honors_source_date_epoch(self) -> None:
        with patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "1"}):
            self.assertEqual(utc_now(), "1970-01-01T00:00:01+00:00")

    def test_utc_now_rejects_invalid_source_date_epoch(self) -> None:
        for value in ("not-a-timestamp", "-1"):
            with self.subTest(value=value):
                with patch.dict(
                    os.environ, {"SOURCE_DATE_EPOCH": value}
                ):
                    with self.assertRaisesRegex(
                        ValueError, "SOURCE_DATE_EPOCH"
                    ):
                        utc_now()


if __name__ == "__main__":
    unittest.main()
