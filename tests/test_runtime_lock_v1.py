from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.runtime_lock_v1 import (
    RUNTIME_LOCK_SPEC_V1_FORMAT,
    RuntimeLockV1Error,
    build_runtime_lock_v1,
)


class RuntimeLockV1Tests(unittest.TestCase):
    def test_is_deterministic_and_content_sensitive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            left = root / "left"
            right = root / "right"
            left.write_text("left", encoding="ascii")
            right.mkdir()
            (right / "value").write_text("right", encoding="ascii")
            rows = [
                {"kind": "profile", "identity": "pe32", "path": str(left)},
                {"kind": "toolchain", "identity": "mingw", "path": str(right)},
            ]
            one = build_runtime_lock_v1(
                {"format": RUNTIME_LOCK_SPEC_V1_FORMAT, "dependencies": rows}
            )
            two = build_runtime_lock_v1(
                {
                    "format": RUNTIME_LOCK_SPEC_V1_FORMAT,
                    "dependencies": list(reversed(rows)),
                }
            )
            self.assertEqual(one, two)
            (right / "value").write_text("changed", encoding="ascii")
            changed = build_runtime_lock_v1(
                {"format": RUNTIME_LOCK_SPEC_V1_FORMAT, "dependencies": rows}
            )
            self.assertNotEqual(one["lock_id"], changed["lock_id"])

    def test_duplicate_dependency_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "value"
            path.write_text("value", encoding="ascii")
            row = {"kind": "profile", "identity": "same", "path": str(path)}
            with self.assertRaisesRegex(RuntimeLockV1Error, "duplicated"):
                build_runtime_lock_v1(
                    {
                        "format": RUNTIME_LOCK_SPEC_V1_FORMAT,
                        "dependencies": [row, row],
                    }
                )


if __name__ == "__main__":
    unittest.main()
