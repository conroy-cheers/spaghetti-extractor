from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.testkit.runner import build_commands


class TestNixFirstRunner(unittest.TestCase):
    def test_static_modes_build_canonical_cached_aggregate(self) -> None:
        command = build_commands(Path("/work/repo"), mode="smoke")

        self.assertEqual(command[0][:4], ("nix", "build", "--impure", "--expr"))
        self.assertIn('flake.packages.x86_64-linux."test-smoke"', command[0][4])
        self.assertIn('"private"', command[0][4])

    def test_affected_builds_only_selected_stable_shards(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src/spaghetti_extractor").mkdir(parents=True)
            (root / "src/spaghetti_extractor/__init__.py").write_text("")
            (root / "src/spaghetti_extractor/value.py").write_text("VALUE = 1\n")
            (root / "tests/smoke").mkdir(parents=True)
            (root / "tests/smoke/test_smoke.py").write_text("VALUE = 1\n")
            (root / "tests/unit/value").mkdir(parents=True)
            (root / "tests/unit/value/test_value.py").write_text(
                "from spaghetti_extractor.value import VALUE\n"
            )

            rendered = build_commands(
                root,
                mode="affected",
                changed=("src/spaghetti_extractor/value.py",),
            )[0]

            self.assertIn('flake.checks.x86_64-linux."test-shard-smoke"', rendered[4])
            self.assertIn('test-shard-pure-', rendered[4])
            self.assertEqual(rendered[-1], "--no-link")


if __name__ == "__main__":
    unittest.main()
