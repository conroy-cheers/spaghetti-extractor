from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.build_support.nix_invocation import (
    BUILDERS_FILE_ENV,
    NixInvocationError,
    builder_arguments,
)


class NixInvocationTests(unittest.TestCase):
    def test_repository_inventory_is_discovered_from_target_flake(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "nix").mkdir()
            (root / "targets").mkdir()
            inventory = root / "nix/stage-a-builders"
            inventory.write_text("ssh-ng://builder x86_64-linux\n", encoding="ascii")
            arguments = builder_arguments(
                target_flake="./targets",
                builders_file=None,
                local=False,
                cwd=root,
            )
        self.assertEqual(arguments[0:2], ["--builders", f"@{inventory.resolve()}"])
        self.assertIn("builders-use-substitutes", arguments)

    def test_environment_inventory_has_priority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inventory = Path(temporary) / "builders"
            inventory.write_text("builder\n", encoding="ascii")
            with patch.dict(os.environ, {BUILDERS_FILE_ENV: str(inventory)}):
                arguments = builder_arguments(
                    target_flake="github:example/targets",
                    builders_file=None,
                    local=False,
                    cwd=Path(temporary),
                )
        self.assertEqual(arguments[1], f"@{inventory.resolve()}")

    def test_local_mode_explicitly_disables_global_builders(self) -> None:
        self.assertEqual(
            builder_arguments(
                target_flake="./targets",
                builders_file=None,
                local=True,
                cwd=Path("/tmp"),
            ),
            ["--builders", ""],
        )

    def test_absent_inventory_explicitly_selects_local_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.assertEqual(
                builder_arguments(
                    target_flake="github:example/targets",
                    builders_file=None,
                    local=False,
                    cwd=Path(temporary),
                ),
                ["--builders", ""],
            )

    def test_missing_explicit_inventory_fails_before_nix(self) -> None:
        with self.assertRaisesRegex(NixInvocationError, "does not exist"):
            builder_arguments(
                target_flake="./targets",
                builders_file=Path("missing-builders"),
                local=False,
                cwd=Path("/tmp"),
            )


if __name__ == "__main__":
    unittest.main()
