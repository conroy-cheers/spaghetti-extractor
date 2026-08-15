from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.build_support.nix_invocation import (
    BUILDERS_FILE_ENV,
    TRUSTED_PUBLIC_KEYS_FILE_ENV,
    NixInvocationError,
    builder_arguments,
    select_builder_policy,
)


class NixInvocationTests(unittest.TestCase):
    def test_repository_inventory_is_discovered_from_target_flake(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "nix").mkdir()
            (root / "targets").mkdir()
            inventory = root / "nix/builders.local"
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

    def test_xdg_inventory_and_trusted_keys_are_discovered_together(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config/spaghetti-extractor"
            config.mkdir(parents=True)
            builders = config / "builders"
            keys = config / "trusted-public-keys"
            builders.write_text(
                "ssh-ng://builder x86_64-linux - 1 1 ca-derivations -\n",
                encoding="ascii",
            )
            keys.write_text("cache.example:abc=\n", encoding="ascii")
            policy = select_builder_policy(
                target_flake="github:example/targets",
                cwd=root,
                environment={"XDG_CONFIG_HOME": str(root / "config")},
            )
        self.assertEqual(policy.source, "xdg-config")
        self.assertEqual(policy.builders_file, builders.resolve())
        self.assertEqual(policy.trusted_public_keys_file, keys.resolve())
        self.assertIn("trusted-public-keys", policy.nix_arguments())

    def test_environment_trusted_keys_require_builders(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            keys = Path(temporary) / "keys"
            keys.write_text("cache.example:abc=\n", encoding="ascii")
            with self.assertRaisesRegex(NixInvocationError, "without a builders"):
                select_builder_policy(
                    target_flake="github:example/targets",
                    cwd=Path(temporary),
                    environment={TRUSTED_PUBLIC_KEYS_FILE_ENV: str(keys)},
                )


if __name__ == "__main__":
    unittest.main()
