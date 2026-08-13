from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.testkit.runner import (
    _canonical_json,
    _filtered_source_sha256,
    _read_evaluation_receipt,
    _receipt_core,
    _realise_derivations,
    _write_evaluation_receipt,
    build_commands,
)


class TestNixFirstRunner(unittest.TestCase):
    def test_static_modes_build_canonical_cached_aggregate(self) -> None:
        command = build_commands(Path("/work/repo"), mode="smoke")

        self.assertEqual(command[0][:4], ("nix", "build", "--impure", "--expr"))
        self.assertIn(
            'flake.legacyPackages.x86_64-linux."test-smoke"',
            command[0][4],
        )
        self.assertIn('"private"', command[0][4])

    def test_target_builds_explicit_target_aggregate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "targets/jq").mkdir(parents=True)
            (root / "targets/jq/target.json").write_text("{}\n")
            (root / "nix").mkdir()
            machines = root / "nix/stage-a-builders"
            machines.write_text(
                "ssh-ng://builder x86_64-linux - 1 1 ca-derivations -\n"
            )
            commands = build_commands(root, mode="target", target="jq")

        self.assertIn(
            'flake.legacyPackages.x86_64-linux."test-smoke"',
            commands[0][4],
        )
        self.assertIn(
            'flake.legacyPackages.x86_64-linux."test-target-jq"',
            commands[1][4],
        )
        self.assertIn(f"@{machines.resolve()}", commands[1])

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
            )

            self.assertIn(
                'flake.legacyPackages.x86_64-linux."test-smoke"',
                rendered[0][4],
            )
            self.assertNotIn("test-shard-smoke", rendered[1][4])
            self.assertIn(
                'flake.legacyPackages.x86_64-linux.test-shards."pure-',
                rendered[1][4],
            )
            self.assertEqual(rendered[1][-1:], ("--no-link",))
            self.assertNotIn("--keep-going", rendered[1])

    def test_public_shard_catalog_includes_target_tier(self) -> None:
        flake = (Path(__file__).resolve().parents[3] / "flake.nix").read_text(
            encoding="utf-8"
        )

        self.assertIn('catalogSuite = mkTestSuite "catalog";', flake)
        self.assertIn("test-shards = catalogSuite.shards;", flake)
        self.assertNotIn("test-shards = fullSuite.shards;", flake)

    def test_repository_builder_inventory_overrides_unrelated_host_builders(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "nix").mkdir()
            machines = root / "nix/stage-a-builders"
            machines.write_text("ssh-ng://builder x86_64-linux - 1 1 ca-derivations -\n")

            command = build_commands(root, mode="full")[1]

            self.assertIn("--builders", command)
            self.assertIn(f"@{machines.resolve()}", command)

    def test_affected_nix_test_builds_only_owned_check(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src/spaghetti_extractor").mkdir(parents=True)
            (root / "src/spaghetti_extractor/__init__.py").write_text("")
            (root / "tests/smoke").mkdir(parents=True)
            (root / "tests/smoke/test_smoke.py").write_text("VALUE = 1\n")

            rendered = build_commands(
                root,
                mode="affected",
                changed=("nix/tests/analysis-v3-machine-ir-input.nix",),
            )

            self.assertEqual(len(rendered), 2)
            self.assertIn(
                'flake.checks.x86_64-linux."analysis-v3-machine-ir-input"',
                rendered[1][4],
            )
            self.assertNotIn("test-shard-pure", rendered[1][4])

    def test_evaluation_fingerprint_ignores_only_declared_source_exclusions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            source = root / "src/value.py"
            source.write_text("VALUE = 1\n")
            (root / "build").mkdir()
            ignored = root / "build/generated.json"
            ignored.write_text("one\n")

            initial = _filtered_source_sha256(root)
            ignored.write_text("two\n")
            self.assertEqual(_filtered_source_sha256(root), initial)
            source.write_text("VALUE = 2\n")
            self.assertNotEqual(_filtered_source_sha256(root), initial)

    def test_cached_realisation_preserves_builder_and_failure_flags(self) -> None:
        command = (
            "nix",
            "build",
            "--impure",
            "--expr",
            "let value = 1; in value",
            "--builders",
            "@/work/builders",
            "--option",
            "builders-use-substitutes",
            "true",
            "--keep-going",
            "--no-link",
        )
        with patch("spaghetti_extractor.testkit.runner.subprocess.run") as run:
            run.return_value.returncode = 0
            status = _realise_derivations(
                ("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example.drv",),
                command,
                repository=Path("/work/repo"),
                environment={},
            )

        self.assertEqual(status, 0)
        rendered = run.call_args.args[0]
        self.assertEqual(rendered[:3], (
            "nix",
            "build",
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example.drv^out",
        ))
        self.assertNotIn("--expr", rendered)
        self.assertNotIn("--impure", rendered)
        self.assertIn("--builders", rendered)
        self.assertIn("--keep-going", rendered)

    def test_evaluation_receipt_rejects_corruption_and_wrong_identity(self) -> None:
        derivation = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example.drv"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"
            core = _receipt_core(
                key="k" * 64,
                source_sha256="1" * 64,
                expression_sha256="2" * 64,
                nix_version="nix (Nix) 2.35.1",
                nix_executable="/nix/store/nix/bin/nix",
                derivations=(derivation,),
            )
            expected = {**core, "derivations": []}
            _write_evaluation_receipt(path, core)
            with patch("pathlib.Path.is_file", return_value=True):
                self.assertEqual(
                    _read_evaluation_receipt(path, expected_core=expected),
                    (derivation,),
                )

                payload = json.loads(path.read_text(encoding="ascii"))
                payload["source_sha256"] = "3" * 64
                path.write_bytes(_canonical_json(payload) + b"\n")
                self.assertIsNone(
                    _read_evaluation_receipt(path, expected_core=expected)
                )


if __name__ == "__main__":
    unittest.main()
