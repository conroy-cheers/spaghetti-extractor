from __future__ import annotations

import json
from io import StringIO
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.testkit import (
    Diagnostic,
    FixtureCatalog,
    ImpactIndex,
    TestRecord,
    TestkitError,
    apply_scaffold_plan,
    build_suite_plan,
    explain_plan_rebuild,
    plan_phase_scaffold,
    plan_test_scaffold,
)
from spaghetti_extractor.testkit.cli import main as developer_main
from spaghetti_extractor.testkit.fixtures import FIXTURE_MANIFEST_FORMAT


def _record(identity: str, input_hash: str) -> TestRecord:
    return TestRecord(
        id=identity,
        path=f"{identity}.py",
        module=identity.replace("/", "."),
        tier="unit",
        subsystem="testkit",
        capabilities=(),
        dependencies=(),
        dependency_paths=(),
        fixtures=(),
        resources=(),
        sha256=input_hash,
        input_sha256=input_hash,
        shard="pure-00",
    )


class TestDeveloperServices(unittest.TestCase):
    def test_fixture_lookup_uses_one_nix_supplied_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            realized = root / "kernel"
            realized.mkdir()
            manifest = root / "fixtures.json"
            manifest.write_text(
                json.dumps(
                    {
                        "format": FIXTURE_MANIFEST_FORMAT,
                        "fixtures": {"lean-isa-runner": str(realized)},
                        "definitions": {
                            "lean-isa-runner": {
                                "description": "shared kernel",
                                "capabilities": ["lean"],
                                "nix_attribute": "isa-kernel",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            catalog = FixtureCatalog.from_environment({"SPAGHETTI_TEST_FIXTURES": str(manifest)})

            self.assertEqual(catalog.lookup("lean-isa-runner"), realized)
            self.assertEqual(catalog.describe("lean-isa-runner")["description"], "shared kernel")
            with self.assertRaisesRegex(TestkitError, "fixture_not_realized"):
                catalog.lookup("headless-wine")

    def test_rebuild_explanation_distinguishes_substitution_from_changed_input(self) -> None:
        old_index = ImpactIndex(repository=".", modules=(), tests=(_record("tests/unit/test_one", "1" * 64),))
        same = build_suite_plan(old_index, mode="full")
        changed_index = ImpactIndex(repository=".", modules=(), tests=(_record("tests/unit/test_one", "2" * 64),))
        changed = build_suite_plan(changed_index, mode="full")

        unchanged = explain_plan_rebuild(same, same)
        rebuilt = explain_plan_rebuild(same, changed)

        self.assertEqual(unchanged["artifacts"][0]["disposition"], "substitute")
        self.assertEqual(rebuilt["artifacts"][0]["disposition"], "rebuild")
        self.assertIn("imported source", rebuilt["artifacts"][0]["reasons"][0])

    def test_scaffolds_render_valid_convention_paths_and_next_commands(self) -> None:
        test = plan_test_scaffold(subsystem="memory", name="alias_kill")
        phase = plan_phase_scaffold(phase_kind="map-sccs", name="alias_summary")

        self.assertEqual(test.files[0].path, "tests/unit/memory/test_alias_kill.py")
        self.assertIn("nix run .#test -- affected", test.next_commands[0])
        self.assertEqual(phase.files[0].path, "src/spaghetti_extractor/authority/alias_summary.py")
        self.assertIn("phase_framework_v3", phase.files[0].content)

    def test_scaffold_apply_creates_files_and_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            plan = plan_test_scaffold(subsystem="memory", name="alias_kill")

            with patch(
                "spaghetti_extractor.testkit.scaffold.refresh_repository_metadata"
            ) as refresh:
                created = apply_scaffold_plan(repository, plan)

            self.assertEqual(created, (repository / plan.files[0].path,))
            refresh.assert_called_once_with(repository.resolve())
            self.assertIn("class AliasKillTests", created[0].read_text(encoding="ascii"))
            with self.assertRaisesRegex(TestkitError, "scaffold_destination_exists"):
                apply_scaffold_plan(repository, plan)

    def test_scaffold_rolls_back_new_files_when_metadata_refresh_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            plan = plan_test_scaffold(subsystem="memory", name="alias_kill")
            failure = TestkitError(
                Diagnostic("error", "refresh_failed", "metadata generation failed")
            )

            with patch(
                "spaghetti_extractor.testkit.scaffold.refresh_repository_metadata",
                side_effect=failure,
            ):
                with self.assertRaisesRegex(TestkitError, "refresh_failed"):
                    apply_scaffold_plan(repository, plan)

            self.assertFalse((repository / plan.files[0].path).exists())
            self.assertFalse((repository / "tests").exists())

    def test_refresh_command_uses_joint_repository_metadata_service(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            updated = repository / "nix/python-module-index.json"
            output = StringIO()

            with patch(
                "spaghetti_extractor.testkit.cli.refresh_repository_metadata",
                return_value=(updated,),
            ) as refresh:
                with redirect_stdout(output):
                    status = developer_main(
                        ["--repository", str(repository), "refresh", "--check"]
                    )

            self.assertEqual(status, 0)
            refresh.assert_called_once_with(repository.resolve(), check=True)
            self.assertEqual(output.getvalue(), "current repository metadata\n")


if __name__ == "__main__":
    unittest.main()
