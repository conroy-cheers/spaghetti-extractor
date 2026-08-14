from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.testkit import TestkitError
from spaghetti_extractor.testkit.model import PlannedShard, SuitePlan, canonical_json
from spaghetti_extractor.testkit.static_manifest import (
    STATIC_MANIFEST_FORMAT,
    build_static_test_manifest,
    check_repository_metadata,
    check_static_test_manifest,
    nix_execution_plan_payload,
    refresh_repository_metadata,
)


def _repository(root: Path) -> Path:
    package = root / "src/spaghetti_extractor"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="ascii")
    (package / "base.py").write_text("VALUE = 1\n", encoding="ascii")
    tests = root / "tests/unit/core"
    tests.mkdir(parents=True)
    (tests / "test_base.py").write_text(
        "from spaghetti_extractor.base import VALUE\n",
        encoding="ascii",
    )
    return root


def _metadata_repository(root: Path) -> Path:
    _repository(root)
    (root / "src/spaghetti_extractor/commands").mkdir()
    (root / "src/spaghetti_extractor/commands/__init__.py").write_text(
        "", encoding="ascii"
    )
    (root / "src/spaghetti_extractor/commands/manifest.py").write_text(
        "SUPPORTED_COMMAND_MANIFEST = ()\n", encoding="ascii"
    )
    (root / "pyproject.toml").write_text(
        """
[project]
name = "metadata-fixture"
version = "0"
[project.scripts]
fixture = "spaghetti_extractor.base:main"
""".lstrip(),
        encoding="ascii",
    )
    return root


class StaticTestManifestTests(unittest.TestCase):
    def test_manifest_contains_all_static_modes_and_stable_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = build_static_test_manifest(_repository(Path(temporary)))

        self.assertEqual(manifest["format"], STATIC_MANIFEST_FORMAT)
        self.assertEqual(
            set(manifest["modes"]),
            {"benchmark", "catalog", "full", "smoke"},
        )
        self.assertEqual(len(manifest["shards"]), 1)
        self.assertEqual(manifest["modes"]["full"]["selected_test_count"], 1)

    def test_source_content_change_does_not_churn_topology(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _repository(Path(temporary))
            before = build_static_test_manifest(root)
            (root / "src/spaghetti_extractor/base.py").write_text(
                "VALUE = 2\n",
                encoding="ascii",
            )
            after = build_static_test_manifest(root)

        self.assertEqual(before, after)

    def test_dependency_change_is_detected_as_stale(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _repository(Path(temporary))
            manifest_path = root / "nix/test-suite-manifest.json"
            manifest_path.parent.mkdir()
            manifest_path.write_text(
                canonical_json(build_static_test_manifest(root)),
                encoding="utf-8",
            )
            (root / "src/spaghetti_extractor/other.py").write_text(
                "OTHER = 1\n",
                encoding="ascii",
            )
            (root / "src/spaghetti_extractor/base.py").write_text(
                "from .other import OTHER\nVALUE = OTHER\n",
                encoding="ascii",
            )

            with self.assertRaises(TestkitError) as raised:
                check_static_test_manifest(root, manifest_path)

        self.assertIn("stale_static_test_manifest", str(raised.exception))
        self.assertIn("nix run .#dev -- refresh", str(raised.exception))

    def test_repository_refresh_updates_and_checks_both_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _metadata_repository(Path(temporary))

            changed = refresh_repository_metadata(root)
            check_repository_metadata(root)
            unchanged = refresh_repository_metadata(root)

            self.assertEqual(
                {path.relative_to(root).as_posix() for path in changed},
                {
                    "nix/python-module-index.json",
                    "nix/test-suite-manifest.json",
                },
            )
            self.assertEqual(unchanged, ())

    def test_repository_check_reports_all_stale_metadata_with_one_remediation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _metadata_repository(Path(temporary))
            (root / "nix").mkdir()
            (root / "nix/python-module-index.json").write_text("{}\n", encoding="ascii")
            (root / "nix/test-suite-manifest.json").write_text("{}\n", encoding="ascii")

            with self.assertRaises(TestkitError) as raised:
                check_repository_metadata(root)

        self.assertEqual(len(raised.exception.diagnostics), 1)
        rendered = str(raised.exception)
        self.assertIn("stale_repository_metadata", rendered)
        self.assertIn("nix/python-module-index.json", rendered)
        self.assertIn("nix/test-suite-manifest.json", rendered)
        self.assertEqual(rendered.count("nix run .#dev -- refresh"), 1)

    def test_repository_refresh_rolls_back_if_publication_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _metadata_repository(Path(temporary))
            (root / "nix").mkdir()
            python_index = root / "nix/python-module-index.json"
            test_manifest = root / "nix/test-suite-manifest.json"
            python_index.write_text("old python index\n", encoding="ascii")
            test_manifest.write_text("old test manifest\n", encoding="ascii")
            original_replace = os.replace
            calls = 0

            def fail_second_replace(source: object, destination: object) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("simulated second publication failure")
                original_replace(source, destination)

            with patch(
                "spaghetti_extractor.testkit.static_manifest.os.replace",
                side_effect=fail_second_replace,
            ):
                with self.assertRaisesRegex(
                    TestkitError, "repository_metadata_write_failed"
                ):
                    refresh_repository_metadata(root)

            self.assertEqual(python_index.read_text(encoding="ascii"), "old python index\n")
            self.assertEqual(test_manifest.read_text(encoding="ascii"), "old test manifest\n")

    def test_generic_manifest_does_not_capture_validation_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _repository(Path(temporary))
            (root / "targets/example").mkdir(parents=True)
            (root / "targets/example/target.json").write_text("{}\n", encoding="ascii")
            test = root / "tests/unit/core/test_base.py"
            test.write_text(
                test.read_text(encoding="ascii")
                + 'from pathlib import Path\nTARGETS = Path(__file__).resolve().parents[3] / "targets"\nlist(TARGETS.glob("*"))\n',
                encoding="ascii",
            )

            manifest = build_static_test_manifest(root)

        files = [path for shard in manifest["shards"] for path in shard["files"]]
        self.assertNotIn("targets", files)

    def test_live_plan_filters_target_resources_and_prebuilt_smoke(self) -> None:
        plan = SuitePlan(
            mode="affected",
            index_identity="0" * 64,
            changed_paths=("src/spaghetti_extractor/value.py",),
            selected_tests=("tests/smoke/test_one", "tests/unit/core/test_two"),
            selection_reasons=(),
            shards=(
                PlannedShard("smoke", "small", (), (), (), (), "1" * 64),
                PlannedShard(
                    "pure-one",
                    "small",
                    ("tests/unit/core/test_two",),
                    ("tests/unit/core/test_two.py",),
                    ("src/spaghetti_extractor/value.py", "targets/example"),
                    (),
                    "2" * 64,
                ),
            ),
        )

        payload = nix_execution_plan_payload(
            plan,
            excluded_shards=frozenset({"smoke"}),
        )

        self.assertEqual([row["id"] for row in payload["shards"]], ["pure-one"])
        self.assertEqual(
            payload["shards"][0]["files"],
            ["src/spaghetti_extractor/value.py"],
        )

    def test_corrupted_identity_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _repository(Path(temporary))
            manifest = build_static_test_manifest(root)
            manifest["identity"] = "0" * 64
            path = root / "manifest.json"
            path.write_text(canonical_json(manifest), encoding="utf-8")

            with self.assertRaises(TestkitError) as raised:
                check_static_test_manifest(root, path)

        self.assertIn("identity_mismatch", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
