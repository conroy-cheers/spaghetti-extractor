from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.testkit import TestkitError
from spaghetti_extractor.testkit.model import PlannedShard, SuitePlan, canonical_json
from spaghetti_extractor.testkit.static_manifest import (
    STATIC_MANIFEST_FORMAT,
    build_static_test_manifest,
    check_static_test_manifest,
    nix_execution_plan_payload,
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
        self.assertIn("static_manifest", str(raised.exception))

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
