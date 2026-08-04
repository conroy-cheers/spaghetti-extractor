from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from spaghetti_extractor.target_intent import (
    load_target_bundle,
    validate_authored_intent,
)


class RepositoryBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).parents[1]

    def test_generic_python_package_contains_no_validation_target_modules(self) -> None:
        package = self.root / "src/spaghetti_extractor"
        forbidden = ("gnu_hello", "dxball")
        offenders = [
            path.relative_to(self.root).as_posix()
            for path in package.rglob("*.py")
            if any(name in path.name.lower() for name in forbidden)
        ]
        self.assertEqual(offenders, [])

    def test_generic_python_contains_no_validation_target_policy(self) -> None:
        package = self.root / "src/spaghetti_extractor"
        forbidden = re.compile(
            r"gnu[_ -]?hello|dx[_ -]?ball|"
            r"(?:^|[^a-z0-9])jq(?:[^a-z0-9]|$)"
        )
        allowed = {
            package / "roundtrip_fuzz/genericity.py",
        }
        offenders = []
        for path in sorted(package.rglob("*.py")):
            if path in allowed:
                continue
            for line_number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if forbidden.search(line.lower()):
                    offenders.append(
                        f"{path.relative_to(self.root).as_posix()}:{line_number}"
                    )
        self.assertEqual(offenders, [])

    def test_generic_nix_modules_do_not_import_target_bundles(self) -> None:
        offenders = []
        for path in sorted((self.root / "nix").glob("*.nix")):
            if "targets/" in path.read_text(encoding="utf-8"):
                offenders.append(path.relative_to(self.root).as_posix())
        self.assertEqual(offenders, [])

    def test_generic_distribution_manifest_contains_no_target_paths(self) -> None:
        manifest = (self.root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertNotIn("targets/", manifest)
        self.assertNotIn("gnu-hello", manifest.lower())
        self.assertNotIn("dxball", manifest.lower())

    def test_target_manifests_reference_existing_authored_inputs(self) -> None:
        target_root = self.root / "targets"
        bundles = [load_target_bundle(path) for path in sorted(target_root.iterdir())]
        self.assertEqual(
            [bundle.identity.target_id for bundle in bundles],
            ["dxball", "gnu-hello", "jq"],
        )

    def test_target_intent_contains_no_generated_evidence(self) -> None:
        for path in sorted((self.root / "targets").glob("*/intent/**/*.json")):
            with self.subTest(path=path.relative_to(self.root)):
                payload = json.loads(path.read_text(encoding="utf-8"))
                validate_authored_intent(
                    payload,
                    expected_format=payload.get("format"),
                    context=path.relative_to(self.root).as_posix(),
                )

    def test_machine_generated_reports_are_not_checked_in_as_documentation(self) -> None:
        reports = sorted((self.root / "docs").glob("*.json"))
        self.assertEqual(reports, [])

    def test_repository_map_covers_public_architecture_surfaces(self) -> None:
        repository_map = (self.root / "REPOSITORY_MAP.md").read_text(
            encoding="utf-8"
        )
        readme = (self.root / "README.md").read_text(encoding="utf-8")
        docs_index = (self.root / "docs/README.md").read_text(encoding="utf-8")
        self.assertIn("REPOSITORY_MAP.md", readme)
        self.assertIn("../REPOSITORY_MAP.md", docs_index)

        for heading in (
            "## 2. End-To-End Data Flow",
            "## 3. Authority And Evidence",
            "## 5. Generic Python Package",
            "## 6. Strict Relational Stage A Python",
            "## 7. Reviewed Lean Kernel",
            "## 8. Nix Build System",
            "## 12. Validation Targets",
            "## 14. Validators And Failure Modes",
            "## 15. Test Suites",
            "## 17. Current Concentrations And Cleanup Frontiers",
        ):
            self.assertIn(heading, repository_map)

        public_files = [
            *(self.root / "src/spaghetti_extractor").glob("*.py"),
            *(self.root / "nix").glob("*"),
            *(self.root / "profiles").glob("*"),
            *(self.root / "isa-catalogs").glob("*"),
            *(self.root / "docs").glob("*"),
        ]
        missing = sorted(
            path.relative_to(self.root).as_posix()
            for path in public_files
            if path.is_file() and path.name not in repository_map
        )
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
