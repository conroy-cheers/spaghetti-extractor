from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

from spaghetti_extractor.python_module_index import production_unreachable_modules
from spaghetti_extractor.analysis_v3.registry import AUTHORITY_PHASE_REGISTRY_V3


TESTKIT = {
    "resources": (
        "README.md",
        "REPOSITORY_MAP.md",
        "docs",
        "flake.nix",
        "isa-catalogs",
        "nix",
        "profiles",
        "pyproject.toml",
    )
}

V3_AUTHORITY_PACKAGE = "spaghetti_extractor.analysis_v3"
V3_NATIVE_IMPORT_ROOTS = frozenset(
    {
        V3_AUTHORITY_PACKAGE,
        "spaghetti_extractor.address_expressions",
        "spaghetti_extractor.artifact_set_v3",
        "spaghetti_extractor.phase_framework_v3",
    }
)
V3_LEGACY_IMPORT_EXCEPTIONS: dict[str, frozenset[str]] = {}
V3_LEGACY_IMPORT_REMEDIATION = (
    "Replace the dependency with native spaghetti_extractor.analysis_v3 records. "
    "Production v3 modules have no legacy import exceptions; do not add one. "
    "Comparison tests must construct native fixture records rather than importing "
    "a legacy analyzer."
)


def _module_name(root: Path, path: Path) -> str:
    relative = path.relative_to(root)
    if relative.parts[0] == "src":
        relative = Path(*relative.parts[1:])
    if relative.name == "__init__.py":
        relative = relative.parent
    else:
        relative = relative.with_suffix("")
    return ".".join(relative.parts)


def _imported_modules(root: Path, path: Path) -> tuple[tuple[int, str], ...]:
    module = _module_name(root, path)
    package = module if path.name == "__init__.py" else module.rpartition(".")[0]
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend((node.lineno, alias.name) for alias in node.names)
            continue
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.level:
            package_parts = package.split(".") if package else []
            trim = node.level - 1
            if trim > len(package_parts):
                raise AssertionError(f"relative import escapes package in {path}")
            target_parts = package_parts[: len(package_parts) - trim]
            if node.module:
                target_parts.extend(node.module.split("."))
            target = ".".join(target_parts)
        else:
            target = node.module or ""
        if node.module is None or target == "spaghetti_extractor":
            imports.extend(
                (node.lineno, f"{target}.{alias.name}".lstrip("."))
                for alias in node.names
                if alias.name != "*"
            )
        elif target:
            imports.append((node.lineno, target))
    return tuple(imports)


def _is_v3_native_import(module: str) -> bool:
    return any(
        module == root or module.startswith(f"{root}.")
        for root in V3_NATIVE_IMPORT_ROOTS
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

    def test_every_package_module_has_a_production_consumer(self) -> None:
        self.assertEqual(production_unreachable_modules(self.root), ())

    def test_generic_python_contains_no_validation_target_policy(self) -> None:
        package = self.root / "src/spaghetti_extractor"
        forbidden = re.compile(
            r"gnu[_ -]?hello|dx[_ -]?ball|"
            r"(?:^|[^a-z0-9])jq(?:[^a-z0-9]|$)"
        )
        offenders = []
        for path in sorted(package.rglob("*.py")):
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

    def test_root_flake_does_not_import_or_name_validation_targets(self) -> None:
        flake = (self.root / "flake.nix").read_text(encoding="utf-8").lower()
        self.assertNotIn("./targets", flake)
        self.assertNotIn("gnu-hello", flake)
        self.assertNotIn("dxball", flake)

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
            "## Runtime Data Flow",
            "## Static Analysis",
            "## Reference Contracts",
            "## Components And Portable Source",
            "## ISA Model And Oracles",
            "## Nix Constructors",
            "## Validation Targets",
            "## Tests",
            "## Adding A Target",
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

    def test_architecture_lists_the_exact_v3_phase_registry(self) -> None:
        architecture = (self.root / "docs" / "architecture.md").read_text(
            encoding="utf-8"
        )
        missing = sorted(
            phase
            for phase in AUTHORITY_PHASE_REGISTRY_V3.names
            if f"`{phase}`" not in architecture
        )
        self.assertEqual(missing, [])

    def test_documented_python_and_nix_files_exist(self) -> None:
        documents = [self.root / "README.md", *(self.root / "docs").glob("*.md")]
        repository_map = (self.root / "REPOSITORY_MAP.md").read_text(
            encoding="utf-8"
        )
        document_texts = [
            *(document.read_text(encoding="utf-8") for document in documents),
            # Test shards intentionally contain only their selected test modules.
            # The production/tooling inventory precedes the Tests section.
            repository_map.split("## Tests", maxsplit=1)[0],
        ]
        available_names = {
            path.name
            for path in self.root.rglob("*")
            if path.is_file() and path.suffix in {".py", ".nix"}
        }
        available_paths = {
            path.relative_to(self.root).as_posix()
            for path in self.root.rglob("*")
            if path.is_file() and path.suffix in {".py", ".nix"}
        }
        missing = []
        pattern = re.compile(
            r"`((?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_][A-Za-z0-9_.-]*\.(?:py|nix))`"
        )
        for document_text in document_texts:
            for name in pattern.findall(document_text):
                if name.startswith("targets/") and not (self.root / "targets").exists():
                    # Generic Nix shards deliberately exclude the validation corpus.
                    # The target flake checks these paths against its explicit registry.
                    continue
                if "/" in name:
                    exists = any(
                        path == name or path.endswith(f"/{name}")
                        for path in available_paths
                    )
                else:
                    exists = name in available_names
                if not exists:
                    missing.append(name)
        self.assertEqual(sorted(set(missing)), [])

    def test_removed_workflows_are_absent_from_public_surfaces(self) -> None:
        public = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (
                self.root / "README.md",
                self.root / "REPOSITORY_MAP.md",
                self.root / "docs" / "architecture.md",
                self.root / "docs" / "target-bundles.md",
                self.root / "pyproject.toml",
                self.root / "flake.nix",
                self.root / "src" / "spaghetti_extractor" / "cli.py",
            )
        )
        for removed in (
            "spaghetti-extractor-slice",
            "stage-b-generate-skeleton",
            "stage-b-generate-semantic-c",
            "stage-a-jq-fixtures-check",
            "stage-b-jq-skeleton",
        ):
            with self.subTest(removed=removed):
                self.assertNotIn(removed, public)

    def test_installed_nix_data_covers_every_generic_nix_surface(self) -> None:
        manifest = (self.root / "pyproject.toml").read_text(encoding="utf-8")
        flake_only = {"target-sdk-v1.nix", "toolkit-context.nix"}
        missing = sorted(
            path.name
            for path in (self.root / "nix").iterdir()
            if path.is_file()
            and path.name not in flake_only
            and f'"nix/{path.name}"' not in manifest
        )
        self.assertEqual(missing, [])

    def test_nix_graph_is_environment_independent_for_evaluation_receipts(self) -> None:
        forbidden = ("builtins.getEnv", "builtins.currentTime")
        offenders = []
        for path in [
            self.root / "flake.nix",
            *(self.root / "nix").glob("*.nix"),
            *(self.root / "targets").glob("**/*.nix"),
        ]:
            source = path.read_text(encoding="utf-8")
            for token in forbidden:
                if token in source:
                    offenders.append(f"{path.relative_to(self.root)}:{token}")
        self.assertEqual(offenders, [])

    def test_v3_authority_consumers_do_not_import_legacy_modules(self) -> None:
        guarded_paths = sorted(
            (self.root / "src/spaghetti_extractor/analysis_v3").rglob("*.py")
        ) + sorted((self.root / "tests/unit/analysis_v3").rglob("*.py"))
        offenders = []
        for path in guarded_paths:
            relative = path.relative_to(self.root).as_posix()
            exceptions = V3_LEGACY_IMPORT_EXCEPTIONS.get(relative, frozenset())
            for line_number, module in _imported_modules(self.root, path):
                if not module.startswith("spaghetti_extractor."):
                    continue
                if _is_v3_native_import(module) or module in exceptions:
                    continue
                offenders.append(f"{relative}:{line_number}: imports {module}")
        self.assertEqual(
            offenders,
            [],
            msg=V3_LEGACY_IMPORT_REMEDIATION,
        )


if __name__ == "__main__":
    unittest.main()
