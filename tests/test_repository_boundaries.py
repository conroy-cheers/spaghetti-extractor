from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

from spaghetti_extractor.build_support.python_module_index import (
    build_python_module_index,
    production_module_closure,
    production_unreachable_modules,
)
from spaghetti_extractor.authority.registry import AUTHORITY_PHASE_REGISTRY_V3


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

V3_AUTHORITY_PACKAGE = "spaghetti_extractor.authority"
V3_NATIVE_IMPORT_ROOTS = frozenset(
    {
        V3_AUTHORITY_PACKAGE,
        "spaghetti_extractor.authority_inputs.address_expressions",
        "spaghetti_extractor.artifacts",
    }
)
V3_LEGACY_IMPORT_EXCEPTIONS: dict[str, frozenset[str]] = {}
V3_LEGACY_IMPORT_REMEDIATION = (
    "Replace the dependency with native spaghetti_extractor.authority records. "
    "Production v3 modules have no legacy import exceptions; do not add one. "
    "Comparison tests must construct native fixture records rather than importing "
    "a legacy analyzer."
)


def _imports_package(module: str, package: str) -> bool:
    return module == package or module.startswith(f"{package}.")


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

    def test_isa_implementation_is_owned_by_isa_package(self) -> None:
        package = self.root / "src/spaghetti_extractor"
        self.assertTrue((package / "isa/__init__.py").is_file())
        self.assertEqual(
            sorted(path.name for path in package.glob("isa_*.py")),
            [],
            msg=(
                "ISA implementation modules belong under spaghetti_extractor/isa; "
                "do not restore flat package-root modules or compatibility shims."
            ),
        )

    def test_pipeline_families_have_no_flat_compatibility_modules(self) -> None:
        package = self.root / "src/spaghetti_extractor"
        forbidden_patterns = (
            "stage_b_*.py",
            "isa_*.py",
            "reconstruction_*.py",
            "external_*.py",
            "component_*.py",
        )
        forbidden_names = {
            "contract_tools.py",
            "opaque_reconstruction.py",
            "rooted_state_machine.py",
            "semantic_components.py",
        }
        offenders = sorted(
            {
                path.name
                for pattern in forbidden_patterns
                for path in package.glob(pattern)
            }
            | {name for name in forbidden_names if (package / name).exists()}
        )
        self.assertEqual(
            offenders,
            [],
            msg=(
                "Pipeline implementations belong to their ownership package; "
                "Git history, not root-level compatibility shims, preserves old paths."
            ),
        )

    def test_candidate_role_closure_excludes_proposal_and_diagnostic_code(self) -> None:
        index = build_python_module_index(self.root)
        closure = set(
            production_module_closure(self.root, index, roles={"candidate"})
        )
        forbidden_prefixes = (
            "spaghetti_extractor.commands.proposals",
            "spaghetti_extractor.external.site_proposals",
        )
        offenders = sorted(
            module
            for module in closure
            if module.startswith(forbidden_prefixes)
        )
        self.assertEqual(offenders, [])

    def test_every_package_module_has_a_production_consumer(self) -> None:
        self.assertEqual(production_unreachable_modules(self.root), ())

    def test_shared_artifact_formats_have_production_consumers(self) -> None:
        formats_path = (
            self.root / "src/spaghetti_extractor/artifacts/formats.py"
        )
        namespace: dict[str, object] = {}
        exec(formats_path.read_text(encoding="utf-8"), namespace)
        exports = namespace["__all__"]
        production_sources = {
            path: path.read_text(encoding="utf-8")
            for path in (self.root / "src/spaghetti_extractor").rglob("*.py")
            if path != formats_path
        }
        unused = sorted(
            name
            for name in exports
            if not any(name in source for source in production_sources.values())
        )
        self.assertEqual(
            unused,
            [],
            msg=(
                "Remove dead shared format identifiers instead of retaining "
                "formats with no producer or consumer."
            ),
        )

    def test_cross_module_artifact_identifiers_are_declared_once(self) -> None:
        declarations: dict[str, list[str]] = {}
        suffixes = ("FORMAT", "MODEL_ID", "PROFILE_ID", "ARTIFACT_KIND")
        package = self.root / "src/spaghetti_extractor"
        for path in sorted(package.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in tree.body:
                if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                names = [target.id for target in targets if isinstance(target, ast.Name)]
                if not any(name.endswith(suffixes) for name in names):
                    continue
                try:
                    value = ast.literal_eval(node.value)
                except (TypeError, ValueError):
                    continue
                if not isinstance(value, str):
                    continue
                declarations.setdefault(value, []).append(
                    path.relative_to(self.root).as_posix()
                )
        duplicates = {
            value: sorted(set(paths))
            for value, paths in declarations.items()
            if len(set(paths)) > 1
        }
        self.assertEqual(
            duplicates,
            {},
            msg=(
                "A cross-module artifact identifier has one literal owner. Import "
                "shared identifiers from artifacts/formats.py instead of copying strings."
            ),
        )

    def test_authorizing_record_fields_are_typed_before_codec_boundaries(self) -> None:
        offenders = []
        record_paths = sorted(
            (self.root / "src/spaghetti_extractor/authority").glob("*_records.py")
        )
        for path in record_paths:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for class_node in (
                node for node in tree.body if isinstance(node, ast.ClassDef)
            ):
                for node in class_node.body:
                    if not isinstance(node, ast.AnnAssign):
                        continue
                    annotation = ast.unparse(node.annotation)
                    if "Any" in annotation or "dict[" in annotation or "Mapping[" in annotation:
                        offenders.append(
                            f"{path.relative_to(self.root).as_posix()}:"
                            f"{node.lineno}:{class_node.name}.{ast.unparse(node.target)}"
                        )
        self.assertEqual(
            offenders,
            [],
            msg=(
                "Authorizing phase records use typed immutable fields. Catch-all "
                "JSON mappings belong in parse/encode functions, not checked records."
            ),
        )

    def test_record_source_closures_do_not_pull_authority_checkers(self) -> None:
        modules = build_python_module_index(self.root)["modules"]
        for record_module, checker_module in (
            (
                "spaghetti_extractor.authority.external_site_records",
                "spaghetti_extractor.authority.external_site_checker",
            ),
            (
                "spaghetti_extractor.authority.target_certificate_records",
                "spaghetti_extractor.authority.target_certificate_checker",
            ),
        ):
            with self.subTest(record_module=record_module):
                pending = [record_module]
                closure = set()
                while pending:
                    module = pending.pop()
                    if module in closure:
                        continue
                    closure.add(module)
                    pending.extend(modules[module]["dependencies"])
                self.assertNotIn(checker_module, closure)

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
        public_paths = [
                self.root / "README.md",
                self.root / "REPOSITORY_MAP.md",
                self.root / "docs" / "architecture.md",
                self.root / "docs" / "target-bundles.md",
                self.root / "pyproject.toml",
                self.root / "flake.nix",
                self.root / "src" / "spaghetti_extractor" / "cli.py",
                *sorted(
                    (self.root / "src" / "spaghetti_extractor" / "commands").glob(
                        "*.py"
                    )
                ),
        ]
        public = "\n".join(
            path.read_text(encoding="utf-8") for path in public_paths
        )
        for removed in (
            "spaghetti-extractor-slice",
            "stage-b-generate-skeleton",
            "stage-b-generate-semantic-c",
            "stage-a-jq-fixtures-check",
            "stage-b-jq-skeleton",
            "stage-b-record-candidate",
            '"stage-b-validate-candidate"',
            "stage-b-explain-delta",
        ):
            with self.subTest(removed=removed):
                self.assertNotIn(removed, public)

    def test_python_distribution_does_not_duplicate_nix_or_profile_inventory(self) -> None:
        manifest = (self.root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertNotIn(
            "[tool.setuptools.data-files]",
            manifest,
            msg=(
                "Nix owns the supported toolkit distribution. Do not restore a "
                "second hand-maintained setuptools inventory for Nix/profile files."
            ),
        )

    def test_test_metadata_does_not_invalidate_the_installed_toolkit(self) -> None:
        context = (self.root / "nix/toolkit-context.nix").read_text(
            encoding="utf-8"
        )
        manifest = (self.root / "pyproject.toml").read_text(encoding="utf-8")
        for path in (
            "nix/test-suite-fixtures.nix",
            "nix/generated/test-suite-manifest.json",
            "nix/test-suite-plan.nix",
            "nix/test-suite-shard.nix",
            "nix/test-suite.nix",
        ):
            with self.subTest(path=path):
                self.assertIn(f"../{path}", context)
                self.assertNotIn(f'"{path}"', manifest)
        self.assertIn(
            "pkgs.lib.fileset.difference ../nix developerOnlyNixFiles",
            context,
        )

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

    def test_python_module_closures_declare_and_record_phase_roles(self) -> None:
        offenders = []
        for path in sorted((self.root / "nix").rglob("*.nix")):
            lines = path.read_text(encoding="utf-8").splitlines()
            for index, line in enumerate(lines):
                if "python-module-closure.nix {" not in line:
                    continue
                nearby = "\n".join(lines[index + 1 : index + 6])
                if "phaseRole" not in nearby:
                    offenders.append(
                        f"{path.relative_to(self.root).as_posix()}:{index + 1}"
                    )
        self.assertEqual(
            offenders,
            [],
            msg=(
                "Every Python closure must state its authority role at the call "
                "site; filenames are not an authority policy."
            ),
        )
        closure = (self.root / "nix/python-module-closure.nix").read_text(
            encoding="utf-8"
        )
        self.assertIn('"phase_role": phase_role', closure)

    def test_v3_authority_consumers_do_not_import_legacy_modules(self) -> None:
        guarded_paths = sorted(
            (self.root / "src/spaghetti_extractor/authority").rglob("*.py")
        ) + sorted((self.root / "tests/unit/authority").rglob("*.py"))
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

    def test_pipeline_packages_follow_the_supported_dependency_direction(self) -> None:
        """Keep proposal, authority, and implementation layers independently usable."""

        package_rules = {
            "extraction": {
                "spaghetti_extractor.authority",
                "spaghetti_extractor.authority_inputs",
                "spaghetti_extractor.candidate",
                "spaghetti_extractor.components",
            },
            "authority_inputs": {
                "spaghetti_extractor.authority.diagnostics",
                "spaghetti_extractor.authority.final_authority",
                "spaghetti_extractor.authority.planning",
                "spaghetti_extractor.authority.registry",
                "spaghetti_extractor.candidate",
                "spaghetti_extractor.components",
            },
            "candidate": {
                "spaghetti_extractor.authority.diagnostics",
                "spaghetti_extractor.authority.planning",
                "spaghetti_extractor.authority.registry",
                "spaghetti_extractor.authority_inputs",
                "spaghetti_extractor.extraction",
            },
            "components": {
                "spaghetti_extractor.authority",
                "spaghetti_extractor.authority_inputs",
                "spaghetti_extractor.candidate",
                "spaghetti_extractor.extraction",
            },
        }
        offenders = []
        for package_name, forbidden_packages in package_rules.items():
            package = self.root / "src/spaghetti_extractor" / package_name
            for path in sorted(package.rglob("*.py")):
                relative = path.relative_to(self.root).as_posix()
                for line_number, module in _imported_modules(self.root, path):
                    if any(
                        _imports_package(module, forbidden)
                        for forbidden in forbidden_packages
                    ):
                        offenders.append(
                            f"{relative}:{line_number}: imports {module}"
                        )
        self.assertEqual(
            offenders,
            [],
            msg=(
                "Layer ownership is strict: extraction cannot depend on proof or "
                "candidate layers; authority-input adapters cannot depend on "
                "terminal authority; candidate code may consume final authority "
                "but not proposal machinery; components stay authority-neutral. "
                "Move shared data to a dependency-free schema module."
            ),
        )

    def test_package_root_contains_only_entrypoints_and_shared_primitives(self) -> None:
        package = self.root / "src/spaghetti_extractor"
        expected = {
            "__init__.py",
            "__main__.py",
            "cli.py",
            "errors.py",
            "util.py",
        }
        actual = {path.name for path in package.glob("*.py")}
        self.assertEqual(actual, expected)
        root_lines = sum(
            len(path.read_text(encoding="utf-8").splitlines())
            for path in package.glob("*.py")
        )
        self.assertLessEqual(
            root_lines,
            500,
            msg=(
                "The package root is a stable entrypoint surface, not an "
                "implementation ownership bucket. Move behavior into a domain package."
            ),
        )

    def test_all_production_modules_remain_reviewable(self) -> None:
        offenders = []
        package = self.root / "src/spaghetti_extractor"
        for path in sorted(package.rglob("*.py")):
            line_count = len(path.read_text(encoding="utf-8").splitlines())
            if line_count > 1600:
                offenders.append(
                    f"{path.relative_to(self.root).as_posix()}: {line_count} lines"
                )
        self.assertEqual(
            offenders,
            [],
            msg=(
                "Every production package is guarded, including package-root and "
                "round-trip code. Split modules by model, codec, checker, and phase "
                "ownership before adding more behavior."
            ),
        )

    def test_test_modules_remain_shardable_by_behavior(self) -> None:
        offenders = []
        for path in sorted((self.root / "tests").rglob("*.py")):
            line_count = len(path.read_text(encoding="utf-8").splitlines())
            if line_count > 1000:
                offenders.append(
                    f"{path.relative_to(self.root).as_posix()}: {line_count} lines"
                )
        self.assertEqual(
            offenders,
            [],
            msg=(
                "Split tests by model, validation, rendering, receipt, or failure "
                "policy so the static Nix sharder can invalidate them independently."
            ),
        )


if __name__ == "__main__":
    unittest.main()
