from __future__ import annotations

import ast
import json
import re
import unittest
from pathlib import Path

from spaghetti_extractor.build_support.python_module_index import (
    build_python_module_index,
    production_module_closure,
    production_unreachable_modules,
)
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

GRANDFATHERED_PRODUCTION_LINE_LIMITS = {
    # These are single deterministic renderers, fixed points, or closed codecs.
    # Their exact ceilings prevent further growth without manufacturing helper
    # subsystems merely to satisfy a physical-file metric.
    "src/spaghetti_extractor/candidate/native_ingress_runtime_source.py": 2125,
    "src/spaghetti_extractor/candidate/runtime_render_core.py": 2364,
    "src/spaghetti_extractor/reconstruction/contract_analysis.py": 1610,
    "src/spaghetti_extractor/semantic_link/module_v2_codec.py": 1669,
    "src/spaghetti_extractor/semantic_objects/semantic_object.py": 2026,
    "src/spaghetti_extractor/testkit/native_module_fixture.py": 3602,
    "src/spaghetti_extractor/transfer/closure_fixed_point.py": 1775,
    "src/spaghetti_extractor/transfer/compiler.py": 1676,
}
GRANDFATHERED_TEST_LINE_LIMITS = {
    "tests/test_repository_boundaries.py": 1003,
    "tests/unit/candidate/test_native_ingress_exports.py": 1050,
    "tests/unit/candidate/test_native_reference_frontiers.py": 1345,
    "tests/unit/semantic_objects/test_semantic_object.py": 1041,
}

V3_AUTHORITY_PACKAGE = "spaghetti_extractor.authority"
V3_NATIVE_IMPORT_ROOTS = frozenset(
    {
        V3_AUTHORITY_PACKAGE,
        "spaghetti_extractor.abi",
        "spaghetti_extractor.artifacts",
        "spaghetti_extractor.boundary",
        "spaghetti_extractor.calls",
        "spaghetti_extractor.libraries",
        "spaghetti_extractor.transfer",
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
            "spx_*.py",
            "isa_*.py",
            "reconstruction_*.py",
            "external_*.py",
            "component_*.py",
        )
        forbidden_names = {
            "contract_tools.py",
            "static_export.py",
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

    def test_semantic_objects_have_one_behavioral_language_and_no_machine_frontend(self) -> None:
        package = self.root / "src/spaghetti_extractor/semantic_objects"
        forbidden_imports = (
            "spaghetti_extractor.machine_ir",
            "spaghetti_extractor.isa",
            "spaghetti_extractor.reconstruction",
            "spaghetti_extractor.authority",
            "spaghetti_extractor.authority_inputs",
            "spaghetti_extractor.candidate",
            "spaghetti_extractor.components",
        )
        offenders = []
        sources = []
        for path in sorted(package.glob("*.py")):
            source = path.read_text(encoding="utf-8")
            sources.append(source)
            for line, module in _imported_modules(self.root, path):
                if any(_imports_package(module, item) for item in forbidden_imports):
                    offenders.append(
                        f"{path.relative_to(self.root).as_posix()}:{line}:{module}"
                    )
        self.assertEqual(
            offenders,
            [],
            msg=(
                "Semantic objects may index checked transfer-v2 and module-interface "
                "facts only; decoding, machine IR, authority, and candidate systems "
                "must not become a second semantic frontend."
            ),
        )
        joined = "\n".join(sources)
        self.assertIn("executable-transfer-plan-v2", joined)
        for forbidden_literal in (
            "llvm-ir", "mlir", "p-code", "vex-ir", "semantic-interpreter"
        ):
            self.assertNotIn(forbidden_literal, joined.lower())

    def test_scheduled_behavioral_c_has_one_semantic_object_input(self) -> None:
        renderer = (
            self.root / "nix/behavioral-c-package.nix"
        ).read_text(encoding="utf-8")
        self.assertIn("semanticObject", renderer)
        self.assertIn("write_spx_behavioral_c_package_from_semantic_object", renderer)
        self.assertNotIn("transferPlan", renderer)
        sdk = (self.root / "nix/target-sdk.nix").read_text(encoding="utf-8")
        self.assertIn("semanticObject = semanticObjectPackage", sdk)
        self.assertIn("semanticObject = semanticObject.artifact", sdk)
        self.assertIn("isaRequirements =", sdk)
        self.assertIn("qualifiedPlatform = qualifiedPlatform.qualifiedPlatform", sdk)
        object_phase = (
            self.root / "nix/semantic-object.nix"
        ).read_text(encoding="utf-8")
        self.assertIn('isa_requirements=inputs.get("isa_requirements")', object_phase)
        self.assertIn('qualified_platform=inputs.get("qualified_platform")', object_phase)

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

    def test_new_formats_are_not_added_to_legacy_central_declarations(self) -> None:
        snapshot = json.loads(
            (
                self.root
                / "docs/baselines/2026-08-23-format-consumers.json"
            ).read_text(encoding="utf-8")
        )
        legacy_files = {
            "src/spaghetti_extractor/artifacts/formats.py",
            "src/spaghetti_extractor/components/formats.py",
        }
        grandfathered = {
            (row["owner_file"], row["name"], row["literal"])
            for row in snapshot["declarations"]
            if row["owner_file"] in legacy_files
        }
        declaration_name = re.compile(
            r"(?:FORMAT|KIND|SCHEMA|MODEL_ID|PROFILE_ID)(?:_V[0-9]+)?$"
        )
        offenders: list[str] = []
        for relative in sorted(legacy_files):
            path = self.root / relative
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
            for node in tree.body:
                if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                    continue
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                names = [
                    target.id
                    for target in targets
                    if isinstance(target, ast.Name)
                    and declaration_name.search(target.id) is not None
                ]
                try:
                    literal = ast.literal_eval(node.value)
                except (TypeError, ValueError):
                    continue
                if not isinstance(literal, str):
                    continue
                offenders.extend(
                    f"{relative}:{node.lineno}:{name}"
                    for name in names
                    if (relative, name, literal) not in grandfathered
                )
        self.assertEqual(
            offenders,
            [],
            msg=(
                "New formats belong in a domain FORMAT_SPECS declaration; the "
                "legacy shared constant modules are a shrinking migration surface."
            ),
        )

    def test_new_python_nix_phases_use_shared_constructors(self) -> None:
        baseline = json.loads(
            (
                self.root
                / "docs/baselines/2026-08-23-unmanaged-nix-python-phases.json"
            ).read_text(encoding="utf-8")
        )
        grandfathered = set(baseline["unmanaged_python_phase_files"])
        constructors = {
            "nix/ca-python-json-phase.nix",
            "nix/ca-json-receipt-gate.nix",
        }
        observed = {
            path.relative_to(self.root).as_posix()
            for path in (self.root / "nix").rglob("*.nix")
            if "runCommand" in path.read_text(encoding="utf-8")
            and "<<'PY'" in path.read_text(encoding="utf-8")
        }
        unmanaged_new = sorted(observed - constructors - grandfathered)
        self.assertEqual(
            unmanaged_new,
            [],
            msg=(
                "New deterministic Python JSON phases must use "
                "ca-python-json-phase.nix or ca-json-receipt-gate.nix; the "
                "recorded direct-heredoc phase inventory may only shrink."
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

    def test_native_ingress_storage_abi_has_one_literal_owner(self) -> None:
        owner = Path(
            "src/spaghetti_extractor/candidate/native_ingress_runtime_abi.py"
        )
        names = {
            "THREAD_MAGIC",
            "THREAD_ABI_VERSION",
            "THREAD_HEADER_BYTES",
            "INGRESS_FRAME_BYTES",
            "MAX_INGRESS_DEPTH",
            "MAX_CAPABILITY_GENERATIONS",
            "FRAME_REGION_OFFSET",
            "FRAME_REGION_BYTES",
            "STATE_REGION_OFFSET",
            "MACHINE_STATE_BYTES",
            "STATE_PAIR_BYTES",
            "STATE_REGION_BYTES",
            "DIAGNOSTIC_REGION_OFFSET",
            "DIAGNOSTIC_REGION_BYTES",
            "RUNTIME_THREAD_STATE_OFFSET",
            "RUNTIME_THREAD_STATE_BYTES",
            "RUNTIME_CONTEXT_OFFSET",
            "MINIMUM_RUNTIME_CONTROL_BYTES",
            "PRIVATE_STACK_SLICE_BYTES",
        }
        assignments: dict[str, list[str]] = {name: [] for name in names}
        runtime_files = sorted(
            (
                self.root
                / "src/spaghetti_extractor/candidate"
            ).glob("native_ingress_runtime*.py")
        )
        for path in runtime_files:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in tree.body:
                targets = (
                    node.targets
                    if isinstance(node, ast.Assign)
                    else [node.target]
                    if isinstance(node, ast.AnnAssign)
                    else []
                )
                for target in targets:
                    if isinstance(target, ast.Name) and target.id in assignments:
                        assignments[target.id].append(
                            path.relative_to(self.root).as_posix()
                        )
        self.assertEqual(
            assignments,
            {name: [owner.as_posix()] for name in names},
            msg=(
                "The exact native-ingress storage ABI has one owner; import its "
                "constants instead of copying PE-TLS geometry across renderers."
            ),
        )

    def test_retired_execution_backends_and_authority_packages_are_absent(self) -> None:
        retired_paths = (
            "src/spaghetti_extractor/candidate/interpreter.py",
            "src/spaghetti_extractor/candidate/interpreter_package.py",
            "src/spaghetti_extractor/candidate/interpreter_render.py",
            "src/spaghetti_extractor/candidate/engine.py",
            "src/spaghetti_extractor/candidate/authority",
            "src/spaghetti_extractor/machine_ir/coverage.py",
            "src/spaghetti_extractor/components/runtime.py",
            "nix/candidate-interpreter-package.nix",
            "nix/candidate-native-object-graph.nix",
            "nix/fallback-coverage-receipt.nix",
            "nix/component-runtime-package.nix",
            "nix/native-ingress-link-receipt.nix",
            "nix/candidate-hybrid.nix",
            "nix/library-behavior-pack.nix",
            "nix/library-component-generation.nix",
            "nix/machine-ir-isa-qualification.nix",
            "nix/authority-isa-frontiers.nix",
            "src/spaghetti_extractor/candidate/c_backend.py",
            "src/spaghetti_extractor/candidate/c_domains.py",
            "src/spaghetti_extractor/candidate/c_render.py",
            "src/spaghetti_extractor/candidate/api_catalog.py",
            "src/spaghetti_extractor/components/activation_receipt.py",
            "src/spaghetti_extractor/components/adapter.py",
            "src/spaghetti_extractor/components/compile_receipt.py",
            "src/spaghetti_extractor/components/compiler.py",
            "src/spaghetti_extractor/components/development_contract.py",
            "src/spaghetti_extractor/components/interface.py",
            "src/spaghetti_extractor/components/qualification.py",
            "src/spaghetti_extractor/components/runtime_support.py",
            "src/spaghetti_extractor/abi/extraction.py",
            "src/spaghetti_extractor/abi/matching.py",
            "src/spaghetti_extractor/abi/compatibility.py",
            "src/spaghetti_extractor/abi/legacy.py",
            "src/spaghetti_extractor/authority/external_site_records.py",
            "src/spaghetti_extractor/authority/parametric_summary_records.py",
            "src/spaghetti_extractor/authority/authority_common.py",
            "src/spaghetti_extractor/authority/exact_units.py",
            "src/spaghetti_extractor/authority/identities.py",
            "src/spaghetti_extractor/authority/isa_qualification.py",
            "src/spaghetti_extractor/authority/semantic_index.py",
            "src/spaghetti_extractor/authority/planning.py",
            "src/spaghetti_extractor/authority/source_plan.py",
            "src/spaghetti_extractor/authority_inputs",
            "src/spaghetti_extractor/authority",
            "src/spaghetti_extractor/artifacts/phases.py",
            "src/spaghetti_extractor/artifacts/scheduling.py",
            "nix/authority-source-plan.nix",
            "nix/authority-machine-ir-input.nix",
            "nix/artifact-seed-v3.nix",
            "nix/artifact-set-v3.nix",
            "nix/artifact-phase-v3.nix",
        )
        self.assertEqual(
            [path for path in retired_paths if (self.root / path).exists()],
            [],
        )
        production = "\n".join(
            path.read_text(encoding="utf-8")
            for root in (self.root / "src", self.root / "nix")
            for path in root.rglob("*")
            if (
                path.is_file()
                and path.suffix in {".py", ".nix"}
                and path != self.root / "nix/flake-modules/checks.nix"
            )
        )
        for literal in (
            "spaghetti-extractor-semantic-interpreter-program-v1",
            "spaghetti-extractor-semantic-interpreter-package-v1",
            "spaghetti-extractor-candidate-authority-v3",
            "spaghetti-extractor-component-source-package-v2",
            "spaghetti-extractor-component-qualification-v1",
            "spaghetti-extractor-component-resolution-v2",
            "spaghetti-extractor-component-resolution-slice-v1",
            "spaghetti-extractor-semantic-component-catalog-v1",
            "spaghetti-extractor-semantic-component-declarations-v1",
            "spaghetti-extractor-component-interface-spec-v1",
            "spaghetti-extractor-component-interface-refinement-v1",
            "spaghetti-extractor-machine-object-authority-v1",
            "logical-c-v1",
            "logical-object-c-v1",
            "portable-interface-v1",
            "outcomeProtocols",
            "sehProtocols",
            "--outcome-protocol",
            "--seh-protocol",
            "code_capability_passthroughs",
            "NativeCallbackPassthrough",
            "pass_through_environment_pointer",
        ):
            self.assertNotIn(literal, production)

    def test_retired_exception_authority_formats_have_no_production_readers(
        self,
    ) -> None:
        retired = (
            "exception-evidence-v3",
            "exceptional-transitions-v3",
            "exceptional-transitions-v4",
            "spaghetti-extractor-exception-evidence-record-v3",
            "spaghetti-extractor-exceptional-transition-record-v3",
            "spaghetti-extractor-exceptional-transition-record-v4",
            "spaghetti-extractor-exception-closure-certificate-v3",
        )
        offenders: list[str] = []
        for root_name in ("src", "nix", "native", "targets"):
            for path in (self.root / root_name).rglob("*"):
                relative = path.relative_to(self.root).as_posix()
                if (
                    not path.is_file()
                    or path.name == "formats.py"
                    or path.name == "format-registry.json"
                    or relative == "nix/flake-modules/checks.nix"
                    or path.suffix
                    not in {".c", ".h", ".json", ".nix", ".py", ".s"}
                ):
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
                offenders.extend(
                    f"{relative}:{literal}"
                    for literal in retired
                    if literal in text
                )
        self.assertEqual(
            offenders,
            [],
            msg=(
                "Retired exception formats may remain only as domain-owned "
                "registry declarations, never as production readers."
            ),
        )

    def test_retired_authority_checkers_are_physically_absent(self) -> None:
        authority = self.root / "src/spaghetti_extractor/authority"
        for name in (
            "external_site_checker.py",
            "target_certificate_checker.py",
            "exceptional_transitions.py",
            "root_closure.py",
            "final_authority.py",
        ):
            self.assertFalse((authority / name).exists(), name)

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
            "## Static Semantics",
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
        retired_documented_paths = {
            "authority-workflow.nix",
            "candidate/policy_gates.py",
            "component-v4-activation-plan.nix",
            "components/contracts_v5.py",
            "components/generated_behavioral_v4.py",
            "components/implementation_facets_v4.py",
            "components/implementation_v4.py",
            "components/lifecycle_v4.py",
            "components/object_authority.py",
            "components/work_package_v5.py",
            "generated-behavioral-c-provider.nix",
            "intrinsic-semantic-providers.nix",
            "nix/intrinsic-semantic-providers.nix",
            "nix/native-realization.nix",
            "nix/portable-c-semantic-provider.nix",
            "nix/native-ingress-plan.nix",
            "native-linked-skeleton.nix", "semantic_index.py",
            "pe32-machine-object-authority.nix",
            "portable-c-semantic-provider-v2.nix",
            "portable-c-semantic-provider.nix",
            "semantic-provider-selection.nix",
        }
        pattern = re.compile(
            r"`((?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_][A-Za-z0-9_.-]*\.(?:py|nix))`"
        )
        for document_text in document_texts:
            for name in pattern.findall(document_text):
                if name in retired_documented_paths:
                    continue
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
            "spaghetti-extractor-generate-skeleton",
            "spaghetti-extractor-generate-semantic-c",
            "spaghetti-extractor-jq-fixtures-check",
            "spaghetti-extractor-jq-skeleton",
            "spaghetti-extractor-record-candidate",
            '"spaghetti-extractor-validate-candidate"',
            "spaghetti-extractor-explain-delta",
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
        self.assertIn("phase_role = phaseRole", closure)

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
                "spaghetti_extractor.candidate",
                "spaghetti_extractor.components",
            },
            "candidate": {
                "spaghetti_extractor.extraction",
            },
            "components": {
                "spaghetti_extractor.authority",
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
            relative = path.relative_to(self.root).as_posix()
            limit = GRANDFATHERED_PRODUCTION_LINE_LIMITS.get(relative, 1600)
            if line_count > limit:
                offenders.append(
                    f"{relative}: {line_count} lines (limit {limit})"
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
            relative = path.relative_to(self.root).as_posix()
            limit = GRANDFATHERED_TEST_LINE_LIMITS.get(relative, 1000)
            if line_count > limit:
                offenders.append(
                    f"{relative}: {line_count} lines (limit {limit})"
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
