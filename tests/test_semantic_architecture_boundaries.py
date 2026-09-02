from __future__ import annotations

import ast
import unittest
from pathlib import Path

TESTKIT = {
    "resources": (
        "src/spaghetti_extractor/testkit/project_semantic_fixture.py",
        "targets/flake.nix",
    )
}


class SemanticArchitectureBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1]

    def test_architecture_names_the_canonical_semantic_module(self) -> None:
        architecture = (self.root / "docs" / "architecture.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("`semantic-object-v1`", architecture)
        self.assertIn("`linked-semantic-module-v2`", architecture)
        self.assertNotIn("`linked-semantic-module-v1`", architecture)
        self.assertFalse(
            (self.root / "src/spaghetti_extractor/authority/registry.py").exists()
        )
        self.assertFalse(
            (self.root / "src/spaghetti_extractor/authority/graph.py").exists()
        )

    def test_production_semantic_link_has_one_packaged_input(self) -> None:
        linker_path = (
            self.root
            / "src/spaghetti_extractor/semantic_link/may_link.py"
        )
        linker = ast.parse(
            linker_path.read_text(encoding="utf-8"),
            filename=str(linker_path),
        )
        compile_function = next(
            node for node in linker.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "compile_semantic_may_link_facts_v2"
        )
        parameters = {
            argument.arg
            for argument in (
                *compile_function.args.args,
                *compile_function.args.kwonlyargs,
            )
        }
        self.assertEqual(parameters, {"semantic_object"})

        imported_modules: set[str] = set()
        for node in ast.walk(linker):
            if isinstance(node, ast.Import):
                imported_modules.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                if node.level:
                    package = ["spaghetti_extractor", "semantic_link"]
                    base = package[:len(package) - node.level + 1]
                    imported_modules.add(".".join((*base, node.module)))
                else:
                    imported_modules.add(node.module)
        forbidden = (
            "spaghetti_extractor.reconstruction",
            "spaghetti_extractor.transfer",
            "spaghetti_extractor.pe32",
            "spaghetti_extractor.isa",
            "z3",
            "capstone",
        )
        self.assertFalse(any(
            module == prefix or module.startswith(f"{prefix}.")
            for module in imported_modules
            for prefix in forbidden
        ))

        production_nix = (
            self.root / "nix/linked-semantic-module.nix"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "inputs = {\n      semantic_object = semanticObject;\n    };",
            production_nix,
        )
        for forbidden_input in (
            "original,",
            "behavioralRoots,",
            "maximumWorklistSteps",
            "maximumCpuMilliseconds",
            "maximumPreparedLinkMilliseconds",
            "linked-semantic-module-performance.nix",
        ):
            self.assertNotIn(forbidden_input, production_nix)

        diagnostic_nix = (
            self.root / "nix/linked-semantic-module-performance.nix"
        ).read_text(encoding="utf-8")
        self.assertIn('phaseRole = "developer";', diagnostic_nix)
        self.assertIn("behavioralRoots", diagnostic_nix)
        self.assertIn("original", diagnostic_nix)

        sdk = (self.root / "nix/target-sdk.nix").read_text(encoding="utf-8")
        self.assertNotIn("linkedSemanticModulePerformancePackage", sdk)
        target_orchestrator = (
            self.root / "targets/flake.nix"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "import ../nix/linked-semantic-module-performance.nix",
            target_orchestrator,
        )
        self.assertIn(
            "canonical = \"${bundles.gnu-hello.artifacts.candidate."
            "linked-semantic-module}/linked-semantic-module.json\";",
            target_orchestrator,
        )

    def test_project_load_planning_consumes_linked_modules_not_ingress(self) -> None:
        planner_path = (
            self.root
            / "src/spaghetti_extractor/candidate/project_load_plan.py"
        )
        planner = ast.parse(
            planner_path.read_text(encoding="utf-8"),
            filename=str(planner_path),
        )
        function = next(
            node for node in planner.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "write_pe32_project_load_plan"
        )
        parameters = {
            argument.arg
            for argument in (*function.args.args, *function.args.kwonlyargs)
        }
        self.assertIn("linked_semantic_modules", parameters)
        self.assertNotIn("module_interfaces", parameters)
        self.assertNotIn("native_ingress_plans", parameters)
        self.assertNotIn("edge_authorities", parameters)
        planner_source = planner_path.read_text(encoding="utf-8")
        self.assertIn("LinkedSemanticModuleV2", planner_source)
        self.assertNotIn("LinkedSemanticModuleV1", planner_source)

        nix_planner = (
            self.root / "nix/pe32-project-load-plan.nix"
        ).read_text(encoding="utf-8")
        self.assertIn("linkedSemanticModules", nix_planner)
        self.assertNotIn("/linked-semantic-module.json", nix_planner)
        self.assertNotIn("moduleInterfaces", nix_planner)
        self.assertNotIn("nativeIngress", nix_planner)
        self.assertNotIn("edgeAuthorities", nix_planner)
        for relative in (
            "nix/target-sdk.nix",
            "src/spaghetti_extractor/commands/runtime.py",
            "src/spaghetti_extractor/testkit/project_semantic_fixture.py",
        ):
            source = (self.root / relative).read_text(encoding="utf-8")
            self.assertNotIn("edgeAuthorities", source)
            self.assertNotIn("edge_authorities", source)
        semantic_link = (
            self.root / "src/spaghetti_extractor/semantic_link/module.py"
        ).read_text(encoding="utf-8")
        self.assertIn('effects["import_uses"]', semantic_link)

        sdk = (self.root / "nix/target-sdk.nix").read_text(encoding="utf-8")
        self.assertIn("linkedSemanticModule.linkedSemanticModule", sdk)
        self.assertNotIn("linkedSemanticModuleV2", sdk)
        self.assertNotIn("v2Derivation", sdk)
        self.assertNotIn("nativeIngressPlans", sdk)
        self.assertNotIn("nativeIngressPlan", sdk)
        self.assertNotIn("moduleNativeIngressPlan", sdk)
        self.assertFalse((self.root / "nix/native-ingress-plan.nix").exists())

        completion = (
            self.root / "src/spaghetti_extractor/candidate/project.py"
        ).read_text(encoding="utf-8")
        self.assertIn("NativeRealizationV2", completion)
        self.assertNotIn("NativeRealizationV1", completion)

        command = (
            self.root / "src/spaghetti_extractor/commands/runtime.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn('"--module-interface"', command)
        self.assertNotIn("native_ingress_plans=", command)
        self.assertNotIn("candidate-native-ingress-plan", command)
        self.assertIn('"--linked-semantic-module"', command)

        facade = (
            self.root
            / "src/spaghetti_extractor/candidate/native_ingress.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn('"write_native_ingress_plan"', facade)

    def test_public_project_exports_linked_module_packages(self) -> None:
        target_sdk = (
            self.root / "nix/target-sdk.nix"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "imageWorkflow.linkedSemanticModule.derivation",
            target_sdk,
        )
        self.assertNotIn(
            "linked-semantic-modules = project.linkedSemanticModules;",
            target_sdk,
        )


if __name__ == "__main__":
    unittest.main()
