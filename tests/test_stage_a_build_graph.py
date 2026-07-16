import json
import os
import shutil
import subprocess
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path
from unittest import mock

from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.relational.build import (
    _locked_flake_input,
    _relational_nix_build_command,
    _relational_nix_expression,
    _relational_node_closure,
    _relational_raw_build_nodes,
    _validate_relational_module_graph,
)
from spaghetti_extractor.relational.schema import RELATIONAL_ACCEPTANCE_THEOREM


class StageABuildGraphTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(__file__).parents[1]

    def test_target_closure_excludes_unrelated_semantic_phase(self):
        graph = {
            "nodes": [
                {"id": "kernel", "modules": ["Kernel"], "dependencies": []},
                {
                    "id": "candidate-decode",
                    "modules": ["CandidateDecode"],
                    "dependencies": ["kernel"],
                },
                {
                    "id": "segment",
                    "modules": ["Segment"],
                    "dependencies": ["candidate-decode"],
                },
                {
                    "id": "unrelated-original-extraction",
                    "modules": ["OriginalExtraction"],
                    "dependencies": ["kernel"],
                },
            ],
        }

        self.assertEqual(
            _relational_node_closure(graph, ["segment"]),
            {"kernel", "candidate-decode", "segment"},
        )

    def test_static_code_map_chunks_are_packed_in_numeric_pages(self):
        modules = {
            "Formal",
            *(f"RelationalStaticCodeMapChunk{index}" for index in range(10)),
        }
        with mock.patch.dict(
            os.environ,
            {
                "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_STATIC_CODE_MAP_NIX_PACK_MODULES": "4"
            },
        ):
            nodes = _relational_raw_build_nodes(modules)

        node_by_id = {node["id"]: node for node in nodes}
        self.assertEqual(
            node_by_id["static-code-map-pack-000"]["modules"],
            [f"RelationalStaticCodeMapChunk{index}" for index in range(4)],
        )
        self.assertEqual(
            node_by_id["static-code-map-pack-001"]["modules"],
            [f"RelationalStaticCodeMapChunk{index}" for index in range(4, 8)],
        )
        self.assertEqual(
            node_by_id["static-code-map-pack-002"]["modules"],
            ["RelationalStaticCodeMapChunk8", "RelationalStaticCodeMapChunk9"],
        )
        self.assertEqual(node_by_id["formal"]["modules"], ["Formal"])
        self.assertEqual(
            {module for node in nodes for module in node["modules"]}, modules
        )

    def test_graph_validation_rejects_omitted_packed_import_dependency(self):
        with tempfile.TemporaryDirectory() as temporary:
            prepared = Path(temporary)
            stage_a = prepared / "lean" / "StageA"
            stage_a.mkdir(parents=True)
            sources = {
                "RelationalStaticCodeMapChunk0": "def chunk0 := 0\n",
                "RelationalStaticEntryTree0Node0": (
                    "import StageA.RelationalStaticCodeMapChunk0\n"
                    "def tree0 := chunk0\n"
                ),
            }
            for module, source in sources.items():
                (stage_a / f"{module}.lean").write_text(source, encoding="utf-8")
            modules = {
                module: {
                    "source": f"lean/StageA/{module}.lean",
                    "source_sha256": sha256(source.encode()).hexdigest(),
                    "imports": (
                        ["RelationalStaticCodeMapChunk0"]
                        if module == "RelationalStaticEntryTree0Node0"
                        else []
                    ),
                }
                for module, source in sources.items()
            }
            graph = {
                "format": "stage-a-lean-module-graph-v1",
                "root_module": "RelationalStaticEntryTree0Node0",
                "final_node": "tree",
                "expected_final_theorem": None,
                "acceptance": {
                    "format": "stage-a-whole-program-acceptance-v1",
                    "status": "incomplete",
                    "required_theorem": RELATIONAL_ACCEPTANCE_THEOREM,
                    "theorem": None,
                    "blockers": [{"next_action": "complete the proof"}],
                },
                "approved_axioms": [],
                "modules": modules,
                "nodes": [
                    {
                        "id": "static-code-map-pack-000",
                        "modules": ["RelationalStaticCodeMapChunk0"],
                        "dependencies": [],
                        "resource_class": "high-memory",
                        "estimated_memory_mb": 4096,
                        "source_sha256": "chunk-pack",
                    },
                    {
                        "id": "tree",
                        "modules": ["RelationalStaticEntryTree0Node0"],
                        "dependencies": [],
                        "resource_class": "light",
                        "estimated_memory_mb": 512,
                        "source_sha256": "tree",
                    },
                ],
            }

            with self.assertRaisesRegex(
                StageAInputError, "dependency inventory does not match imports"
            ):
                _validate_relational_module_graph(prepared, graph)

    def test_nix_expression_content_addresses_sources_not_full_prepared_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            prepared = Path(temporary)
            stage_a = prepared / "lean" / "StageA"
            stage_a.mkdir(parents=True)
            modules = {
                "Kernel": "def kernel := 1\n",
                "CandidateDecode": "import StageA.Kernel\ndef candidate := kernel\n",
                "UnusedReportProof": "def unused := 2\n",
            }
            for module, source in modules.items():
                (stage_a / f"{module}.lean").write_text(source, encoding="utf-8")
            graph = {
                "modules": {
                    module: {"source": f"lean/StageA/{module}.lean"}
                    for module in modules
                },
                "nodes": [
                    {"id": "kernel", "modules": ["Kernel"], "dependencies": []},
                    {
                        "id": "candidate-decode",
                        "modules": ["CandidateDecode"],
                        "dependencies": ["kernel"],
                    },
                    {
                        "id": "unused-report-proof",
                        "modules": ["UnusedReportProof"],
                        "dependencies": [],
                    },
                ],
            }
            (prepared / "module-graph.json").write_text("{}\n", encoding="utf-8")
            (prepared / "prepared-proof.json").write_text("{}\n", encoding="utf-8")
            (prepared / "large-analysis-report.json").write_bytes(b"x" * 4096)

            expression, focused = _relational_nix_expression(
                prepared=prepared,
                graph=graph,
                evaluator=self.repo / "nix" / "stage-a-lean-graph.nix",
                flake_root=self.repo,
                target_node="candidate-decode",
                target_nodes=[],
            )

            self.assertNotIn("prepared = builtins.path", expression)
            self.assertIn("graphFile = builtins.path", expression)
            self.assertIn("preparedManifest = builtins.path", expression)
            self.assertIn("sourceRoot = builtins.toPath", expression)
            self.assertNotIn("large-analysis-report.json", expression)
            self.assertEqual(focused, {
                "nodes": 2,
                "modules": 2,
                "source_bytes": len(modules["Kernel"].encode())
                + len(modules["CandidateDecode"].encode()),
            })

    def test_remote_build_command_disables_local_jobs_and_uses_substitutes(self):
        command = _relational_nix_build_command(
            "proof-expression", Path("/tmp/stage-a-builders")
        )

        self.assertEqual(command[:2], ["nix", "build"])
        self.assertIn("--max-jobs", command)
        self.assertEqual(command[command.index("--max-jobs") + 1], "0")
        self.assertIn("@/tmp/stage-a-builders", command)
        self.assertIn("builders-use-substitutes", command)
        self.assertEqual(command[command.index("builders-use-substitutes") + 1], "true")

    @unittest.skipUnless(shutil.which("nix"), "Nix is required for graph identity check")
    def test_standalone_graph_invalidates_only_import_dependency_closure(self):
        with tempfile.TemporaryDirectory() as temporary:
            source_root = Path(temporary) / "source-v1"
            source_root.mkdir()
            formal = source_root / "Formal.lean"
            consumer = source_root / "Consumer.lean"
            unrelated = source_root / "Unrelated.lean"
            formal.write_text("def formal := 1\n", encoding="utf-8")
            consumer.write_text(
                "import StageA.Formal\ndef consumer := formal\n", encoding="utf-8"
            )
            unrelated.write_text("def unrelated := 1\n", encoding="utf-8")

            initial = self._standalone_target_drv(source_root)
            changed_root = Path(temporary) / "source-v2"
            shutil.copytree(source_root, changed_root)
            (changed_root / "Unrelated.lean").write_text(
                "def unrelated := 2\n", encoding="utf-8"
            )
            after_unrelated = self._standalone_target_drv(changed_root)
            (changed_root / "Formal.lean").write_text(
                "def formal := 2\n", encoding="utf-8"
            )
            after_dependency = self._standalone_target_drv(changed_root)

            self.assertEqual(initial, after_unrelated)
            self.assertNotEqual(initial, after_dependency)

    def _standalone_target_drv(self, source_root: Path) -> str:
        locked_nixpkgs = _locked_flake_input(self.repo / "flake.lock", "nixpkgs")
        evaluator = self.repo / "nix" / "stage-a-lean-graph.nix"
        expression = "\n".join([
            "let",
            "  nixpkgs = builtins.fetchTree (builtins.fromJSON "
            + json.dumps(json.dumps(locked_nixpkgs, sort_keys=True))
            + ");",
            "  pkgs = import nixpkgs { system = builtins.currentSystem; };",
            "  results = import (builtins.toPath " + json.dumps(str(evaluator)) + ") {",
            "    inherit pkgs;",
            "    standaloneSourceRoot = builtins.toPath "
            + json.dumps(str(source_root))
            + ";",
            '    standaloneModules = [ "Formal" "Consumer" "Unrelated" ];',
            '    targetNodes = [ "Consumer" ];',
            "  };",
            "in map (result: result.drvPath) results",
        ])
        process = subprocess.run(
            ["nix", "eval", "--impure", "--json", "--expr", expression],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if process.returncode != 0:
            self.fail("Nix graph identity evaluation failed:\n" + process.stderr[-4000:])
        paths = json.loads(process.stdout)
        self.assertEqual(len(paths), 1)
        return paths[0]


if __name__ == "__main__":
    unittest.main()
