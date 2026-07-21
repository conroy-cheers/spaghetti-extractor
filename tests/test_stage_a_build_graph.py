import json
import os
import shutil
import subprocess
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.relational.build import (
    _finalize_nix_proof_ir,
    _locked_flake_input,
    _relational_nix_build_command,
    _relational_nix_realize_command,
    _relational_nix_expression,
    _relational_node_closure,
    _relational_raw_build_nodes,
    _validate_relational_module_graph,
    _write_relational_module_graph,
    stage_a_build_relational_from_nix,
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

    def test_acceptance_closure_excludes_auxiliary_proof_roots(self):
        graph = {
            "nodes": [
                {"id": "kernel", "modules": ["Kernel"], "dependencies": []},
                {
                    "id": "segment",
                    "modules": ["Segment"],
                    "dependencies": ["kernel"],
                },
                {
                    "id": "acceptance",
                    "modules": ["Acceptance"],
                    "dependencies": ["segment"],
                },
                {
                    "id": "auxiliary-analysis",
                    "modules": ["AuxiliaryAnalysis"],
                    "dependencies": ["kernel"],
                },
            ],
        }

        self.assertEqual(
            _relational_node_closure(graph, ["acceptance"]),
            {"kernel", "segment", "acceptance"},
        )

    def test_affine_call_bindings_are_an_auxiliary_proof_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            prepared = Path(temporary)
            stage_a = prepared / "lean" / "StageA"
            stage_a.mkdir(parents=True)
            (stage_a / "RelationalBundle.lean").write_text(
                "def relationalBundle := 0\n", encoding="utf-8"
            )
            (stage_a / "RelationalAffineLinkedCallBindings.lean").write_text(
                "def checkedAffineCalls := 0\n", encoding="utf-8"
            )
            (prepared / "whole-program-acceptance.json").write_text(
                json.dumps({
                    "format": "stage-a-whole-program-acceptance-v1",
                    "status": "incomplete",
                    "required_theorem": RELATIONAL_ACCEPTANCE_THEOREM,
                    "theorem": None,
                    "blockers": [{"next_action": "complete composition"}],
                }),
                encoding="utf-8",
            )

            binary = SimpleNamespace(sha256="00" * 32)
            graph = _write_relational_module_graph(
                prepared,
                original_bin=binary,
                candidate_bin=binary,
                trusted_base={"approved_axioms": []},
            )

            self.assertIn(
                "RelationalAffineLinkedCallBindings",
                graph["auxiliary_modules"],
            )
            self.assertIn(
                "RelationalAffineLinkedCallBindings", graph["modules"]
            )

    def test_final_theorem_records_runtime_frame_and_launch_obligation_witnesses(self):
        obligations = [
            {"id": f"obligation:{kind}", "kind": kind, "status": "incomplete"}
            for kind in (
                "paired_stack_range_world",
                "return_pop",
                "return_slot_runtime_frame",
                "stack_window_reachability",
                "relational_segment_refinement",
            )
        ]

        finalized = _finalize_nix_proof_ir(
            {"obligations": obligations},
            theorem_checked=True,
            theorem=RELATIONAL_ACCEPTANCE_THEOREM,
            result_path=Path("/nix/store/checked-proof"),
        )

        self.assertEqual(finalized["status"], "satisfied")
        self.assertTrue(all(
            obligation["status"] == "proved"
            for obligation in finalized["obligations"]
        ))
        evidence_by_kind = {
            obligation["kind"]: obligation["evidence"]
            for obligation in finalized["obligations"]
        }
        self.assertEqual(
            evidence_by_kind["paired_stack_range_world"]["certificate_field"],
            "WholeProgramCertificate.launchRealizable",
        )
        self.assertEqual(
            evidence_by_kind["return_pop"]["certificate_field"],
            "WholeProgramCertificate.runningProductNodesRefined",
        )
        self.assertEqual(
            evidence_by_kind["relational_segment_refinement"]["certificate_field"],
            "WholeProgramCertificate.reachableExecutionEdgesRefined",
        )

    def test_final_theorem_projects_runtime_obligations_from_its_certificate(self):
        runtime_kinds = (
            "direct_call_push",
            "return_slot_affine_transfer",
            "return_slot_return_affine_transfer",
            "machine_import_call_boundary",
            "external_jump_control_refinement",
            "memory_transition_preservation",
        )
        finalized = _finalize_nix_proof_ir(
            {
                "obligations": [
                    {
                        "id": f"obligation:{kind}",
                        "kind": kind,
                        "status": "incomplete",
                    }
                    for kind in runtime_kinds
                ]
            },
            theorem_checked=True,
            theorem=RELATIONAL_ACCEPTANCE_THEOREM,
            result_path=Path("/nix/store/checked-proof"),
        )

        self.assertEqual(finalized["status"], "satisfied")
        evidence_by_kind = {
            obligation["kind"]: obligation["evidence"]
            for obligation in finalized["obligations"]
        }
        self.assertIn(
            "WholeProgramCertificate.runningProductNodesRefined",
            evidence_by_kind["direct_call_push"]["certificate_fields"],
        )
        self.assertIn(
            "WholeProgramCertificate.environmentsRefined",
            evidence_by_kind["machine_import_call_boundary"]["certificate_fields"],
        )
        self.assertEqual(
            evidence_by_kind["memory_transition_preservation"][
                "certificate_fields"
            ],
            [
                "WholeProgramCertificate.reachableExecutionEdgesRefined",
                "WholeProgramCertificate.runningProductNodesRefined",
            ],
        )

    def test_final_theorem_does_not_close_unknown_proof_inventory_obligations(self):
        finalized = _finalize_nix_proof_ir(
            {"obligations": [{
                "id": "obligation:unknown",
                "kind": "future_unmodeled_requirement",
                "status": "incomplete",
            }]},
            theorem_checked=True,
            theorem=RELATIONAL_ACCEPTANCE_THEOREM,
            result_path=Path("/nix/store/checked-proof"),
        )

        self.assertEqual(finalized["status"], "incomplete")
        self.assertEqual(finalized["obligations"][0]["status"], "incomplete")

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

    def test_static_code_map_chunks_are_individually_cacheable_by_default(self):
        modules = {
            "Formal",
            *(f"RelationalStaticCodeMapChunk{index}" for index in range(3)),
        }
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(
                "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_STATIC_CODE_MAP_NIX_PACK_MODULES",
                None,
            )
            nodes = _relational_raw_build_nodes(modules)

        static_nodes = [
            node for node in nodes if node["id"].startswith("static-code-map-pack-")
        ]
        self.assertEqual(
            [node["modules"] for node in static_nodes],
            [[f"RelationalStaticCodeMapChunk{index}"] for index in range(3)],
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

    def test_prepared_realization_command_uses_same_remote_builder_policy(self):
        command = _relational_nix_realize_command(
            ".#stage-a-example-preflight", Path("/tmp/stage-a-builders")
        )

        self.assertEqual(command[:2], ["nix", "build"])
        self.assertIn("--max-jobs", command)
        self.assertEqual(command[command.index("--max-jobs") + 1], "0")
        self.assertIn("@/tmp/stage-a-builders", command)
        self.assertIn("builders-use-substitutes", command)
        self.assertIn("--no-link", command)
        self.assertIn("--json", command)
        self.assertEqual(command[-1], ".#stage-a-example-preflight")

    def test_realized_prepared_output_is_passed_to_dynamic_graph_builder(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            flake = root / "flake"
            flake.mkdir()
            (flake / "flake.nix").write_text("{}\n", encoding="utf-8")
            (flake / "flake.lock").write_text("{}\n", encoding="utf-8")
            builders = root / "builders"
            builders.write_text("builder\n", encoding="utf-8")
            realized = root / "realized"
            prepared = realized / "report" / "relational-v3"
            prepared.mkdir(parents=True)
            out = root / "proof"

            process = mock.Mock(
                returncode=0,
                stdout=json.dumps([{"outputs": {"out": str(realized)}}]),
                stderr="",
            )

            def build_graph(**kwargs):
                kwargs["out"].mkdir(parents=True)
                return {"format": "stage-a-relational-nix-node-build-v1", "status": "checked"}

            with mock.patch(
                "spaghetti_extractor.relational.build.subprocess.run",
                return_value=process,
            ) as run, mock.patch(
                "spaghetti_extractor.relational.build.stage_a_build_relational",
                side_effect=build_graph,
            ) as build:
                result = stage_a_build_relational_from_nix(
                    prepared_nix_ref=".#stage-a-example-preflight",
                    prepared_subpath=Path("report/relational-v3"),
                    out=out,
                    flake=flake,
                    builders_file=builders,
                    target_nodes=["example-certificate"],
                )

            self.assertEqual(run.call_args.kwargs["cwd"], flake)
            self.assertEqual(build.call_args.kwargs["prepared"], prepared)
            self.assertEqual(
                build.call_args.kwargs["target_nodes"], ["example-certificate"]
            )
            self.assertEqual(result["status"], "checked")
            realization = json.loads(
                (out / "prepared-nix-realization.json").read_text(encoding="utf-8")
            )
            self.assertEqual(realization["status"], "realized")
            self.assertEqual(realization["result_path"], str(realized))
            self.assertEqual(realization["prepared_path"], str(prepared))

    def test_realized_prepared_subpath_cannot_escape_nix_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(StageAInputError, "must remain inside"):
                stage_a_build_relational_from_nix(
                    prepared_nix_ref=".#stage-a-example-preflight",
                    prepared_subpath=Path("../outside"),
                    out=Path(temporary) / "proof",
                    flake=self.repo,
                )

    @unittest.skipUnless(shutil.which("nix"), "Nix is required for graph identity check")
    def test_standalone_graph_invalidates_only_import_dependency_closure(self):
        with tempfile.TemporaryDirectory() as temporary:
            source_root = Path(temporary) / "source-v1"
            source_root.mkdir()
            formal = source_root / "Formal.lean"
            middle = source_root / "Middle.lean"
            consumer = source_root / "Consumer.lean"
            unrelated = source_root / "Unrelated.lean"
            formal.write_text("def formal := 1\n", encoding="utf-8")
            middle.write_text("def middle := 1\n", encoding="utf-8")
            consumer.write_text(
                "import StageA.Middle\nimport StageA.Formal\nimport StageA.Formal\n"
                "def consumer := formal + middle\n",
                encoding="utf-8",
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
            '    standaloneModules = [ "Formal" "Middle" "Consumer" "Unrelated" ];',
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
