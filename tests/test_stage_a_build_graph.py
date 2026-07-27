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
    _attach_relational_semantic_identities,
    _cached_relational_nix_installables,
    _ca_builder_stores,
    _check_remote_ca_build_trace_compatibility,
    _content_addressed_derivations_requested,
    _finalize_nix_proof_ir,
    _locked_flake_input,
    _nix_executable,
    _nix_store_version,
    _relational_nix_build_command,
    _relational_nix_evaluation_cache_key,
    _relational_nix_installable_build_command,
    _relational_nix_work_reused,
    _relational_nix_realize_command,
    _relational_nix_expression,
    _relational_focused_input,
    _relational_incremental_evaluation,
    _relational_node_closure,
    _relational_raw_build_nodes,
    _publish_relational_nix_evaluation,
    _validate_relational_module_graph,
    _write_relational_module_graph,
    stage_a_build_relational_from_nix,
)
from spaghetti_extractor.relational.cache_qualification import (
    diff_semantic_invalidation,
)
from spaghetti_extractor.relational.schema import (
    RELATIONAL_ACCEPTANCE_THEOREM,
    RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
)
from spaghetti_extractor.relational.verdict import _write_relational_verdict


class StageABuildGraphTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(__file__).parents[1]

    def test_nix_reuse_is_classified_from_real_build_events(self):
        self.assertTrue(_relational_nix_work_reused("", succeeded=True))
        self.assertTrue(
            _relational_nix_work_reused(
                "these 757 derivations will be built:\n"
                "  /nix/store/example.drv\n",
                succeeded=True,
            )
        )
        self.assertFalse(
            _relational_nix_work_reused(
                "building '/nix/store/example.drv' on 'acacia'\n",
                succeeded=True,
            )
        )
        self.assertFalse(
            _relational_nix_work_reused(
                "copying 14 paths from 'ssh://acacia'\n",
                succeeded=True,
            )
        )
        self.assertFalse(_relational_nix_work_reused("", succeeded=False))

    def test_nix_executable_prefers_explicit_override(self):
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "nix-proof-client"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)
            with mock.patch.dict(
                os.environ,
                {"SPAGHETTI_EXTRACTOR_NIX": str(executable)},
            ):
                self.assertEqual(_nix_executable(), str(executable.resolve()))

    def test_nix_executable_rejects_invalid_override(self):
        with mock.patch.dict(
            os.environ,
            {"SPAGHETTI_EXTRACTOR_NIX": "/missing/stage-a-nix"},
        ):
            with self.assertRaisesRegex(
                StageAInputError,
                "does not identify an executable Nix client",
            ):
                _nix_executable()

    def test_nix_executable_prefers_active_system_client_over_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            active = Path(temporary) / "active-system-nix"
            ambient = Path(temporary) / "stale-profile-nix"
            for executable in (active, ambient):
                executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                executable.chmod(0o755)
            with (
                mock.patch.dict(os.environ, {}, clear=True),
                mock.patch(
                    "spaghetti_extractor.relational.build._NIXOS_SYSTEM_NIX",
                    active,
                ),
                mock.patch(
                    "spaghetti_extractor.relational.build.shutil.which",
                    return_value=str(ambient),
                ),
            ):
                self.assertEqual(_nix_executable(), str(active))

    def test_content_addressed_derivations_are_the_default(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(_content_addressed_derivations_requested())

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

    def test_incremental_evaluation_instantiates_only_changed_closure(self):
        graph = {
            "final_node": "segment",
            "nodes": [
                {
                    "id": "kernel",
                    "modules": ["Kernel"],
                    "dependencies": [],
                    "semantic_id": "1" * 64,
                },
                {
                    "id": "candidate-decode",
                    "modules": ["CandidateDecode"],
                    "dependencies": ["kernel"],
                    "semantic_id": "2" * 64,
                },
                {
                    "id": "segment",
                    "modules": ["Segment"],
                    "dependencies": ["candidate-decode"],
                    "semantic_id": "3" * 64,
                },
                {
                    "id": "unrelated",
                    "modules": ["Unrelated"],
                    "dependencies": [],
                    "semantic_id": "4" * 64,
                },
            ],
        }

        def cached(node):
            if node["id"] == "kernel":
                return Path("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-kernel")
            return None

        with mock.patch(
            "spaghetti_extractor.relational.build."
            "_cached_relational_semantic_boundary",
            side_effect=cached,
        ):
            active, boundaries = _relational_incremental_evaluation(
                graph, ["segment"]
            )

        self.assertEqual(active, ["candidate-decode", "segment"])
        self.assertEqual(set(boundaries), {"kernel"})
        self.assertEqual(
            boundaries["kernel"]["semantic_path"],
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-kernel",
        )

    def test_semantic_node_identity_tracks_only_dependency_closure(self):
        nodes = [
            {
                "id": "kernel",
                "modules": ["Kernel"],
                "dependencies": [],
                "source_sha256": "1" * 64,
            },
            {
                "id": "segment",
                "modules": ["Segment"],
                "dependencies": ["kernel"],
                "source_sha256": "2" * 64,
            },
            {
                "id": "unrelated",
                "modules": ["Unrelated"],
                "dependencies": [],
                "source_sha256": "3" * 64,
            },
        ]
        _attach_relational_semantic_identities(nodes)
        initial = {node["id"]: node["semantic_id"] for node in nodes}

        nodes[0]["source_sha256"] = "4" * 64
        _attach_relational_semantic_identities(nodes)
        changed = {node["id"]: node["semantic_id"] for node in nodes}

        self.assertNotEqual(initial["kernel"], changed["kernel"])
        self.assertNotEqual(initial["segment"], changed["segment"])
        self.assertEqual(initial["unrelated"], changed["unrelated"])
        self.assertEqual(
            nodes[1]["dependency_semantic_ids"],
            [nodes[0]["semantic_id"]],
        )

    def test_semantic_invalidation_report_rejects_identity_drift(self):
        def graph() -> dict[str, object]:
            nodes = [
                {
                    "id": "kernel",
                    "modules": ["Kernel"],
                    "dependencies": [],
                    "source_sha256": "1" * 64,
                    "resource_class": "light",
                    "estimated_memory_mb": 512,
                },
                {
                    "id": "segment",
                    "modules": ["Segment"],
                    "dependencies": ["kernel"],
                    "source_sha256": "2" * 64,
                    "resource_class": "light",
                    "estimated_memory_mb": 512,
                },
                {
                    "id": "unrelated",
                    "modules": ["Unrelated"],
                    "dependencies": [],
                    "source_sha256": "3" * 64,
                    "resource_class": "light",
                    "estimated_memory_mb": 512,
                },
            ]
            _attach_relational_semantic_identities(nodes)
            return {
                "format": "stage-a-lean-module-graph-v1",
                "root_module": "Segment",
                "expected_final_theorem": None,
                "nodes": nodes,
            }

        before = graph()
        after = json.loads(json.dumps(before))
        after_nodes = {
            node["id"]: node for node in after["nodes"]
        }
        after_nodes["kernel"]["source_sha256"] = "4" * 64
        _attach_relational_semantic_identities(after["nodes"])

        report = diff_semantic_invalidation(before, after)
        self.assertEqual(report.status, "satisfied")
        self.assertEqual(report.direct_changes, ("kernel",))
        self.assertEqual(
            report.observed_invalidated,
            ("kernel", "segment"),
        )
        self.assertEqual(report.reused, ("unrelated",))

        after_nodes["unrelated"]["semantic_id"] = "5" * 64
        report = diff_semantic_invalidation(before, after)
        self.assertEqual(report.status, "violated")
        self.assertEqual(report.unexpected_invalidated, ("unrelated",))

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

    def test_launch_realizability_uses_measured_high_memory_class(self):
        with tempfile.TemporaryDirectory() as temporary:
            prepared = Path(temporary)
            stage_a = prepared / "lean" / "StageA"
            stage_a.mkdir(parents=True)
            (stage_a / "RelationalBundle.lean").write_text(
                "def relationalBundle := 0\n", encoding="utf-8"
            )
            (stage_a / "RelationalLaunchRealizabilityCertificate.lean").write_text(
                "def launchRealizability := 0\n", encoding="utf-8"
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

            launch = next(
                node for node in graph["nodes"]
                if node["modules"] == ["RelationalLaunchRealizabilityCertificate"]
            )
            self.assertEqual(launch["resource_class"], "high-memory")
            self.assertGreaterEqual(launch["estimated_memory_mb"], 10240)

    def test_linked_acceptance_selects_linked_final_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            prepared = Path(temporary)
            stage_a = prepared / "lean" / "StageA"
            stage_a.mkdir(parents=True)
            (stage_a / "RelationalBundle.lean").write_text(
                "def relationalBundle := 0\n", encoding="utf-8"
            )
            (stage_a / "RelationalAcceptance.lean").write_text(
                "import StageA.RelationalBundle\ndef linkedAcceptance := relationalBundle\n",
                encoding="utf-8",
            )
            (prepared / "whole-program-acceptance.json").write_text(
                json.dumps({
                    "format": "stage-a-whole-program-acceptance-v1",
                    "status": "ready",
                    "required_theorem": RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
                    "theorem": RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
                    "node_steps": [],
                    "linked_acceptance": {
                        "status": "ready",
                        "theorem": RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
                    },
                    "blockers": [],
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

            self.assertEqual(
                graph["expected_final_theorem"],
                RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
            )
            self.assertEqual(
                _validate_relational_module_graph(prepared)[
                    "expected_final_theorem"
                ],
                RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
            )

            graph["acceptance"]["theorem"] = RELATIONAL_ACCEPTANCE_THEOREM
            with self.assertRaisesRegex(
                StageAInputError, "does not match its requirement"
            ):
                _validate_relational_module_graph(prepared, graph)

    def test_linked_final_theorem_projects_linked_certificate_fields(self):
        finalized = _finalize_nix_proof_ir(
            {
                "obligations": [{
                    "id": "obligation:return",
                    "kind": "return_pop",
                    "status": "incomplete",
                }],
            },
            theorem_checked=True,
            theorem=RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
            result_path=Path("/nix/store/checked-linked-proof"),
        )

        self.assertEqual(finalized["status"], "satisfied")
        self.assertEqual(
            finalized["obligations"][0]["evidence"]["certificate_field"],
            "LinkedWholeProgramCertificate.runningProductNodesRefined",
        )

    def test_verdict_accepts_only_the_selected_linked_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary)
            (out / "certificates").mkdir()
            (out / "relation-contract.json").write_text("{}\n", encoding="utf-8")
            (out / "trusted-base.json").write_text("{}\n", encoding="utf-8")
            (out / "whole-program-acceptance.json").write_text(
                json.dumps({
                    "format": "stage-a-whole-program-acceptance-v1",
                    "status": "ready",
                    "required_theorem": RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
                    "theorem": RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
                    "linked_acceptance": {
                        "status": "ready",
                        "theorem": RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
                    },
                }),
                encoding="utf-8",
            )
            binary_path = out / "binary.exe"
            binary_path.write_bytes(b"PE")
            binary = SimpleNamespace(path=binary_path, sha256="00" * 32)
            arguments = {
                "out": out,
                "started_at": "2026-07-22T00:00:00Z",
                "original": binary,
                "candidate": binary,
                "contract": {"regions": []},
                "proof_ir": {"obligations": []},
                "trusted_base": {},
                "certificates": [],
                "blocker": None,
            }

            accepted = _write_relational_verdict(
                **arguments,
                verdict="pass",
                lean={
                    "status": "checked",
                    "theorem": RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
                },
            )
            self.assertEqual(accepted["verdict"], "pass")
            self.assertEqual(
                accepted["expected_final_theorem"],
                RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
            )
            self.assertTrue(accepted["claim_scope"]["acceptance_eligible"])

            rejected = _write_relational_verdict(
                **arguments,
                verdict="pass",
                lean={
                    "status": "checked",
                    "theorem": RELATIONAL_ACCEPTANCE_THEOREM,
                },
            )
            self.assertEqual(rejected["verdict"], "incomplete")
            self.assertFalse(rejected["claim_scope"]["acceptance_eligible"])

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

    def test_shard_pack_assignment_is_stable_when_one_shard_is_added(self):
        initial_modules = {
            *(f"RelationalDefinitionsShard{index}" for index in range(64)),
            *(f"RelationalProofShard{index}" for index in range(64)),
        }
        with mock.patch.dict(
            os.environ,
            {
                "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_NIX_PACK_BUCKETS": "8",
            },
        ):
            initial_nodes = _relational_raw_build_nodes(initial_modules)
            extended_nodes = _relational_raw_build_nodes({
                *initial_modules,
                "RelationalDefinitionsShard64",
                "RelationalProofShard64",
            })

        def assignments(nodes):
            return {
                module: node["id"]
                for node in nodes
                for module in node["modules"]
            }

        initial_assignments = assignments(initial_nodes)
        extended_assignments = assignments(extended_nodes)
        self.assertEqual(
            initial_assignments,
            {
                module: extended_assignments[module]
                for module in initial_modules
            },
        )
        changed_packs = {
            extended_assignments["RelationalDefinitionsShard64"],
            extended_assignments["RelationalProofShard64"],
        }
        initial_members = {
            node["id"]: set(node["modules"]) for node in initial_nodes
        }
        extended_members = {
            node["id"]: set(node["modules"]) for node in extended_nodes
        }
        self.assertTrue(all(
            initial_members.get(node_id, set())
            != extended_members[node_id]
            for node_id in changed_packs
        ))
        self.assertTrue(all(
            initial_members[node_id] == extended_members[node_id]
            for node_id in set(initial_members) - changed_packs
        ))

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

            expression = _relational_nix_expression(
                prepared=prepared,
                graph=graph,
                evaluator=self.repo / "nix" / "stage-a-lean-graph.nix",
                flake_root=self.repo,
                target_nodes=["candidate-decode"],
            )
            focused = _relational_focused_input(
                prepared, graph, ["candidate-decode"]
            )

            self.assertNotIn("prepared = builtins.path", expression)
            self.assertIn("graphFile = builtins.path", expression)
            self.assertIn("preparedManifest = null", expression)
            self.assertNotIn("stage-a-prepared-proof.json", expression)
            self.assertIn("sourceRoot = builtins.toPath", expression)
            self.assertNotIn("large-analysis-report.json", expression)
            self.assertEqual(focused, {
                "nodes": 2,
                "modules": 2,
                "source_bytes": len(modules["Kernel"].encode())
                + len(modules["CandidateDecode"].encode()),
            })

    def test_nix_expression_can_select_input_addressed_scheduling(self):
        with tempfile.TemporaryDirectory() as temporary:
            prepared = Path(temporary)
            stage_a = prepared / "lean" / "StageA"
            stage_a.mkdir(parents=True)
            (stage_a / "Root.lean").write_text("def root := 1\n", encoding="utf-8")
            (prepared / "module-graph.json").write_text("{}\n", encoding="utf-8")
            (prepared / "prepared-proof.json").write_text("{}\n", encoding="utf-8")
            graph = {
                "modules": {"Root": {"source": "lean/StageA/Root.lean"}},
                "nodes": [{"id": "root", "modules": ["Root"], "dependencies": []}],
            }
            with mock.patch.dict(os.environ, {
                "SPAGHETTI_EXTRACTOR_STAGE_A_NIX_CONTENT_ADDRESSED": "false"
            }):
                expression = _relational_nix_expression(
                    prepared=prepared,
                    graph=graph,
                    evaluator=self.repo / "nix" / "stage-a-lean-graph.nix",
                    flake_root=self.repo,
                    target_nodes=[],
                )

        self.assertIn("contentAddressed = false;", expression)

    def test_nix_expression_projects_prebuilt_semantic_boundaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            prepared = Path(temporary)
            stage_a = prepared / "lean" / "StageA"
            stage_a.mkdir(parents=True)
            for module in ("Kernel", "Segment"):
                (stage_a / f"{module}.lean").write_text(
                    f"def {module.lower()} := 1\n", encoding="utf-8"
                )
            (prepared / "module-graph.json").write_text("{}\n", encoding="utf-8")
            (prepared / "prepared-proof.json").write_text("{}\n", encoding="utf-8")
            graph = {
                "modules": {
                    module: {"source": f"lean/StageA/{module}.lean"}
                    for module in ("Kernel", "Segment")
                },
                "nodes": [
                    {"id": "kernel", "modules": ["Kernel"], "dependencies": []},
                    {
                        "id": "segment",
                        "modules": ["Segment"],
                        "dependencies": ["kernel"],
                    },
                ],
            }
            expression = _relational_nix_expression(
                prepared=prepared,
                graph=graph,
                evaluator=self.repo / "nix" / "stage-a-lean-graph.nix",
                flake_root=self.repo,
                target_nodes=["segment"],
                active_node_ids=["segment"],
                prebuilt_nodes={
                    "kernel": {
                        "node_id": "kernel",
                        "semantic_id": "1" * 64,
                        "semantic_path":
                            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-kernel",
                    }
                },
            )

        self.assertIn('activeNodeIds = [ "segment" ];', expression)
        self.assertIn(
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-kernel",
            expression,
        )
        self.assertIn(
            "targetNodes activeNodeIds prebuiltNodes;",
            expression,
        )

    def test_remote_build_command_disables_local_jobs_and_uses_substitutes(self):
        with mock.patch(
            "spaghetti_extractor.relational.build._nix_builders_spec",
            return_value="ssh-ng://builder x86_64-linux - 1 1",
        ):
            command = _relational_nix_build_command(
                "proof-expression", Path("/tmp/stage-a-builders")
            )

        self.assertEqual(Path(command[0]).name, "nix")
        self.assertEqual(command[1], "build")
        self.assertIn("--max-jobs", command)
        self.assertEqual(command[command.index("--max-jobs") + 1], "0")
        self.assertIn("ssh-ng://builder x86_64-linux - 1 1", command)
        self.assertIn("builders-use-substitutes", command)
        self.assertEqual(command[command.index("builders-use-substitutes") + 1], "true")

    def test_cached_nix_evaluation_realizes_drv_without_expression_evaluation(self):
        with mock.patch(
            "spaghetti_extractor.relational.build._nix_builders_spec",
            return_value="ssh-ng://builder x86_64-linux - 1 1",
        ):
            command = _relational_nix_installable_build_command(
                ["/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-proof.drv^out"],
                Path("/tmp/stage-a-builders"),
            )

        self.assertNotIn("--expr", command)
        self.assertNotIn("--impure", command)
        self.assertEqual(
            command[-1],
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-proof.drv^out",
        )

    def test_nix_evaluation_cache_binds_key_and_drv_installables(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / "evaluation.json"
            drv = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-proof.drv"
            _publish_relational_nix_evaluation(
                cache,
                cache_key="semantic-key",
                build_outputs=[{
                    "drvPath": drv,
                    "outputs": {"out": "/nix/store/result"},
                }],
            )
            with mock.patch("pathlib.Path.is_file", return_value=True):
                self.assertEqual(
                    _cached_relational_nix_installables(
                        cache,
                        cache_key="semantic-key",
                    ),
                    [f"{drv}^out"],
                )
                self.assertIsNone(
                    _cached_relational_nix_installables(
                        cache,
                        cache_key="different-key",
                    )
                )

    def test_focused_evaluation_cache_ignores_final_manifest_only_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepared = root / "prepared"
            prepared.mkdir()
            (prepared / "module-graph.json").write_text(
                '{"format":"graph"}\n', encoding="utf-8"
            )
            manifest = prepared / "prepared-proof.json"
            manifest.write_text('{"status":"first"}\n', encoding="utf-8")
            evaluator = root / "evaluator.nix"
            evaluator.write_text("{}\n", encoding="utf-8")
            (root / "flake.lock").write_text("{}\n", encoding="utf-8")

            focused_before = _relational_nix_evaluation_cache_key(
                prepared=prepared,
                evaluator=evaluator,
                flake_root=root,
                requested_target_nodes=["node"],
            )
            final_before = _relational_nix_evaluation_cache_key(
                prepared=prepared,
                evaluator=evaluator,
                flake_root=root,
                requested_target_nodes=[],
            )
            manifest.write_text('{"status":"second"}\n', encoding="utf-8")
            focused_after = _relational_nix_evaluation_cache_key(
                prepared=prepared,
                evaluator=evaluator,
                flake_root=root,
                requested_target_nodes=["node"],
            )
            final_after = _relational_nix_evaluation_cache_key(
                prepared=prepared,
                evaluator=evaluator,
                flake_root=root,
                requested_target_nodes=[],
            )

        self.assertEqual(focused_before, focused_after)
        self.assertNotEqual(final_before, final_after)

    def test_ca_builder_inventory_ignores_non_ca_exceptional_lanes(self):
        with tempfile.TemporaryDirectory() as temporary:
            builders = Path(temporary) / "builders"
            builders.write_text(
                "ssh-ng://root@primary x86_64-linux /tmp/key 20 2 "
                "big-parallel,ca-derivations - key\n"
                "ssh-ng://root@exceptional x86_64-linux /tmp/key 1 2 "
                "big-parallel,large-memory - key\n",
                encoding="utf-8",
            )

            stores = _ca_builder_stores(builders)

        self.assertEqual(
            stores,
            ["ssh-ng://root@primary?ssh-key=%2Ftmp%2Fkey"],
        )

    def test_ca_remote_build_rejects_nix_235_protocol_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            builders = Path(temporary) / "builders"
            builders.write_text(
                "ssh-ng://root@builder x86_64-linux /tmp/key 20 2 "
                "big-parallel,ca-derivations - key\n",
                encoding="utf-8",
            )
            with mock.patch(
                "spaghetti_extractor.relational.build._nix_store_version",
                side_effect=[
                    (2, 34, "2.34.8"),
                    (2, 35, "2.35.2"),
                ],
            ), mock.patch(
                "spaghetti_extractor.relational.build._nix_client_version",
                return_value=(2, 34, "2.34.8"),
            ):
                with self.assertRaisesRegex(
                    StageAInputError,
                    "Upgrade the coordinating local Nix daemon",
                ):
                    _check_remote_ca_build_trace_compatibility(builders)

    def test_ca_remote_build_accepts_matching_build_trace_protocols(self):
        with tempfile.TemporaryDirectory() as temporary:
            builders = Path(temporary) / "builders"
            builders.write_text(
                "ssh-ng://root@builder x86_64-linux /tmp/key 20 2 "
                "big-parallel,ca-derivations - key\n",
                encoding="utf-8",
            )
            with mock.patch(
                "spaghetti_extractor.relational.build._nix_store_version",
                side_effect=[
                    (2, 35, "2.35.2"),
                    (2, 35, "2.35.2"),
                ],
            ), mock.patch(
                "spaghetti_extractor.relational.build._nix_client_version",
                return_value=(2, 35, "2.35.2"),
            ):
                _check_remote_ca_build_trace_compatibility(builders)

    def test_ca_build_rejects_client_daemon_protocol_boundary(self):
        with mock.patch(
            "spaghetti_extractor.relational.build._nix_client_version",
            return_value=(2, 34, "2.34.7"),
        ), mock.patch(
            "spaghetti_extractor.relational.build._nix_store_version",
            return_value=(2, 35, "2.35.1"),
        ):
            with self.assertRaisesRegex(
                StageAInputError,
                "client uses Nix 2.34.7",
            ):
                _check_remote_ca_build_trace_compatibility(None)

    def test_remote_store_probe_uses_isolated_persistent_ssh_connection(self):
        process = mock.Mock(
            returncode=0,
            stdout=json.dumps({"version": "2.35.2"}),
            stderr="",
        )
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ,
            {
                "XDG_CACHE_HOME": temporary,
                "NIX_SSHOPTS": "-o BatchMode=yes",
            },
        ), mock.patch(
            "spaghetti_extractor.relational.build.subprocess.run",
            return_value=process,
        ) as run:
            self.assertEqual(
                _nix_store_version(store="ssh-ng://root@builder?ssh-key=/tmp/key"),
                (2, 35, "2.35.2"),
            )

        environment = run.call_args.kwargs["env"]
        self.assertIn("-o BatchMode=yes", environment["NIX_SSHOPTS"])
        self.assertIn("-o IdentitiesOnly=yes", environment["NIX_SSHOPTS"])
        self.assertIn("-o ControlMaster=auto", environment["NIX_SSHOPTS"])
        self.assertIn("-o ControlPersist=4h", environment["NIX_SSHOPTS"])
        self.assertIn(
            str(Path(temporary) / "spaghetti-extractor" / "ssh" / "%C"),
            environment["NIX_SSHOPTS"],
        )

    def test_analysis_dataflow_uses_ca_projection_boundaries(self):
        dataflow_graph = (
            self.repo / "nix" / "stage-a-register-dataflow-graph.nix"
        ).read_text(encoding="utf-8")
        analysis_graph = (
            self.repo / "nix" / "stage-a-relational-analysis-graph.nix"
        ).read_text(encoding="utf-8")

        self.assertIn(", contentAddressed ? true", dataflow_graph)
        self.assertIn("caAttrs = lib.optionalAttrs contentAddressed", dataflow_graph)
        self.assertEqual(dataflow_graph.count("__contentAddressed = true;"), 1)
        self.assertNotIn("value = builtins.path", dataflow_graph)
        self.assertIn(
            "stage-a-register-dataflow-input-${pack.id}",
            dataflow_graph,
        )
        self.assertIn(
            "stage-a-register-dataflow-transfer-context",
            dataflow_graph,
        )
        self.assertIn("dataflowContentAddressed ? true", analysis_graph)
        self.assertIn(
            "contentAddressed = dataflowContentAddressed;",
            analysis_graph,
        )

    def test_downstream_uses_canonical_machine_call_contract_inventory(self):
        for relative in (
            "src/spaghetti_extractor/relational/lean/acceptance.py",
            "src/spaghetti_extractor/relational/lean/segments.py",
        ):
            source = (self.repo / relative).read_text(encoding="utf-8")
            self.assertNotIn("MachineImportCallContractsChunk", source)
            self.assertNotIn("MachineImportCallContractsDecodeChunk", source)

    def test_prepared_realization_command_uses_same_remote_builder_policy(self):
        with mock.patch(
            "spaghetti_extractor.relational.build._nix_builders_spec",
            return_value="ssh-ng://builder x86_64-linux - 1 1",
        ):
            command = _relational_nix_realize_command(
                ".#stage-a-example-preflight", Path("/tmp/stage-a-builders")
            )

        self.assertEqual(Path(command[0]).name, "nix")
        self.assertEqual(command[1], "build")
        self.assertIn("--max-jobs", command)
        self.assertEqual(command[command.index("--max-jobs") + 1], "0")
        self.assertIn("ssh-ng://builder x86_64-linux - 1 1", command)
        self.assertIn("builders-use-substitutes", command)
        self.assertIn("--no-link", command)
        self.assertIn("--json", command)
        self.assertEqual(command[-1], ".#stage-a-example-preflight")

    def test_remote_build_policy_can_select_qualified_substituters(self):
        with mock.patch.dict(os.environ, {
            "SPAGHETTI_EXTRACTOR_NIX_BUILDERS_USE_SUBSTITUTES": "false",
            "SPAGHETTI_EXTRACTOR_NIX_SUBSTITUTERS": (
                "https://cache.corncheese.org/nix-cache https://cache.nixos.org/"
            ),
        }), mock.patch(
            "spaghetti_extractor.relational.build._nix_builders_spec",
            return_value="ssh-ng://builder x86_64-linux - 1 1",
        ):
            command = _relational_nix_build_command(
                "proof-expression", Path("/tmp/stage-a-builders")
            )

        self.assertEqual(
            command[command.index("builders-use-substitutes") + 1], "false"
        )
        self.assertEqual(
            command[command.index("substituters") + 1],
            "https://cache.corncheese.org/nix-cache https://cache.nixos.org/",
        )

    def test_remote_build_command_authenticates_signed_builder_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            keys = Path(temporary) / "builder-public-keys"
            keys.write_text(
                "builder-a-1:QUJDRA==\n"
                "# a comment\n"
                "builder-b-1:RUZHSA==\n",
                encoding="utf-8",
            )
            with mock.patch(
                "spaghetti_extractor.relational.build._nix_builders_spec",
                return_value="ssh-ng://builder x86_64-linux - 1 1",
            ):
                command = _relational_nix_build_command(
                    "proof-expression",
                    Path("/tmp/stage-a-builders"),
                    keys,
                )

        self.assertEqual(
            command[command.index("extra-trusted-public-keys") + 1],
            "builder-a-1:QUJDRA== builder-b-1:RUZHSA==",
        )

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
            "  pkgs = import nixpkgs {",
            "    system = builtins.currentSystem;",
            "    config = {};",
            "    overlays = [];",
            "  };",
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
