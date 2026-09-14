from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.boundary import BoundaryModelError
from spaghetti_extractor.components.bisimulation import ComponentBisimulationIntentV1
from spaghetti_extractor.components.bisimulation_connected import (
    connected_source_prefix,
    render_connected_summary_wrapper,
)
from spaghetti_extractor.components.bisimulation_connected import (
    _connected_replay_source,
)
from spaghetti_extractor.components.binding_intent import (
    ComponentMachineBindingIntentV1,
)
from spaghetti_extractor.components.bisimulation_refinement import (
    _compact_exact_temporaries,
    _exit_comparisons,
    _finite_control_proof_model,
    _next_barrier_sync_ids,
    _obligation_functions,
    _render_proof_header,
    _required_assertion_descriptions,
    _segment_exact_unit_ids,
    _render_source_expression,
    _source_service_unit_costs,
    _specialize_exact_function_source,
    _specialize_machine_overlay_for_proof,
    _world_source,
    build_typed_proof_service_thunk_renderer,
    check_bisimulation_refinement,
)
from spaghetti_extractor.components.capabilities import spx_reference_runtime_header
from spaghetti_extractor.components.cbmc_backend import (
    discover_cbmc_assertions,
    discover_cbmc_loops,
    discover_cbmc_safety_properties,
    run_cbmc_cover,
    run_cbmc_properties,
)
from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
from spaghetti_extractor.components.interface_package_v5 import (
    ComponentInterfaceIntentV1,
    compile_component_interface_v5,
)
from spaghetti_extractor.components.bisimulation_typed_services import (
    _canonical_proof_service_bindings,
    _proof_call_specs,
)
from spaghetti_extractor.components.machine_binding import MachineProjectionV1
from spaghetti_extractor.components.refinement_v5 import (
    _logical_projection,
    _materialize_kernel_finite_control_targets,
)
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.components.source_profile import (
    _block_scope_static_storage,
    _nonconstant_macro_definitions,
    _top_level_object_declarations,
    check_component_source_profile,
)
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from spaghetti_extractor.util import sha256_file
from tests.unit.components.test_inductive_relation import _interface, _operation


ROOT = Path(__file__).parents[3]

TESTKIT = {
    "fixtures": ("cbmc", "compiler"),
    "resources": (
        "targets/dxball/intent/interfaces-v5/directdraw-init.json",
        "targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json",
        "targets/gnu-hello/intent/interfaces-v5/program-name-selection.json",
        "targets/gnu-hello/intent/interfaces-v5/startup-callback-registration.json",
        "targets/jq/intent/interfaces-v5/output-value-pipeline.json",
    ),
}


def _intent() -> ComponentBisimulationIntentV1:
    return ComponentBisimulationIntentV1.create(
        component_id="countdown",
        operations=[
            {
                "operation_id": "run",
                "syncs": [
                    {
                        "id": "loop",
                        "exact_unit_id": (
                            "semantic-transfer:original-cutpoint-00001010-00001020"
                        ),
                        "invariant": {"op": "true"},
                        "captures": [
                            {
                                "kind": "parameter",
                                "id": "count",
                                "mode": "machine_codec",
                                "projection": {
                                    "kind": "register",
                                    "register": "ecx",
                                    "width": 32,
                                    "at": "entry",
                                },
                                "encoding": {"op": "parameter", "name": "count"},
                                "decoding": None,
                            },
                            {
                                "kind": "source_state",
                                "id": "n",
                                "mode": "machine_codec",
                                "projection": {
                                    "kind": "register",
                                    "register": "edx",
                                    "width": 32,
                                    "at": "entry",
                                },
                                "encoding": {"op": "state_input", "name": "n"},
                                "decoding": {"op": "projected_value"},
                            },
                        ],
                        "derived": [
                            {
                                "id": "mirror",
                                "projection": {
                                    "kind": "register",
                                    "register": "eax",
                                    "width": 32,
                                    "at": "entry",
                                },
                                "expression": {"op": "state_input", "name": "n"},
                            }
                        ],
                    }
                ],
            }
        ],
    )


class BisimulationRefinementTests(unittest.TestCase):
    def test_connected_memory_agreement_is_a_mandatory_proof_goal(self) -> None:
        required = _required_assertion_descriptions(
            authored=_intent().operations[0],
            proof_function="spx_check_entry",
            active_start_sync_id=None,
            next_sync_ids=set(),
            logical_projection={"results": [], "state": []},
            continuous_acyclic=False,
            typed_call_positions=(),
            connected_summary_ids=(3, 7),
        )
        self.assertIn("spx-bisimulation-connected-summary-memory:3", required)
        self.assertIn("spx-bisimulation-connected-summary-memory:7", required)

    def test_connected_summary_wraps_one_qualified_logical_call(self) -> None:
        intent = ComponentInterfaceIntentV1.parse(
            json.loads(
                (
                    ROOT
                    / "targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json"
                ).read_text(encoding="utf-8")
            )
        )
        bundle = compile_component_interface_v5(intent)
        symbols = {"compare": "gnu_hello_memory_regions_equal"}
        summary_ids = {"compare": 3}

        renamed = connected_source_prefix(symbols, summary_ids)
        wrapper = render_connected_summary_wrapper(
            bundle=bundle,
            operation_symbols=symbols,
            summary_ids=summary_ids,
        )

        self.assertIn(
            "#define gnu_hello_memory_regions_equal "
            "spx_proof_connected_impl_0003_gnu_hello_memory_regions_equal",
            renamed,
        )
        self.assertIn("spx_proof_connected_view_equal", wrapper)
        self.assertIn('"spx-bisimulation-connected-summary-input:3"', wrapper)
        self.assertEqual(
            wrapper.count(
                "spx_proof_connected_impl_0003_gnu_hello_memory_regions_equal("
            ),
            2,
        )
        replay = wrapper[wrapper.index("uint32_t inputs_match") :]
        self.assertNotIn(
            "spx_proof_connected_impl_0003_gnu_hello_memory_regions_equal(",
            replay,
        )

    def test_connected_summary_replays_only_its_public_effect_interval(self) -> None:
        rendered = "\n".join(
            _connected_replay_source(
                [
                    {
                        "summary_id": 0,
                        "summary_capacity": 2,
                    }
                ],
                max_writes=2,
                max_calls=3,
                max_atomics=1,
            )
        )

        self.assertIn('"spx-bisimulation-connected-summary-prefix:0"', rendered)
        self.assertEqual(
            rendered.count("spx_source_world.calls[target] = spx_exact_world.calls["),
            3,
        )
        self.assertEqual(
            rendered.count("spx_proof_source_write(0, event.address, event.width, event.value, &replay_fault);"),
            2,
        )
        self.assertIn("spx_proof_connected_summaries_equal", rendered)

    def test_obligation_start_rva_comes_from_the_exact_source_map(self) -> None:
        authored = _intent().operations[0]
        authored = replace(
            authored,
            syncs=(
                replace(
                    authored.syncs[0],
                    exact_unit_id="semantic-transfer:named-cutpoint",
                ),
            ),
        )
        functions = _obligation_functions(
            authored,
            {"entry_unit_ids": ["entry"]},
            entry_rva=0x1000,
            unit_rvas={"semantic-transfer:named-cutpoint": 0x1010},
        )
        self.assertEqual(functions[1]["start_rva"], 0x1010)

    def _finite_control_projection(self) -> dict[str, object]:
        proof_routes = []
        semantic_routes = []
        for selector, logical, target_rva in ((0, 5, 0x3A73), (1, 6, 0x3A7B)):
            target_address = 0x400000 + target_rva
            proof_routes.append(
                {
                    "selector_value": selector,
                    "entry_address": 0x402000 + selector * 4,
                    "entry_rva": 0x2000 + selector * 4,
                    "bytes_le": list(target_address.to_bytes(4, "little")),
                    "target_rva": target_rva,
                    "target_address": target_address,
                }
            )
            semantic_routes.append(
                {
                    "selector_value": selector,
                    "logical_value": logical,
                    "target_rva": target_rva,
                    "target_address": target_address,
                }
            )
        table_bytes = b"".join(bytes(row["bytes_le"]) for row in proof_routes)
        inventory_bytes = b"".join(
            int(row["selector_value"]).to_bytes(4, "little") + bytes(row["bytes_le"])
            for row in proof_routes
        )
        evidence = {
            "unit_id": "dispatch",
            "source_rva": 0x1000,
            "source_unit_ir_sha256": "1" * 64,
            "outcome_expression_sha256": "2" * 64,
            "index_expression_sha256": "3" * 64,
            "selector_domain_sha256": "4" * 64,
            "index_provenance": {"kind": "direct_index"},
            "pe_sha256": "a" * 64,
            "image_base": 0x400000,
            "image_size": 0x10000,
            "table": {
                "address": 0x402000,
                "rva_start": 0x2000,
                "rva_end": 0x2008,
                "entry_width": 4,
                "bytes_sha256": hashlib.sha256(table_bytes).hexdigest(),
                "inventory_sha256": hashlib.sha256(inventory_bytes).hexdigest(),
            },
            "routes": proof_routes,
        }
        evidence["route_inventory_sha256"] = canonical_sha256_v3(evidence)
        return {
            "parameters": [
                {
                    "id": "selector",
                    "projection": {
                        "kind": "register",
                        "register": "eax",
                        "width": 8,
                        "at": "entry",
                    },
                }
            ],
            "results": [
                {
                    "id": "target",
                    "projection": {
                        "kind": "finite_control_target",
                        "unit_id": "dispatch",
                        "selector_parameter_id": "selector",
                        "target_inventory_sha256": evidence["route_inventory_sha256"],
                        "proof_evidence": evidence,
                        "routes": semantic_routes,
                    },
                }
            ],
        }

    def test_finite_control_world_uses_domain_bytes_and_route_witnesses(self) -> None:
        projected = self._finite_control_projection()["results"][0]["projection"]
        MachineProjectionV1.parse({**projected, "at": "exit"})
        model = _finite_control_proof_model(
            self._finite_control_projection(),
            machine_image={
                "pe_sha256": "a" * 64,
                "preferred_base": 0x400000,
                "image_size": 0x10000,
            },
        )
        self.assertIsNotNone(model)
        assert model is not None
        self.assertEqual(
            model["preconditions"],
            [
                "  __CPROVER_assume(((uint32_t)(((initial_state.eax) & UINT32_C(255)))) == UINT32_C(0) || ((uint32_t)(((initial_state.eax) & UINT32_C(255)))) == UINT32_C(1));"
            ],
        )
        self.assertEqual(len(model["immutable_bytes"]), 8)
        self.assertEqual(
            model["witness_functions"],
            ["spx_finite_control_route_0000", "spx_finite_control_route_0001"],
        )
        rendered = "\n".join(model["witness_definitions"])
        self.assertIn("__CPROVER_cover(selector == UINT32_C(0));", rendered)
        self.assertNotIn("spx_proof_exact_result", rendered)

    def test_finite_control_world_rejects_duplicate_selectors(self) -> None:
        projection = self._finite_control_projection()
        result = projection["results"][0]["projection"]
        result["routes"][1]["selector_value"] = 0
        with self.assertRaisesRegex(ValueError, "duplicated or noncanonical"):
            _finite_control_proof_model(
                projection,
                machine_image={
                    "pe_sha256": "a" * 64,
                    "preferred_base": 0x400000,
                    "image_size": 0x10000,
                },
            )

    def test_remapped_finite_control_is_closure_only_until_proof_modeled(self) -> None:
        projection = self._finite_control_projection()
        projected = projection["results"][0]["projection"]
        evidence = projected["proof_evidence"]
        evidence.pop("route_inventory_sha256")
        evidence["index_provenance"] = {
            "kind": "immutable_u8_remap",
            "source_expression_sha256": "5" * 64,
            "source_upper_exclusive": 3,
            "address": 0x402100,
            "rva_start": 0x2100,
            "rva_end": 0x2103,
            "bytes_sha256": hashlib.sha256(bytes((0, 1, 1))).hexdigest(),
            "bytes_le": [0, 1, 1],
            "possible_values": [0, 1],
        }
        evidence["route_inventory_sha256"] = canonical_sha256_v3(evidence)
        projected["target_inventory_sha256"] = evidence["route_inventory_sha256"]
        with self.assertRaisesRegex(
            ValueError, "remapped finite-control selectors lack a proof model"
        ):
            _finite_control_proof_model(
                projection,
                machine_image={
                    "pe_sha256": "a" * 64,
                    "preferred_base": 0x400000,
                    "image_size": 0x10000,
                },
            )
        with self.assertRaisesRegex(
            ValueError, "remapped finite-control selectors lack a proof model"
        ):
            MachineProjectionV1.parse({**projected, "at": "exit"})

        operation = {
            "results": [
                {
                    "id": "target",
                    "projection": {
                        "kind": "finite_control_target",
                        "at": "exit",
                        "unit_id": "dispatch",
                        "selector_parameter_id": "selector",
                        "targets": [
                            {
                                "logical_value": route["logical_value"],
                                "target_rva": route["target_rva"],
                            }
                            for route in projected["routes"]
                        ],
                    },
                }
            ],
        }
        with self.assertRaisesRegex(
            BoundaryModelError,
            "remapped finite-control selectors lack a proof model",
        ):
            _materialize_kernel_finite_control_targets(
                operation,
                finite_control_routes=[evidence],
                expected_pe_sha256="a" * 64,
                machine_image={
                    "pe_sha256": "a" * 64,
                    "preferred_base": 0x400000,
                    "image_size": 0x10000,
                },
            )

    def test_control_results_are_compared_by_step_outcome_only(self) -> None:
        self.assertEqual(
            _exit_comparisons(
                {
                    "results": [
                        {
                            "id": "route",
                            "projection": {"kind": "control_condition"},
                        },
                        {
                            "id": "target",
                            "projection": {
                                "kind": "finite_control_target",
                                "targets": [{"logical_value": 0, "target_rva": 0x1000}],
                            },
                        },
                    ],
                    "state": [],
                }
            ),
            [],
        )

    def test_logical_results_are_observable_on_all_normal_region_exits(self) -> None:
        self.assertEqual(
            _exit_comparisons(
                {
                    "results": [
                        {
                            "id": "value",
                            "projection": {
                                "kind": "register",
                                "register": "eax",
                                "width": 32,
                                "at": "exit",
                            },
                        }
                    ],
                    "state": [],
                }
            ),
            [
                {
                    "id": "result:value",
                    "left": "((spx_proof_exact_output.eax))",
                    "right": "((source_state.eax))",
                    "condition": "!(source_result.kind == SPX_FALLTHROUGH || source_result.kind == SPX_JUMP || source_result.kind == SPX_BRANCH || source_result.kind == SPX_RETURN || source_result.kind == SPX_INDIRECT_JUMP)",
                }
            ],
        )

    def test_nonvacuity_requires_every_declared_witness_function(self) -> None:
        goals = [
            {
                "goal": "source.coverage.1",
                "status": "SATISFIED",
                "sourceLocation": {"function": "source_segment"},
            },
            {
                "goal": "terminal.coverage.1",
                "status": "FAILED",
                "sourceLocation": {"function": "terminal_check"},
            },
        ]
        completed = subprocess.CompletedProcess(
            args=["cbmc"],
            returncode=0,
            stdout=json.dumps([{"goals": goals}]),
            stderr="",
        )
        with patch("subprocess.run", return_value=completed):
            incomplete = run_cbmc_cover(
                command=["cbmc"],
                expected_functions=["source_segment", "terminal_check"],
                timeout_seconds=1,
            )
        self.assertEqual(incomplete["status"], "incomplete")

        goals[1]["status"] = "SATISFIED"
        completed = subprocess.CompletedProcess(
            args=["cbmc"],
            returncode=0,
            stdout=json.dumps([{"goals": goals}]),
            stderr="",
        )
        with patch("subprocess.run", return_value=completed):
            satisfied = run_cbmc_cover(
                command=["cbmc"],
                expected_functions=["source_segment", "terminal_check"],
                timeout_seconds=1,
            )
        self.assertEqual(satisfied["status"], "satisfied")
        self.assertEqual(
            satisfied["witnessed_functions"],
            ["source_segment", "terminal_check"],
        )

    def test_nonvacuity_rejects_an_undeclared_cover_goal(self) -> None:
        goals = [
            {
                "goal": "selected.coverage.1",
                "status": "SATISFIED",
                "sourceLocation": {"function": "selected_target"},
            },
            {
                "goal": "wrapper.coverage.1",
                "status": "FAILED",
                "sourceLocation": {"function": "source_segment"},
            },
        ]
        completed = subprocess.CompletedProcess(
            args=["cbmc"],
            returncode=0,
            stdout=json.dumps([{"goals": goals}]),
            stderr="",
        )
        with patch("subprocess.run", return_value=completed):
            result = run_cbmc_cover(
                command=["cbmc"],
                expected_functions=["selected_target"],
                timeout_seconds=1,
            )
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["code"], "cbmc_nonvacuity_unwitnessed")

    def test_stop_on_fail_direct_result_is_a_counterexample(self) -> None:
        direct_result = {
            "property": "check.assertion.4",
            "status": "failed",
            "description": "observable result differs",
            "trace": [
                {
                    "stepType": "assignment",
                    "lhs": "source_result.kind",
                    "value": {"data": "SPX_MEMORY_FAULT"},
                },
                {
                    "stepType": "failure",
                    "comment": "observable result differs",
                    "sourceLocation": {"file": "proof.c", "line": "42"},
                },
            ],
        }
        completed = subprocess.CompletedProcess(
            args=["cbmc"],
            returncode=10,
            stdout=json.dumps(
                [
                    direct_result,
                    {"messageType": "STATUS-MESSAGE", "messageText": "failed"},
                    {"cProverStatus": "failure"},
                ]
            ),
            stderr="",
        )
        with patch("subprocess.run", return_value=completed):
            result = run_cbmc_properties(command=["cbmc"], timeout_seconds=1)
        self.assertEqual(result["status"], "violated")
        self.assertEqual(result["code"], "cbmc_counterexample")
        self.assertEqual(result["detail"], "observable result differs")
        self.assertEqual(result["source"], {"file": "proof.c", "line": "42"})
        self.assertEqual(len(result["counterexample"]), 2)

    def test_invented_direct_success_result_cannot_authorize_a_proof(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["cbmc"],
            returncode=0,
            stdout=json.dumps([{"property": "check.assertion.1", "status": "success"}]),
            stderr="",
        )
        with patch("subprocess.run", return_value=completed):
            result = run_cbmc_properties(command=["cbmc"], timeout_seconds=1)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["code"], "cbmc_no_properties_checked")

    def test_addressed_object_limit_has_a_distinct_non_authorizing_diagnostic(self) -> None:
        message = ("too many addressed objects: maximum number of objects is set to 2^n=256 "
                   "(with n=8); use the `--object-bits n` option to increase the maximum number")
        completed = subprocess.CompletedProcess(args=["cbmc"], returncode=6,
            stdout=json.dumps([{"messageType": "ERROR", "messageText": message}]), stderr="")
        with patch("subprocess.run", return_value=completed):
            result = run_cbmc_properties(command=["cbmc"], timeout_seconds=1)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["code"], "cbmc_object_limit")
        self.assertEqual(result["detail"], message)

    def test_timeout_retains_partial_solver_bytes_without_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory) / "query"
            error = subprocess.TimeoutExpired(["cbmc"], 1, output=b'[{"partial": "\xff', stderr=b"timeout")
            with patch("subprocess.run", side_effect=error):
                result = run_cbmc_properties(command=["cbmc"], timeout_seconds=1, output_prefix=prefix)
            self.assertEqual(result["code"], "cbmc_timeout")
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(prefix.with_suffix(".stdout").read_bytes(), error.stdout)
            self.assertEqual(prefix.with_suffix(".stderr").read_bytes(), error.stderr)

    def test_assertion_inventory_is_unique_and_canonical(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["cbmc"],
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "properties": [
                            {
                                "class": "assertion",
                                "name": "proof.assertion.2",
                                "description": "second",
                                "sourceLocation": {"function": "proof"},
                            },
                            {"class": "pointer dereference", "name": "proof.pointer.1"},
                            {
                                "class": "assertion",
                                "name": "proof.assertion.1",
                                "description": "first",
                                "sourceLocation": {"function": "proof"},
                            },
                        ]
                    }
                ]
            ),
            stderr="",
        )
        with patch("subprocess.run", return_value=completed):
            result = discover_cbmc_assertions(
                command=["cbmc", "model.goto", "--show-properties"],
                timeout_seconds=1,
            )
        self.assertEqual(result["status"], "satisfied")
        self.assertEqual(
            result["property_ids"],
            ["proof.assertion.1", "proof.assertion.2"],
        )

    def test_assertion_inventory_rejects_incomplete_metadata(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["cbmc"],
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "properties": [
                            {
                                "class": "assertion",
                                "name": "proof.assertion.1",
                                "description": "typed property without source owner",
                                "sourceLocation": {},
                            }
                        ]
                    }
                ]
            ),
            stderr="",
        )
        with patch("subprocess.run", return_value=completed):
            result = discover_cbmc_assertions(
                command=["cbmc", "model.goto", "--show-properties"],
                timeout_seconds=1,
            )
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(
            result["code"],
            "cbmc_assertion_inventory_empty_or_ambiguous",
        )

    def test_safety_and_loop_inventories_preserve_cbmc_classification(
        self,
    ) -> None:
        safety = subprocess.CompletedProcess(
            args=["cbmc"],
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "properties": [
                            {
                                "class": "pointer dereference",
                                "name": "proof.pointer_dereference.1",
                                "description": "pointer invalid",
                                "sourceLocation": {"function": "proof"},
                            },
                            {
                                "class": "overflow",
                                "name": "proof.overflow.1",
                                "description": "signed overflow",
                                "sourceLocation": {"function": "helper"},
                            },
                        ]
                    }
                ]
            ),
            stderr="",
        )
        loops = subprocess.CompletedProcess(
            args=["cbmc"],
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "loops": [
                            {
                                "name": "helper.2",
                                "sourceLocation": {"function": "helper"},
                            },
                            {
                                "name": "proof.0",
                                "sourceLocation": {"function": "proof"},
                            },
                        ]
                    }
                ]
            ),
            stderr="",
        )
        with patch("subprocess.run", side_effect=[safety, loops]):
            safety_result = discover_cbmc_safety_properties(
                command=["cbmc", "model.goto", "--show-properties"],
                timeout_seconds=1,
            )
            loop_result = discover_cbmc_loops(
                command=["cbmc", "model.goto", "--show-loops"],
                timeout_seconds=1,
            )
        self.assertEqual(safety_result["status"], "satisfied")
        self.assertEqual(
            [item["class"] for item in safety_result["safety_properties"]],
            ["overflow", "pointer dereference"],
        )
        self.assertEqual(
            loop_result["unwinding_property_ids"],
            ["helper.unwind.2", "proof.unwind.0"],
        )



















if __name__ == "__main__":
    unittest.main()
