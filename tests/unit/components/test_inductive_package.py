from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.inductive_package import (
    InductivePackageError,
    materialize_inductive_package,
    write_inductive_package,
)
from spaghetti_extractor.components.inductive_receipts import (
    CheckedInductiveMachineReceiptV1,
)
from spaghetti_extractor.components.inductive_relation import (
    InductiveCutpointRelationV1,
)
from spaghetti_extractor.components.inductive_source import InductiveSourcePlanV1

from .test_inductive_relation import _interface, _operation, _register


def _semantic_contract() -> dict[str, object]:
    interface = _interface()
    core: dict[str, object] = {
        "format": "spaghetti-extractor-component-semantic-contract-v1",
        "status": "satisfied",
        "component_id": "countdown-component",
        "bindings": {
            "pe_sha256": "a" * 64,
            "machine_ir_sha256": "b" * 64,
            "machine_ir_manifest_sha256": "c" * 64,
            "interface_sha256": interface.sha256,
            "machine_binding_sha256": "d" * 64,
        },
        "operations": [_operation()],
        "services": [],
        "issues": [],
        "policy": {
            "original_binary_executed": False,
            "behavior_is_machine_derived": True,
            "operator_expected_outputs_accepted": False,
            "unsupported_semantics_fail_closed": True,
        },
    }
    return {**core, "contract_sha256": canonical_sha256_v3(core)}


def _declaration() -> dict[str, object]:
    return {
        "format": "spaghetti-extractor-inductive-component-declaration-v1",
        "source": {
            "operation_id": "run",
            "state": [{"id": "n", "type_id": "u32"}],
            "phase_ids": ["loop"],
            "completion_ids": ["return"],
            "symbols": {
                "wrapper": "countdown_run",
                "initialize": "countdown_initialize",
                "step": "countdown_step",
                "finish": "countdown_finish",
            },
            "cutpoints": [{
                "unit_id": "head",
                "phase_id": "loop",
                "values": [
                    {
                        "kind": "parameter",
                        "id": "count",
                        "mode": "machine_codec",
                        "projection": _register("ecx", "entry"),
                        "encoding": {"op": "parameter", "name": "count"},
                        "decoding": None,
                    },
                    {
                        "kind": "source_state",
                        "id": "n",
                        "mode": "machine_codec",
                        "projection": _register("edx", "entry"),
                        "encoding": {"op": "state_input", "name": "n"},
                        "decoding": {"op": "projected_value"},
                    },
                ],
                "derived": [{
                    "id": "mirror",
                    "projection": _register("eax", "entry"),
                    "expression": {"op": "state_input", "name": "n"},
                }],
            }],
            "completion_routes": [{
                "source": {"kind": "cutpoint", "id": "head"},
                "target_exit_unit_id": "exit",
                "completion_id": "return",
            }, {
                "source": {"kind": "operation_entry", "id": "entry"},
                "target_exit_unit_id": "exit",
                "completion_id": "return",
            }],
        },
        "proof": {
            "invariants": [{
                "id": "invariant:n-bounded",
                "owner_cutpoint_id": "head",
                "expression": {
                    "op": "ule32",
                    "args": [
                        {"op": "loop_variable", "name": "n"},
                        {"op": "parameter", "name": "count"},
                    ],
                },
            }],
            "measures": [{
                "id": "measure:n",
                "owner_cutpoint_id": "head",
                "variable_id": "n",
                "expression": {"op": "loop_variable", "name": "n"},
            }],
        },
    }


class InductivePackageTests(unittest.TestCase):
    def test_materializes_every_generated_identity_from_exact_semantics(self) -> None:
        package = materialize_inductive_package(
            declaration=_declaration(),
            interface=_interface().to_payload(),
            semantic_contract=_semantic_contract(),
        )
        plan = InductiveSourcePlanV1.parse(package["source_plan"])
        machine = CheckedInductiveMachineReceiptV1.parse(
            package["machine_receipt"], exact_operation=_operation()
        )
        relation = InductiveCutpointRelationV1.parse(
            package["cutpoint_relation"]
        )
        relation.validate_for(_interface(), plan, machine)
        self.assertEqual(package["manifest"]["status"], "checked")
        self.assertFalse(
            package["manifest"]["policy"][
                "generated_segment_ids_accepted_from_operator"
            ]
        )
        self.assertNotIn("segment_id", str(_declaration()))
        self.assertTrue(
            all(
                item["segment_id"].startswith("component-segment-v1:")
                for item in package["cutpoint_relation"]["completion_segments"]
            )
        )

    def test_writes_separate_content_bound_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            package = write_inductive_package(
                declaration=_declaration(),
                interface=_interface().to_payload(),
                semantic_contract=_semantic_contract(),
                out_dir=output,
            )
            self.assertEqual(
                sorted(item.name for item in output.iterdir()),
                [
                    "cutpoint-relation.json",
                    "induction-package.json",
                    "machine-receipt.json",
                    "source-plan.json",
                ],
            )
            self.assertEqual(
                package["manifest"]["artifacts"]["source_plan"]["sha256"],
                package["source_plan"]["plan_sha256"],
            )

    def test_missing_exact_completion_route_fails_closed(self) -> None:
        declaration = copy.deepcopy(_declaration())
        declaration["source"]["completion_routes"][0][
            "target_exit_unit_id"
        ] = "missing"
        with self.assertRaisesRegex(InductivePackageError, "no completion route"):
            materialize_inductive_package(
                declaration=declaration,
                interface=_interface().to_payload(),
                semantic_contract=_semantic_contract(),
            )

    def test_generated_fields_are_not_accepted_from_operator(self) -> None:
        declaration = copy.deepcopy(_declaration())
        declaration["source"]["semantic_contract_sha256"] = "f" * 64
        with self.assertRaisesRegex(InductivePackageError, "exactly"):
            materialize_inductive_package(
                declaration=declaration,
                interface=_interface().to_payload(),
                semantic_contract=_semantic_contract(),
            )


if __name__ == "__main__":
    unittest.main()
