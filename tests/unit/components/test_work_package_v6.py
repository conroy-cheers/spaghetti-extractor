from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.formats import (
    COMPONENT_ADOPTION_INTENT_V1_FORMAT,
    COMPONENT_WORK_PACKAGE_V6_FORMAT,
)
from spaghetti_extractor.components.work_package_v6 import (
    ComponentAdoptionIntentV1,
    ComponentWorkPackageV6,
    ComponentWorkPackageV6Error,
    _machine_review_frontier,
)
from spaghetti_extractor.semantic_providers.formats import SEMANTIC_SLICE_V2_FORMAT


def _payload() -> dict[str, object]:
    definition = {
        "definition_id": "semantic-definition-v2:" + "1" * 64,
        "symbol_id": "original:function:unit.00401000",
        "definition_kind": "transfer_v2",
        "definition_sha256": "2" * 64,
        "dependency_contract_sha256s": ["3" * 64],
        "allowed_provider_kinds": [
            "generated_behavioral_c", "qualified_portable_c",
        ],
    }
    slice_core = {
        "format": SEMANTIC_SLICE_V2_FORMAT,
        "definitions": [definition],
        "obligations": [],
        "dependency_contract_sha256s": ["3" * 64],
    }
    semantic_slice = {
        **slice_core,
        "semantic_slice_sha256": canonical_sha256_v3(slice_core),
    }
    operation = {
        "operation_id": "run",
        "symbol": "fixture_run",
        "signature_id": "operation.run",
        "semantic_sha256": "4" * 64,
        "definition_ids": [definition["definition_id"]],
        "unit_ids": ["unit.00401000"],
        "context_transfer_ids": ["unit.00401000", "unit.00401010"],
        "entry_rvas": [0x401000],
        "entry_unit_ids": ["unit.00401000"],
        "exit_unit_ids": ["unit.00401010"],
        "projection_sha256": "5" * 64,
        "projection_receipt_sha256": "6" * 64,
        "lifecycle_sha256": "7" * 64,
        "lifecycle_receipt_sha256": "8" * 64,
        "effect_ids": [],
        "service_ids": [],
        "callback_ids": [],
        "outcome_protocol_ids": ["normal"],
        "object_authority_selectors": [],
        "pointer_views": [],
        "machine_projection": {"operation": {}},
    }
    core = {
        "format": COMPONENT_WORK_PACKAGE_V6_FORMAT,
        "status": "ready",
        "authority": False,
        "component_id": "fixture-component",
        "proof_classification": "machine_overlay",
        "bindings": {
            "linked_semantic_module_sha256": "9" * 64,
            "semantic_slice_sha256": semantic_slice["semantic_slice_sha256"],
            "executable_transfer_plan_sha256": "a" * 64,
            "interface_sha256": "b" * 64,
            "schema_sha256": "c" * 64,
            "binding_intent_sha256": "d" * 64,
            "behavioral_c_source_map_sha256": "e" * 64,
        },
        "operations": [operation],
        "semantic_slice": semantic_slice,
        "faithful_c_slices": [{
            "unit_id": "unit.00401000",
            "source_path": "baseline/behavioral-fn-00401000.c",
            "source_sha256": "f" * 64,
            "rva_start": 0x401000,
            "rva_end": 0x401010,
            "line_start": 4,
            "line_end": 19,
        }],
        "requirements": {
            "service_ids": [],
            "object_authority_selectors": [],
            "lifecycle_ids": ["lifecycle-run"],
            "callback_ids": [],
            "outcome_protocol_ids": ["normal"],
            "obligation_ids": [],
            "dependency_contract_sha256s": ["3" * 64],
        },
        "blockers": [],
        "suggested_tests": [{
            "code": "component-contextual-refinement-case",
            "operation_id": "run",
            "rank": 1,
            "veto_only": True,
        }],
        "generated_files": [
            {"path": "include/component.h", "sha256": "0" * 64},
            {"path": "src/component.c", "sha256": "1" * 64},
        ],
        "policy": {
            "authorizes_implementation": False,
            "generated_baseline_mutable": False,
            "operator_machine_hashes_required": False,
            "tests_authorize": False,
        },
    }
    return {**core, "work_package_sha256": canonical_sha256_v3(core)}


class ComponentWorkPackageV6Tests(unittest.TestCase):
    def test_seed_adoption_intent_is_canonical_and_digest_free(self) -> None:
        intent = ComponentAdoptionIntentV1.for_seed(
            0x401000, ["single-entry", "function-like", "single-entry"]
        )
        self.assertEqual(intent.payload["format"], COMPONENT_ADOPTION_INTENT_V1_FORMAT)
        self.assertEqual(intent.payload["component_id"], "component-00401000")
        self.assertEqual(
            intent.payload["proposal_kinds"], ["function-like", "single-entry"]
        )
        self.assertFalse(any(key.endswith("_sha256") for key in intent.payload))

    def test_seed_adoption_intent_rejects_noncanonical_entries(self) -> None:
        payload = dict(ComponentAdoptionIntentV1.for_seed(0x401000, []).payload)
        payload["operations"] = [{
            "id": "operation",
            "symbol": "fixture",
            "entry_rvas": [0x401010, 0x401000],
        }]
        with self.assertRaisesRegex(
            ComponentWorkPackageV6Error, "operation is malformed"
        ):
            ComponentAdoptionIntentV1.parse(payload)

    def test_package_is_non_authorizing_and_owns_only_slice_definitions(self) -> None:
        package = ComponentWorkPackageV6.parse(_payload())
        self.assertFalse(package.payload["authority"])
        self.assertFalse(package.payload["policy"]["tests_authorize"])
        self.assertEqual(package.payload["proof_classification"], "machine_overlay")
        self.assertEqual(
            package.payload["operations"][0]["definition_ids"],
            [package.payload["semantic_slice"]["definitions"][0]["definition_id"]],
        )
        self.assertEqual(
            package.payload["operations"][0]["context_transfer_ids"],
            ["unit.00401000", "unit.00401010"],
        )

    def test_context_cannot_silently_expand_semantic_ownership(self) -> None:
        payload = _payload()
        payload["operations"][0]["definition_ids"] = []
        core = {key: value for key, value in payload.items()
                if key != "work_package_sha256"}
        payload["work_package_sha256"] = canonical_sha256_v3(core)
        with self.assertRaisesRegex(
            ComponentWorkPackageV6Error, "operation definitions"
        ):
            ComponentWorkPackageV6.parse(payload)

    def test_stale_embedded_slice_is_rejected(self) -> None:
        payload = copy.deepcopy(_payload())
        payload["semantic_slice"]["dependency_contract_sha256s"] = []
        core = {key: value for key, value in payload.items()
                if key != "work_package_sha256"}
        payload["work_package_sha256"] = canonical_sha256_v3(core)
        with self.assertRaisesRegex(ValueError, "semantic-slice"):
            ComponentWorkPackageV6.parse(payload)

    def test_machine_review_frontier_is_exact_and_non_authorizing(self) -> None:
        expressions = [
            {
                "id": index,
                "op": "const",
                "operands": [],
                "parameters": {
                    "aux": 0,
                    "identity": None,
                    "immediate": index,
                },
                "result_sort": "bitvector",
                "width_bits": 32,
            }
            for index in range(16)
        ]
        expressions[12]["parameters"]["immediate"] = 80
        expressions[13] = {
            **expressions[13], "op": "reg",
            "parameters": {"aux": 2, "identity": None, "immediate": 1},
        }
        expressions[14] = {
            **expressions[14], "op": "add32", "operands": [12, 13],
        }
        expressions[15] = {
            **expressions[15], "op": "load", "operands": [14],
            "parameters": {"aux": 4, "identity": None, "immediate": 0},
        }
        call_base = {
            "target_rva": 0,
            "return_rva": 0x401008,
            "ordinal": None,
            "register_nodes": list(range(8)),
            "flag_nodes": list(range(8, 14)),
            "argument_nodes": [],
            "stack_inputs": [[0, 4, 14]],
        }
        transfer_id = "unit.00401000"
        transfer_payload = {
            "plan_sha256": "a" * 64,
            "transfers": [{
                "identity": transfer_id,
                "source": {
                    "rva_start": 0x401000,
                    "rva_end": 0x401010,
                    "contract_sha256": "b" * 64,
                    "instruction_bytes_sha256": "c" * 64,
                    "unit_ir_sha256": "d" * 64,
                },
                "expressions": expressions,
                "calls": [
                    {
                        **call_base,
                        "id": 0,
                        "kind": "external_call",
                        "instruction_rva": 0x401002,
                        "event_index": 0,
                        "target_node": None,
                        "dll": "ddraw.dll",
                        "symbol": "DirectDrawCreate",
                    },
                    {
                        **call_base,
                        "id": 1,
                        "kind": "indirect_call",
                        "instruction_rva": 0x401008,
                        "event_index": 1,
                        "target_node": 15,
                        "dll": None,
                        "symbol": None,
                    },
                ],
                "effects": [{
                    "id": 0,
                    "op": "memory_write",
                    "operands": [0, 1],
                    "parameters": {"aux": 4},
                }],
                "terminator": {
                    "op": "outcome_return",
                    "operands": [2],
                    "parameters": {"aux": 0},
                },
            }],
        }
        frontier = _machine_review_frontier(
            transfer_payload=transfer_payload,
            operations=[{
                "operation_id": "initialize",
                "context_transfer_ids": [transfer_id],
                "service_ids": ["directdraw_create", "set_cooperative_level"],
                "machine_projection": {"service_bindings": []},
            }],
            admitted_domains=[{
                "kind": "checked_indirect_callable_targets_v3",
                "domain_sha256": "e" * 64,
                "external_interface_targets": [{
                    "profile_id": "directx-v1",
                    "profile_sha256": "f" * 64,
                    "interface_id": "IDirectDraw7",
                    "method_contract_sha256": "1" * 64,
                    "method": {
                        "argument_words": 3,
                        "external_protocol": {
                            "kind": "pe32-interface-method",
                            "method": "SetCooperativeLevel",
                            "slot": 20,
                            "offset": 80,
                        },
                        "receiver_resource": {
                            "argument_index": 0,
                            "dispatch_slot": 20,
                            "lifecycle_effect": "preserve",
                            "required_state": "live",
                            "view_id": "IDirectDraw7",
                        },
                    },
                }],
            }],
        )
        operation = frontier["operations"][0]
        self.assertFalse(frontier["authority"])
        self.assertFalse(frontier["policy"]["adopts_service_bindings"])
        self.assertEqual(operation["counts"]["call_events"], 2)
        self.assertEqual(operation["counts"]["indirect_calls"], 1)
        self.assertEqual(operation["counts"]["memory_writes"], 1)
        self.assertEqual(
            operation["counts"]["structurally_classified_indirect_calls"], 1
        )
        self.assertEqual(
            operation["counts"]["structural_interface_candidates"], 1
        )
        structural = operation["exact_call_events"][1][
            "structural_interface_candidates"
        ]
        self.assertEqual(structural[0]["method"], "SetCooperativeLevel")
        self.assertEqual(
            structural[0]["matching_declared_service_ids"],
            ["set_cooperative_level"],
        )
        self.assertFalse(structural[0]["authority"])
        self.assertEqual(
            [row["id"] for row in operation["control_outcomes"][0][
                "expression_nodes"
            ]],
            [2],
        )
        self.assertEqual(
            operation["unmapped_service_ids"],
            ["directdraw_create", "set_cooperative_level"],
        )
        self.assertEqual(
            [row["service_id"] for row in operation["lexical_service_candidates"]],
            ["directdraw_create"],
        )
        self.assertTrue(all(
            row["authority"] is False
            for row in operation["lexical_service_candidates"]
        ))

    def test_stale_review_frontier_is_rejected(self) -> None:
        payload = _payload()
        frontier_core = {
            "authority": False,
            "source_format": "spaghetti-extractor-executable-transfer-plan-v2",
            "source_plan_sha256": "a" * 64,
            "operations": [],
            "policy": {
                "adopts_service_bindings": False,
                "authorizes_effects": False,
                "authorizes_outcomes": False,
                "lexical_candidates_are_presentation_only": True,
                "structural_candidates_are_presentation_only": True,
                "tests_authorize": False,
            },
        }
        payload["blockers"] = [{
            "code": "fixture",
            "review_frontier": {
                **frontier_core,
                "frontier_sha256": canonical_sha256_v3(frontier_core),
            },
        }]
        payload["blockers"][0]["review_frontier"]["authority"] = True
        core = {
            key: value for key, value in payload.items()
            if key != "work_package_sha256"
        }
        payload["work_package_sha256"] = canonical_sha256_v3(core)
        with self.assertRaisesRegex(
            ComponentWorkPackageV6Error, "review frontier fields"
        ):
            ComponentWorkPackageV6.parse(payload)


if __name__ == "__main__":
    unittest.main()
