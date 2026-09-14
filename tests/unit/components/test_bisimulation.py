from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation import (
    COMPONENT_PROOF_PLAN_V1_FORMAT,
    ComponentBisimulationError,
    ComponentBisimulationIntentV1,
    build_component_proof_plan_v1,
    scan_source_proof_markers,
)
from spaghetti_extractor.components.contextual_bisimulation import (
    _validate_contextual_model_bounds,
    build_contextual_refinement_v2,
)
from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface


def _unit(identity: str, rva: int, targets: list[int]) -> dict[str, object]:
    return {
        "id": identity,
        "source": {"original": {"rva_start": rva, "rva_end": rva + 1}},
        "semantics": {
            "edge_conditions": [
                {"target_rva": target, "condition": {"op": "true"}}
                for target in targets
            ],
            "outcome": (
                {"kind": "return"}
                if not targets
                else {"kind": "jump", "target_rva": targets[0]}
            ),
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [],
            "external_events": [],
            "faults": [],
        },
    }


def _operation() -> dict[str, object]:
    return {
        "operation_id": "run",
        "entry_unit_ids": ["entry"],
        "exit_unit_ids": ["exit"],
        "units": [
            _unit("entry", 0x1000, [0x1010]),
            _unit("head", 0x1010, [0x1020, 0x1030]),
            _unit("body", 0x1020, [0x1010]),
            _unit("exit", 0x1030, []),
        ],
    }


def _acyclic_operation() -> dict[str, object]:
    operation = _operation()
    operation["units"] = [
        (
            unit
            if unit["id"] != "body"
            else {
                **unit,
                "semantics": {
                    **unit["semantics"],
                    "edge_conditions": [
                        {"target_rva": 0x1030, "condition": {"op": "true"}}
                    ],
                    "outcome": {"kind": "jump", "target_rva": 0x1030},
                },
            }
        )
        for unit in operation["units"]
    ]
    return operation


def _interface() -> ProofKernelComponentInterface:
    return ProofKernelComponentInterface.parse(
        {
            "id": "counter",
            "types": [{"id": "u32", "kind": "scalar", "c_type": "uint32_t"}],
            "state": [],
            "operations": [
                {
                    "id": "run",
                    "kind": "operation",
                    "parameters": [{"id": "limit", "type_id": "u32"}],
                    "results": [{"id": "result", "type_id": "u32"}],
                    "effect_ids": [],
                    "allowed_service_ids": [],
                    "pre_states": ["ready"],
                    "post_states": ["ready"],
                }
            ],
            "effects": [],
            "services": [],
            "protocol": {"states": ["ready"], "initial_state": "ready"},
        }
    )


def _intent() -> ComponentBisimulationIntentV1:
    return ComponentBisimulationIntentV1.create(
        component_id="counter",
        operations=[
            {
                "operation_id": "run",
                "syncs": [
                    {
                        "id": "loop",
                        "exact_unit_id": "head",
                        "invariant": {"op": "true"},
                        "captures": [
                            {
                                "kind": "parameter",
                                "id": "limit",
                                "mode": "machine_codec",
                                "projection": {
                                    "kind": "register",
                                    "register": "ecx",
                                    "width": 32,
                                    "at": "entry",
                                },
                                "encoding": {"op": "parameter", "name": "limit"},
                                "decoding": None,
                            },
                            {
                                "kind": "source_state",
                                "id": "cursor",
                                "mode": "machine_codec",
                                "projection": {
                                    "kind": "register",
                                    "register": "edx",
                                    "width": 32,
                                    "at": "entry",
                                },
                                "encoding": {"op": "state_input", "name": "cursor"},
                                "decoding": {"op": "projected_value"},
                            },
                        ],
                        "derived": [],
                    }
                ],
            }
        ],
    )


class ComponentBisimulationTests(unittest.TestCase):

    def test_source_member_binding_is_structured_and_content_bound(self) -> None:
        operations = _intent().to_payload()["operations"]
        operations[0]["syncs"][0]["source_bindings"] = {
            "cursor": {"root": "context", "members": [
                {"access": "pointer", "name": "state"},
                {"access": "direct", "name": "cursor"},
            ]},
        }
        intent = ComponentBisimulationIntentV1.create(component_id="counter", operations=operations)
        self.assertNotEqual(intent.intent_sha256, _intent().intent_sha256)
        self.assertEqual(ComponentBisimulationIntentV1.parse(intent.to_payload()), intent)
        sync = intent.operations[0].syncs[0]
        self.assertEqual(sync.source_arguments(), ("limit", "context->state.cursor"))
        scan_source_proof_markers(
            "SPX_PROOF_BEGIN(run); SPX_PROOF_SYNC(loop, 1, limit, context -> state . cursor);",
            operation_id="run", expected_syncs=(sync,),
        )
        for expression in ("cursor", "context->other.cursor", "context->state.cursor++", "get()->state.cursor"):
            with self.subTest(expression=expression), self.assertRaises(ComponentBisimulationError):
                scan_source_proof_markers(
                    "SPX_PROOF_BEGIN(run); SPX_PROOF_SYNC(loop, 1, limit, " + expression + ");",
                    operation_id="run", expected_syncs=(sync,),
                )

    def test_source_member_bindings_reject_code_and_unknown_values(self) -> None:
        for binding in (
            {"root": "context()", "members": []},
            {"root": "context", "members": [{"access": "call", "name": "value"}]},
            {"root": "context", "members": [{"access": "direct", "name": "value[0]"}]},
            {"root": "context", "members": [], "code": "ignored()"},
        ):
            operations = _intent().to_payload()["operations"]
            operations[0]["syncs"][0]["source_bindings"] = {"cursor": binding}
            with self.subTest(binding=binding), self.assertRaises(ComponentBisimulationError):
                ComponentBisimulationIntentV1.create(component_id="counter", operations=operations)
        operations[0]["syncs"][0]["source_bindings"] = {"unknown": {"root": "x", "members": []}}
        with self.assertRaisesRegex(ComponentBisimulationError, "unknown captures"):
            ComponentBisimulationIntentV1.create(component_id="counter", operations=operations)

    def test_sync_invariant_rejects_raw_c(self) -> None:
        operation = _intent().to_payload()["operations"][0]
        operation["syncs"][0]["invariant"] = {
            "op": "raw_c",
            "value": "cursor <= limit",
        }
        with self.assertRaisesRegex(ComponentBisimulationError, "unsupported"):
            ComponentBisimulationIntentV1.create(
                component_id="counter", operations=[operation]
            )

    def test_sync_invariant_rejects_values_outside_capture_environment(self) -> None:
        operation = _intent().to_payload()["operations"][0]
        operation["syncs"][0]["invariant"] = {
            "op": "eq",
            "args": [
                {"op": "loop_variable", "name": "hidden"},
                {"op": "const", "value": 0, "width": 32},
            ],
        }
        with self.assertRaisesRegex(ComponentBisimulationError, "capture environment"):
            ComponentBisimulationIntentV1.create(
                component_id="counter", operations=[operation]
            )

    def test_operation_shared_captures_are_expanded_without_intent_duplication(self) -> None:
        capture = {
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
        }
        intent = ComponentBisimulationIntentV1.create(
            component_id="countdown",
            operations=[
                {
                    "operation_id": "run",
                    "shared_captures": [capture],
                    "syncs": [
                        {
                            "id": "loop",
                            "exact_unit_id": "semantic-transfer:original-cutpoint-00001010-00001020",
                            "invariant": {"op": "true"},
                            "captures": [],
                            "derived": [],
                        }
                    ],
                }
            ],
        )

        self.assertEqual(intent.operations[0].syncs[0].captures[0].identity, "n")
        operation = intent.to_payload()["operations"][0]
        self.assertEqual(operation["shared_captures"], [capture])
        self.assertEqual(operation["syncs"][0]["captures"], [])
        self.assertEqual(ComponentBisimulationIntentV1.parse(intent.to_payload()), intent)

    def test_plan_has_one_shard_per_entry_and_sync_and_no_paths(self) -> None:
        result = build_component_proof_plan_v1(
            component_id="counter",
            semantic_contract_sha256="a" * 64,
            interface=_interface(),
            operations=[_operation()],
            operation_sources={
                "run": """
uint32_t counter_run(uint32_t limit) {
  uint32_t cursor = 0U;
  SPX_PROOF_BEGIN(run);
  while (cursor != limit) {
    SPX_PROOF_SYNC(loop, cursor <= limit, limit, cursor);
    ++cursor;
  }
  return cursor;
}
"""
            },
            source_package_sha256="b" * 64,
            intent=_intent(),
        )

        self.assertEqual(result["format"], COMPONENT_PROOF_PLAN_V1_FORMAT)
        self.assertEqual(result["cost"]["shards"], 2)
        self.assertEqual(result["cost"]["materialized_paths"], 0)
        self.assertTrue(result["operations"][0]["closure"]["exact_cycles_cut"])

    def test_acyclic_plan_has_one_continuous_entry_obligation(self) -> None:
        intent = ComponentBisimulationIntentV1.create(
            component_id="counter",
            operations=[{"operation_id": "run", "syncs": []}],
        )
        result = build_component_proof_plan_v1(
            component_id="counter",
            semantic_contract_sha256="a" * 64,
            interface=_interface(),
            operations=[_acyclic_operation()],
            operation_sources={"run": "SPX_PROOF_BEGIN(run);"},
            source_package_sha256="b" * 64,
            intent=intent,
        )

        self.assertEqual(result["cost"]["shards"], 1)
        self.assertEqual(
            result["operations"][0]["obligations"],
            [
                {
                    "id": "entry:entry",
                    "source": {"kind": "operation_entry", "id": "entry"},
                    "exact_start_unit_id": "entry",
                }
            ],
        )
        self.assertEqual(result["operations"][0]["exact"]["cyclic_sccs"], [])
        self.assertTrue(
            result["policy"]["unsegmented_acyclic_operations_use_single_entry_obligation"]
        )

    def test_acyclic_sync_creates_a_checked_continuation_obligation(self) -> None:
        result = build_component_proof_plan_v1(
            component_id="counter",
            semantic_contract_sha256="a" * 64,
            interface=_interface(),
            operations=[_acyclic_operation()],
            operation_sources={
                "run": "SPX_PROOF_BEGIN(run); "
                "SPX_PROOF_SYNC(loop, 1, limit, cursor);"
            },
            source_package_sha256="b" * 64,
            intent=_intent(),
        )
        self.assertEqual(result["operations"][0]["exact"]["cyclic_sccs"], [])
        self.assertEqual(result["cost"]["shards"], 2)
        self.assertEqual(result["cost"]["materialized_paths"], 0)
        self.assertEqual(result["operations"][0]["obligations"][1]["id"], "sync:loop")
        self.assertTrue(result["policy"]["acyclic_and_cyclic_syncs_checked"])

    def test_uncut_exact_cycle_fails_closed(self) -> None:
        with self.assertRaisesRegex(ComponentBisimulationError, "exact cycle"):
            build_component_proof_plan_v1(
                component_id="counter",
                semantic_contract_sha256="a" * 64,
                interface=_interface(),
                operations=[_operation()],
                operation_sources={"run": "SPX_PROOF_BEGIN(run);"},
                source_package_sha256="b" * 64,
                intent=None,
            )

    def test_acyclic_cut_does_not_discharge_an_uncut_cycle(self) -> None:
        payload = _intent().to_payload()
        payload["operations"][0]["syncs"][0]["exact_unit_id"] = "entry"
        payload.pop("intent_sha256")
        intent = ComponentBisimulationIntentV1.create(
            component_id="counter", operations=payload["operations"],
        )
        with self.assertRaisesRegex(ComponentBisimulationError, "exact cycle"):
            build_component_proof_plan_v1(
                component_id="counter", semantic_contract_sha256="a" * 64,
                interface=_interface(), operations=[_operation()],
                operation_sources={
                    "run": "SPX_PROOF_BEGIN(run); SPX_PROOF_SYNC(loop, 1, limit, cursor);"
                },
                source_package_sha256="b" * 64, intent=intent,
            )

    def test_unannotated_source_loop_fails_closed(self) -> None:
        with self.assertRaisesRegex(ComponentBisimulationError, "unannotated"):
            build_component_proof_plan_v1(
                component_id="counter",
                semantic_contract_sha256="a" * 64,
                interface=_interface(),
                operations=[_operation()],
                operation_sources={
                    "run": "SPX_PROOF_BEGIN(run); while (1) { break; } "
                    "SPX_PROOF_SYNC(loop, 1, limit, cursor);"
                },
                source_package_sha256="b" * 64,
                intent=_intent(),
            )

    def test_explicit_goto_source_control_fails_closed(self) -> None:
        with self.assertRaisesRegex(ComponentBisimulationError, "explicit goto"):
            build_component_proof_plan_v1(
                component_id="counter",
                semantic_contract_sha256="a" * 64,
                interface=_interface(),
                operations=[_operation()],
                operation_sources={
                    "run": "SPX_PROOF_BEGIN(run); retry: goto retry; "
                    "SPX_PROOF_SYNC(loop, 1, limit, cursor);"
                },
                source_package_sha256="b" * 64,
                intent=_intent(),
            )

    def test_stale_intent_digest_is_rejected(self) -> None:
        payload = _intent().to_payload()
        stale = copy.deepcopy(payload)
        stale["component_id"] = "changed"
        with self.assertRaisesRegex(ComponentBisimulationError, "stale"):
            ComponentBisimulationIntentV1.parse(stale)



if __name__ == "__main__":
    unittest.main()
