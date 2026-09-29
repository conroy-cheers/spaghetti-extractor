from __future__ import annotations

import unittest
from copy import deepcopy

from spaghetti_extractor.boundary import BoundaryModelError
from spaghetti_extractor.components.binding_intent import (
    ComponentMachineBindingIntentV1,
    MachineOperationSemanticsV1,
)
from spaghetti_extractor.components.interface_package_v5 import (
    ComponentInterfaceIntentV1,
    compile_component_interface_v5,
)
from spaghetti_extractor.components.normalized_component import (
    NormalizedComponentContract,
    NormalizedMachineBinding,
)
from spaghetti_extractor.components.machine_binding import (
    ComponentMachineBindingError, OperationMachineBindingV1,
)
from tests.unit.boundary._support import schema, value


class EffectFactReferenceTests(unittest.TestCase):
    def projection(self):
        return {"operation_id": "run", "entry_unit_ids": ["loop"],
            "exit_unit_ids": ["tail"], "parameters": [], "results": [],
            "state": [], "preserved_state_ids": [], "callback_operation_ids": [],
            "continuation_unit_ids": [], "effects": [
                {"effect_id": "text_written", "unit_id": unit, "family": "memory_event",
                 "index": index, "fact_sha256": digest * 64}
                for unit, index, digest in (("loop", 0, "a"), ("loop", 1, "b"), ("tail", 0, "c"))]}

    def test_one_logical_effect_retains_every_machine_fact(self):
        projection = self.projection()
        parsed = OperationMachineBindingV1.parse(projection, "operation")
        self.assertEqual(len(parsed.effects), 3)
        self.assertEqual(parsed.to_payload(), projection)
        for count in (0, 1):
            projection = self.projection()
            projection["effects"] = projection["effects"][:count]
            self.assertEqual(OperationMachineBindingV1.parse(projection, "operation").to_payload(), projection)

    def test_duplicate_fact_identity_or_unordered_references_fail_closed(self):
        for mutation in ("duplicate", "changed_digest", "reversed"):
            with self.subTest(mutation=mutation):
                projection = self.projection()
                if mutation == "reversed":
                    projection["effects"].reverse()
                else:
                    duplicate = deepcopy(projection["effects"][0])
                    if mutation == "changed_digest": duplicate["fact_sha256"] = "d" * 64
                    projection["effects"].insert(1, duplicate)
                with self.assertRaisesRegex(ComponentMachineBindingError, "fact references"):
                    OperationMachineBindingV1.parse(projection, "operation")


def _bundle():
    intent = ComponentInterfaceIntentV1.create(
        component_id="fixture-component",
        schema=schema(),
        state=[],
        operations=[
            {
                "id": "run",
                "signature_id": "operation",
                "source_values": [
                    value("argument", "pair"),
                    value("result", "pair"),
                ],
                "projection_entries": [
                    {
                        "source_id": "argument",
                        "target": {
                            "root": "parameter",
                            "value_id": "argument",
                            "fields": [],
                        },
                    },
                    {
                        "source_id": "result",
                        "target": {
                            "root": "result",
                            "value_id": "result",
                            "fields": [],
                        },
                    },
                ],
                "lifecycle_bindings": [],
                "lifecycle_additional_roots": {},
                "checked_interaction_contract_ids": [],
                "effect_ids": ["observe"],
                "allowed_service_ids": [],
                "pre_states": ["ready"],
                "post_states": ["ready"],
            }
        ],
        effects=[
            {
                "id": "observe",
                "kind": "observable",
                "operation": "run",
                "target": None,
            }
        ],
        services=[],
        protocol_states=["ready"],
        initial_protocol_state="ready",
    )
    return compile_component_interface_v5(intent)


def _semantics() -> MachineOperationSemanticsV1:
    return MachineOperationSemanticsV1.create(
        operation_id="run",
        kind="operation",
        unit_ids=["unit.00401000"],
        entry_rvas=[0x1000],
        transfer_ids=["transfer.00401000"],
        effect_ids=["observe"],
        service_ids=[],
        callback_ids=[],
        outcome_protocol_ids=["normal"],
    )


def _authority() -> dict[str, object]:
    return {
        "object_authority_selectors": [
            {
                "authority_id": "image.data",
                "rule_id": "image:test:section:1",
            }
        ],
        "pointer_views": [],
        "service_ids": [],
        "callback_ids": [],
        "outcome_protocol_ids": ["normal"],
        "relation_receipt_sha256s": [],
        "induction_evidence_sha256": None,
    }


class ComponentBindingIntentTests(unittest.TestCase):
    def test_declared_continuation_is_proof_context_without_becoming_owned(self):
        from spaghetti_extractor.components.refinement_v5 import _contract_transfer_ids
        from spaghetti_extractor.semantic_providers.portable_c_inputs import _direct_operation_rows
        from types import SimpleNamespace

        row = _semantics().to_payload()
        row.pop("semantic_sha256")
        row["machine_projection"] = {"operation": {"continuation_unit_ids": ["continuation"]}}
        intent = ComponentMachineBindingIntentV1.create(
            component_id="fixture-component", operations=[{**row, **_authority()}])
        semantics = intent.operations[0].semantics
        before = intent.to_payload()
        self.assertEqual(semantics.proof_context_transfer_ids,
                         ("continuation", "transfer.00401000"))
        self.assertEqual(_contract_transfer_ids(SimpleNamespace(machine_semantics=[semantics])),
                         semantics.proof_context_transfer_ids)
        operations = _direct_operation_rows(binding=intent,
            semantic_slice=SimpleNamespace(payload={"definitions": [{
                "symbol_id": "original:function:unit.00401000", "definition_id": "owned"}]}))
        self.assertEqual(operations[0]["context_transfer_ids"], list(semantics.proof_context_transfer_ids))
        self.assertEqual(operations[0]["unit_ids"], ["unit.00401000"])
        self.assertEqual(operations[0]["definition_ids"], ["owned"])
        self.assertEqual(intent.to_payload(), before)

    def test_intent_is_content_bound_and_round_trips(self) -> None:
        semantics = _semantics().to_payload()
        semantics.pop("semantic_sha256")
        intent = ComponentMachineBindingIntentV1.create(
            component_id="fixture-component",
            operations=[
                {
                    **semantics,
                    **_authority(),
                }
            ],
        )
        self.assertEqual(
            ComponentMachineBindingIntentV1.parse(intent.to_payload()), intent
        )
        stale = intent.to_payload()
        stale["operations"][0]["entry_rvas"] = [0x1004]
        with self.assertRaisesRegex(BoundaryModelError, "stale"):
            ComponentMachineBindingIntentV1.parse(stale)

    def test_normalized_models_are_format_free_and_fail_closed(self) -> None:
        bundle = _bundle()
        contract = NormalizedComponentContract.create(
            interface=bundle.interface,
            machine_semantics=[_semantics()],
        )
        self.assertEqual(contract.status, "checked")
        digest = "a" * 64
        binding = NormalizedMachineBinding.create(
            bundle=bundle,
            contract=contract,
            artifacts={
                "pe_sha256": digest,
                "machine_ir_sha256": digest,
                "machine_ir_manifest_sha256": digest,
                "structural_units_sha256": digest,
                "unit_inventory_sha256": digest,
                "component_unit_inventory_sha256": digest,
            },
            operation_authority={"run": _authority()},
        )
        self.assertEqual(binding.status, "checked")
        self.assertEqual(binding.operations[0]["id"], "run")
        with self.assertRaisesRegex(BoundaryModelError, "artifact set"):
            NormalizedMachineBinding.create(
                bundle=bundle,
                contract=contract,
                artifacts={},
                operation_authority={},
            )

    def test_missing_semantics_remains_incomplete(self) -> None:
        contract = NormalizedComponentContract.create(
            interface=_bundle().interface,
            machine_semantics=[],
        )
        self.assertEqual(contract.status, "incomplete")
        self.assertEqual(
            contract.issues[0]["code"],
            "machine_operation_semantics_missing",
        )


if __name__ == "__main__":
    unittest.main()
