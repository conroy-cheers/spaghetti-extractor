from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.components.relation_ir import (
    ComponentRelationIRError,
    ComponentRelationIRV1,
)
from spaghetti_extractor.components.relation_receipt import (
    ComponentRelationReceiptError,
    ComponentRelationReceiptV1,
)
from spaghetti_extractor.components.interface_ir import PortableComponentInterfaceV2
from spaghetti_extractor.components.interaction_contract import (
    InteractionContractCatalogV1,
)
from spaghetti_extractor.components.interaction_inventory import (
    ComponentInteractionInventoryV1,
    OperationInteractionInventoryV1,
)
from spaghetti_extractor.components.universal_binding import (
    ComponentMachineBindingV3,
    build_component_machine_binding_v4,
)
from spaghetti_extractor.components.relation_lean import render_relation_certificate
from spaghetti_extractor.components.relation_solver import prove_binding_lens


_DIGESTS = {
    "interface_sha256": "1" * 64,
    "machine_binding_sha256": "2" * 64,
    "semantic_contract_sha256": "3" * 64,
    "machine_ir_sha256": "4" * 64,
    "interaction_inventory_sha256": "5" * 64,
    "interaction_contract_catalog_sha256": "6" * 64,
}


def _sort(width: int = 32) -> dict[str, object]:
    return {"kind": "bitvector", "width": width}


def _bool() -> dict[str, object]:
    return {"kind": "bool"}


def _place(*, phase: str = "exit", rva: int = 4096) -> dict[str, object]:
    return {
        "kind": "static_slot",
        "phase": phase,
        "width": 32,
        "selector": {"rva": rva},
    }


def _logical(root: str, identity: str) -> dict[str, object]:
    return {
        "op": "logical",
        "sort": _sort(),
        "args": [],
        "attributes": {
            "path": {"root": root, "id": identity, "fields": []}
        },
    }


def _machine(place: dict[str, object]) -> dict[str, object]:
    return {
        "op": "machine",
        "sort": _sort(),
        "args": [],
        "attributes": {"place": place},
    }


def _true() -> dict[str, object]:
    return {"op": "true", "sort": _bool(), "args": [], "attributes": {}}


def _binding() -> dict[str, object]:
    place = _place()
    return {
        "id": "result.value",
        "kind": "binding",
        "phase": "exit",
        "logical_path": {"root": "result", "id": "value", "fields": []},
        "observe": _machine(place),
        "realize": [
            {"place": place, "value": _logical("result", "value"), "guard": _true()}
        ],
        "predicate": None,
        "effect_id": None,
        "machine_event": None,
        "reads": [place],
        "writes": [place],
    }


def _relation() -> ComponentRelationIRV1:
    return ComponentRelationIRV1.create(
        component_id="fixture",
        machine_backend="x86-pe32-v1",
        bindings=_DIGESTS,
        operations=[{"operation_id": "run", "clauses": [_binding()], "interactions": []}],
    )


class ComponentRelationIRTests(unittest.TestCase):
    def test_constructive_binding_round_trips_canonically(self) -> None:
        relation = _relation()
        self.assertEqual(
            ComponentRelationIRV1.parse(relation.to_payload()), relation
        )
        self.assertEqual(relation.operations[0].clauses[0].writes[0].kind, "static_slot")

    def test_lean_certificate_is_bound_to_exact_relation(self) -> None:
        relation = _relation()
        interface = PortableComponentInterfaceV2.parse(
            {
                "format": "spaghetti-extractor-component-interface-ir-v2",
                "id": "fixture",
                "types": [{"id": "u32", "kind": "scalar", "c_type": "uint32_t"}],
                "state": [],
                "operations": [
                    {
                        "id": "run",
                        "kind": "operation",
                        "parameters": [],
                        "results": [{"id": "value", "type_id": "u32"}],
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
        interface_bound = ComponentRelationIRV1.create(
            component_id=relation.component_id,
            machine_backend=relation.machine_backend,
            bindings={**relation.bindings, "interface_sha256": interface.sha256},
            operations=relation.operations,
        )
        catalog = InteractionContractCatalogV1.create([
            __import__(
                "spaghetti_extractor.components.interaction_contract",
                fromlist=["InteractionContractV1"],
            ).InteractionContractV1.create(
                identity="fixture.unused-v1",
                subject={"kind": "fixture"},
                primitive_id="service.invoke",
                type_parameters=[{
                    "id": "word", "kind": "scalar", "width": 32,
                    "element_width": None, "access": None,
                    "nullable": None, "nul_terminated": None,
                }],
                ports=[{"id": "value", "direction": "input", "type_parameter": "word"}],
                provenance={"kind": "test", "source": "fixture", "reviewed": True},
            )
        ])
        inventory = ComponentInteractionInventoryV1.create(
            component_id="fixture",
            bindings={
                "interface_sha256": interface.sha256,
                "machine_binding_sha256": "2" * 64,
                "semantic_contract_sha256": "3" * 64,
                "machine_ir_sha256": "4" * 64,
                "interaction_contract_catalog_sha256": catalog.catalog_sha256,
            },
            operations=[OperationInteractionInventoryV1("run", ())],
        )
        interface_bound = ComponentRelationIRV1.create(
            component_id=relation.component_id,
            machine_backend=relation.machine_backend,
            bindings={
                **relation.bindings,
                "interface_sha256": interface.sha256,
                "interaction_inventory_sha256": inventory.inventory_sha256,
                "interaction_contract_catalog_sha256": catalog.catalog_sha256,
            },
            operations=relation.operations,
        )
        source = render_relation_certificate(
            relation=interface_bound,
            interface=interface,
            interaction_inventory=inventory,
            contract_catalog=catalog,
        )
        self.assertIn(interface_bound.relation_sha256, source)
        self.assertIn("certificate_checked", source)
        self.assertIn("by\n  rfl", source)
        self.assertNotIn("native_decide", source)
        self.assertIn("#print axioms certificate_sound", source)

    def test_exported_binding_requires_realization(self) -> None:
        clause = _binding()
        clause["realize"] = []
        clause["writes"] = []
        with self.assertRaisesRegex(ComponentRelationIRError, "nonconstructive"):
            ComponentRelationIRV1.create(
                component_id="fixture",
                machine_backend="x86-pe32-v1",
                bindings=_DIGESTS,
                operations=[{"operation_id": "run", "clauses": [clause], "interactions": []}],
            )

    def test_expression_reads_must_be_in_footprint(self) -> None:
        clause = _binding()
        clause["reads"] = []
        with self.assertRaisesRegex(ComponentRelationIRError, "absent from its footprint"):
            ComponentRelationIRV1.create(
                component_id="fixture",
                machine_backend="x86-pe32-v1",
                bindings=_DIGESTS,
                operations=[{"operation_id": "run", "clauses": [clause], "interactions": []}],
            )

    def test_stale_digest_is_rejected(self) -> None:
        payload = _relation().to_payload()
        payload["component_id"] = "different"
        with self.assertRaisesRegex(ComponentRelationIRError, "digest is stale"):
            ComponentRelationIRV1.parse(payload)

    def test_overlapping_writers_are_rejected(self) -> None:
        first = _binding()
        first["id"] = "a"
        second = copy.deepcopy(first)
        second["id"] = "b"
        second["logical_path"] = {"root": "state", "id": "other", "fields": []}
        second["realize"][0]["value"] = _logical("state", "other")
        with self.assertRaisesRegex(ComponentRelationIRError, "overlapping writers"):
            ComponentRelationIRV1.create(
                component_id="fixture",
                machine_backend="x86-pe32-v1",
                bindings=_DIGESTS,
                operations=[{"operation_id": "run", "clauses": [first, second], "interactions": []}],
            )

    def test_solver_rejects_a_present_but_unlawful_realizer(self) -> None:
        clause = _binding()
        clause["realize"][0]["value"] = {
            "op": "const",
            "sort": _sort(),
            "args": [],
            "attributes": {"value": 0},
        }
        relation = ComponentRelationIRV1.create(
            component_id="fixture",
            machine_backend="x86-pe32-v1",
            bindings=_DIGESTS,
            operations=[{"operation_id": "run", "clauses": [clause], "interactions": []}],
        )
        proof = prove_binding_lens(relation.operations[0].clauses[0])
        self.assertEqual(proof.status, "violated")
        self.assertEqual(proof.code, "observe_after_realize_counterexample")

class PortableInterfaceV4Tests(unittest.TestCase):
    def _payload(self) -> dict[str, object]:
        return {
            "format": "spaghetti-extractor-component-interface-ir-v4",
            "id": "interior_reference",
            "types": [
                {"id": "u8", "kind": "scalar", "c_type": "uint8_t"},
                {
                    "id": "cstring",
                    "kind": "view",
                    "element_type_id": "u8",
                    "access": "read",
                    "extent": {"kind": "nul_terminated"},
                    "ownership": "borrowed",
                },
                {
                    "id": "char_ref",
                    "kind": "reference",
                    "element_type_id": "u8",
                    "access": "read",
                    "nullable": True,
                    "allow_one_past": False,
                    "lifetime": "origin",
                },
            ],
            "state": [
                {
                    "id": "selected",
                    "type_id": "char_ref",
                    "initial": {
                        "domain": 0,
                        "object": 0,
                        "generation": 0,
                        "offset": 0,
                        "extent": 0,
                        "permissions": 0,
                    },
                }
            ],
            "operations": [
                {
                    "id": "select",
                    "kind": "operation",
                    "parameters": [{"id": "value", "type_id": "cstring"}],
                    "results": [{"id": "result", "type_id": "char_ref"}],
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

    def test_reference_and_view_are_machine_free_and_render_opaque_abi(self) -> None:
        interface = PortableComponentInterfaceV2.parse(self._payload())
        self.assertEqual(interface.to_payload(), self._payload())
        header = interface.render_public_header()
        self.assertIn("} spx_ref_v1;", header)
        self.assertIn("} spx_view_v1;", header)
        self.assertIn("spx_ref_v1", interface.operation_c_result(interface.operations[0]))

    def test_one_past_initial_reference_is_rejected(self) -> None:
        payload = self._payload()
        payload["state"][0]["initial"] = {
            "domain": 1,
            "object": 2,
            "generation": 1,
            "offset": 4,
            "extent": 4,
            "permissions": 1,
        }
        with self.assertRaisesRegex(Exception, "outside its origin"):
            PortableComponentInterfaceV2.parse(payload)


class ComponentRelationReceiptTests(unittest.TestCase):
    def test_checked_receipt_is_content_bound(self) -> None:
        relation = _relation()
        receipt = ComponentRelationReceiptV1.create(
            relation=relation,
            obligations=[
                {
                    "id": "lens.result.value",
                    "status": "checked",
                    "code": "constructive_lens_valid",
                    "evidence": ["5" * 64],
                }
            ],
            lean_artifact_sha256="6" * 64,
        )
        self.assertTrue(receipt.authorizing)
        receipt.validate_for(relation)
        self.assertEqual(ComponentRelationReceiptV1.parse(receipt.to_payload()), receipt)

    def test_unchecked_obligation_cannot_authorize(self) -> None:
        relation = _relation()
        receipt = ComponentRelationReceiptV1.create(
            relation=relation,
            obligations=[
                {
                    "id": "origin.value",
                    "status": "incomplete",
                    "code": "origin_unknown",
                    "evidence": [],
                }
            ],
        )
        self.assertFalse(receipt.authorizing)
        payload = receipt.to_payload()
        payload["status"] = "checked"
        from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3

        core = {key: value for key, value in payload.items() if key != "receipt_sha256"}
        payload["receipt_sha256"] = canonical_sha256_v3(core)
        with self.assertRaisesRegex(ComponentRelationReceiptError, "unchecked obligation"):
            ComponentRelationReceiptV1.parse(payload)

    def test_checked_relation_upgrades_universal_binding_v4(self) -> None:
        relation = _relation()
        receipt = ComponentRelationReceiptV1.create(
            relation=relation,
            obligations=[
                {
                    "id": "proof",
                    "status": "checked",
                    "code": "lean_relation_certificate_checked",
                    "evidence": [],
                }
            ],
            lean_artifact_sha256="6" * 64,
        )
        base = ComponentMachineBindingV3(
            component_id="fixture",
            contract_sha256="7" * 64,
            interface_sha256="1" * 64,
            machine_binding_sha256="2" * 64,
            machine_binding_receipt_sha256="8" * 64,
            semantic_contract_sha256="3" * 64,
            pe_sha256="9" * 64,
            machine_ir_sha256="4" * 64,
            machine_ir_manifest_sha256="a" * 64,
            unit_ids=("unit",),
            operation_bindings=(("run", "b" * 64, "c" * 64),),
            status="checked",
            issues=(),
            binding_sha256="d" * 64,
        )
        upgraded = build_component_machine_binding_v4(
            binding=base,
            relation=relation,
            relation_receipt=receipt,
        )
        self.assertTrue(upgraded.authorizing)
        self.assertEqual(
            upgraded.format_version,
            "spaghetti-extractor-component-machine-binding-v4",
        )
        self.assertEqual(upgraded.relation_ir_sha256, relation.relation_sha256)
        self.assertEqual(
            ComponentMachineBindingV3.parse(upgraded.to_payload()), upgraded
        )


if __name__ == "__main__":
    unittest.main()
