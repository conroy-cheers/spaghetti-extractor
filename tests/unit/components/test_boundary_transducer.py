from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.components.boundary_evaluator import (
    BoundaryEvaluationContextV1,
    BoundaryEvaluationError,
    evaluate_expression,
)
from spaghetti_extractor.components.boundary_plan import (
    ComponentBoundaryPlanError,
    ComponentBoundaryPlanReceiptV2,
    ComponentBoundaryPlanV2,
    compile_component_boundary_plan,
)
from spaghetti_extractor.components.boundary_primitives import (
    DEFAULT_BOUNDARY_PRIMITIVES,
)
from spaghetti_extractor.components.capabilities import ReferencePermission
from spaghetti_extractor.components.object_authority import (
    MachineObjectAuthorityV1,
)
from spaghetti_extractor.components.relation_ir import (
    ComponentRelationIRV1,
    RelationExpressionV1,
)
from spaghetti_extractor.components.relation_receipt import (
    ComponentRelationReceiptV1,
)


_DIGESTS = {
    "interface_sha256": "1" * 64,
    "machine_binding_sha256": "2" * 64,
    "semantic_contract_sha256": "3" * 64,
    "machine_ir_sha256": "4" * 64,
    "interaction_inventory_sha256": "5" * 64,
    "interaction_contract_catalog_sha256": "6" * 64,
}


def _authority() -> MachineObjectAuthorityV1:
    return MachineObjectAuthorityV1(
        machine_backend="x86-pe32-v1",
        bindings={"machine_ir_sha256": "4" * 64},
        rules=[
            {
                "id": "argv.0",
                "kind": "process",
                "domain": 1,
                "object": 7,
                "base": 0x2000,
                "extent": 32,
                "permissions": int(ReferencePermission.READ),
                "lifetime": "process",
                "evidence_sha256": "a" * 64,
            }
        ],
    )


def _authority_expression(primitive: str, args: list[dict[str, object]], result: dict[str, object]) -> dict[str, object]:
    return {
        "op": "authority_call",
        "sort": result,
        "args": args,
        "attributes": {"primitive": primitive, "binding": "program.name"},
    }


def _const(value: int) -> dict[str, object]:
    return {
        "op": "const",
        "sort": {"kind": "bitvector", "width": 32},
        "args": [],
        "attributes": {"value": value},
    }


class ObjectAuthorityTests(unittest.TestCase):
    def test_interior_reference_round_trips_to_the_same_origin(self) -> None:
        authority = _authority()
        resolved = authority.resolve(
            0x2008,
            requested_extent=4,
            required_permissions=int(ReferencePermission.READ),
        )
        self.assertEqual(resolved.code, "origin_resolved")
        assert resolved.reference is not None
        self.assertEqual(resolved.reference.offset, 8)
        status, address, code = authority.realize(
            resolved.reference,
            required_permissions=int(ReferencePermission.READ),
        )
        self.assertEqual(int(status), 0)
        self.assertEqual(address, 0x2008)
        self.assertEqual(code, "reference_realized")

    def test_ambiguous_live_origins_fail_closed(self) -> None:
        authority = MachineObjectAuthorityV1(
            machine_backend="x86-pe32-v1",
            bindings={"machine_ir_sha256": "4" * 64},
            rules=[
                {
                    "id": identity,
                    "kind": "static",
                    "domain": 1,
                    "object": object_id,
                    "base": 0x3000,
                    "extent": 8,
                    "permissions": 1,
                    "lifetime": "image",
                    "evidence_sha256": digest * 64,
                }
                for identity, object_id, digest in (("a", 1, "a"), ("b", 2, "b"))
            ],
        )
        result = authority.resolve(0x3001, requested_extent=1, required_permissions=1)
        self.assertEqual(result.code, "origin_ambiguous")

class BoundaryPlanTests(unittest.TestCase):
    def _relation(self) -> ComponentRelationIRV1:
        place = {
            "kind": "static_slot",
            "phase": "exit",
            "width": 32,
            "selector": {"rva": 4096},
        }
        logical = {
            "op": "logical",
            "sort": {"kind": "bitvector", "width": 32},
            "args": [],
            "attributes": {"path": {"root": "result", "id": "value", "fields": []}},
        }
        return ComponentRelationIRV1.create(
            component_id="fixture",
            machine_backend="x86-pe32-v1",
            bindings={**_DIGESTS, "object_authority_sha256": _authority().authority_sha256},
            operations=[
                {
                    "operation_id": "run",
                    "clauses": [
                        {
                            "id": "result.value",
                            "kind": "binding",
                            "phase": "exit",
                            "logical_path": {"root": "result", "id": "value", "fields": []},
                            "observe": {
                                "op": "machine",
                                "sort": {"kind": "bitvector", "width": 32},
                                "args": [],
                                "attributes": {"place": place},
                            },
                            "realize": [
                                {
                                    "place": place,
                                    "value": logical,
                                    "guard": {"op": "true", "sort": {"kind": "bool"}, "args": [], "attributes": {}},
                                }
                            ],
                            "predicate": None,
                            "effect_id": None,
                            "machine_event": None,
                            "reads": [place],
                            "writes": [place],
                        }
                    ],
                    "interactions": [],
                }
            ],
        )

    def test_checked_relation_compiles_to_a_content_bound_plan(self) -> None:
        relation = self._relation()
        receipt = ComponentRelationReceiptV1.create(
            relation=relation,
            obligations=[
                {"id": "all", "status": "checked", "code": "checked", "evidence": [relation.relation_sha256]}
            ],
            lean_artifact_sha256="b" * 64,
        )
        plan, plan_receipt = compile_component_boundary_plan(
            relation=relation,
            relation_receipt=receipt,
            object_authority_sha256=_authority().authority_sha256,
        )
        self.assertTrue(plan_receipt.authorizing)
        self.assertEqual(ComponentBoundaryPlanV2.parse(plan.to_payload()), plan)
        self.assertEqual(
            ComponentBoundaryPlanReceiptV2.parse(plan_receipt.to_payload()),
            plan_receipt,
        )
        self.assertEqual(plan.operations[0].actions[0].effect_class, "machine_write")

    def test_unchecked_relation_cannot_compile(self) -> None:
        relation = self._relation()
        receipt = ComponentRelationReceiptV1.create(
            relation=relation,
            obligations=[
                {"id": "proof", "status": "incomplete", "code": "missing", "evidence": []}
            ],
        )
        with self.assertRaisesRegex(ComponentBoundaryPlanError, "unchecked relation"):
            compile_component_boundary_plan(
                relation=relation,
                relation_receipt=receipt,
                object_authority_sha256=_authority().authority_sha256,
            )

    def test_origin_primitive_uses_runtime_object_authority(self) -> None:
        expression = RelationExpressionV1.parse(
            _authority_expression(
                "origin.resolve",
                [_const(0x2004), _const(4)],
                {"kind": "reference", "type_id": "char_ref"},
            )
        )
        context = BoundaryEvaluationContextV1(
            machine_values={},
            logical_values={},
            object_authority=_authority(),
            authority_bindings={
                "program.name": {
                    "permissions": int(ReferencePermission.READ),
                    "nullable": False,
                    "allow_one_past": False,
                }
            },
        )
        reference = evaluate_expression(expression, context)
        self.assertEqual(reference.offset, 4)
        missing = copy.deepcopy(expression.to_payload())
        missing["args"][0]["attributes"]["value"] = 0x5000
        with self.assertRaisesRegex(BoundaryEvaluationError, "origin_missing"):
            evaluate_expression(RelationExpressionV1.parse(missing), context)

    def test_registry_manifest_is_canonical(self) -> None:
        payload = DEFAULT_BOUNDARY_PRIMITIVES.to_payload()
        self.assertEqual(
            DEFAULT_BOUNDARY_PRIMITIVES.parse(payload).sha256,
            DEFAULT_BOUNDARY_PRIMITIVES.sha256,
        )


if __name__ == "__main__":
    unittest.main()
