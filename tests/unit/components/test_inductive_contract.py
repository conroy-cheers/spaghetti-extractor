from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.inductive_contract import (
    INDUCTIVE_OPERATION_CERTIFICATE_V1,
    InductiveOperationCertificateV1,
    InductiveOperationCheckV1,
    InductiveOperationContractError,
    check_inductive_operation_certificate,
)


def _ref(op: str, name: str) -> dict[str, object]:
    return {"op": op, "name": name}


def _const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def _binary(op: str, left: object, right: object) -> dict[str, object]:
    return {"op": op, "args": [left, right]}


def _countdown_core() -> dict[str, object]:
    n = _ref("loop_variable", "n")
    one = _const(1)
    zero = _const(0)
    semantic_digest = "4" * 64
    return {
        "format": INDUCTIVE_OPERATION_CERTIFICATE_V1,
        "bindings": {
            "interface_id": "countdown",
            "interface_sha256": "1" * 64,
            "operation_id": "run",
            "machine_binding_id": "countdown-binding",
            "machine_binding_sha256": "2" * 64,
            "machine_semantic_contract_id": "countdown-semantics",
            "machine_semantic_contract_sha256": semantic_digest,
            "source_plan_sha256": "7" * 64,
            "cutpoint_relation_sha256": "8" * 64,
            "implementation_sha256": "9" * 64,
        },
        "dependencies": [],
        "receipts": [
            {
                "kind": "machine_semantics",
                "receipt_id": "machine-check",
                "receipt_sha256": "5" * 64,
                "operation_id": "run",
                "semantic_contract_sha256": semantic_digest,
            },
            {
                "kind": "source_semantics",
                "receipt_id": "source-cbmc-check",
                "receipt_sha256": "6" * 64,
                "operation_id": "run",
                "semantic_contract_sha256": semantic_digest,
            },
        ],
        "machine": {
            "unit_ids": ["unit:body", "unit:exit"],
            "sccs": [
                {
                    "id": "scc:countdown",
                    "unit_ids": ["unit:body", "unit:exit"],
                    "cutpoint_ids": ["cp:exit", "cp:loop"],
                    "entry_cutpoint_ids": ["cp:loop"],
                    "exit_cutpoint_ids": ["cp:exit"],
                    "transition_ids": ["transition:decrement"],
                    "bridge_ids": [],
                    "completion_ids": ["completion:return"],
                }
            ],
        },
        "variables": [
            {
                "id": "count",
                "type_id": "u32",
                "domain": {
                    "kind": "unsigned",
                    "width": 32,
                    "minimum": 0,
                    "maximum": 0xFFFFFFFF,
                },
                "origin": {"kind": "operation_parameter", "value_id": "count"},
            },
            {
                "id": "n",
                "type_id": "u32",
                "domain": {
                    "kind": "unsigned",
                    "width": 32,
                    "minimum": 0,
                    "maximum": 0xFFFFFFFF,
                },
                "origin": {"kind": "cutpoint_value", "cutpoint_id": "cp:loop"},
            },
        ],
        "predicates": [
            {
                "id": "invariant:n-bounded",
                "scc_id": "scc:countdown",
                "kind": "invariant",
                "expression": _binary(
                    "ule32", n, _ref("parameter", "count")
                ),
            },
            {
                "id": "postcondition:zero",
                "scc_id": "scc:countdown",
                "kind": "postcondition",
                "expression": _binary("eq", n, zero),
            },
        ],
        "initialization": [
            {
                "id": "init:loop",
                "scc_id": "scc:countdown",
                "cutpoint_id": "cp:loop",
                "establishes": ["invariant:n-bounded"],
                "dependencies": [],
            }
        ],
        "preservation": [
            {
                "id": "preserve:decrement",
                "scc_id": "scc:countdown",
                "transition_id": "transition:decrement",
                "source_cutpoint_id": "cp:loop",
                "target_cutpoint_id": "cp:loop",
                "machine_unit_ids": ["unit:body"],
                "guard": _binary("ult32", zero, n),
                "updates": [
                    {
                        "variable_id": "n",
                        "expression": _binary("sub32", n, one),
                    }
                ],
                "preserves": ["invariant:n-bounded"],
                "dependencies": ["init:loop"],
            }
        ],
        "bridges": [],
        "decreases": [
            {
                "id": "decrease:decrement",
                "scc_id": "scc:countdown",
                "transition_id": "transition:decrement",
                "measure_id": "n",
                "before": n,
                "after": _binary("sub32", n, one),
                "relation": "unsigned_lt",
                "dependencies": ["preserve:decrement"],
            }
        ],
        "exits": [
            {
                "id": "exit:zero",
                "scc_id": "scc:countdown",
                "cutpoint_id": "cp:exit",
                "guard": _binary("eq", n, zero),
                "establishes": ["postcondition:zero"],
                "completion_ids": ["completion:return"],
                "dependencies": ["decrease:decrement"],
            }
        ],
        "completions": [
            {
                "id": "completion:return",
                "scc_id": "scc:countdown",
                "exit_witness_id": "exit:zero",
                "kind": "return",
                "machine_unit_ids": ["unit:exit"],
                "postcondition_ids": ["postcondition:zero"],
                "dependencies": ["exit:zero"],
            }
        ],
    }


def _certificate(mutator: object | None = None) -> dict[str, object]:
    core = _countdown_core()
    if mutator is not None:
        mutator(core)  # type: ignore[operator]
    return {**core, "certificate_sha256": canonical_sha256_v3(core)}


class InductiveOperationContractTests(unittest.TestCase):
    def test_complete_finite_countdown_round_trips(self) -> None:
        payload = _certificate()
        certificate = InductiveOperationCertificateV1.parse(payload)
        check = check_inductive_operation_certificate(certificate)

        self.assertEqual(certificate.to_payload(), payload)
        self.assertEqual(check.status, "incomplete")
        self.assertEqual(
            {item.code for item in check.issues},
            {"authority_receipt_contents_missing"},
        )
        self.assertEqual(
            InductiveOperationCheckV1.parse(check.to_payload()), check
        )
        self.assertFalse(
            check.assurance.to_value()["receipt_contents_replayed_by_this_checker"]
        )

    def test_multiple_sccs_keep_local_invariant_inventories(self) -> None:
        def mutate(core: dict[str, object]) -> None:
            machine = core["machine"]  # type: ignore[assignment]
            machine["unit_ids"] = [  # type: ignore[index]
                "unit:body", "unit:body2", "unit:exit", "unit:exit2"
            ]
            machine["sccs"].append(  # type: ignore[index,union-attr]
                {
                    "id": "scc:second",
                    "unit_ids": ["unit:body2", "unit:exit2"],
                    "cutpoint_ids": ["cp:exit2", "cp:loop2"],
                    "entry_cutpoint_ids": ["cp:loop2"],
                    "exit_cutpoint_ids": ["cp:exit2"],
                    "transition_ids": ["transition:second"],
                    "bridge_ids": [],
                    "completion_ids": ["completion:second"],
                }
            )
            m = _ref("loop_variable", "m")
            zero = _const(0)
            one = _const(1)
            core["variables"].insert(  # type: ignore[union-attr]
                1,
                {
                    "id": "m",
                    "type_id": "u32",
                    "domain": {
                        "kind": "unsigned", "width": 32,
                        "minimum": 0, "maximum": 0xFFFFFFFF,
                    },
                    "origin": {
                        "kind": "cutpoint_value", "cutpoint_id": "cp:loop2"
                    },
                },
            )
            core["predicates"].extend(  # type: ignore[union-attr]
                [
                    {
                        "id": "invariant:m-bounded",
                        "scc_id": "scc:second",
                        "kind": "invariant",
                        "expression": _binary(
                            "ule32", m, _ref("parameter", "count")
                        ),
                    },
                    {
                        "id": "postcondition:second-zero",
                        "scc_id": "scc:second",
                        "kind": "postcondition",
                        "expression": _binary("eq", m, zero),
                    },
                ]
            )
            core["predicates"].sort(key=lambda row: row["id"])  # type: ignore[union-attr]
            core["initialization"].append(  # type: ignore[union-attr]
                {
                    "id": "init:second", "scc_id": "scc:second",
                    "cutpoint_id": "cp:loop2",
                    "establishes": ["invariant:m-bounded"], "dependencies": [],
                }
            )
            core["preservation"].append(  # type: ignore[union-attr]
                {
                    "id": "preserve:second", "scc_id": "scc:second",
                    "transition_id": "transition:second",
                    "source_cutpoint_id": "cp:loop2",
                    "target_cutpoint_id": "cp:loop2",
                    "machine_unit_ids": ["unit:body2"],
                    "guard": _binary("ult32", zero, m),
                    "updates": [{
                        "variable_id": "m",
                        "expression": _binary("sub32", m, one),
                    }],
                    "preserves": ["invariant:m-bounded"],
                    "dependencies": ["init:second"],
                }
            )
            core["decreases"].append(  # type: ignore[union-attr]
                {
                    "id": "decrease:second", "scc_id": "scc:second",
                    "transition_id": "transition:second", "measure_id": "m",
                    "before": m, "after": _binary("sub32", m, one),
                    "relation": "unsigned_lt",
                    "dependencies": ["preserve:second"],
                }
            )
            core["exits"].append(  # type: ignore[union-attr]
                {
                    "id": "exit:second", "scc_id": "scc:second",
                    "cutpoint_id": "cp:exit2", "guard": _binary("eq", m, zero),
                    "establishes": ["postcondition:second-zero"],
                    "completion_ids": ["completion:second"],
                    "dependencies": ["decrease:second"],
                }
            )
            core["exits"].sort(key=lambda row: row["id"])  # type: ignore[union-attr]
            core["completions"].append(  # type: ignore[union-attr]
                {
                    "id": "completion:second", "scc_id": "scc:second",
                    "exit_witness_id": "exit:second", "kind": "return",
                    "machine_unit_ids": ["unit:exit2"],
                    "postcondition_ids": ["postcondition:second-zero"],
                    "dependencies": ["exit:second"],
                }
            )

        check = check_inductive_operation_certificate(_certificate(mutate))
        self.assertEqual(check.status, "incomplete", check.to_payload())
        self.assertEqual(
            {item.code for item in check.issues},
            {"authority_receipt_contents_missing"},
        )

    def test_rejects_stale_certificate_digest(self) -> None:
        payload = _certificate()
        payload["certificate_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            InductiveOperationContractError, "digest is stale"
        ):
            InductiveOperationCertificateV1.parse(payload)

    def test_missing_authority_receipt_is_incomplete(self) -> None:
        def mutate(core: dict[str, object]) -> None:
            core["receipts"] = core["receipts"][1:]  # type: ignore[index]

        check = check_inductive_operation_certificate(_certificate(mutate))
        self.assertEqual(check.status, "incomplete")
        self.assertIn("missing_authority_receipt", {item.code for item in check.issues})
        self.assertFalse(check.assurance.to_value()["machine_semantics_checked"])

    def test_mismatched_receipt_is_violated(self) -> None:
        def mutate(core: dict[str, object]) -> None:
            core["receipts"][0]["operation_id"] = "other"  # type: ignore[index]

        check = check_inductive_operation_certificate(_certificate(mutate))
        self.assertEqual(check.status, "violated")
        self.assertIn(
            "authority_receipt_binding_mismatch", {item.code for item in check.issues}
        )

    def test_missing_scc_transition_inventory_is_incomplete(self) -> None:
        def mutate(core: dict[str, object]) -> None:
            core["machine"]["sccs"][0]["transition_ids"] = []  # type: ignore[index]
            core["preservation"] = []
            core["decreases"] = []
            core["exits"][0]["dependencies"] = []  # type: ignore[index]

        check = check_inductive_operation_certificate(_certificate(mutate))
        self.assertEqual(check.status, "incomplete")
        self.assertIn("missing_scc_transitions", {item.code for item in check.issues})

    def test_missing_each_obligation_family_is_reported(self) -> None:
        mutations = {
            "missing_initialization_witness": lambda core: core.update(
                {"initialization": []}
            ),
            "missing_preservation_witness": lambda core: core.update(
                {"preservation": []}
            ),
            "missing_strict_decrease_witness": lambda core: core.update(
                {"decreases": []}
            ),
            "missing_exit_witness": lambda core: core.update(
                {"exits": [], "completions": []}
            ),
            "missing_completion_witness": lambda core: core.update(
                {"completions": []}
            ),
        }
        for expected, mutate in mutations.items():
            with self.subTest(expected=expected):
                check = check_inductive_operation_certificate(
                    _certificate(mutate)
                )
                self.assertIn(expected, {item.code for item in check.issues})

    def test_self_justifying_dependency_cycle_is_violated(self) -> None:
        def mutate(core: dict[str, object]) -> None:
            core["initialization"][0]["dependencies"] = ["preserve:decrement"]  # type: ignore[index]

        check = check_inductive_operation_certificate(_certificate(mutate))
        self.assertEqual(check.status, "violated")
        self.assertIn(
            "self_justifying_dependency_cycle", {item.code for item in check.issues}
        )

    def test_writable_bounded_byte_fact_is_incomplete(self) -> None:
        def mutate(core: dict[str, object]) -> None:
            core["variables"].append(  # type: ignore[union-attr]
                {
                    "id": "view",
                    "type_id": "bytes",
                    "domain": {
                        "kind": "bounded_bytes",
                        "extent_variable_id": "count",
                        "access": "write",
                    },
                    "origin": {"kind": "operation_parameter", "value_id": "view"},
                }
            )

        check = check_inductive_operation_certificate(_certificate(mutate))
        self.assertEqual(check.status, "incomplete")

    def test_nul_terminated_view_requires_its_checked_extent_origin(self) -> None:
        def mutate(core: dict[str, object]) -> None:
            core["variables"].extend(  # type: ignore[union-attr]
                [
                    {
                        "id": "view",
                        "type_id": "bytes",
                        "domain": {
                            "kind": "nul_terminated_bytes",
                            "extent_variable_id": "view:extent",
                            "access": "read",
                        },
                        "origin": {
                            "kind": "operation_parameter",
                            "value_id": "view",
                        },
                    },
                    {
                        "id": "view:extent",
                        "type_id": "builtin:u32",
                        "domain": {
                            "kind": "unsigned",
                            "width": 32,
                            "minimum": 1,
                            "maximum": 0xFFFFFFFF,
                        },
                        "origin": {"kind": "byte_extent", "view_id": "view"},
                    },
                ]
            )

        check = check_inductive_operation_certificate(_certificate(mutate))
        self.assertEqual(check.status, "incomplete", check.to_payload())
        self.assertEqual(
            {item.code for item in check.issues},
            {"authority_receipt_contents_missing"},
        )

        def corrupt(core: dict[str, object]) -> None:
            mutate(core)
            core["variables"][-1]["origin"]["view_id"] = "other"  # type: ignore[index]

        corrupted = check_inductive_operation_certificate(_certificate(corrupt))
        self.assertEqual(corrupted.status, "violated")
        self.assertIn(
            "invalid_nul_extent_origin",
            {item.code for item in corrupted.issues},
        )

    def test_explicit_unsupported_domain_is_incomplete(self) -> None:
        def mutate(core: dict[str, object]) -> None:
            core["variables"].append(  # type: ignore[union-attr]
                {
                    "id": "surface",
                    "type_id": "surface",
                    "domain": {
                        "kind": "unsupported",
                        "feature": "opaque_resource",
                    },
                    "origin": {
                        "kind": "operation_parameter",
                        "value_id": "surface",
                    },
                }
            )

        check = check_inductive_operation_certificate(_certificate(mutate))
        self.assertEqual(check.status, "incomplete")
        self.assertIn("variable_domain_unsupported", {item.code for item in check.issues})

    def test_non_boolean_invariant_is_violated(self) -> None:
        def mutate(core: dict[str, object]) -> None:
            core["predicates"][0]["expression"] = _ref("loop_variable", "n")  # type: ignore[index]

        check = check_inductive_operation_certificate(_certificate(mutate))
        self.assertEqual(check.status, "violated")
        self.assertIn("predicate_not_boolean", {item.code for item in check.issues})

    def test_rejects_machine_register_expression(self) -> None:
        def mutate(core: dict[str, object]) -> None:
            core["predicates"][0]["expression"] = {  # type: ignore[index]
                "op": "reg",
                "name": "eax",
            }

        with self.assertRaisesRegex(
            InductiveOperationContractError, "machine-specific"
        ):
            InductiveOperationCertificateV1.parse(_certificate(mutate))

    def test_rejects_duplicate_or_nondeterministic_inventory(self) -> None:
        def duplicate(core: dict[str, object]) -> None:
            core["variables"].append(copy.deepcopy(core["variables"][0]))  # type: ignore[index,union-attr]

        with self.assertRaisesRegex(InductiveOperationContractError, "duplicates"):
            InductiveOperationCertificateV1.parse(_certificate(duplicate))

        def reorder(core: dict[str, object]) -> None:
            core["variables"].reverse()  # type: ignore[union-attr]

        with self.assertRaisesRegex(
            InductiveOperationContractError, "deterministic"
        ):
            InductiveOperationCertificateV1.parse(_certificate(reorder))


if __name__ == "__main__":
    unittest.main()
