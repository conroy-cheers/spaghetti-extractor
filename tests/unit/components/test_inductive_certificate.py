from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.inductive_certificate import (
    materialize_inductive_certificate,
)
from spaghetti_extractor.components.inductive_contract import (
    check_inductive_operation_certificate,
)
from spaghetti_extractor.components.inductive_package import (
    materialize_inductive_package,
)
from spaghetti_extractor.components.inductive_receipts import (
    CheckedInductiveMachineReceiptV1,
)
from spaghetti_extractor.components.inductive_relation import (
    InductiveCutpointRelationV1,
)
from spaghetti_extractor.components.inductive_source import InductiveSourcePlanV1
from spaghetti_extractor.components.source import build_component_source_package

from .test_inductive_package import _declaration, _semantic_contract
from .test_inductive_refinement import _SOURCE
from .test_inductive_relation import _interface, _register, _unit


def _proof_declaration() -> dict[str, object]:
    return {
        "format": "spaghetti-extractor-inductive-proof-declaration-v1",
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
    }


def _two_loop_operation() -> dict[str, object]:
    zero = {"op": "const", "value": 0, "width": 32}
    one = {"op": "const", "value": 1, "width": 32}
    n = {"op": "reg", "name": "edx", "width": 32}
    m = {"op": "reg", "name": "ebx", "width": 32}

    def is_zero(value: object) -> dict[str, object]:
        return {"op": "eq", "args": [value, zero]}

    def nonzero(value: object) -> dict[str, object]:
        return {"op": "not", "args": [is_zero(value)]}

    return {
        "operation_id": "run",
        "entry_unit_ids": ["entry"],
        "exit_unit_ids": ["exit"],
        "parameters": [
            {"id": "count", "projection": _register("ecx", "entry")}
        ],
        "results": [
            {"id": "result", "projection": _register("eax", "exit")}
        ],
        "state": [],
        "preserved_state_ids": [],
        "effects": [],
        "callback_operation_ids": [],
        "units": [
            _unit(
                "entry",
                0x2000,
                [(0x2010, {"op": "true"})],
                [
                    {
                        "register": "ebx",
                        "value": {"op": "reg", "name": "ecx", "width": 32},
                    },
                    {
                        "register": "edx",
                        "value": {"op": "reg", "name": "ecx", "width": 32},
                    },
                ],
            ),
            _unit(
                "head1",
                0x2010,
                [(0x2030, is_zero(n)), (0x2020, nonzero(n))],
                [],
            ),
            _unit(
                "body1",
                0x2020,
                [(0x2010, {"op": "true"})],
                [{
                    "register": "edx",
                    "value": {"op": "sub32", "args": [n, one]},
                }],
            ),
            _unit(
                "head2",
                0x2030,
                [(0x2050, is_zero(m)), (0x2040, nonzero(m))],
                [],
            ),
            _unit(
                "body2",
                0x2040,
                [(0x2030, {"op": "true"})],
                [{
                    "register": "ebx",
                    "value": {"op": "sub32", "args": [m, one]},
                }],
            ),
            _unit(
                "exit",
                0x2050,
                [],
                [{"register": "eax", "value": m}],
            ),
        ],
    }


def _two_loop_semantic_contract() -> dict[str, object]:
    interface = _interface()
    core: dict[str, object] = {
        "format": "spaghetti-extractor-component-semantic-contract-v1",
        "status": "satisfied",
        "component_id": "two-loop-component",
        "bindings": {
            "pe_sha256": "a" * 64,
            "machine_ir_sha256": "b" * 64,
            "machine_ir_manifest_sha256": "c" * 64,
            "interface_sha256": interface.sha256,
            "machine_binding_sha256": "d" * 64,
        },
        "operations": [_two_loop_operation()],
        "services": [],
        "issues": [],
        "policy": {
            "original_binary_executed": False,
            "behavior_is_machine_derived": True,
            "operator_expected_outputs_accepted": False,
            "unsupported_semantics_fail_closed": True,
        },
    }
    from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3

    return {**core, "contract_sha256": canonical_sha256_v3(core)}


def _two_loop_declaration() -> dict[str, object]:
    values = [
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
            "id": "m",
            "mode": "machine_codec",
            "projection": _register("ebx", "entry"),
            "encoding": {"op": "state_input", "name": "m"},
            "decoding": {"op": "projected_value"},
        },
        {
            "kind": "source_state",
            "id": "n",
            "mode": "machine_codec",
            "projection": _register("edx", "entry"),
            "encoding": {"op": "state_input", "name": "n"},
            "decoding": {"op": "projected_value"},
        },
    ]
    count = {"op": "parameter", "name": "count"}
    n = {"op": "loop_variable", "name": "n"}
    m = {"op": "loop_variable", "name": "m"}
    zero = {"op": "const", "value": 0, "width": 32}
    return {
        "format": "spaghetti-extractor-inductive-component-declaration-v1",
        "source": {
            "operation_id": "run",
            "state": [
                {"id": "m", "type_id": "u32"},
                {"id": "n", "type_id": "u32"},
            ],
            "phase_ids": ["loop1", "loop2"],
            "completion_ids": ["return"],
            "symbols": {
                "wrapper": "countdown_run",
                "initialize": "countdown_initialize",
                "step": "countdown_step",
                "finish": "countdown_finish",
            },
            "cutpoints": [
                {
                    "unit_id": "head1",
                    "phase_id": "loop1",
                    "values": values,
                    "derived": [],
                },
                {
                    "unit_id": "head2",
                    "phase_id": "loop2",
                    "values": values,
                    "derived": [],
                },
            ],
            "completion_routes": [{
                "source": {"kind": "cutpoint", "id": "head2"},
                "target_exit_unit_id": "exit",
                "completion_id": "return",
            }],
        },
        "proof": {
            "invariants": [
                {
                    "id": "invariant:first-m-fixed",
                    "owner_cutpoint_id": "head1",
                    "expression": {"op": "eq", "args": [m, count]},
                },
                {
                    "id": "invariant:first-n-bounded",
                    "owner_cutpoint_id": "head1",
                    "expression": {"op": "ule32", "args": [n, count]},
                },
                {
                    "id": "invariant:second-m-bounded",
                    "owner_cutpoint_id": "head2",
                    "expression": {"op": "ule32", "args": [m, count]},
                },
                {
                    "id": "invariant:second-n-zero",
                    "owner_cutpoint_id": "head2",
                    "expression": {"op": "eq", "args": [n, zero]},
                },
            ],
            "measures": [
                {
                    "id": "measure:first",
                    "owner_cutpoint_id": "head1",
                    "variable_id": "n",
                    "expression": n,
                },
                {
                    "id": "measure:second",
                    "owner_cutpoint_id": "head2",
                    "variable_id": "m",
                    "expression": m,
                },
            ],
        },
    }


class InductiveCertificateMaterializerTests(unittest.TestCase):
    def test_derives_checked_bridge_between_exact_sccs(self) -> None:
        interface = _interface()
        declaration = _two_loop_declaration()
        semantic = _two_loop_semantic_contract()
        package = materialize_inductive_package(
            declaration=declaration,
            interface=interface.to_payload(),
            semantic_contract=semantic,
        )
        plan = InductiveSourcePlanV1.parse(package["source_plan"])
        machine = CheckedInductiveMachineReceiptV1.parse(
            package["machine_receipt"]
        )
        relation = InductiveCutpointRelationV1.parse(
            package["cutpoint_relation"]
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "two-loop.c"
            source_path.write_text(_SOURCE, encoding="ascii")
            source_package = root / "source"
            build_component_source_package(
                lift_unit_id="two-loop",
                files={"two-loop.c": source_path},
                shared_inputs={},
                operation_symbols={"run": "countdown_run"},
                out_dir=source_package,
            )
            certificate = materialize_inductive_certificate(
                proof_declaration=declaration,
                semantic_contract=semantic,
                interface=interface.to_payload(),
                source_package=source_package,
                source_plan=plan,
                machine_receipt=machine,
                cutpoint_relation=relation,
            )

        payload = certificate.to_payload()
        self.assertEqual(len(payload["machine"]["sccs"]), 2)
        self.assertEqual(len(payload["bridges"]), 1)
        bridge = payload["bridges"][0]
        self.assertNotEqual(bridge["source_scc_id"], bridge["target_scc_id"])
        self.assertEqual(
            set(bridge["establishes"]),
            {"invariant:second-m-bounded", "invariant:second-n-zero"},
        )
        target_scc = next(
            item
            for item in payload["machine"]["sccs"]
            if item["id"] == bridge["target_scc_id"]
        )
        self.assertEqual(target_scc["entry_cutpoint_ids"], ["head2"])
        self.assertFalse(
            any(item["scc_id"] == target_scc["id"] for item in payload["initialization"])
        )
        check = check_inductive_operation_certificate(
            certificate,
            receipt_payloads={"machine-check": machine.to_payload()},
        )
        self.assertEqual(check.status, "incomplete", check.to_payload())
        self.assertEqual(
            {item.code for item in check.issues},
            {"authority_receipt_contents_missing"},
        )
        corrupted = certificate.to_payload()
        corrupted["bridges"][0]["target_cutpoint_id"] = "head1"
        from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3

        core = dict(corrupted)
        core.pop("certificate_sha256")
        corrupted["certificate_sha256"] = canonical_sha256_v3(core)
        corrupted_check = check_inductive_operation_certificate(
            corrupted,
            receipt_payloads={"machine-check": machine.to_payload()},
        )
        self.assertEqual(corrupted_check.status, "violated")
        self.assertIn(
            "bridge_exact_segment_mismatch",
            {item.code for item in corrupted_check.issues},
        )

    def test_derives_scc_transitions_updates_and_completions(self) -> None:
        interface = _interface()
        package = materialize_inductive_package(
            declaration=_declaration(),
            interface=interface.to_payload(),
            semantic_contract=_semantic_contract(),
        )
        plan = InductiveSourcePlanV1.parse(package["source_plan"])
        machine = CheckedInductiveMachineReceiptV1.parse(
            package["machine_receipt"]
        )
        relation = InductiveCutpointRelationV1.parse(
            package["cutpoint_relation"]
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "countdown.c"
            source_path.write_text(_SOURCE, encoding="ascii")
            source_package = root / "source"
            build_component_source_package(
                lift_unit_id="countdown",
                files={"countdown.c": source_path},
                shared_inputs={},
                operation_symbols={"run": "countdown_run"},
                out_dir=source_package,
            )
            certificate = materialize_inductive_certificate(
                proof_declaration=_declaration(),
                semantic_contract=_semantic_contract(),
                interface=interface.to_payload(),
                source_package=source_package,
                source_plan=plan,
                machine_receipt=machine,
                cutpoint_relation=relation,
            )

        payload = certificate.to_payload()
        self.assertNotIn("segment_id", str(_declaration()))
        self.assertEqual(len(payload["machine"]["sccs"]), 1)
        self.assertEqual(len(payload["preservation"]), 1)
        self.assertEqual(
            payload["preservation"][0]["updates"],
            [{
                "variable_id": "n",
                "expression": {
                    "op": "add32",
                    "args": [
                        {"op": "state_input", "name": "n"},
                        {
                            "op": "const",
                            "value": 0xFFFFFFFF,
                            "width": 32,
                        },
                    ],
                },
            }],
        )
        self.assertEqual(
            payload["decreases"][0]["after"],
            payload["preservation"][0]["updates"][0]["expression"],
        )
        check = check_inductive_operation_certificate(
            certificate,
            receipt_payloads={"machine-check": machine.to_payload()},
        )
        self.assertEqual(check.status, "incomplete")
        self.assertEqual(
            {item.code for item in check.issues},
            {"authority_receipt_contents_missing"},
        )


if __name__ == "__main__":
    unittest.main()
