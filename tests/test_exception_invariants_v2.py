from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.exception_invariants_v2 import (
    EXCEPTION_INVARIANT_CERTIFICATE_V2_FORMAT,
    EXCEPTION_INVARIANT_PROPOSAL_V2_FORMAT,
    SUPPORTED_SEH_INVENTORY_V2_FORMAT,
    canonical_sha256,
    check_exception_invariant_certificate_v2,
    derive_exception_scc_inventory,
    exception_invariant_unit_binding,
    synthesize_exception_invariant_certificate_v2,
)


BINARY_SHA = "1" * 64
MACHINE_IR_SHA = "2" * 64


def _reg(name: str) -> dict:
    return {"op": "reg", "name": name, "width": 32}


def _const(value: int) -> dict:
    return {"op": "const", "value": value, "width": 32}


def _not(value: dict) -> dict:
    return {"op": "not", "args": [value]}


def _ult(left: dict, right: dict) -> dict:
    return {"op": "ult32", "args": [left, right]}


def _loop_unit() -> dict:
    condition = {"op": "eq", "args": [_reg("ecx"), _const(0)]}
    return {
        "id": "unit:loop",
        "status": "qualified",
        "source": {
            "contract_sha256": "3" * 64,
            "instruction_bytes_sha256": "4" * 64,
            "original": {"rva_start": 0x1000, "rva_end": 0x1002},
        },
        "semantics": {
            "outcome": {"kind": "jump", "target_rva": 0x1000},
            "edge_conditions": [{
                "target_rva": 0x1000,
                "condition": {"op": "true"},
            }],
            "register_writes": [],
            "flag_writes": [],
            "faults": [{"kind": "divide_error", "condition": condition}],
        },
    }


def _certificate(unit: dict, *, divisor: int) -> dict:
    units = [unit]
    inventory = derive_exception_scc_inventory(units, ["unit:loop"])
    fact = {
        "kind": "finite_values",
        "expression": _reg("ecx"),
        "values": [divisor],
    }
    fault = unit["semantics"]["faults"][0]
    return {
        "format": EXCEPTION_INVARIANT_CERTIFICATE_V2_FORMAT,
        "bindings": {
            "binary_sha256": BINARY_SHA,
            "machine_ir_sha256": MACHINE_IR_SHA,
            "units": [exception_invariant_unit_binding(unit)],
        },
        "scc": {
            "members": ["unit:loop"],
            "edges": inventory["edges"],
            "exits": inventory["exits"],
        },
        "invariants": [{"unit_id": "unit:loop", "facts": [fact]}],
        "preservation": inventory["edges"],
        "initiation": [{
            "edge": None,
            "target_unit_id": "unit:loop",
            "assumptions": [{
                "op": "eq",
                "args": [_reg("ecx"), _const(divisor)],
            }],
        }],
        "faults": [{
            "source_unit_id": "unit:loop",
            "fault_index": 0,
            "fault_sha256": canonical_sha256(fault),
            "outcome": {"kind": "checked_infeasible"},
        }],
    }


def _handler_unit() -> dict:
    return {
        "id": "unit:handler",
        "status": "qualified",
        "source": {
            "contract_sha256": "7" * 64,
            "instruction_bytes_sha256": "8" * 64,
            "original": {"rva_start": 0x2000, "rva_end": 0x2001},
        },
        "semantics": {
            "outcome": {"kind": "return"},
            "register_writes": [],
            "flag_writes": [],
            "faults": [],
        },
    }


class ExceptionInvariantV2Tests(unittest.TestCase):
    def _replay_synthesis(self, proposal: dict, units: list[dict]) -> dict:
        self.assertEqual(
            proposal["format"], EXCEPTION_INVARIANT_PROPOSAL_V2_FORMAT
        )
        self.assertFalse(proposal["authorizing"])
        return check_exception_invariant_certificate_v2(
            proposal["certificate"],
            units=units,
            binary_sha256=BINARY_SHA,
            machine_ir_sha256=MACHINE_IR_SHA,
        )

    def test_safe_division_loop_closes_without_bounded_path_search(self) -> None:
        unit = _loop_unit()
        report = check_exception_invariant_certificate_v2(
            _certificate(unit, divisor=1),
            units=[unit],
            binary_sha256=BINARY_SHA,
            machine_ir_sha256=MACHINE_IR_SHA,
        )

        self.assertEqual(report["status"], "complete", report["issues"])
        self.assertFalse(report["uses_bounded_paths"])
        self.assertEqual(report["faults"][0]["outcome"], "checked_infeasible")

    def test_feasible_divide_fault_is_violated_with_counterexample(self) -> None:
        unit = _loop_unit()
        report = check_exception_invariant_certificate_v2(
            _certificate(unit, divisor=0),
            units=[unit],
            binary_sha256=BINARY_SHA,
            machine_ir_sha256=MACHINE_IR_SHA,
        )

        self.assertEqual(report["status"], "violated")
        self.assertEqual(
            report["faults"][0]["reason_code"],
            "fault_infeasibility_not_proved",
        )

    def test_unconditional_machine_fault_is_observable_termination(self) -> None:
        unit = _loop_unit()
        unit["semantics"]["outcome"] = {
            "kind": "fault",
            "fault_kind": "divide_error",
        }
        unit["semantics"]["faults"][0]["condition"] = {"op": "true"}
        certificate = _certificate(unit, divisor=0)
        certificate["faults"][0]["outcome"] = {
            "kind": "observable_terminal_fault"
        }

        report = check_exception_invariant_certificate_v2(
            certificate,
            units=[unit],
            binary_sha256=BINARY_SHA,
            machine_ir_sha256=MACHINE_IR_SHA,
        )

        self.assertEqual(report["status"], "complete", report["issues"])
        self.assertEqual(
            report["faults"][0]["outcome"], "observable_terminal_fault"
        )

    def test_finite_supported_seh_target_is_checked_independently(self) -> None:
        unit = _loop_unit()
        handler = _handler_unit()
        certificate = _certificate(unit, divisor=0)
        inventory = {
            "format": SUPPORTED_SEH_INVENTORY_V2_FORMAT,
            "source_unit_id": unit["id"],
            "fault_index": 0,
            "status": "complete",
            "platform_effects": "complete",
            "targets": [{
                "target_unit_id": handler["id"],
                "unit_sha256": canonical_sha256(handler),
                "condition": {"op": "true"},
            }],
        }
        certificate["faults"][0]["outcome"] = {
            "kind": "finite_supported_seh_target",
            "handler_inventory_sha256": canonical_sha256(inventory),
            "target_unit_ids": [handler["id"]],
        }

        report = check_exception_invariant_certificate_v2(
            certificate,
            units=[unit, handler],
            binary_sha256=BINARY_SHA,
            machine_ir_sha256=MACHINE_IR_SHA,
            seh_inventories=[inventory],
        )

        self.assertEqual(report["status"], "complete", report["issues"])
        self.assertEqual(
            report["faults"][0]["target_unit_ids"], [handler["id"]]
        )

    def test_unresolved_seh_handler_remains_incomplete(self) -> None:
        unit = _loop_unit()
        handler = _handler_unit()
        certificate = _certificate(unit, divisor=0)
        inventory = {
            "format": SUPPORTED_SEH_INVENTORY_V2_FORMAT,
            "source_unit_id": unit["id"],
            "fault_index": 0,
            "status": "complete",
            "platform_effects": "complete",
            "targets": [{
                "target_unit_id": handler["id"],
                "unit_sha256": canonical_sha256(handler),
                "condition": {"op": "true"},
            }],
        }
        certificate["faults"][0]["outcome"] = {
            "kind": "finite_supported_seh_target",
            "handler_inventory_sha256": canonical_sha256(inventory),
            "target_unit_ids": [handler["id"]],
        }

        report = check_exception_invariant_certificate_v2(
            certificate,
            units=[unit, handler],
            binary_sha256=BINARY_SHA,
            machine_ir_sha256=MACHINE_IR_SHA,
        )

        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(
            report["faults"][0]["reason_code"],
            "seh_platform_inventory_unknown",
        )

    def test_stale_exact_unit_binding_is_violated(self) -> None:
        unit = _loop_unit()
        certificate = _certificate(unit, divisor=1)
        certificate = copy.deepcopy(certificate)
        certificate["bindings"]["units"][0]["unit_sha256"] = "0" * 64

        report = check_exception_invariant_certificate_v2(
            certificate,
            units=[unit],
            binary_sha256=BINARY_SHA,
            machine_ir_sha256=MACHINE_IR_SHA,
        )

        self.assertEqual(report["status"], "violated")
        self.assertIn(
            "exact_binding_contradiction",
            {issue["code"] for issue in report["issues"]},
        )

    def test_missing_invariants_fail_closed(self) -> None:
        unit = _loop_unit()
        certificate = _certificate(unit, divisor=1)
        certificate["invariants"] = []

        report = check_exception_invariant_certificate_v2(
            certificate,
            units=[unit],
            binary_sha256=BINARY_SHA,
            machine_ir_sha256=MACHINE_IR_SHA,
        )

        self.assertEqual(report["status"], "incomplete")
        self.assertIn(
            "cutpoint_invariant_missing",
            {issue["code"] for issue in report["issues"]},
        )

    def test_synthesizes_and_replays_safe_division_loop(self) -> None:
        unit = _loop_unit()
        proposal = synthesize_exception_invariant_certificate_v2(
            units=[unit],
            member_ids=["unit:loop"],
            binary_sha256=BINARY_SHA,
            machine_ir_sha256=MACHINE_IR_SHA,
            root_assumptions={
                "unit:loop": [_not(_ult(_reg("ecx"), _const(1)))]
            },
        )

        self.assertEqual(proposal["status"], "complete", proposal["issues"])
        self.assertFalse(proposal["uses_bounded_paths"])
        facts = proposal["certificate"]["invariants"][0]["facts"]
        self.assertEqual(
            facts,
            [{
                "kind": "range",
                "expression": _reg("ecx"),
                "minimum": 1,
                "maximum": 0xFFFFFFFF,
            }],
        )
        report = self._replay_synthesis(proposal, [unit])
        self.assertEqual(report["status"], "complete", report["issues"])
        self.assertEqual(report["faults"][0]["outcome"], "checked_infeasible")

    def test_synthesized_feasible_divide_fault_remains_incomplete(self) -> None:
        unit = _loop_unit()
        proposal = synthesize_exception_invariant_certificate_v2(
            units=[unit],
            member_ids=["unit:loop"],
            binary_sha256=BINARY_SHA,
            machine_ir_sha256=MACHINE_IR_SHA,
            root_assumptions={
                "unit:loop": [{
                    "op": "eq",
                    "args": [_reg("ecx"), _const(0)],
                }]
            },
        )

        self.assertEqual(proposal["status"], "incomplete")
        self.assertEqual(
            proposal["certificate"]["faults"][0]["outcome"],
            {"kind": "incomplete"},
        )
        report = self._replay_synthesis(proposal, [unit])
        self.assertEqual(report["status"], "incomplete", report["issues"])
        self.assertEqual(
            report["faults"][0]["reason_code"], "fault_explicitly_incomplete"
        )

    def test_synthesizes_congruence_preserved_by_loop_update(self) -> None:
        unit = _loop_unit()
        unit["semantics"]["register_writes"] = [{
            "register": "ecx",
            "value": {"op": "add32", "args": [_reg("ecx"), _const(4)]},
        }]
        congruence = {
            "op": "eq",
            "args": [
                {"op": "and32", "args": [_reg("ecx"), _const(3)]},
                _const(1),
            ],
        }
        proposal = synthesize_exception_invariant_certificate_v2(
            units=[unit],
            member_ids=["unit:loop"],
            binary_sha256=BINARY_SHA,
            machine_ir_sha256=MACHINE_IR_SHA,
            root_assumptions={"unit:loop": [congruence]},
        )

        self.assertEqual(proposal["status"], "complete", proposal["issues"])
        facts = proposal["certificate"]["invariants"][0]["facts"]
        self.assertEqual(
            facts,
            [{
                "kind": "congruence",
                "expression": _reg("ecx"),
                "modulus": 4,
                "remainder": 1,
            }],
        )
        report = self._replay_synthesis(proposal, [unit])
        self.assertEqual(report["status"], "complete", report["issues"])

    def test_synthesizes_finite_value_from_exact_predecessor_write(self) -> None:
        loop = _loop_unit()
        entry = {
            "id": "unit:entry",
            "status": "qualified",
            "source": {
                "contract_sha256": "5" * 64,
                "instruction_bytes_sha256": "6" * 64,
                "original": {"rva_start": 0x900, "rva_end": 0x902},
            },
            "semantics": {
                "outcome": {"kind": "jump", "target_rva": 0x1000},
                "edge_conditions": [{
                    "target_rva": 0x1000,
                    "condition": {"op": "true"},
                }],
                "register_writes": [{"register": "ecx", "value": _const(7)}],
                "flag_writes": [],
                "faults": [],
            },
        }
        proposal = synthesize_exception_invariant_certificate_v2(
            units=[entry, loop],
            member_ids=["unit:loop"],
            binary_sha256=BINARY_SHA,
            machine_ir_sha256=MACHINE_IR_SHA,
        )

        self.assertEqual(proposal["status"], "complete", proposal["issues"])
        self.assertEqual(
            proposal["certificate"]["invariants"][0]["facts"],
            [{
                "kind": "finite_values",
                "expression": _reg("ecx"),
                "values": [7],
            }],
        )
        report = self._replay_synthesis(proposal, [entry, loop])
        self.assertEqual(report["status"], "complete", report["issues"])

    def test_unsupported_predicate_and_budget_overflow_fail_closed(self) -> None:
        unit = _loop_unit()
        alternatives = [
            {"op": "eq", "args": [_reg("ecx"), _const(value)]}
            for value in range(3)
        ]
        predicate = {
            "op": "or_bool",
            "args": [alternatives[0], {
                "op": "or_bool",
                "args": alternatives[1:],
            }],
        }
        proposal = synthesize_exception_invariant_certificate_v2(
            units=[unit],
            member_ids=["unit:loop"],
            binary_sha256=BINARY_SHA,
            machine_ir_sha256=MACHINE_IR_SHA,
            root_assumptions={"unit:loop": [predicate]},
            finite_value_budget=2,
        )

        self.assertEqual(proposal["status"], "incomplete")
        self.assertFalse(proposal["uses_bounded_paths"])
        self.assertEqual(
            proposal["certificate"]["invariants"],
            [{"unit_id": "unit:loop", "facts": []}],
        )
        report = self._replay_synthesis(proposal, [unit])
        self.assertEqual(report["status"], "incomplete")
        self.assertNotIn(
            "inductive_preservation_failed",
            {issue["code"] for issue in report["issues"]},
        )
        self.assertEqual(
            report["faults"][0]["reason_code"], "fault_explicitly_incomplete"
        )


if __name__ == "__main__":
    unittest.main()
