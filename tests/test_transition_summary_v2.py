from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.authority_bindings_v2 import (
    AuthorityDataError,
    BinaryBinding,
)
from spaghetti_extractor.machine_ir_authority_v2 import machine_ir_sha256
from spaghetti_extractor.transition_summary_v2 import (
    TransitionSummaryV2,
    TransitionSummaryV2Error,
    check_transition_summary_v2,
    derive_transition_summary_v2,
)


PE_SHA256 = "a" * 64


def _reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def _unit(*, unsupported: bool = False) -> dict[str, object]:
    register_write = {
        "register": "eax",
        "value": (
            {"op": "unsupported", "reason": "fixture"}
            if unsupported
            else _const(7)
        ),
    }
    memory_event = {
        "kind": "write",
        "width": 4,
        "instruction_rva": 0x1001,
        "address": _const(0x401000),
        "value": _reg("eax"),
    }
    external_event = {
        "kind": "import_call",
        "instruction_rva": 0x1002,
        "dll": "KERNEL32.dll",
        "symbol": "GetLastError",
        "arguments": [],
    }
    callback_event = {
        "kind": "callback_registration",
        "instruction_rva": 0x1003,
        "abi_contract": {
            "callback_source": {"kind": "argument_word", "argument": 0},
            "callback_abi": {"kind": "stdcall", "argument_words": 1},
        },
    }
    fault = {
        "kind": "divide_error",
        "instruction_rva": 0x1004,
        "predicate": {"op": "eq", "args": [_reg("ecx"), _const(0)]},
    }
    guard = {
        "kind": "branch_guard",
        "condition": {"op": "ne", "args": [_reg("eax"), _const(0)]},
    }
    ordered_event = {
        "kind": "write",
        "instruction_rva": 0x1001,
        "address": _const(0x401000),
        "width": 4,
        "value": _reg("eax"),
    }
    semantics = {
        "pre_state": {
            "registers": {"eax": _reg("eax"), "esp": _reg("esp")},
            "flags": {"zf": {"op": "flag", "name": "zf"}},
            "memory": {
                "op": "memory",
                "name": "mem0",
                "address_width": 32,
                "value_width": 8,
            },
        },
        "register_writes": [register_write],
        "flag_writes": [{"flag": "zf", "value": _const(0)}],
        "memory_events": [memory_event],
        "external_events": [external_event, callback_event],
        "faults": [fault],
        "ordered_events": [ordered_event],
        "edge_conditions": [guard],
        "outcome": {"kind": "direct_jump", "target_rva": 0x1010},
        "stack_delta": {
            "status": "derived",
            "net_bytes": 0,
            "expression": _reg("esp"),
        },
        "counts": {
            "register_writes": 1,
            "flag_writes": 1,
            "memory_events": 1,
            "external_events": 2,
            "faults": 1,
            "ordered_events": 1,
            "edge_conditions": 1,
        },
    }
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": "unit:entry",
        "status": "qualified",
        "source": {
            "original": {"rva_start": 0x1000, "rva_end": 0x1008},
            "instruction_bytes_sha256": "b" * 64,
        },
        "expression_model": "stage-a-semantic-ir-v1",
        "instructions": [],
        "semantics": semantics,
        "control": {
            "kind": "direct_jump",
            "direct_targets": [0x1010],
            "has_indirect_target": False,
        },
    }


def _binary(units: list[dict[str, object]]) -> BinaryBinding:
    return BinaryBinding(PE_SHA256, machine_ir_sha256(units))


class TransitionSummaryV2Tests(unittest.TestCase):
    def test_exact_summary_round_trip_and_recheck(self) -> None:
        unit = _unit()
        binary = _binary([unit])

        summary = derive_transition_summary_v2(unit, binary=binary)
        parsed = TransitionSummaryV2.parse(summary.to_payload())
        checked = check_transition_summary_v2(
            parsed,
            unit_row=unit,
            binary=binary,
        )

        self.assertEqual(checked, summary)
        self.assertEqual(summary.status, "complete")
        self.assertTrue(summary.to_payload()["root_independent"])
        self.assertEqual(
            [row.category for row in summary.exits],
            ["external", "callback", "outcome"],
        )
        self.assertEqual(len(summary.memory_accesses), 1)
        self.assertEqual(summary.memory_accesses[0].binding.event_index, 0)
        self.assertEqual(len(summary.guards), 1)
        self.assertEqual(len(summary.faults), 1)

    def test_stale_or_omitted_effect_cannot_recheck(self) -> None:
        unit = _unit()
        binary = _binary([unit])
        summary = derive_transition_summary_v2(unit, binary=binary)
        changed = copy.deepcopy(unit)
        changed["semantics"]["register_writes"][0]["value"]["value"] = 8

        with self.assertRaisesRegex(
            TransitionSummaryV2Error,
            "contradicts its exact machine-IR unit",
        ):
            check_transition_summary_v2(
                summary,
                unit_row=changed,
                binary=binary,
            )

        omitted = copy.deepcopy(summary.to_payload())
        omitted["guards"] = []
        with self.assertRaises(AuthorityDataError):
            TransitionSummaryV2.parse(omitted)

    def test_parser_rejects_extra_fields_and_stale_nested_ids(self) -> None:
        summary = derive_transition_summary_v2(_unit(), binary=_binary([_unit()]))
        extra = copy.deepcopy(summary.to_payload())
        extra["proposal_seed"] = True
        with self.assertRaises(AuthorityDataError):
            TransitionSummaryV2.parse(extra)

        stale = copy.deepcopy(summary.to_payload())
        stale["memory_accesses"][0]["width_bytes"] = 8
        with self.assertRaises(AuthorityDataError):
            TransitionSummaryV2.parse(stale)

    def test_unsupported_semantics_are_explicit_and_fail_closed(self) -> None:
        unit = _unit(unsupported=True)
        summary = derive_transition_summary_v2(unit, binary=_binary([unit]))

        self.assertEqual(summary.status, "incomplete")
        self.assertEqual(len(summary.unsupported_effects), 1)
        self.assertEqual(
            summary.unsupported_effects[0].code,
            "unsupported_expression",
        )
        self.assertIn(
            "register_writes[0].value",
            summary.unsupported_effects[0].location,
        )

    def test_machine_state_output_and_instruction_schedule_are_retained(self) -> None:
        unit = _unit()
        unit["semantics"]["fpu_state"] = {
            "model": "x87-physical-v1",
            "top": 0,
        }
        unit["semantics"]["instruction_effect_schedule"] = {
            "format": "stage-a-instruction-ordered-effect-schedule-v1",
            "records": [{
                "instruction_rva": 0x1000,
                "effects": ["register_write:eax"],
            }],
        }
        summary = derive_transition_summary_v2(unit, binary=_binary([unit]))

        state_outputs = [row for row in summary.outputs if row.category == "state"]
        self.assertEqual([row.destination for row in state_outputs], ["fpu_state"])
        self.assertEqual(
            [row.family for row in summary.ordered_events],
            ["instruction_effect", "ordered_event"],
        )

        unit["semantics"]["instruction_effect_schedule"] = None
        without_schedule = derive_transition_summary_v2(
            unit, binary=_binary([unit])
        )
        self.assertEqual(
            [row.family for row in without_schedule.ordered_events],
            ["ordered_event"],
        )

    def test_noncanonical_machine_ir_is_rejected(self) -> None:
        unit = _unit()
        del unit["record_kind"]

        with self.assertRaisesRegex(
            TransitionSummaryV2Error,
            "canonical v2 unit",
        ):
            derive_transition_summary_v2(unit, binary=_binary([unit]))


if __name__ == "__main__":
    unittest.main()
