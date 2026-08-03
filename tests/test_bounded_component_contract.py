from __future__ import annotations

import copy
import json
import unittest
from hashlib import sha256

from spaghetti_extractor.bounded_component_contract import (
    BOUNDED_STRING_CONTRACT_FORMAT,
    derive_bounded_pairwise_byte_compare_contract,
    derive_bounded_string_length_contract,
)
from spaghetti_extractor.stage_binary import StageAInputError


def _reg(name: str) -> dict[str, object]:
    return {"kind": "register", "name": name}


def _imm(value: int) -> dict[str, object]:
    return {"kind": "immediate", "value": value}


def _mem(base: str, displacement: int, width_bits: int) -> dict[str, object]:
    return {
        "kind": "memory",
        "base": base,
        "displacement": displacement,
        "width_bits": width_bits,
        "index": None,
        "scale": 1,
    }


def _instruction(mnemonic: str, *operands: dict[str, object]) -> dict[str, object]:
    return {"mnemonic": mnemonic, "operands": list(operands)}


def _unit(
    index: int,
    rva: int,
    instructions: list[dict[str, object]],
    control_kind: str,
    targets: list[int],
    outcome: dict[str, object],
    external_events: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "id": f"unit:{index}",
        "instructions": instructions,
        "control": {"kind": control_kind, "direct_targets": targets},
        "semantics": {
            "outcome": outcome,
            "external_events": external_events or [],
            "instruction_effect_schedule": {"records": []},
        },
        "source": {
            "original": {"rva_start": rva, "rva_end": rva + 1},
            "instruction_bytes_sha256": f"bytes-{index}",
            "semantic_export": {"semantic_transfer_sha256": f"semantic-{index}"},
        },
    }


def _fixture() -> tuple[dict[str, object], list[dict[str, object]]]:
    rvas = [0x1000, 0x1010, 0x1020, 0x1030, 0x1040, 0x1050, 0x1060, 0x1070]
    units = [
        _unit(
            0,
            rvas[0],
            [
                _instruction("push", _reg("ebx")),
                _instruction("mov", _reg("ebx"), _mem("esp", 8, 32)),
                _instruction("xor", _reg("edx"), _reg("edx")),
                _instruction("mov", _reg("ecx"), _mem("esp", 12, 32)),
            ],
            "fallthrough",
            [rvas[1]],
            {"kind": "fallthrough", "target_rva": rvas[1]},
        ),
        _unit(
            1,
            rvas[1],
            [
                _instruction("mov", _reg("eax"), _reg("ebx")),
                _instruction("test", _reg("ecx"), _reg("ecx")),
                _instruction("jne", _imm(rvas[5])),
            ],
            "branch",
            [rvas[5], rvas[2]],
            {
                "kind": "branch",
                "true_target_rva": rvas[5],
                "false_target_rva": rvas[2],
            },
        ),
        _unit(
            2,
            rvas[2],
            [_instruction("jmp", _imm(rvas[6]))],
            "jump",
            [rvas[6]],
            {"kind": "jump", "target_rva": rvas[6]},
        ),
        _unit(
            3,
            rvas[3],
            [
                _instruction("add", _reg("eax"), _imm(1)),
                _instruction("mov", _reg("edx"), _reg("eax")),
                _instruction("sub", _reg("edx"), _reg("ebx")),
                _instruction("cmp", _reg("edx"), _reg("ecx")),
            ],
            "fallthrough",
            [rvas[4]],
            {"kind": "fallthrough", "target_rva": rvas[4]},
        ),
        _unit(
            4,
            rvas[4],
            [_instruction("jae", _imm(rvas[6]))],
            "branch",
            [rvas[6], rvas[5]],
            {
                "kind": "branch",
                "true_target_rva": rvas[6],
                "false_target_rva": rvas[5],
            },
        ),
        _unit(
            5,
            rvas[5],
            [
                _instruction("cmp", _mem("eax", 0, 8), _imm(0)),
                _instruction("jne", _imm(rvas[3])),
            ],
            "branch",
            [rvas[3], rvas[6]],
            {
                "kind": "branch",
                "true_target_rva": rvas[3],
                "false_target_rva": rvas[6],
            },
        ),
        _unit(
            6,
            rvas[6],
            [
                _instruction("mov", _reg("eax"), _reg("edx")),
                _instruction("pop", _reg("ebx")),
                _instruction("xor", _reg("edx"), _reg("edx")),
                _instruction("xor", _reg("ecx"), _reg("ecx")),
            ],
            "fallthrough",
            [rvas[7]],
            {"kind": "fallthrough", "target_rva": rvas[7]},
        ),
        _unit(7, rvas[7], [_instruction("ret")], "return", [], {"kind": "return"}),
    ]
    component = {
        "id": "bounded-length",
        "component_sha256": "component",
        "membership": {"resolved_unit_ids": [unit["id"] for unit in units]},
        "machine_boundary": {
            "counts": {
                "entries": 1,
                "exits": 1,
                "external_events": 0,
                "faults": 0,
            },
            "call_closure": {"status": "complete"},
            "internal_calls": [],
            "exits": [{"kind": "return", "source_unit_id": "unit:7"}],
        },
    }
    return component, units


def _hash(payload: dict[str, object]) -> str:
    return sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _pairwise_fixture() -> tuple[
    dict[str, object], list[dict[str, object]], dict[str, object]
]:
    rvas = [0x2000 + index * 0x10 for index in range(12)]
    target_rva = 0x4000

    def call_event(pointer: str, return_rva: int) -> dict[str, object]:
        return {
            "kind": "internal_call",
            "target_rva": target_rva,
            "return_rva": return_rva,
            "stack_inputs": [
                {
                    "offset": 0,
                    "width": 4,
                    "value": {
                        "op": "and32",
                        "args": [
                            {"op": "const", "value": 255, "width": 32},
                            {
                                "op": "load",
                                "width": 1,
                                "address": {
                                    "op": "reg",
                                    "name": pointer,
                                    "width": 32,
                                },
                            },
                        ],
                    },
                }
            ],
        }

    units = [
        _unit(0, rvas[0], [_instruction("push", _reg("edi")), _instruction("xor", _reg("eax"), _reg("eax")), _instruction("push", _reg("esi")), _instruction("push", _reg("ebx"))], "fallthrough", [rvas[1]], {"kind": "fallthrough", "target_rva": rvas[1]}),
        _unit(1, rvas[1], [_instruction("sub", _reg("esp"), _imm(16)), _instruction("mov", _reg("edi"), _mem("esp", 32, 32)), _instruction("mov", _reg("esi"), _mem("esp", 36, 32)), _instruction("cmp", _reg("edi"), _reg("esi"))], "fallthrough", [rvas[2]], {"kind": "fallthrough", "target_rva": rvas[2]}),
        _unit(2, rvas[2], [_instruction("jne", _imm(rvas[5]))], "branch", [rvas[5], rvas[3]], {"kind": "branch", "true_target_rva": rvas[5], "false_target_rva": rvas[3]}),
        _unit(3, rvas[3], [_instruction("jmp", _imm(rvas[10]))], "jump", [rvas[10]], {"kind": "jump", "target_rva": rvas[10]}),
        _unit(4, rvas[4], [_instruction("add", _reg("edi"), _imm(1)), _instruction("add", _reg("esi"), _imm(1))], "fallthrough", [rvas[5]], {"kind": "fallthrough", "target_rva": rvas[5]}),
        _unit(5, rvas[5], [_instruction("movzx", _reg("eax"), _mem("edi", 0, 8)), _instruction("mov", _mem("esp", 0, 32), _reg("eax")), _instruction("call", _imm(target_rva))], "fallthrough", [rvas[6]], {"kind": "fallthrough", "target_rva": rvas[6]}, [call_event("edi", rvas[6])]),
        _unit(6, rvas[6], [_instruction("mov", _reg("ebx"), _reg("eax")), _instruction("movzx", _reg("eax"), _mem("esi", 0, 8)), _instruction("mov", _mem("esp", 0, 32), _reg("eax")), _instruction("call", _imm(target_rva))], "fallthrough", [rvas[7]], {"kind": "fallthrough", "target_rva": rvas[7]}, [call_event("esi", rvas[7])]),
        _unit(7, rvas[7], [_instruction("test", _reg("bl"), _reg("bl")), _instruction("je", _imm(rvas[9]))], "branch", [rvas[9], rvas[8]], {"kind": "branch", "true_target_rva": rvas[9], "false_target_rva": rvas[8]}),
        _unit(8, rvas[8], [_instruction("cmp", _reg("bl"), _reg("al")), _instruction("je", _imm(rvas[4]))], "branch", [rvas[4], rvas[9]], {"kind": "branch", "true_target_rva": rvas[4], "false_target_rva": rvas[9]}),
        _unit(9, rvas[9], [_instruction("movzx", _reg("edx"), _reg("al")), _instruction("movzx", _reg("eax"), _reg("bl")), _instruction("sub", _reg("eax"), _reg("edx"))], "fallthrough", [rvas[10]], {"kind": "fallthrough", "target_rva": rvas[10]}),
        _unit(10, rvas[10], [_instruction("add", _reg("esp"), _imm(16)), _instruction("pop", _reg("ebx")), _instruction("pop", _reg("esi")), _instruction("pop", _reg("edi"))], "fallthrough", [rvas[11]], {"kind": "fallthrough", "target_rva": rvas[11]}),
        _unit(11, rvas[11], [_instruction("xor", _reg("edx"), _reg("edx")), _instruction("xor", _reg("ecx"), _reg("ecx")), _instruction("ret")], "return", [], {"kind": "return"}),
    ]
    callsites = [
        {"source_unit_id": "unit:5", "gap_id": "gap:5"},
        {"source_unit_id": "unit:6", "gap_id": "gap:6"},
    ]
    component_call = {
        "target_component_id": "normalize-byte",
        "target_proposal_id": "proposal:normalize",
        "target_rva": target_rva,
        "target_unit_id": "unit:normalize",
        "dependency_sha256": "selection-dependency",
        "callsites": callsites,
    }
    component = {
        "id": "pairwise",
        "component_sha256": "component-pairwise",
        "component_calls": [component_call],
        "membership": {"resolved_unit_ids": [unit["id"] for unit in units]},
        "machine_boundary": {
            "counts": {"entries": 1, "exits": 3, "external_events": 2, "faults": 0},
            "call_closure": {"status": "complete"},
            "exits": [
                {"kind": "internal_call", "source_unit_id": "unit:5", "target_rva": target_rva, "target_unit_id": "unit:normalize", "return_rva": rvas[6]},
                {"kind": "internal_call", "source_unit_id": "unit:6", "target_rva": target_rva, "target_unit_id": "unit:normalize", "return_rva": rvas[7]},
                {"kind": "return", "source_unit_id": "unit:11"},
            ],
        },
    }
    scalar_core = {
        "format": "stage-b-finite-component-contract-v1",
        "status": "derived",
        "executes_original_binary": False,
        "profile": "finite_acyclic_scalar_v1",
        "component": {"id": "normalize-byte"},
        "paths": [{"guards": [], "output": {"op": "reg", "name": "component_input"}}],
    }
    scalar = {**scalar_core, "contract_sha256": _hash(scalar_core)}
    dependency_core = {
        "target_component_id": "normalize-byte",
        "target_rva": target_rva,
        "target_unit_id": "unit:normalize",
        "selection_dependency_sha256": "selection-dependency",
        "callsites": callsites,
        "qualification_sha256": "qualification",
        "refinement_sha256": "refinement",
        "portable_symbol": "normalize_byte",
        "portable_source_sha256": "source",
        "activation": {"authorized": True, "kind": "total"},
        "finite_component_contract": scalar,
    }
    dependency = {**dependency_core, "binding_sha256": _hash(dependency_core)}
    return component, units, dependency


class BoundedComponentContractTests(unittest.TestCase):
    def test_canonical_loop_derives_a_guarded_contract(self) -> None:
        component, units = _fixture()
        contract = derive_bounded_string_length_contract(
            component=component,
            units=units,
            machine_ir_sha256="machine",
            max_bytes=16,
        )
        self.assertEqual(contract["format"], BOUNDED_STRING_CONTRACT_FORMAT)
        self.assertEqual(contract["domain"]["max_bytes"], 16)
        self.assertEqual(contract["loop"]["variant"], "limit - index")

    def test_changed_byte_load_width_fails_closed(self) -> None:
        component, units = _fixture()
        corrupted = copy.deepcopy(units)
        corrupted[5]["instructions"][0]["operands"][0]["width_bits"] = 32
        with self.assertRaisesRegex(StageAInputError, "normalized loop shape"):
            derive_bounded_string_length_contract(
                component=component,
                units=corrupted,
                machine_ir_sha256="machine",
                max_bytes=16,
            )

    def test_changed_back_edge_fails_closed(self) -> None:
        component, units = _fixture()
        corrupted = copy.deepcopy(units)
        corrupted[5]["semantics"]["outcome"]["true_target_rva"] = 0x9999
        with self.assertRaisesRegex(StageAInputError, "branch does not match"):
            derive_bounded_string_length_contract(
                component=component,
                units=corrupted,
                machine_ir_sha256="machine",
                max_bytes=16,
            )

    def test_pairwise_loop_binds_scalar_component_calls(self) -> None:
        component, units, dependency = _pairwise_fixture()
        contract = derive_bounded_pairwise_byte_compare_contract(
            component=component,
            units=units,
            machine_ir_sha256="machine",
            max_bytes=16,
            component_dependency=dependency,
        )
        self.assertEqual(
            contract["format"], "stage-b-bounded-pairwise-byte-contract-v1"
        )
        self.assertEqual(contract["domain"]["max_bytes"], 16)
        self.assertEqual(
            contract["component_call"]["target_component_id"], "normalize-byte"
        )

    def test_pairwise_wrong_call_argument_fails_closed(self) -> None:
        component, units, dependency = _pairwise_fixture()
        corrupted = copy.deepcopy(units)
        corrupted[5]["semantics"]["external_events"][0]["stack_inputs"][0][
            "value"
        ]["args"][1]["address"]["name"] = "esi"
        with self.assertRaisesRegex(StageAInputError, "expected byte"):
            derive_bounded_pairwise_byte_compare_contract(
                component=component,
                units=corrupted,
                machine_ir_sha256="machine",
                max_bytes=16,
                component_dependency=dependency,
            )


if __name__ == "__main__":
    unittest.main()
