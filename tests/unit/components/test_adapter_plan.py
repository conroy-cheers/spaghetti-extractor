"""Checked component adapter-plan tests."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.adapter import build_component_adapter_plan
from spaghetti_extractor.components.formats import COMPONENT_CONTRACT_PACKAGE_V2_FORMAT
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.external.contracts import (
    CheckedExternalSiteContract,
    CheckedStackArgument,
    ExternalSiteIdentity,
)
from spaghetti_extractor.reconstruction.ir import MACHINE_IR_FORMAT


class ComponentAdapterPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.machine = self.root / "machine"
        self.machine.mkdir()
        self.contract = self.root / "contract"
        self.contract.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_scalar_plan_keeps_the_existing_direct_projection(self) -> None:
        self._write_machine([_return_unit()])
        self._write_contract(["unit:return"], _scalar_interface())
        source = self._source("logical-c-v1", "uint32_t f(uint32_t value) { return value; }\n")

        plan = build_component_adapter_plan(
            contract=self.contract,
            implementation=source,
            machine_ir=self.machine,
            out_dir=self.root / "plan",
        )

        self.assertEqual(plan["status"], "checked")
        self.assertEqual(plan["lowering"]["kind"], "scalar-machine-projection-v1")
        self.assertFalse(plan["policy"]["machine_ir_fallback_used"])
        self.assertEqual(
            plan["policy"]["runtime_completion"],
            "checked-machine-projection-v1",
        )

    def test_cyclic_object_plan_requires_total_explicit_completion(self) -> None:
        self._write_machine(_loop_units())
        interface = _object_interface()
        self._write_contract(["unit:loop", "unit:return"], interface)
        source = self._source(
            "logical-object-c-v1",
            '#include "spaghetti-component-abi.h"\n'
            "uint32_t f(const stage_b_ro_bytes_v1 *value, uint32_t maximum) "
            "{ (void)value; return maximum; }\n",
        )

        plan = build_component_adapter_plan(
            contract=self.contract,
            implementation=source,
            machine_ir=self.machine,
            out_dir=self.root / "plan",
        )

        self.assertEqual(plan["status"], "checked")
        self.assertEqual(plan["lowering"]["kind"], "checked-object-view-v1")
        self.assertTrue((self.root / "plan" / "spaghetti-component-abi.h").is_file())

    def test_missing_completion_fails_closed_before_evidence(self) -> None:
        self._write_machine(_loop_units())
        interface = _object_interface()
        interface.pop("completion")
        self._write_contract(["unit:loop", "unit:return"], interface)
        source = self._source(
            "logical-object-c-v1",
            '#include "spaghetti-component-abi.h"\n'
            "uint32_t f(const stage_b_ro_bytes_v1 *value, uint32_t maximum) "
            "{ (void)value; return maximum; }\n",
        )

        plan = build_component_adapter_plan(
            contract=self.contract,
            implementation=source,
            machine_ir=self.machine,
            out_dir=self.root / "plan",
        )

        self.assertEqual(plan["status"], "incomplete")
        self.assertIn(
            "component_completion_missing",
            {row["code"] for row in plan["issues"]},
        )

    def test_scalar_control_plan_binds_result_to_exact_branch(self) -> None:
        self._write_machine([_branch_unit()])
        self._write_contract(["unit:branch"], _control_interface())
        source = self._source(
            "logical-c-v1",
            "uint32_t f(uint32_t value) { return value != 7U; }\n",
        )

        plan = build_component_adapter_plan(
            contract=self.contract,
            implementation=source,
            machine_ir=self.machine,
            out_dir=self.root / "plan",
        )

        self.assertEqual(plan["status"], "checked")
        self.assertEqual(plan["lowering"]["kind"], "scalar-control-projection-v1")
        self.assertEqual(
            plan["policy"]["runtime_completion"],
            "checked-machine-projection-v1",
        )
        self.assertEqual(
            plan["lowering"]["branch"]["true_target_rva"], 0x2000
        )

    def test_scalar_control_plan_rejects_stale_condition_binding(self) -> None:
        self._write_machine([_branch_unit()])
        interface = _control_interface()
        interface["results"][0]["machine_source"]["expression"] = {
            "op": "const",
            "value": 1,
            "width": 32,
        }
        self._write_contract(["unit:branch"], interface)
        source = self._source(
            "logical-c-v1",
            "uint32_t f(uint32_t value) { return value != 7U; }\n",
        )

        plan = build_component_adapter_plan(
            contract=self.contract,
            implementation=source,
            machine_ir=self.machine,
            out_dir=self.root / "plan",
        )

        self.assertEqual(plan["status"], "violated")
        self.assertIn(
            "scalar_control_condition_binding_mismatch",
            {row["code"] for row in plan["issues"]},
        )

    def test_checked_external_call_is_bound_into_the_adapter(self) -> None:
        unit = _return_unit()
        unit["semantics"]["external_events"] = [
            {
                "kind": "external_call",
                "dll": "msvcrt.dll",
                "symbol": "memcmp",
                "arguments": [],
            }
        ]
        self._write_machine([unit])
        interface = _scalar_interface()
        contract = _memcmp_contract()
        interface["services"] = [
            {
                "id": "memcmp",
                "events": [
                    {
                        "family": "external_event",
                        "unit_id": "unit:return",
                        "index": 0,
                        "external_contract_id": contract.contract_id,
                    }
                ],
                "external_contract": contract.payload(),
            }
        ]
        self._write_contract(["unit:return"], interface)
        source = self._source(
            "logical-c-v1", "uint32_t f(uint32_t value) { return value; }\n"
        )

        plan = build_component_adapter_plan(
            contract=self.contract,
            implementation=source,
            machine_ir=self.machine,
            out_dir=self.root / "plan",
        )

        self.assertEqual(plan["status"], "incomplete")
        self.assertEqual(
            plan["lowering"]["external_calls"],
            [
                {
                    "unit_id": "unit:return",
                    "event_index": 0,
                    "contract": contract.payload(),
                }
            ],
        )
        self.assertFalse(plan["policy"]["external_calls_emitted"])
        self.assertIn(
            "component_runtime_external_calls_not_lowerable",
            {row["code"] for row in plan["issues"]},
        )

        interface["services"][0].pop("external_contract")
        self._write_contract(["unit:return"], interface)
        missing = build_component_adapter_plan(
            contract=self.contract,
            implementation=source,
            machine_ir=self.machine,
            out_dir=self.root / "missing-plan",
        )
        self.assertEqual(missing["status"], "incomplete")
        self.assertIn(
            "scalar_adapter_external_event_uncontracted",
            {row["code"] for row in missing["issues"]},
        )

    def test_object_external_call_gets_one_checked_runtime_replay(self) -> None:
        units = _external_object_units()
        contract = _memcmp_contract()
        self._write_machine(units)
        self._write_contract(
            [str(unit["id"]) for unit in units],
            _external_object_interface(contract),
        )
        source = self._source(
            "logical-object-c-v1",
            '#include "spaghetti-component-abi.h"\n'
            "uint32_t f(const stage_b_ro_bytes_v1 *left, "
            "const stage_b_ro_bytes_v1 *right, uint32_t count) "
            "{ (void)left; (void)right; return count == 0U; }\n",
        )

        plan = build_component_adapter_plan(
            contract=self.contract,
            implementation=source,
            machine_ir=self.machine,
            out_dir=self.root / "external-plan",
        )

        self.assertEqual(plan["status"], "checked")
        self.assertTrue(plan["policy"]["external_calls_emitted"])
        self.assertEqual(
            plan["lowering"]["external_replay"],
            {
                "kind": "linear-read-only-call-v1",
                "prefix_unit_ids": ["unit:prepare", "unit:call"],
                "call": {
                    "unit_id": "unit:call",
                    "event_index": 0,
                    "contract_id": contract.contract_id,
                },
            },
        )

    def test_object_external_call_reentry_fails_closed(self) -> None:
        units = _external_object_units()
        units[-1]["semantics"]["outcome"] = {
            "kind": "jump",
            "target_rva": 0x1010,
        }
        contract = _memcmp_contract()
        self._write_machine(units)
        self._write_contract(
            [str(unit["id"]) for unit in units],
            _external_object_interface(contract),
        )
        source = self._source(
            "logical-object-c-v1",
            '#include "spaghetti-component-abi.h"\n'
            "uint32_t f(const stage_b_ro_bytes_v1 *left, "
            "const stage_b_ro_bytes_v1 *right, uint32_t count) "
            "{ (void)left; (void)right; return count == 0U; }\n",
        )

        plan = build_component_adapter_plan(
            contract=self.contract,
            implementation=source,
            machine_ir=self.machine,
            out_dir=self.root / "repeating-plan",
        )

        self.assertEqual(plan["status"], "incomplete")
        self.assertIn(
            "component_runtime_external_call_may_repeat",
            {row["code"] for row in plan["issues"]},
        )

    def _source(self, abi: str, text: str) -> Path:
        source_file = self.root / (abi + ".c")
        source_file.write_text("#include <stdint.h>\n" + text, encoding="ascii")
        package = self.root / (abi + "-source")
        build_component_source_package(
            lift_unit_id="fixture",
            files={source_file.name: source_file},
            shared_inputs={},
            entry={"abi": abi, "symbol": "f"},
            out_dir=package,
        )
        return package

    def _write_contract(self, unit_ids: list[str], interface: object) -> None:
        core = {
            "format": COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
            "status": "checked",
            "lift_unit": {
                "kind": "component",
                "id": "fixture",
                "label": "Fixture",
                "unit_ids": unit_ids,
                "evidence_profile": "bounded-equivalence-v1",
            },
            "bindings": {},
            "authority": {},
            "review": {},
            "artifacts": {},
            "blockers": [],
        }
        _write(
            self.contract / "contract.json",
            {**core, "contract_sha256": _canonical_hash(core)},
        )
        _write(self.contract / "reviewed-interface.json", interface)
        _write(
            self.contract / "semantic-component-catalog.json",
            {
                "components": [
                    {
                        "id": "fixture",
                        "machine_boundary": {
                            "entries": [{"unit_id": unit_ids[0]}]
                        },
                    }
                ]
            },
        )

    def _write_machine(self, units: list[dict[str, object]]) -> None:
        path = self.machine / "machine-ir.jsonl"
        path.write_text(
            "".join(json.dumps(unit, sort_keys=True) + "\n" for unit in units),
            encoding="ascii",
        )
        _write(
            self.machine / "machine-ir-manifest.json",
            {
                "format": MACHINE_IR_FORMAT,
                "artifacts": {
                    "machine_ir": {"path": path.name, "sha256": _file_hash(path)}
                },
                "binary": {"sha256": "a" * 64},
            },
        )


def _return_unit() -> dict[str, object]:
    return {
        "format": MACHINE_IR_FORMAT,
        "id": "unit:return",
        "source": {"original": {"rva_start": 0x1010, "rva_end": 0x1011}},
        "semantics": {
            "register_writes": [
                {
                    "register": "eax",
                    "value": {"op": "reg", "name": "ecx", "width": 32},
                }
            ],
            "flag_writes": [],
            "memory_events": [],
            "external_events": [],
            "faults": [],
            "outcome": {
                "kind": "return",
                "value": {
                    "op": "load",
                    "width": 4,
                    "address": {"op": "reg", "name": "esp", "width": 32},
                },
            },
        },
    }


def _loop_units() -> list[dict[str, object]]:
    loop = {
        "format": MACHINE_IR_FORMAT,
        "id": "unit:loop",
        "source": {"original": {"rva_start": 0x1000, "rva_end": 0x1010}},
        "semantics": {
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [
                {
                    "kind": "read",
                    "width": 1,
                    "address": {"op": "reg", "name": "eax", "width": 32},
                }
            ],
            "external_events": [],
            "faults": [],
            "outcome": {
                "kind": "branch",
                "condition": {"op": "reg", "name": "ecx", "width": 32},
                "true_target_rva": 0x1000,
                "false_target_rva": 0x1010,
            },
        },
    }
    return [loop, _return_unit()]


def _branch_unit() -> dict[str, object]:
    condition = {
        "op": "not",
        "args": [
            {
                "op": "eq",
                "args": [
                    {"op": "reg", "name": "ecx", "width": 32},
                    {"op": "const", "value": 7, "width": 32},
                ],
            }
        ],
    }
    return {
        "format": MACHINE_IR_FORMAT,
        "id": "unit:branch",
        "source": {"original": {"rva_start": 0x1000, "rva_end": 0x1004}},
        "semantics": {
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [],
            "external_events": [],
            "faults": [],
            "outcome": {
                "kind": "branch",
                "condition": condition,
                "true_target_rva": 0x2000,
                "false_target_rva": 0x3000,
            },
        },
    }


def _scalar_interface() -> dict[str, object]:
    return {
        "source_abi": "logical-c-v1",
        "parameters": [{"id": "value", "type": "uint32_t"}],
        "results": [{"id": "result", "kind": "return", "type": "uint32_t"}],
    }


def _object_interface() -> dict[str, object]:
    state = {
        name: {"op": "entry", "name": name}
        for name in (
            "eax",
            "ebx",
            "ecx",
            "edx",
            "esi",
            "edi",
            "ebp",
            "esp",
            "cf",
            "zf",
            "sf",
            "of",
            "pf",
            "df",
        )
    }
    state["eax"] = {"op": "logical_result", "result_id": "result"}
    state["esp"] = {
        "op": "add32",
        "args": [state["esp"], {"op": "const", "value": 4, "width": 32}],
    }
    return {
        "source_abi": "logical-object-c-v1",
        "parameters": [
            {
                "id": "value",
                "type": "read-only-bytes-v1",
                "memory_view": {
                    "kind": "indexed-read-view-v1",
                    "extent_parameter_id": "maximum",
                    "element_width": 1,
                    "event_refs": [
                        {"family": "memory_event", "unit_id": "unit:loop", "index": 0}
                    ],
                    "access_witness": {"kind": "finite-domain-machine-replay-v1"},
                },
            },
            {"id": "maximum", "type": "uint32_t"},
        ],
        "results": [{"id": "result", "kind": "return", "type": "uint32_t"}],
        "completion": {
            "kind": "explicit-machine-state-v1",
            "state": state,
            "memory_writes": [],
            "return_target": {
                "op": "load",
                "width": 4,
                "address": {"op": "entry", "name": "esp"},
            },
        },
    }


def _control_interface() -> dict[str, object]:
    condition = _branch_unit()["semantics"]["outcome"]["condition"]
    return {
        "source_abi": "logical-c-v1",
        "parameters": [
            {
                "id": "value",
                "type": "uint32_t",
                "machine_source": {
                    "kind": "register",
                    "name": "ecx",
                    "width": 32,
                    "evidence": {
                        "unit_id": "unit:branch",
                        "json_pointer": "/semantics/outcome/condition/args/0/args/0",
                    },
                },
            }
        ],
        "results": [
            {
                "id": "route",
                "kind": "value",
                "type": "uint32_t",
                "machine_source": {
                    "kind": "expression",
                    "expression": condition,
                    "evidence": {
                        "unit_id": "unit:branch",
                        "json_pointer": "/semantics/outcome/condition",
                    },
                },
                "effect_refs": [],
            },
            {
                "id": "control",
                "kind": "control",
                "control": {
                    "unit_id": "unit:branch",
                    "outcome_kind": "branch",
                    "condition": condition,
                    "routes": [
                        {"target_rva": 0x2000, "when": True},
                        {"target_rva": 0x3000, "when": False},
                    ],
                },
            },
        ],
    }


def _memcmp_contract() -> CheckedExternalSiteContract:
    arguments = tuple(
        {
            "op": "load",
            "width": 4,
            "address": {
                "op": "add32",
                "args": [
                    {"op": "reg", "name": "esp", "width": 32},
                    {"op": "const", "value": index * 4, "width": 32},
                ],
            },
        }
        for index in range(3)
    )
    return CheckedExternalSiteContract(
        identity=ExternalSiteIdentity(
            kind="import", dll="msvcrt.dll", symbol="memcmp"
        ),
        transfer_kind="call",
        disposition="returns_here",
        profile_disposition="returns",
        abi_template="pe32-cdecl-v1",
        argument_words=3,
        argument_base_offset=0,
        arguments=arguments,
        stack_arguments=tuple(
            CheckedStackArgument(index, index * 4, 4, argument)
            for index, argument in enumerate(arguments)
        ),
        contract_id="external-contract-v3:memcmp-fixture",
        profile_binding={"profile_id": "fixture", "profile_sha256": "0" * 64},
        result_register_relations=({"register": "eax", "relation": "exact"},),
        memory_effect="readOnly",
        memory_footprints=(
            {
                "access": "read",
                "base_argument": 0,
                "offset": 0,
                "size": {"kind": "argument", "argument": 2, "scale": 1},
                "nullable": False,
            },
            {
                "access": "read",
                "base_argument": 1,
                "offset": 0,
                "size": {"kind": "argument", "argument": 2, "scale": 1},
                "nullable": False,
            },
        ),
        world_effect="none",
        callback_effect="none",
        callback_adapter=None,
    )


def _external_object_units() -> list[dict[str, object]]:
    register = lambda name: {"op": "reg", "name": name, "width": 32}
    constant = lambda value: {"op": "const", "value": value, "width": 32}
    subtract = lambda left, right: {"op": "sub32", "args": [left, right]}
    add = lambda left, right: {"op": "add32", "args": [left, right]}
    prepare_writes = [
        {
            "kind": "write",
            "width": 4,
            "address": subtract(register("esp"), constant(offset)),
            "value": register(value),
        }
        for offset, value in ((12, "eax"), (8, "edx"), (4, "ecx"))
    ]
    call_event = {
        "kind": "external_call",
        "instruction_rva": 0x1010,
        "return_rva": 0x1020,
        "register_inputs": {"esp": register("esp")},
        "flag_inputs": {},
        "dll": "msvcrt.dll",
        "symbol": "memcmp",
    }
    common = {"format": MACHINE_IR_FORMAT}
    return [
        {
            **common,
            "id": "unit:prepare",
            "source": {"original": {"rva_start": 0x1000, "rva_end": 0x1010}},
            "semantics": {
                "register_writes": [
                    {
                        "register": "esp",
                        "value": subtract(register("esp"), constant(12)),
                    }
                ],
                "flag_writes": [],
                "memory_events": prepare_writes,
                "ordered_events": [
                    {"family": "memory", **write} for write in prepare_writes
                ],
                "external_events": [],
                "faults": [],
                "outcome": {"kind": "jump", "target_rva": 0x1010},
            },
        },
        {
            **common,
            "id": "unit:call",
            "source": {"original": {"rva_start": 0x1010, "rva_end": 0x1020}},
            "semantics": {
                "register_writes": [
                    {
                        "register": "eax",
                        "value": {
                            "op": "call_response",
                            "call_index": 0,
                            "register": "eax",
                        },
                    }
                ],
                "flag_writes": [],
                "memory_events": [],
                "ordered_events": [{"family": "external", **call_event}],
                "external_events": [call_event],
                "faults": [],
                "outcome": {"kind": "jump", "target_rva": 0x1020},
            },
        },
        {
            **common,
            "id": "unit:return",
            "source": {"original": {"rva_start": 0x1020, "rva_end": 0x1030}},
            "semantics": {
                "register_writes": [
                    {
                        "register": "esp",
                        "value": add(register("esp"), constant(16)),
                    }
                ],
                "flag_writes": [],
                "memory_events": [],
                "external_events": [],
                "faults": [],
                "outcome": {
                    "kind": "return",
                    "value": {
                        "op": "load",
                        "width": 4,
                        "address": add(register("esp"), constant(12)),
                    },
                },
            },
        },
    ]


def _external_object_interface(
    contract: CheckedExternalSiteContract,
) -> dict[str, object]:
    interface = _object_interface()
    interface["parameters"] = [
        {
            "id": "left",
            "type": "read-only-bytes-v1",
            "machine_source": {"kind": "register", "name": "eax", "width": 32},
            "memory_view": {
                "kind": "indexed-read-view-v1",
                "extent_parameter_id": "count",
                "element_width": 1,
                "event_refs": [],
                "access_witness": {"kind": "finite-domain-machine-replay-v1"},
            },
        },
        {
            "id": "right",
            "type": "read-only-bytes-v1",
            "machine_source": {"kind": "register", "name": "edx", "width": 32},
            "memory_view": {
                "kind": "indexed-read-view-v1",
                "extent_parameter_id": "count",
                "element_width": 1,
                "event_refs": [],
                "access_witness": {"kind": "finite-domain-machine-replay-v1"},
            },
        },
        {
            "id": "count",
            "type": "uint32_t",
            "machine_source": {"kind": "register", "name": "ecx", "width": 32},
        },
    ]
    interface["services"] = [
        {
            "id": "memcmp",
            "events": [
                {
                    "family": "external_event",
                    "unit_id": "unit:call",
                    "index": 0,
                    "external_contract_id": contract.contract_id,
                }
            ],
            "external_contract": contract.payload(),
        }
    ]
    state = interface["completion"]["state"]
    state["eax"] = {
        "op": "external_result",
        "unit_id": "unit:call",
        "event_index": 0,
        "register": "eax",
    }
    return interface


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii")


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


if __name__ == "__main__":
    unittest.main()
