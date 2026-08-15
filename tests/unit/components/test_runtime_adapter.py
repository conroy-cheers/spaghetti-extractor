"""Portable component adapter lowering tests."""

from __future__ import annotations

import unittest

from spaghetti_extractor.components.intent import ComponentIntentError
from spaghetti_extractor.components.runtime import _render_component_adapter
from spaghetti_extractor.external.contracts import (
    CheckedExternalSiteContract,
    CheckedStackArgument,
    ExternalSiteIdentity,
)


class ComponentRuntimeAdapterTests(unittest.TestCase):
    def test_cyclic_object_component_calls_source_without_machine_replay(self) -> None:
        symbols: list[tuple[int, str, str]] = []
        rendered = _render_component_adapter(
            identity="loop",
            interface=_object_interface(),
            source={
                "entry": {
                    "abi": "logical-object-c-v1",
                    "symbol": "portable_loop",
                }
            },
            adapter_plan={
                "lowering": {
                    "kind": "checked-object-view-v1",
                    "completion": _completion(),
                }
            },
            members=_loop_members(),
            entry_ids=("unit:loop",),
            symbols=symbols,
        )

        self.assertNotIn("spx_interpreter_step", rendered)
        self.assertNotIn("machine_rva", rendered)
        self.assertIn("logical_result = portable_loop(&argument_0,", rendered)
        self.assertIn("index >= view->extent", rendered)
        self.assertIn("view->base > UINT32_MAX - index", rendered)
        self.assertIn("component_write(rt, completed_write_0_address", rendered)
        self.assertEqual(symbols[0][0], 0x1000)

    def test_unchecked_lowering_cannot_render(self) -> None:
        with self.assertRaisesRegex(ComponentIntentError, "no checked runtime lowering"):
            _render_component_adapter(
                identity="loop",
                interface=_object_interface(),
                source={
                    "entry": {
                        "abi": "logical-object-c-v1",
                        "symbol": "portable_loop",
                    }
                },
                adapter_plan={"lowering": {}},
                members=_loop_members(),
                entry_ids=("unit:loop",),
                symbols=[],
            )

    def test_scalar_control_component_routes_from_portable_result(self) -> None:
        symbols: list[tuple[int, str, str]] = []
        member = _control_member()
        rendered = _render_component_adapter(
            identity="route",
            interface=_control_interface(),
            source={"entry": {"abi": "logical-c-v1", "symbol": "portable_route"}},
            adapter_plan={
                "lowering": {
                    "kind": "scalar-control-projection-v1",
                    "path_unit_ids": ["unit:branch"],
                }
            },
            members={"unit:branch": member},
            entry_ids=("unit:branch",),
            symbols=symbols,
        )

        self.assertIn("logical_result = portable_route(argument_0)", rendered)
        self.assertIn("SPX_BRANCH", rendered)
        self.assertIn("8192U : 12288U", rendered)
        self.assertNotIn("state->eax = (uint32_t)logical_result", rendered)

    def test_c_string_view_has_no_synthetic_extent(self) -> None:
        interface = _object_interface()
        interface["parameters"] = [
            {
                "id": "value",
                "type": "nul-terminated-bytes-v1",
                "memory_view": {
                    "kind": "nul-terminated-read-view-v1",
                    "element_width": 1,
                    "event_refs": [
                        {"family": "memory_event", "unit_id": "unit:loop", "index": 0}
                    ],
                    "access_witness": {"kind": "finite-domain-machine-replay-v1"},
                },
                "machine_source": {
                    "kind": "register",
                    "name": "eax",
                    "width": 32,
                    "evidence": {
                        "unit_id": "unit:loop",
                        "json_pointer": "/semantics/memory_events/0/address",
                    },
                },
            }
        ]
        interface["results"][0]["value_relation"] = {
            "kind": "offset-into-view-v1",
            "parameter_id": "value",
        }
        rendered = _render_component_adapter(
            identity="loop",
            interface=interface,
            source={
                "entry": {
                    "abi": "logical-object-c-v1",
                    "symbol": "portable_loop",
                }
            },
            adapter_plan={
                "lowering": {
                    "kind": "checked-object-view-v1",
                    "completion": _completion(),
                }
            },
            members=_loop_members(),
            entry_ids=("unit:loop",),
            symbols=[],
        )

        self.assertIn("spx_c_string_v1 argument_0", rendered)
        self.assertIn("{ rt, argument_0_machine, 0U, 0U, 0U }", rendered)
        self.assertNotIn("UINT32_MAX, component_read_u8", rendered)

    def test_checked_external_replay_emits_import_and_exposes_exact_result(self) -> None:
        contract = _memcmp_contract()
        interface = _external_interface()
        rendered = _render_component_adapter(
            identity="external",
            interface=interface,
            source={
                "entry": {
                    "abi": "logical-object-c-v1",
                    "symbol": "portable_external",
                }
            },
            adapter_plan={
                "lowering": {
                    "kind": "checked-object-view-v1",
                    "completion": interface["completion"],
                    "external_calls": [
                        {
                            "unit_id": "unit:call",
                            "event_index": 0,
                            "contract": contract.payload(),
                        }
                    ],
                    "external_replay": {
                        "kind": "linear-read-only-call-v1",
                        "prefix_unit_ids": ["unit:call"],
                        "call": {
                            "unit_id": "unit:call",
                            "event_index": 0,
                            "contract_id": contract.contract_id,
                        },
                    },
                }
            },
            members=_external_members(),
            entry_ids=("unit:call",),
            symbols=[],
        )

        self.assertIn("SPX_CALL_EXTERNAL_IMPORT", rendered)
        self.assertIn('"msvcrt.dll", "memcmp"', rendered)
        self.assertIn("spx_invoke_call(", rendered)
        self.assertIn("external_call_0_arguments[3]", rendered)
        self.assertIn("external_call_0_output.eax", rendered)
        self.assertIn("external_replay_state.esp", rendered)
        self.assertNotIn("external_block_0_eax", rendered)
        self.assertEqual(rendered.count("portable_external("), 2)

    def test_completion_renders_generic_arithmetic_flag_expressions(self) -> None:
        interface = _object_interface()
        completion = _completion()
        completion["state"]["cf"] = {
            "op": "not",
            "args": [{"op": "entry", "name": "cf"}],
        }
        completion["state"]["of"] = {
            "op": "add_overflow",
            "args": [
                32,
                {"op": "entry", "name": "esp"},
                {"op": "const", "value": 28, "width": 32},
                {
                    "op": "add32",
                    "args": [
                        {"op": "entry", "name": "esp"},
                        {"op": "const", "value": 28, "width": 32},
                    ],
                },
            ],
        }
        completion["state"]["pf"] = {
            "op": "parity",
            "args": [32, {"op": "entry", "name": "esp"}],
        }
        completion["state"]["sf"] = {
            "op": "msb",
            "args": [32, {"op": "entry", "name": "esp"}],
        }
        interface["completion"] = completion

        rendered = _render_component_adapter(
            identity="flags",
            interface=interface,
            source={
                "entry": {
                    "abi": "logical-object-c-v1",
                    "symbol": "portable_flags",
                }
            },
            adapter_plan={
                "lowering": {
                    "kind": "checked-object-view-v1",
                    "completion": completion,
                }
            },
            members=_loop_members(),
            entry_ids=("unit:loop",),
            symbols=[],
        )

        self.assertIn("component_add_overflow(", rendered)
        self.assertIn("component_parity(", rendered)
        self.assertIn(">> (32 - 1U)", rendered)
        self.assertIn("(!(entry_cf))", rendered)


def _object_interface() -> dict[str, object]:
    register = {"op": "reg", "name": "ecx", "width": 32}
    return {
        "source_abi": "logical-object-c-v1",
        "parameters": [
            {
                "id": "bytes",
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
                "machine_source": {
                    "kind": "register",
                    "name": "eax",
                    "width": 32,
                    "evidence": {
                        "unit_id": "unit:loop",
                        "json_pointer": "/semantics/memory_events/0/address",
                    },
                },
            },
            {
                "id": "maximum",
                "type": "uint32_t",
                "machine_source": {
                    "kind": "register",
                    "name": "ecx",
                    "width": 32,
                    "evidence": {
                        "unit_id": "unit:loop",
                        "json_pointer": "/semantics/outcome/condition",
                    },
                },
            },
        ],
        "results": [
            {
                "id": "result",
                "kind": "return",
                "type": "uint32_t",
                "machine_source": {
                    "kind": "expression",
                    "expression": register,
                    "evidence": {
                        "unit_id": "unit:return",
                        "json_pointer": "/semantics/register_writes/0/value",
                    },
                },
                "effect_refs": [
                    {"family": "register_write", "unit_id": "unit:return", "index": 0}
                ],
            }
        ],
    }


def _completion() -> dict[str, object]:
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
    return {
        "kind": "explicit-machine-state-v1",
        "state": state,
        "memory_writes": [
            {
                "address": {
                    "op": "sub32",
                    "args": [
                        {"op": "entry", "name": "esp"},
                        {"op": "const", "value": 4, "width": 32},
                    ],
                },
                "width": 4,
                "value": {"op": "entry", "name": "ebx"},
            }
        ],
        "return_target": {
            "op": "load",
            "width": 4,
            "address": {"op": "entry", "name": "esp"},
        },
    }


def _loop_members() -> dict[str, dict[str, object]]:
    register = {"op": "reg", "name": "ecx", "width": 32}
    common = {
        "flag_writes": [],
        "external_events": [],
        "faults": [],
    }
    return {
        "unit:loop": {
            "id": "unit:loop",
            "source": {"original": {"rva_start": 0x1000, "rva_end": 0x1010}},
            "semantics": {
                **common,
                "register_writes": [],
                "memory_events": [
                    {
                        "kind": "read",
                        "width": 1,
                        "address": {"op": "reg", "name": "eax", "width": 32},
                    }
                ],
                "outcome": {
                    "kind": "branch",
                    "condition": register,
                    "true_target_rva": 0x1000,
                    "false_target_rva": 0x1010,
                },
            },
        },
        "unit:return": {
            "id": "unit:return",
            "source": {"original": {"rva_start": 0x1010, "rva_end": 0x1011}},
            "semantics": {
                **common,
                "register_writes": [{"register": "eax", "value": register}],
                "memory_events": [],
                "outcome": {
                    "kind": "return",
                    "value": {
                        "op": "load",
                        "width": 4,
                        "address": {"op": "reg", "name": "esp", "width": 32},
                    },
                },
            },
        },
    }


def _control_member() -> dict[str, object]:
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


def _control_interface() -> dict[str, object]:
    condition = _control_member()["semantics"]["outcome"]["condition"]
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
                },
            }
        ],
        "results": [
            {
                "id": "route",
                "kind": "value",
                "type": "uint32_t",
                "machine_source": {"kind": "expression", "expression": condition},
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
        contract_id="external-contract-v3:runtime-fixture",
        profile_binding={"profile_id": "fixture", "profile_sha256": "0" * 64},
        result_register_relations=({"register": "eax", "relation": "exact"},),
        memory_effect="readOnly",
        memory_footprints=(),
        world_effect="none",
        callback_effect="none",
        callback_adapter=None,
    )


def _external_interface() -> dict[str, object]:
    interface = _object_interface()
    interface["completion"] = _completion()
    interface["completion"]["state"]["eax"] = {
        "op": "external_result",
        "unit_id": "unit:call",
        "event_index": 0,
        "register": "eax",
    }
    return interface


def _external_members() -> dict[str, dict[str, object]]:
    call_event = {
        "kind": "external_call",
        "instruction_rva": 0x1000,
        "return_rva": 0x1010,
        "register_inputs": {
            "esp": {"op": "reg", "name": "esp", "width": 32}
        },
        "flag_inputs": {},
        "dll": "msvcrt.dll",
        "symbol": "memcmp",
    }
    return {
        "unit:call": {
            "id": "unit:call",
            "source": {"original": {"rva_start": 0x1000, "rva_end": 0x1010}},
            "semantics": {
                "register_writes": [],
                "flag_writes": [],
                "memory_events": [],
                "ordered_events": [{"family": "external", **call_event}],
                "external_events": [call_event],
                "faults": [],
                "outcome": {"kind": "jump", "target_rva": 0x1010},
            },
        }
    }


if __name__ == "__main__":
    unittest.main()
