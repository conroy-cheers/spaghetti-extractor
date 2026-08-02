from __future__ import annotations

import json
import unittest

from spaghetti_extractor.reconstruction_contract_analysis import (
    RECONSTRUCTION_CONTRACT_ANALYSIS_FORMAT,
    analyze_reconstruction_contracts,
)


def _reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def _add(base: dict[str, object], offset: int) -> dict[str, object]:
    return {"op": "add32", "args": [base, _const(offset)]}


def _unit(
    identity: str,
    rva: int,
    *,
    memory_events: list[dict[str, object]] | None = None,
    instructions: list[dict[str, object]] | None = None,
    external_events: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "format": "stage-a-machine-ir-v2",
        "id": identity,
        "source": {"original": {"rva_start": rva, "rva_end": rva + 1}},
        "instructions": instructions or [],
        "semantics": {
            "memory_events": memory_events or [],
            "external_events": external_events or [],
        },
    }


def _memory_operand(
    *, base: str = "eax", displacement: int = 4
) -> dict[str, object]:
    return {
        "kind": "memory",
        "segment": None,
        "base": base,
        "index": None,
        "scale": 1,
        "displacement": displacement,
        "width_bits": 32,
        "access": "read_write",
    }


def _cmpxchg_instruction(*, locked: bool) -> dict[str, object]:
    return {
        "rva_start": 0x1010,
        "mnemonic": "lock cmpxchg" if locked else "cmpxchg",
        "operands": [
            _memory_operand(),
            {
                "kind": "register",
                "name": "ebx",
                "width_bits": 32,
                "access": "read",
            },
        ],
    }


def _catalog_entry(
    symbol: str,
    *,
    argument_words: int,
    world_effect: str,
    **extra: object,
) -> dict[str, object]:
    return {
        "id": f"kernel32:{symbol}",
        "import": {"dll": "kernel32.dll", "symbol": symbol},
        "abi_template": "pe32-stdcall-v1",
        "argument_words": argument_words,
        "disposition": "returns",
        "memory_effect": "none",
        "memory_footprints": [],
        "world_effect": world_effect,
        **extra,
    }


class ReconstructionContractAnalysisTests(unittest.TestCase):
    def test_groups_struct_like_fields_with_exact_widths_and_accesses(self) -> None:
        units = [
            _unit(
                "field-zero",
                0x1000,
                memory_events=[
                    {"kind": "read", "address": _reg("eax"), "width": 4}
                ],
            ),
            _unit(
                "field-four",
                0x1010,
                memory_events=[
                    {
                        "kind": "write",
                        "address": _add(_reg("eax"), 4),
                        "width": 2,
                        "value": _const(7),
                    },
                    {
                        "kind": "read",
                        "address": _add(_reg("eax"), 4),
                        "width": 2,
                    },
                ],
            ),
        ]

        first = analyze_reconstruction_contracts(units)
        second = analyze_reconstruction_contracts(list(reversed(units)))

        self.assertEqual(first["format"], RECONSTRUCTION_CONTRACT_ANALYSIS_FORMAT)
        self.assertEqual(first["status"], "complete")
        self.assertEqual(
            json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True)
        )
        self.assertEqual(len(first["memory_views"]), 1)
        fields = first["memory_views"][0]["fields"]
        self.assertEqual(
            [
                (field["offset"], field["width_bytes"], field["accesses"])
                for field in fields
            ],
            [(0, 4, ["read"]), (4, 2, ["read", "write"])],
        )
        self.assertEqual(fields[0]["type"], {"kind": "opaque_bits", "width_bits": 32})
        self.assertEqual(len(first["preconditions"]["valid_memory"]), 2)

    def test_stack_and_object_views_emit_alias_resolution_precondition(self) -> None:
        result = analyze_reconstruction_contracts(
            [
                _unit(
                    "stack",
                    0x1000,
                    memory_events=[
                        {
                            "kind": "write",
                            "address": _add(_reg("esp"), 8),
                            "width": 4,
                            "value": _const(1),
                        }
                    ],
                ),
                _unit(
                    "object",
                    0x1010,
                    memory_events=[
                        {"kind": "read", "address": _reg("eax"), "width": 4}
                    ],
                ),
            ]
        )

        roles = {view["base_role"] for view in result["memory_views"]}
        self.assertEqual(roles, {"stack_frame", "object_pointer"})
        self.assertEqual(len(result["preconditions"]["aliasing"]), 1)
        alias = result["preconditions"]["aliasing"][0]
        self.assertEqual(alias["relationship"], "stack_object")
        self.assertEqual(
            alias["requirement"],
            "disjoint_or_same_object_with_compatible_fields",
        )

    def test_absolute_location_is_a_complete_typed_memory_view(self) -> None:
        result = analyze_reconstruction_contracts(
            [
                _unit(
                    "static-slot",
                    0x1000,
                    memory_events=[
                        {"kind": "read", "address": _const(0x430344), "width": 4},
                        {
                            "kind": "write",
                            "address": _const(0x430344),
                            "width": 4,
                            "value": _const(7),
                        },
                    ],
                )
            ]
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(len(result["memory_views"]), 1)
        view = result["memory_views"][0]
        self.assertEqual(view["base_role"], "absolute_location")
        self.assertEqual(view["base"], _const(0x430344))
        self.assertEqual(view["fields"][0]["offset"], 0)
        self.assertEqual(view["fields"][0]["accesses"], ["read", "write"])

    def test_lock_cmpxchg_is_atomic_and_retains_concrete_read_write(self) -> None:
        address = _add(_reg("eax"), 4)
        events = [
            {"kind": "read", "address": address, "width": 4},
            {
                "kind": "write",
                "address": address,
                "width": 4,
                "value": {
                    "op": "ite",
                    "args": [
                        {"op": "eq", "args": [_reg("eax"), _const(0)]},
                        _reg("ebx"),
                        {"op": "load", "address": address, "width": 4},
                    ],
                },
            },
        ]
        result = analyze_reconstruction_contracts(
            [
                _unit(
                    "locked",
                    0x1010,
                    instructions=[_cmpxchg_instruction(locked=True)],
                    memory_events=events,
                )
            ]
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(len(result["atomic_effects"]), 1)
        atomic = result["atomic_effects"][0]
        self.assertEqual(atomic["effect_kind"], "atomic_read_modify_write")
        self.assertEqual(atomic["operation"], "compare_exchange")
        self.assertTrue(atomic["conditional_write"])
        self.assertEqual(len(atomic["concrete_reads"]), 1)
        self.assertEqual(len(atomic["concrete_writes"]), 1)
        self.assertEqual(len(atomic["concrete_memory_events"]), 2)
        self.assertEqual(len(result["concrete_effects"]["memory_events"]), 2)

    def test_plain_cmpxchg_is_not_misclassified_as_atomic(self) -> None:
        address = _add(_reg("eax"), 4)
        result = analyze_reconstruction_contracts(
            [
                _unit(
                    "plain",
                    0x1010,
                    instructions=[_cmpxchg_instruction(locked=False)],
                    memory_events=[
                        {"kind": "read", "address": address, "width": 4},
                        {
                            "kind": "write",
                            "address": address,
                            "width": 4,
                            "value": _reg("ebx"),
                        },
                    ],
                )
            ]
        )

        self.assertEqual(result["atomic_effects"], [])
        self.assertEqual(len(result["concrete_effects"]["memory_events"]), 2)

    def test_sleep_becomes_typed_external_service_from_normalized_catalog(self) -> None:
        event = {
            "kind": "external_call",
            "dll": "KERNEL32.dll",
            "symbol": "Sleep",
            "ordinal": None,
            "arguments": [_const(25)],
            "abi_contract": {
                "template": "pe32-stdcall-v1",
                "argument_words": 1,
            },
        }
        catalog = {
            "machine_import_call_contracts": [
                _catalog_entry(
                    "Sleep",
                    argument_words=1,
                    world_effect="none",
                    parameters=[
                        {
                            "name": "milliseconds",
                            "direction": "in",
                            "type": {"kind": "uint", "width_bits": 32},
                        }
                    ],
                    return_type={"kind": "void"},
                )
            ]
        }

        result = analyze_reconstruction_contracts(
            [_unit("sleep", 0x2000, external_events=[event])], catalog
        )

        self.assertEqual(result["status"], "complete")
        service = result["external_services"][0]
        self.assertEqual(service["identity"], {"dll": "kernel32.dll", "symbol": "Sleep"})
        self.assertEqual(service["service_kind"], "external_service")
        self.assertEqual(service["signature"]["calling_convention"], "stdcall")
        self.assertEqual(
            service["signature"]["arguments"][0]["type"],
            {"kind": "uint", "width_bits": 32},
        )
        self.assertEqual(service["effects"]["world_effect"], "none")

    def test_callback_registration_emits_target_abi_lifetime_and_nested_frame(self) -> None:
        callback_abi = {
            "kind": "generic_callback",
            "argument_words": 1,
            "stack_cleanup_bytes": 4,
            "nullable": True,
        }
        event = {
            "kind": "external_call",
            "dll": "kernel32.dll",
            "symbol": "SetUnhandledExceptionFilter",
            "ordinal": None,
            "arguments": [_reg("ecx")],
            "abi_contract": {
                "template": "pe32-stdcall-v1",
                "argument_words": 1,
                "memory_effect": "none",
                "world_effect": "callbackRegistration",
                "world_effect_argument": 0,
                "callback_abi": callback_abi,
            },
        }
        catalog = {
            "entries": [
                _catalog_entry(
                    "SetUnhandledExceptionFilter",
                    argument_words=1,
                    world_effect="callbackRegistration",
                    world_effect_argument=0,
                    callback_abi=callback_abi,
                    callback_lifetime="until_replaced_or_process_exit",
                )
            ]
        }

        result = analyze_reconstruction_contracts(
            [_unit("register", 0x3000, external_events=[event])], catalog
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(len(result["callbacks"]), 1)
        callback = result["callbacks"][0]
        self.assertEqual(callback["target"], _reg("ecx"))
        self.assertEqual(callback["abi"], callback_abi)
        self.assertEqual(
            callback["lifetime"],
            {
                "status": "complete",
                "policy": "until_replaced_or_process_exit",
            },
        )
        self.assertTrue(callback["nested_frame"]["required"])
        self.assertEqual(callback["nested_frame"]["status"], "complete")
        self.assertEqual(callback["nested_frame"]["argument_words"], 1)
        self.assertEqual(callback["nested_frame"]["stack_cleanup_bytes"], 4)

    def test_checked_stack_input_supplies_concrete_callback_target(self) -> None:
        callback_abi = {
            "kind": "generic_callback",
            "argument_words": 1,
            "stack_cleanup_bytes": 4,
            "nullable": True,
        }
        event = {
            "kind": "external_call",
            "dll": "kernel32.dll",
            "symbol": "SetUnhandledExceptionFilter",
            "ordinal": None,
            "arguments": [
                {"op": "load", "address": _reg("esp"), "width": 4}
            ],
            "stack_inputs": [{"offset": 0, "width": 4, "value": _const(0x40A9A0)}],
            "abi_contract": {
                "template": "pe32-stdcall-v1",
                "argument_words": 1,
                "memory_effect": "none",
                "world_effect": "callbackRegistration",
                "world_effect_argument": 0,
                "callback_lifetime": "until_replaced_or_process_exit",
                "callback_abi": callback_abi,
            },
        }
        result = analyze_reconstruction_contracts(
            [_unit("register", 0x3000, external_events=[event])]
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["callbacks"][0]["target"], _const(0x40A9A0))

    def test_ambiguous_catalog_fails_closed(self) -> None:
        event = {
            "kind": "external_call",
            "dll": "kernel32.dll",
            "symbol": "Sleep",
            "ordinal": None,
            "arguments": [_const(1)],
            "abi_contract": {
                "template": "pe32-stdcall-v1",
                "argument_words": 1,
            },
        }
        entry = _catalog_entry("Sleep", argument_words=1, world_effect="none")
        result = analyze_reconstruction_contracts(
            [_unit("ambiguous", 0x4000, external_events=[event])],
            {"entries": [entry, dict(entry)]},
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["external_services"][0]["status"], "incomplete")
        self.assertIn(
            "ambiguous_external_signature",
            {issue["category"] for issue in result["issues"]},
        )


if __name__ == "__main__":
    unittest.main()
