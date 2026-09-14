from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.machine_binding import (
    create_proof_kernel_machine_binding,
)
from spaghetti_extractor.components.semantic_contract import (
    ComponentSemanticContractError,
    _checked_external_argument_transducers,
    _checked_external_result_projection,
    build_proof_kernel_semantic_contract,
)
from spaghetti_extractor.components.semantic_services import service_event_index
from spaghetti_extractor.components.interface_ir import (
    ProofKernelComponentInterface,
    ProofKernelLogicalType,
)
from spaghetti_extractor.components.refinement import check_component_refinement
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.components.source_profile import (
    check_component_source_profile,
)
from spaghetti_extractor.components.semantic_paths import (
    build_operation_path_model,
    _nonnull_minimum_remaining,
)
from spaghetti_extractor.external.resolved import bind_launch_policy_v1


SHA = hashlib.sha256(b"semantic-external-service").hexdigest()
TESTKIT = {"fixtures": ("cbmc", "compiler")}


def _resolved_environment(
    contract_row: dict[str, object] | None = None,
    *,
    interface_catalogs: tuple[dict[str, object], ...] = (),
) -> dict[str, object]:
    launch = {
        "assumptions": {
            name: {"contract": f"fixture-{name}"}
            for name in (
                "argv",
                "environment",
                "fs",
                "iat",
                "initial_stack",
                "relocations",
            )
        },
        "feature_inventory": {
            "direct_syscalls": [],
            "executable_writes": [],
            "threads": [],
            "unknown_async_callbacks": [],
            "unmodelled_seh": [],
        },
        "format": "spaghetti-extractor-pe32-launch-assumption-template-v1",
        "schema_version": 1,
    }
    rows = [] if contract_row is None else [contract_row]
    payload: dict[str, object] = {
        "format": "spaghetti-extractor-resolved-external-environment-v1",
        "status": "complete",
        "bindings": {
            "module_interface_sha256": "1" * 64,
            "module_pe_sha256": "a" * 64,
            "environment_intent_sha256": "3" * 64,
            "runtime_profile_pack_sha256s": [],
            "interface_profile_pack_sha256s": [],
        },
        "target": {"abi": "pe32-i686-mingw32", "data_layout": "pe32-ilp32-v1"},
        "launch_policy": bind_launch_policy_v1(
            launch, source_sha256="4" * 64, filename="fixture-launch.json"
        ),
        "canonical_boundaries": [],
        "interface_method_catalogs": list(interface_catalogs),
        "machine_import_contracts": rows,
        "original_semantic_imports": rows,
        "generated_runtime_support_imports": [],
        "loader_service_contracts": [],
        "static_authority_bindings": [],
        "checked_exception_protocols": [],
        "blockers": [],
        "authority": "checked_static_environment",
    }
    payload["resolved_environment_sha256"] = canonical_sha256_v3(payload)
    return payload


def _reference_projection(register: str = "eax") -> dict[str, object]:
    return {
        "kind": "reference",
        "source": {
            "kind": "register",
            "register": register,
            "width": 32,
            "at": "call",
        },
        "requested_extent": {"kind": "constant", "value": 1, "width": 32},
        "authority": {
            "id": "input_string",
            "kind": "external",
            "lifetime": "invocation",
        },
        "at": "call",
    }

class SemanticInterfaceServiceTests(unittest.TestCase):
    def test_external_contract_supplies_abi_boundary_and_typed_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unit_id = "unit:select"
            event = {
                "kind": "external_call",
                "dll": "msvcrt.dll",
                "symbol": "strrchr",
                "ordinal": None,
                "instruction_rva": 0x1004,
                "return_rva": 0x1008,
                "target_rva": 0,
                "register_inputs": {
                    register: {"op": "reg", "name": register, "width": 32}
                    for register in (
                        "eax",
                        "ebx",
                        "ecx",
                        "edx",
                        "esi",
                        "edi",
                        "ebp",
                        "esp",
                    )
                },
                "stack_inputs": [
                    {
                        "offset": 0,
                        "width": 4,
                        "value": {
                            "op": "load",
                            "width": 4,
                            "address": {"op": "reg", "name": "esp", "width": 32},
                        },
                    }
                ],
            }
            unit = {
                "format": "spaghetti-extractor-machine-ir-v3",
                "record_kind": "unit",
                "id": unit_id,
                "status": "qualified",
                "source": {
                    "original": {"rva_start": 0x1000, "rva_end": 0x1010},
                    "contract_sha256": "b" * 64,
                    "instruction_bytes_sha256": "c" * 64,
                },
                "semantics": {
                    "outcome": {"kind": "return"},
                    "external_events": [
                        event,
                        {
                            **event,
                            "instruction_rva": 0x100C,
                            "return_rva": 0x1010,
                        },
                    ],
                    "memory_events": [],
                    "register_writes": [],
                    "flag_writes": [],
                    "faults": [],
                },
            }
            machine = root / "machine-ir.jsonl"
            machine.write_text(
                json.dumps(unit, sort_keys=True) + "\n",
                encoding="ascii",
            )
            machine_sha256 = hashlib.sha256(machine.read_bytes()).hexdigest()
            manifest = root / "machine-ir-manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "format": "spaghetti-extractor-machine-ir-v3",
                        "binary": {"sha256": "a" * 64},
                        "artifacts": {"machine_ir": {"sha256": machine_sha256}},
                    }
                ),
                encoding="ascii",
            )
            interface = {
                "id": "external_reference",
                "types": [
                    {"id": "u8", "kind": "scalar", "c_type": "uint8_t"},
                    {
                        "id": "input",
                        "kind": "view",
                        "element_type_id": "u8",
                        "access": "read",
                        "extent": {"kind": "nul_terminated"},
                        "ownership": "borrowed",
                    },
                    {
                        "id": "character",
                        "kind": "reference",
                        "element_type_id": "u8",
                        "access": "read",
                        "nullable": True,
                        "allow_one_past": False,
                        "lifetime": "origin",
                    },
                ],
                "state": [],
                "operations": [
                    {
                        "id": "select",
                        "kind": "operation",
                        "parameters": [{"id": "input", "type_id": "input"}],
                        "results": [],
                        "effect_ids": [],
                        "allowed_service_ids": ["find"],
                        "pre_states": ["ready"],
                        "post_states": ["ready"],
                    }
                ],
                "effects": [],
                "services": [
                    {
                        "id": "find",
                        "parameter_type_ids": ["input", "u8"],
                        "result_type_id": "character",
                        "effect_ids": [],
                    }
                ],
                "protocol": {"states": ["ready"], "initial_state": "ready"},
            }
            identity = {
                "dll": "msvcrt.dll",
                "symbol": "strrchr",
                "ordinal": None,
            }
            contract_id = "fixture-strrchr-contract"
            contract_row = {
                "import_kind": "ordinary",
                "identity": identity,
                "descriptor_index": 0,
                "cell_index": 0,
                "iat_rva": 0x2000,
                "contract": {
                    "profile_id": "pe32-msvcrt-lockstep-v1",
                    "profile_sha256": SHA,
                    "entry_key": "strrchr",
                    "entry_index": 0,
                    "payload": {
                        "id": contract_id,
                        "abi_template": "pe32-cdecl-v1",
                        "argument_words": 2,
                        "memory_effect": "readOnly",
                        "world_effect": "none",
                        "result_register_relations": [
                            {"register": "eax", "relation": "related_word"}
                        ],
                        "memory_footprints": [],
                        "out_pointer_relations": [],
                        "out_interface_relations": [],
                    },
                },
                "boundary": {"fixture": True},
            }
            environment = _resolved_environment(contract_row)
            binding = create_proof_kernel_machine_binding(
                id="external-reference",
                binary={
                    "pe_sha256": "a" * 64,
                    "machine_ir_sha256": machine_sha256,
                },
                interface={
                    "id": "external_reference",
                    "sha256": canonical_sha256_v3(interface),
                },
                unit_ids=[unit_id],
                operations=[
                    {
                        "operation_id": "select",
                        "entry_unit_ids": [unit_id],
                        "exit_unit_ids": [unit_id],
                        "parameters": [
                            {
                                "id": "input",
                                "projection": {
                                    "kind": "view",
                                    "base": {
                                        "kind": "register",
                                        "register": "ebx",
                                        "width": 32,
                                        "at": "entry",
                                    },
                                    "extent": {"kind": "origin_remainder"},
                                    "requested_extent": {
                                        "kind": "constant",
                                        "value": 1,
                                        "width": 32,
                                    },
                                    "authority": {
                                        "id": "input_string",
                                        "kind": "external",
                                        "lifetime": "invocation",
                                    },
                                    "at": "entry",
                                },
                            }
                        ],
                        "results": [],
                        "state": [],
                        "preserved_state_ids": [],
                        "effects": [],
                        "callback_operation_ids": [],
                        "continuation_unit_ids": [],
                    }
                ],
                services=[
                    {
                        "service_id": "find",
                        "provider": {
                            "kind": "external_call",
                            "events": [
                                {"unit_id": unit_id, "event_index": event_index}
                                for event_index in range(2)
                            ],
                            "identity": identity,
                            "result_projection": _reference_projection(),
                        },
                        "mediation": "direct",
                    }
                ],
            )
            semantic = build_proof_kernel_semantic_contract(
                interface=interface,
                binding=binding,
                machine_ir=machine,
                machine_ir_manifest=manifest,
                resolved_external_environment=environment,
            )

        self.assertEqual(semantic["status"], "satisfied", semantic["issues"])
        provider = semantic["services"][0]["provider"]
        self.assertEqual(
            provider["call_boundary"],
            {
                "contract_id": contract_id,
                "abi_template": "pe32-cdecl-v1",
                "preserved_registers": ["ebp", "ebx", "edi", "esi"],
                "stack_pointer_adjustment": 0,
            },
        )
        self.assertEqual(provider["events"][0]["result"], _reference_projection())
        self.assertEqual(
            [event["event_index"] for event in provider["events"]],
            [0, 1],
        )
        self.assertEqual(
            provider["events"][0]["arguments"],
            [
                {
                    "op": "load",
                    "address": {"op": "reg", "name": "esp", "width": 32},
                    "width": 4,
                },
                {
                    "op": "load",
                    "address": {
                        "op": "add32",
                        "args": [
                            {"op": "reg", "name": "esp", "width": 32},
                            {"op": "const", "value": 4, "width": 32},
                        ],
                    },
                    "width": 4,
                },
            ],
        )
        bound = next(
            iter(service_event_index(semantic["services"], {"find": {}}).values())
        )
        self.assertEqual(bound.preserved_registers, ("ebp", "ebx", "edi", "esi"))
        self.assertEqual(bound.stack_pointer_adjustment, 0)
        self.assertEqual(bound.result.kind, "reference")

    def test_interface_method_uses_checked_external_service_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unit_id = "unit:interface-call"
            receiver_argument = {
                "op": "load",
                "width": 4,
                "address": {"op": "reg", "name": "esp", "width": 32},
            }
            event = {
                "kind": "indirect_call",
                "dll": None,
                "symbol": None,
                "ordinal": None,
                "instruction_rva": 0x1104,
                "return_rva": 0x1108,
                "target_rva": 0,
                "target": {
                    "op": "load",
                    "address": {
                        "op": "add32",
                        "args": [
                            {
                                "op": "load",
                                "address": receiver_argument,
                                "width": 4,
                            },
                            {"op": "const", "value": 80, "width": 32},
                        ],
                    },
                    "width": 4,
                },
                "register_inputs": {
                    register: {"op": "reg", "name": register, "width": 32}
                    for register in (
                        "eax",
                        "ebx",
                        "ecx",
                        "edx",
                        "esi",
                        "edi",
                        "ebp",
                        "esp",
                    )
                },
                "stack_inputs": [
                    {
                        "offset": 0,
                        "width": 4,
                        "value": receiver_argument,
                    }
                ],
                "arguments": [
                    receiver_argument,
                    {"op": "const", "value": 1, "width": 32},
                    {"op": "const", "value": 2, "width": 32},
                ],
            }
            unit = {
                "format": "spaghetti-extractor-machine-ir-v3",
                "record_kind": "unit",
                "id": unit_id,
                "status": "qualified",
                "source": {
                    "original": {"rva_start": 0x1100, "rva_end": 0x1110},
                    "contract_sha256": "b" * 64,
                    "instruction_bytes_sha256": "c" * 64,
                },
                "semantics": {
                    "outcome": {"kind": "return"},
                    "external_events": [event],
                    "memory_events": [],
                    "register_writes": [],
                    "flag_writes": [],
                    "faults": [],
                },
            }
            machine = root / "machine-ir.jsonl"
            machine.write_text(
                json.dumps(unit, sort_keys=True) + "\n", encoding="ascii"
            )
            machine_sha256 = hashlib.sha256(machine.read_bytes()).hexdigest()
            manifest = root / "machine-ir-manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "format": "spaghetti-extractor-machine-ir-v3",
                        "binary": {"sha256": "a" * 64},
                        "artifacts": {"machine_ir": {"sha256": machine_sha256}},
                    }
                ),
                encoding="ascii",
            )
            interface = {
                "id": "interface_service",
                "types": [
                    {"id": "status", "kind": "scalar", "c_type": "uint32_t"},
                    {
                        "id": "receiver",
                        "kind": "resource",
                        "resource_kind": "interface_object",
                        "ownership": "borrowed",
                    },
                    {
                        "id": "window",
                        "kind": "resource",
                        "resource_kind": "window_handle",
                        "ownership": "borrowed",
                    },
                ],
                "state": [],
                "operations": [
                    {
                        "id": "run",
                        "kind": "operation",
                        "parameters": [],
                        "results": [],
                        "effect_ids": [],
                        "allowed_service_ids": ["set_level"],
                        "pre_states": ["ready"],
                        "post_states": ["ready"],
                    }
                ],
                "effects": [],
                "services": [
                    {
                        "id": "set_level",
                        "parameter_type_ids": ["receiver", "window", "status"],
                        "result_type_id": "status",
                        "effect_ids": [],
                    }
                ],
                "protocol": {"states": ["ready"], "initial_state": "ready"},
            }
            profile_sha256 = "7" * 64
            receiver = {
                "argument_index": 0,
                "dispatch_slot": 20,
                "lifecycle_effect": "preserve",
                "required_state": "live",
                "view_id": "IFixture",
            }
            method = {
                "abi": {
                    "callee_cleanup": True,
                    "clobbered_registers": ["eax", "ecx", "edx"],
                    "preserved_registers": ["ebp", "ebx", "edi", "esi"],
                    "template": "pe32-stdcall-v1",
                },
                "argument_words": 3,
                "callback_effect": "none",
                "external_protocol": {
                    "kind": "pe32-interface-method",
                    "profile_id": "fixture-profile",
                    "profile_sha256": profile_sha256,
                    "interface_id": "IFixture",
                    "method": "SetLevel",
                    "slot": 20,
                    "offset": 80,
                },
                "receiver_resource": receiver,
            }
            method_core = {
                "profile_id": "fixture-profile",
                "profile_sha256": profile_sha256,
                "interface_id": "IFixture",
                "method": method,
            }
            method_sha256 = canonical_sha256_v3(method_core)
            binding = create_proof_kernel_machine_binding(
                id="interface-service",
                binary={
                    "pe_sha256": "a" * 64,
                    "machine_ir_sha256": machine_sha256,
                },
                interface={
                    "id": "interface_service",
                    "sha256": canonical_sha256_v3(interface),
                },
                unit_ids=[unit_id],
                operations=[
                    {
                        "operation_id": "run",
                        "entry_unit_ids": [unit_id],
                        "exit_unit_ids": [unit_id],
                        "parameters": [],
                        "results": [],
                        "state": [],
                        "preserved_state_ids": [],
                        "effects": [],
                        "callback_operation_ids": [],
                        "continuation_unit_ids": [],
                    }
                ],
                services=[
                    {
                        "service_id": "set_level",
                        "provider": {
                            "kind": "interface_method",
                            "events": [
                                {
                                    "unit_id": unit_id,
                                    "event_index": 0,
                                }
                            ],
                            "method_contract_sha256": method_sha256,
                        },
                        "mediation": "direct",
                    }
                ],
            )
            environment = _resolved_environment(
                interface_catalogs=(
                    {
                        "profile_id": "fixture-profile",
                        "profile_sha256": profile_sha256,
                        "interface_id": "IFixture",
                        "methods": [method],
                    },
                )
            )
            semantic = build_proof_kernel_semantic_contract(
                interface=interface,
                binding=binding,
                machine_ir=machine,
                machine_ir_manifest=manifest,
                resolved_external_environment=environment,
            )

        self.assertEqual(semantic["status"], "satisfied", semantic["issues"])
        provider = semantic["services"][0]["provider"]
        self.assertEqual(provider["kind"], "checked_external_call_events")
        self.assertEqual(provider["call_boundary"]["stack_pointer_adjustment"], 12)
        self.assertEqual(
            provider["events"][0]["identity"]["method_contract_sha256"],
            method_sha256,
        )
        self.assertEqual(
            provider["events"][0]["identity"]["receiver_resource"], receiver
        )
        bound = next(
            iter(service_event_index(semantic["services"], {"set_level": {}}).values())
        )
        self.assertEqual(bound.preserved_registers, ("ebp", "ebx", "edi", "esi"))
        self.assertEqual(bound.stack_pointer_adjustment, 12)
        self.assertEqual(bound.result.kind, "register")
        self.assertEqual(len(bound.physical_argument_expressions), 3)
        self.assertEqual(len(bound.argument_guards), 4)
        released = json.loads(json.dumps(semantic["services"]))
        released[0]["provider"]["events"][0]["identity"]["receiver_resource"][
            "required_state"
        ] = "released"
        with self.assertRaisesRegex(ValueError, "interface receiver is not live"):
            service_event_index(released, {"set_level": {}})
