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


class SemanticExternalServiceTests(unittest.TestCase):
    def _factory_refinement_fixture(self, root: Path) -> dict[str, Path]:
        relation = {
            "argument_index": 1,
            "interface_id": "IFixture",
            "nullable": False,
            "object_size": 4,
            "success_condition": "hresult_succeeded_eax",
            "vtable_size": 12,
            "write_width": 4,
        }
        relation_sha256 = canonical_sha256_v3(relation)
        interface = {
            "id": "factory_refinement",
            "types": [
                {"id": "status", "kind": "scalar", "c_type": "int32_t"},
                {
                    "id": "fixture",
                    "kind": "resource",
                    "resource_kind": "fixture_object",
                    "ownership": "borrowed",
                },
                {
                    "id": "fixture_cell",
                    "kind": "resource_cell",
                    "resource_kind": "fixture_object",
                    "ownership": "borrowed",
                    "access": "write",
                },
            ],
            "state": [],
            "operations": [
                {
                    "id": "run",
                    "kind": "operation",
                    "parameters": [],
                    "results": [
                        {"id": "status", "type_id": "status"},
                        {"id": "created", "type_id": "fixture"},
                    ],
                    "effect_ids": [],
                    "allowed_service_ids": ["create"],
                    "pre_states": ["ready"],
                    "post_states": ["ready"],
                }
            ],
            "effects": [],
            "services": [
                {
                    "id": "create",
                    "parameter_type_ids": ["fixture_cell"],
                    "result_type_id": "status",
                    "effect_ids": [],
                }
            ],
            "protocol": {"states": ["ready"], "initial_state": "ready"},
        }
        interface_path = root / "interface.json"
        interface_path.write_text(json.dumps(interface), encoding="ascii")

        call_esp = {
            "op": "sub32",
            "args": [
                {"op": "reg", "name": "esp", "width": 32},
                {"op": "const", "value": 16, "width": 32},
            ],
        }

        def stack_address(index: int) -> dict[str, object]:
            address = json.loads(json.dumps(call_esp))
            if index:
                return {
                    "op": "add32",
                    "args": [
                        address,
                        {"op": "const", "value": index * 4, "width": 32},
                    ],
                }
            return address

        def stack_load(index: int) -> dict[str, object]:
            return {"op": "load", "address": stack_address(index), "width": 4}

        event = {
            "kind": "external_call",
            "dll": "fixture.dll",
            "symbol": "CreateFixture",
            "ordinal": None,
            "instruction_rva": 0x1004,
            "return_rva": 0x1009,
            "target_rva": 0,
            "register_inputs": {
                register: (
                    json.loads(json.dumps(call_esp))
                    if register == "esp"
                    else {"op": "reg", "name": register, "width": 32}
                )
                for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
            },
            "stack_inputs": [
                {"offset": index * 4, "width": 4, "value": stack_load(index)}
                for index in range(1)
            ],
        }
        writes = [
            {
                "kind": "write",
                "width": 4,
                "address": stack_address(index),
                "value": (
                    stack_address(3)
                    if index == 1
                    else {"op": "const", "value": 0, "width": 32}
                ),
            }
            for index in range(3)
        ]
        writes.append(
            {
                "kind": "write",
                "width": 4,
                "address": stack_address(3),
                "value": {"op": "const", "value": 0, "width": 32},
            }
        )
        unit = {
            "format": "spaghetti-extractor-machine-ir-v3",
            "record_kind": "unit",
            "id": "unit:factory",
            "status": "qualified",
            "source": {
                "contract_sha256": "b" * 64,
                "instruction_bytes_sha256": "c" * 64,
                "original": {"rva_start": 0x1000, "rva_end": 0x1010},
            },
            "semantics": {
                "outcome": {"kind": "return"},
                "edge_conditions": [],
                "memory_events": writes,
                "external_events": [event],
                "ordered_events": [
                    *({"family": "memory", **write} for write in writes),
                    {"family": "external"},
                ],
                "faults": [],
                "register_writes": [
                    {
                        "register": "eax",
                        "value": {
                            "op": "call_response",
                            "call_index": 0,
                            "register": "eax",
                            "width": 32,
                        },
                    }
                ],
                "flag_writes": [],
            },
        }
        machine_path = root / "machine-ir.jsonl"
        machine_path.write_text(
            json.dumps(unit, sort_keys=True) + "\n", encoding="ascii"
        )
        machine_sha256 = hashlib.sha256(machine_path.read_bytes()).hexdigest()
        manifest_path = root / "machine-ir-manifest.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "format": "spaghetti-extractor-machine-ir-v3",
                    "binary": {"sha256": "a" * 64},
                    "artifacts": {"machine_ir": {"sha256": machine_sha256}},
                }
            ),
            encoding="ascii",
        )
        identity = {
            "dll": "fixture.dll",
            "symbol": "CreateFixture",
            "ordinal": None,
        }
        binding = create_proof_kernel_machine_binding(
            id="factory-refinement-component",
            binary={"pe_sha256": "a" * 64, "machine_ir_sha256": machine_sha256},
            interface={
                "id": "factory_refinement",
                "sha256": canonical_sha256_v3(interface),
            },
            unit_ids=["unit:factory"],
            operations=[
                {
                    "operation_id": "run",
                    "entry_unit_ids": ["unit:factory"],
                    "exit_unit_ids": ["unit:factory"],
                    "parameters": [],
                    "results": [
                        {
                            "id": "created",
                            "projection": {
                                "kind": "resource",
                                "resource_kind": "fixture_object",
                                "source": {
                                    "kind": "stack",
                                    "offset": -4,
                                    "width": 32,
                                    "at": "exit",
                                },
                            },
                        },
                        {
                            "id": "status",
                            "projection": {
                                "kind": "register",
                                "register": "eax",
                                "width": 32,
                                "at": "exit",
                            },
                        },
                    ],
                    "state": [],
                    "preserved_state_ids": [],
                    "effects": [],
                    "callback_operation_ids": [],
                    "continuation_unit_ids": [],
                }
            ],
            services=[
                {
                    "service_id": "create",
                    "mediation": "direct",
                    "provider": {
                        "kind": "external_call",
                        "events": [
                            {
                                "unit_id": "unit:factory",
                                "event_index": 0,
                            }
                        ],
                        "identity": identity,
                        "argument_transducers": [
                            {"kind": "constant", "value": 0},
                            {
                                "kind": "out_interface",
                                "parameter_index": 0,
                                "out_interface_relation_sha256": relation_sha256,
                            },
                            {"kind": "constant", "value": 0},
                        ],
                    },
                }
            ],
        )
        binding_path = root / "binding.json"
        binding_path.write_text(json.dumps(binding), encoding="ascii")
        external_contract = {
            "import_kind": "ordinary",
            "identity": identity,
            "descriptor_index": 0,
            "cell_index": 0,
            "iat_rva": 0x2000,
            "contract": {
                "profile_id": "fixture-profile",
                "profile_sha256": "7" * 64,
                "entry_key": "fixture-entry",
                "entry_index": 0,
                "payload": {
                    "id": "fixture-contract",
                    "abi_template": "pe32-stdcall-v1",
                    "argument_words": 3,
                    "memory_effect": "argumentRanges",
                    "world_effect": "opaqueResources",
                    "out_interface_relations": [relation],
                    "result_register_relations": [
                        {"register": "eax", "relation": "exact"},
                    ],
                },
            },
            "boundary": {"fixture": True},
        }
        resolved = _resolved_environment(external_contract)
        contract_path = root / "semantic-contract.json"
        contract_path.write_text(
            json.dumps(
                build_proof_kernel_semantic_contract(
                    interface=interface_path,
                    binding=binding_path,
                    machine_ir=machine_path,
                    machine_ir_manifest=manifest_path,
                    resolved_external_environment=resolved,
                )
            ),
            encoding="ascii",
        )
        source_file = root / "factory-refinement.c"
        source_file.write_text(
            '#include "portable-component-implementation.h"\n\n'
            "spx_factory_refinement_run_result_v2 component_factory_run(\n"
            "    spx_factory_refinement_context_v2 *context) {\n"
            "  spx_factory_refinement_run_result_v2 result = {0};\n"
            "  result.status = context->services->create(\n"
            "      context->services->context, &result.created);\n"
            "  return result;\n"
            "}\n",
            encoding="ascii",
        )
        source_package = root / "source-package"
        build_component_source_package(
            lift_unit_id="factory-refinement-component",
            files={"factory-refinement.c": source_file},
            shared_inputs={},
            operation_symbols={"run": "component_factory_run"},
            out_dir=source_package,
        )
        profile_path = root / "source-profile.json"
        profile_path.write_text(
            json.dumps(check_component_source_profile(package=source_package)),
            encoding="ascii",
        )
        return {
            "contract": contract_path,
            "interface": interface_path,
            "source": source_package,
            "profile": profile_path,
        }

    def test_hresult_out_interface_transducer_is_contract_derived_and_total(
        self,
    ) -> None:
        relation = {
            "argument_index": 1,
            "interface_id": "IFixture",
            "nullable": False,
            "object_size": 4,
            "success_condition": "hresult_succeeded_eax",
            "vtable_size": 12,
            "write_width": 4,
        }
        relation_sha256 = canonical_sha256_v3(relation)
        arguments = [
            {
                "op": "load",
                "address": (
                    {"op": "reg", "name": "esp", "width": 32}
                    if index == 0
                    else {
                        "op": "add32",
                        "args": [
                            {"op": "reg", "name": "esp", "width": 32},
                            {"op": "const", "value": index * 4, "width": 32},
                        ],
                    }
                ),
                "width": 4,
            }
            for index in range(3)
        ]
        transducers = [
            {"kind": "constant", "value": 0},
            {
                "kind": "out_interface",
                "parameter_index": 0,
                "out_interface_relation_sha256": relation_sha256,
            },
            {"kind": "constant", "value": 0},
        ]
        logical = SimpleNamespace(parameter_type_ids=("directdraw.cell",))
        logical_types = {
            "directdraw.cell": ProofKernelLogicalType(
                "directdraw.cell",
                "resource_cell",
                access="write",
                resource_kind="directdraw_object",
                ownership="borrowed",
            )
        }
        logical_arguments, physical, guards, writebacks = (
            _checked_external_argument_transducers(
                transducers,
                logical=logical,
                logical_types=logical_types,
                contract={"profile_sha256": "7" * 64},
                contract_payload={"out_interface_relations": [relation]},
                contract_arguments=arguments,
            )
        )
        self.assertEqual(logical_arguments, [{"op": "const", "value": 0, "width": 64}])
        self.assertEqual([row["index"] for row in physical], [0, 1, 2])
        self.assertEqual(len(guards), 3)
        self.assertEqual(writebacks[0]["parameter_index"], 0)
        self.assertEqual(writebacks[0]["interface_id"], "IFixture")
        self.assertEqual(
            writebacks[0]["projection"]["source"]["address"],
            {"kind": "stack", "offset": 4, "width": 32, "at": "call"},
        )
        with self.assertRaisesRegex(
            ComponentSemanticContractError, "checked relation position"
        ):
            _checked_external_argument_transducers(
                [
                    transducers[0],
                    transducers[2],
                    transducers[1],
                ],
                logical=logical,
                logical_types=logical_types,
                contract={"profile_sha256": "7" * 64},
                contract_payload={"out_interface_relations": [relation]},
                contract_arguments=arguments,
            )

    def test_finite_word_map_decodes_machine_words_and_rejects_other_values(
        self,
    ) -> None:
        machine_argument = {
            "op": "load",
            "address": {"op": "reg", "name": "esp", "width": 32},
            "width": 4,
        }
        transducer = {
            "kind": "finite_word_map",
            "parameter_index": 0,
            "cases": [
                {"logical_value": 1, "physical_value": 0x401000},
                {"logical_value": 2, "physical_value": 0x402000},
            ],
        }
        logical_arguments, physical, guards, writebacks = (
            _checked_external_argument_transducers(
                [transducer],
                logical=SimpleNamespace(parameter_type_ids=("message_kind",)),
                logical_types={
                    "message_kind": ProofKernelLogicalType(
                        "message_kind", "enum", c_type="uint32_t"
                    )
                },
                contract={"profile_sha256": "7" * 64},
                contract_payload={},
                contract_arguments=[machine_argument],
            )
        )
        self.assertEqual(physical[0]["transducer"], transducer)
        self.assertEqual(writebacks, [])
        self.assertEqual(
            logical_arguments,
            [
                {
                    "op": "ite",
                    "args": [
                        {
                            "op": "eq",
                            "args": [
                                machine_argument,
                                {"op": "const", "value": 0x401000, "width": 32},
                            ],
                        },
                        {"op": "const", "value": 1, "width": 32},
                        {"op": "const", "value": 2, "width": 32},
                    ],
                }
            ],
        )
        self.assertEqual(guards[0]["op"], "or")
        self.assertEqual(
            [item["args"][1]["value"] for item in guards[0]["args"]],
            [0x401000, 0x402000],
        )

    def test_hresult_out_interface_writeback_enters_one_semantic_path(self) -> None:
        relation = {
            "argument_index": 1,
            "interface_id": "IFixture",
            "nullable": False,
            "object_size": 4,
            "success_condition": "hresult_succeeded_eax",
            "vtable_size": 12,
            "write_width": 4,
        }
        relation_sha256 = canonical_sha256_v3(relation)
        logical = SimpleNamespace(parameter_type_ids=("fixture_cell",))
        logical_types = {
            "fixture_cell": ProofKernelLogicalType(
                "fixture_cell",
                "resource_cell",
                access="write",
                resource_kind="fixture_object",
                ownership="borrowed",
            )
        }

        call_esp: dict[str, object] = {
            "op": "sub32",
            "args": [
                {"op": "reg", "name": "esp", "width": 32},
                {"op": "const", "value": 16, "width": 32},
            ],
        }

        def stack_address(index: int) -> dict[str, object]:
            address = json.loads(json.dumps(call_esp))
            if index:
                address = {
                    "op": "add32",
                    "args": [
                        address,
                        {"op": "const", "value": index * 4, "width": 32},
                    ],
                }
            return address

        def stack_load(index: int) -> dict[str, object]:
            return {"op": "load", "address": stack_address(index), "width": 4}

        def physical_stack_load(index: int) -> dict[str, object]:
            address: dict[str, object] = {
                "op": "reg",
                "name": "esp",
                "width": 32,
            }
            if index:
                address = {
                    "op": "add32",
                    "args": [
                        address,
                        {"op": "const", "value": index * 4, "width": 32},
                    ],
                }
            return {"op": "load", "address": address, "width": 4}

        machine_arguments = [physical_stack_load(index) for index in range(3)]
        transducers = [
            {"kind": "constant", "value": 0},
            {
                "kind": "out_interface",
                "parameter_index": 0,
                "out_interface_relation_sha256": relation_sha256,
            },
            {"kind": "constant", "value": 0},
        ]
        logical_arguments, physical, guards, writebacks = (
            _checked_external_argument_transducers(
                transducers,
                logical=logical,
                logical_types=logical_types,
                contract={"profile_sha256": "7" * 64},
                contract_payload={"out_interface_relations": [relation]},
                contract_arguments=machine_arguments,
            )
        )
        event = {
            "kind": "external_call",
            "dll": "fixture.dll",
            "symbol": "CreateFixture",
            "ordinal": None,
            "instruction_rva": 0x1004,
            "return_rva": 0x1009,
            "target_rva": 0,
            "register_inputs": {
                register: (
                    json.loads(json.dumps(call_esp))
                    if register == "esp"
                    else {"op": "reg", "name": register, "width": 32}
                )
                for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
            },
            "stack_inputs": [
                {"offset": index * 4, "width": 4, "value": stack_load(index)}
                for index in range(3)
            ],
        }
        writes = [
            {
                "kind": "write",
                "width": 4,
                "address": stack_address(index),
                "value": (
                    stack_address(3)
                    if index == 1
                    else {"op": "const", "value": 0, "width": 32}
                ),
            }
            for index in range(3)
        ]
        writes.append(
            {
                "kind": "write",
                "width": 4,
                "address": stack_address(3),
                "value": {"op": "const", "value": 0, "width": 32},
            }
        )
        interface = ProofKernelComponentInterface.parse(
            {
                "id": "factory_path",
                "types": [
                    {"id": "status", "kind": "scalar", "c_type": "int32_t"},
                    {
                        "id": "fixture",
                        "kind": "resource",
                        "resource_kind": "fixture_object",
                        "ownership": "borrowed",
                    },
                    {
                        "id": "fixture_cell",
                        "kind": "resource_cell",
                        "resource_kind": "fixture_object",
                        "ownership": "borrowed",
                        "access": "write",
                    },
                ],
                "state": [],
                "operations": [
                    {
                        "id": "run",
                        "kind": "operation",
                        "parameters": [],
                        "results": [
                            {"id": "status", "type_id": "status"},
                            {"id": "created", "type_id": "fixture"},
                        ],
                        "effect_ids": [],
                        "allowed_service_ids": ["create"],
                        "pre_states": ["ready"],
                        "post_states": ["ready"],
                    }
                ],
                "effects": [],
                "services": [
                    {
                        "id": "create",
                        "parameter_type_ids": ["fixture_cell"],
                        "result_type_id": "status",
                        "effect_ids": [],
                    }
                ],
                "protocol": {"states": ["ready"], "initial_state": "ready"},
            }
        )
        services = [
            {
                "service_id": "create",
                "mediation": "direct",
                "provider": {
                    "kind": "checked_external_call_events",
                    "call_boundary": {
                        "contract_id": "fixture-factory",
                        "abi_template": "pe32-stdcall-v1",
                        "preserved_registers": ["ebp", "ebx", "edi", "esi"],
                        "stack_pointer_adjustment": 12,
                    },
                    "events": [
                        {
                            "unit_id": "unit:factory",
                            "event_index": 0,
                            "event_sha256": canonical_sha256_v3(event),
                            "identity": {
                                "dll": "fixture.dll",
                                "symbol": "CreateFixture",
                                "ordinal": None,
                            },
                            "arguments": logical_arguments,
                            "physical_arguments": physical,
                            "argument_guards": guards,
                            "writebacks": writebacks,
                            "result": {
                                "kind": "register",
                                "register": "eax",
                                "width": 32,
                                "at": "call",
                            },
                        }
                    ],
                },
            }
        ]
        operation = {
            "operation_id": "run",
            "entry_unit_ids": ["unit:factory"],
            "exit_unit_ids": ["unit:factory"],
            "parameters": [],
            "results": [
                {
                    "id": "status",
                    "projection": {
                        "kind": "register",
                        "register": "eax",
                        "width": 32,
                        "at": "exit",
                    },
                },
                {
                    "id": "created",
                    "projection": {
                        "kind": "resource",
                        "resource_kind": "fixture_object",
                        "source": {
                            "kind": "stack",
                            "offset": -4,
                            "width": 32,
                            "at": "exit",
                        },
                    },
                },
            ],
            "state": [],
            "preserved_state_ids": [],
            "effects": [],
            "callback_operation_ids": [],
            "continuation_unit_ids": [],
            "units": [
                {
                    "id": "unit:factory",
                    "source": {"original": {"rva_start": 0x1000, "rva_end": 0x1010}},
                    "semantics": {
                        "outcome": {"kind": "return"},
                        "edge_conditions": [],
                        "memory_events": writes,
                        "external_events": [event],
                        "ordered_events": [
                            *({"family": "memory", **write} for write in writes),
                            {"family": "external"},
                        ],
                        "faults": [],
                        "register_writes": [
                            {
                                "register": "eax",
                                "value": {
                                    "op": "call_response",
                                    "call_index": 0,
                                    "register": "eax",
                                    "width": 32,
                                },
                            }
                        ],
                        "flag_writes": [],
                    },
                }
            ],
        }
        model = build_operation_path_model(operation, interface, services)
        path = model["paths"][0]
        self.assertEqual(
            path["trace"][0]["arguments"],
            [{"op": "const", "value": 0, "width": 64}],
        )
        self.assertEqual(path["results"]["status"]["op"], "service_result")
        self.assertEqual(path["results"]["created"]["op"], "ite")
        self.assertEqual(
            path["results"]["created"]["args"][1]["op"],
            "service_writeback",
        )

    def test_cbmc_proves_hresult_out_interface_transaction(self) -> None:
        cbmc = shutil.which("cbmc")
        if cbmc is None:
            self.skipTest("CBMC is required for the out-interface vertical")
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._factory_refinement_fixture(Path(temporary))
            result = check_component_refinement(
                semantic_contract=paths["contract"],
                interface=paths["interface"],
                source_package=paths["source"],
                source_profile=paths["profile"],
                cbmc=cbmc,
                timeout_seconds=60,
            )
        self.assertEqual(result["status"], "satisfied", result["issues"])
        self.assertTrue(result["activation_authorized"])

    def test_checked_nonzero_search_result_preserves_one_following_byte(self) -> None:
        site = "service:find:unit:0"

        def logical(direction: str, port: str) -> dict[str, object]:
            return {
                "op": "logical",
                "sort": {"kind": "reference"},
                "args": [],
                "attributes": {
                    "path": {
                        "root": "interaction",
                        "id": site,
                        "fields": [direction, port],
                    }
                },
            }

        result = logical("output", "result")
        needle = logical("input", "argument.1")

        def constant(value: int, width: int) -> dict[str, object]:
            return {
                "op": "const",
                "sort": {"kind": "bitvector", "width": width},
                "args": [],
                "attributes": {"value": value},
            }

        ensures = [
            {
                "op": "or",
                "sort": {"kind": "bool"},
                "attributes": {},
                "args": [
                    {
                        "op": "ref_is_null",
                        "sort": {"kind": "bool"},
                        "attributes": {},
                        "args": [result],
                    },
                    {
                        "op": "or",
                        "sort": {"kind": "bool"},
                        "attributes": {},
                        "args": [
                            {
                                "op": "eq",
                                "sort": {"kind": "bool"},
                                "attributes": {},
                                "args": [needle, constant(0, 8)],
                            },
                            {
                                "op": "ult",
                                "sort": {"kind": "bool"},
                                "attributes": {},
                                "args": [
                                    constant(1, 64),
                                    {
                                        "op": "ref_remaining",
                                        "sort": {"kind": "bitvector", "width": 64},
                                        "attributes": {},
                                        "args": [result],
                                    },
                                ],
                            },
                        ],
                    },
                ],
            }
        ]
        self.assertEqual(_nonnull_minimum_remaining(ensures, site), (1, 2))

    def test_checked_result_adapter_only_wraps_authorized_register(self) -> None:
        projection = _reference_projection()
        self.assertEqual(
            _checked_external_result_projection(
                projection,
                logical_kind="reference",
                machine_register="eax",
            ),
            projection,
        )
        with self.assertRaisesRegex(
            ComponentSemanticContractError, "disagrees with its ABI contract"
        ):
            _checked_external_result_projection(
                _reference_projection("edx"),
                logical_kind="reference",
                machine_register="eax",
            )




if __name__ == "__main__":
    unittest.main()
