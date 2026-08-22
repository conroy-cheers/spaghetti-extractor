from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.machine_binding import (
    ComponentMachineBindingV1,
    MachineProjectionV1,
    create_component_machine_binding_v1,
)
from spaghetti_extractor.components.interface_ir import PortableComponentInterfaceV2
from spaghetti_extractor.components.refinement import check_component_refinement
from spaghetti_extractor.components.semantic_contract import (
    ComponentSemanticContractError,
    ComponentSemanticContractV1,
    build_component_semantic_contract,
)
from spaghetti_extractor.components.semantic_paths import (
    SemanticPathError,
    SemanticPathViolation,
    _expression_key,
    _read_call_projection,
    build_operation_path_model,
)
from spaghetti_extractor.components.runtime_paths import render_finite_path_operation
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.components.source_profile import (
    check_component_source_profile,
)


def _interface() -> dict[str, object]:
    return {
        "format": "spaghetti-extractor-component-interface-ir-v2",
        "id": "increment",
        "types": [{"id": "u32", "kind": "scalar", "c_type": "uint32_t"}],
        "state": [],
        "operations": [{
            "id": "run", "kind": "operation",
            "parameters": [{"id": "value", "type_id": "u32"}],
            "results": [{"id": "result", "type_id": "u32"}],
            "effect_ids": [], "allowed_service_ids": [],
            "pre_states": ["ready"], "post_states": ["ready"],
        }],
        "effects": [], "services": [],
        "protocol": {"states": ["ready"], "initial_state": "ready"},
    }


class SemanticRefinementTests(unittest.TestCase):
    def test_call_projection_reads_argument_prepared_by_prior_unit(self) -> None:
        projection = MachineProjectionV1.parse({
            "kind": "stack", "offset": 4, "width": 32, "at": "call",
        })
        entry_esp = {"op": "symbol", "name": "machine_esp", "width": 32}
        address = {
            "op": "add32",
            "args": [
                entry_esp,
                {"op": "const", "value": 4, "width": 32},
            ],
        }
        expected = {"op": "const", "value": 47, "width": 32}
        observed = _read_call_projection(
            projection,
            {
                "register_inputs": {
                    "esp": {"op": "reg", "name": "esp", "width": 32}
                },
                "stack_inputs": [],
            },
            {"esp": entry_esp},
            {},
            {_expression_key(address): expected},
            {},
        )
        self.assertEqual(observed, expected)

    def test_finite_control_target_becomes_checked_route_paths(self) -> None:
        interface = PortableComponentInterfaceV2.parse({
            "format": "spaghetti-extractor-component-interface-ir-v2",
            "id": "selector_dispatch",
            "types": [
                {"id": "selector", "kind": "scalar", "c_type": "uint8_t"},
                {"id": "route", "kind": "enum", "c_type": "uint32_t"},
            ],
            "state": [],
            "operations": [{
                "id": "select", "kind": "operation",
                "parameters": [{"id": "selector", "type_id": "selector"}],
                "results": [{"id": "route", "type_id": "route"}],
                "effect_ids": [], "allowed_service_ids": [],
                "pre_states": ["ready"], "post_states": ["ready"],
            }],
            "effects": [], "services": [],
            "protocol": {"states": ["ready"], "initial_state": "ready"},
        })
        address = {
            "op": "add32",
            "args": [
                {"op": "const", "value": 0x402000, "width": 32},
                {"op": "mul32", "args": [
                    {"op": "and32", "args": [
                        {"op": "const", "value": 0xff, "width": 32},
                        {"op": "reg", "name": "eax", "width": 32},
                    ]},
                    {"op": "const", "value": 4, "width": 32},
                ]},
            ],
        }
        unit = {
            "id": "unit:dispatch", "status": "qualified",
            "source": {"original": {"rva_start": 0x1000, "rva_end": 0x100a}},
            "semantics": {
                "outcome": {"kind": "indirect_jump", "target": {
                    "op": "load", "width": 4, "address": address,
                }},
                "memory_events": [{"kind": "read", "width": 4, "address": address}],
                "external_events": [], "faults": [], "flag_writes": [],
                "register_writes": [{"register": "edx", "value": {
                    "op": "and32", "args": [
                        {"op": "const", "value": 0xff, "width": 32},
                        {"op": "reg", "name": "eax", "width": 32},
                    ],
                }}],
            },
        }
        operation = {
            "operation_id": "select",
            "entry_unit_ids": ["unit:dispatch"],
            "exit_unit_ids": ["unit:dispatch"],
            "parameters": [{"id": "selector", "projection": {
                "kind": "register", "register": "eax", "width": 8,
                "at": "entry",
            }}],
            "results": [{"id": "route", "projection": {
                "kind": "finite_control_target", "at": "exit",
                "unit_id": "unit:dispatch",
                "selector_parameter_id": "selector",
                "target_inventory_sha256": "d" * 64,
                "routes": [
                    {"selector_value": 0, "logical_value": 7,
                     "target_rva": 0x1100, "target_address": 0x401100},
                    {"selector_value": 1, "logical_value": 9,
                     "target_rva": 0x1200, "target_address": 0x401200},
                ],
            }}],
            "state": [], "preserved_state_ids": [], "effects": [],
            "callback_operation_ids": [], "continuation_unit_ids": [],
            "units": [unit],
        }

        model = build_operation_path_model(operation, interface, [])

        self.assertEqual(len(model["entry_preconditions"]), 2)
        routes = {
            path["guards"][-1]["args"][1]["value"]: (
                path["results"]["route"]["value"],
                path["completion"]["outcome"]["target"]["value"],
            )
            for path in model["paths"]
        }
        self.assertEqual(routes, {0: (7, 0x401100), 1: (9, 0x401200)})
        binding = ComponentMachineBindingV1.parse(create_component_machine_binding_v1(
            id="selector-dispatch",
            binary={"pe_sha256": "a" * 64, "machine_ir_sha256": "b" * 64},
            interface={"id": interface.identity, "sha256": interface.sha256},
            unit_ids=["unit:dispatch"],
            operations=[{key: value for key, value in operation.items() if key != "units"}],
            services=[],
        )).operations[0]
        rendered = render_finite_path_operation(
            interface=interface,
            operation=interface.operations[0],
            binding=binding,
            service_bindings=[],
            source_symbol="component_select",
            adapter_symbol="component_select_adapter",
            model=model,
        )
        self.assertIn("SPX_INDIRECT_JUMP", rendered)
        self.assertIn("UINT32_C(4198656)", rendered)
        self.assertIn("UINT32_C(4198912)", rendered)

    def _fixture(
        self,
        root: Path,
        expression: str = "value + UINT32_C(1)",
        *,
        parameter_c_type: str = "uint32_t",
        machine_expression: dict[str, object] | None = None,
    ) -> dict[str, Path]:
        interface = _interface()
        if parameter_c_type != "uint32_t":
            interface["types"].append({
                "id": "input", "kind": "scalar", "c_type": parameter_c_type,
            })
            interface["operations"][0]["parameters"][0]["type_id"] = "input"
        interface_path = root / "interface.json"
        interface_path.write_text(json.dumps(interface), encoding="ascii")
        unit = {
            "format": "spaghetti-extractor-machine-ir-v3",
            "record_kind": "unit", "id": "unit:increment", "status": "qualified",
            "source": {
                "contract_sha256": "b" * 64,
                "instruction_bytes_sha256": "c" * 64,
                "original": {"rva_start": 0x1000, "rva_end": 0x1010},
            },
            "semantics": {
                "outcome": {"kind": "return", "value": {
                    "op": "load", "width": 4,
                    "address": {"op": "reg", "name": "esp", "width": 32},
                }},
                "memory_events": [], "external_events": [], "faults": [],
                "register_writes": [{"register": "eax", "value": (
                    machine_expression if machine_expression is not None else {
                        "op": "add32", "args": [
                            {"op": "reg", "name": "ecx", "width": 32},
                            {"op": "const", "value": 1, "width": 32},
                        ],
                    }
                )}],
                "flag_writes": [],
            },
        }
        machine = root / "machine-ir.jsonl"
        machine.write_text(json.dumps(unit, sort_keys=True) + "\n", encoding="ascii")
        machine_sha256 = hashlib.sha256(machine.read_bytes()).hexdigest()
        manifest = root / "machine-ir-manifest.json"
        manifest.write_text(json.dumps({
            "format": "spaghetti-extractor-machine-ir-v3",
            "binary": {"sha256": "a" * 64},
            "artifacts": {"machine_ir": {"sha256": machine_sha256}},
        }), encoding="ascii")
        binding = create_component_machine_binding_v1(
            id="increment-component",
            binary={"pe_sha256": "a" * 64, "machine_ir_sha256": machine_sha256},
            interface={"id": "increment", "sha256": canonical_sha256_v3(interface)},
            unit_ids=["unit:increment"],
            operations=[{
                "operation_id": "run",
                "entry_unit_ids": ["unit:increment"],
                "exit_unit_ids": ["unit:increment"],
                "parameters": [{"id": "value", "projection": {
                    "kind": "register", "register": "ecx", "width": 32, "at": "entry",
                }}],
                "results": [{"id": "result", "projection": {
                    "kind": "register", "register": "eax", "width": 32, "at": "exit",
                }}],
                "state": [], "preserved_state_ids": [], "effects": [],
                "callback_operation_ids": [], "continuation_unit_ids": [],
            }],
            services=[],
        )
        binding_path = root / "binding.json"
        binding_path.write_text(json.dumps(binding), encoding="ascii")
        source_file = root / "increment.c"
        source_file.write_text(
            '#include "portable-component-implementation.h"\n\n'
            "uint32_t component_increment_run(\n"
            f"    spx_increment_context_v2 *context, {parameter_c_type} value) {{\n"
            "  (void)context;\n"
            f"  return {expression};\n"
            "}\n",
            encoding="ascii",
        )
        source_package = root / "source-package"
        build_component_source_package(
            lift_unit_id="increment-component", files={"increment.c": source_file},
            shared_inputs={}, operation_symbols={"run": "component_increment_run"},
            out_dir=source_package,
        )
        contract = build_component_semantic_contract(
            interface=interface_path, binding=binding_path, machine_ir=machine,
            machine_ir_manifest=manifest,
        )
        contract_path = root / "semantic-contract.json"
        contract_path.write_text(json.dumps(contract), encoding="ascii")
        profile = check_component_source_profile(package=source_package)
        profile_path = root / "source-profile.json"
        profile_path.write_text(json.dumps(profile), encoding="ascii")
        return {
            "interface": interface_path, "binding": binding_path,
            "machine": machine, "manifest": manifest, "contract": contract_path,
            "source": source_package, "profile": profile_path,
        }

    def _service_fixture(
        self,
        root: Path,
        *,
        argument: str = "value",
        failure: str = "service_result",
        byte_view: bool = False,
    ) -> dict[str, Path]:
        interface = {
            "format": "spaghetti-extractor-component-interface-ir-v2",
            "id": "service_branch",
            "types": [
                {"id": "u32", "kind": "scalar", "c_type": "uint32_t"},
                *([{
                    "id": "bytes", "kind": "bytes", "access": "read",
                    "extent_parameter_id": "value", "nul_terminated": False,
                }] if byte_view else []),
            ],
            "state": [],
            "operations": [{
                "id": "run", "kind": "operation",
                "parameters": ([{"id": "buffer", "type_id": "bytes"}]
                               if byte_view else [])
                + [{"id": "value", "type_id": "u32"}],
                "results": [{"id": "result", "type_id": "u32"}],
                "effect_ids": [], "allowed_service_ids": ["choose"],
                "pre_states": ["ready"], "post_states": ["ready"],
            }],
            "effects": [],
            "services": [{
                "id": "choose",
                "parameter_type_ids": (["bytes"] if byte_view else []) + ["u32"],
                "result_type_id": "u32", "effect_ids": [],
            }],
            "protocol": {"states": ["ready"], "initial_state": "ready"},
        }
        interface_path = root / "interface.json"
        interface_path.write_text(json.dumps(interface), encoding="ascii")
        response = {"op": "call_response", "call_index": 0, "register": "eax", "width": 32}
        event = {
            "kind": "external_call", "dll": "test.dll", "symbol": "choose",
            "instruction_rva": 0x1004, "return_rva": 0x1008,
            "target_rva": 0x3000,
            "register_inputs": {
                "ecx": {"op": "reg", "name": "ecx", "width": 32},
                **({"edx": {"op": "reg", "name": "edx", "width": 32}}
                   if byte_view else {}),
            },
            "flag_inputs": {},
            "arguments": [
                {"op": "reg", "name": "ecx", "width": 32},
                *([{"op": "reg", "name": "edx", "width": 32}]
                  if byte_view else []),
            ],
            "stack_inputs": [],
        }
        units = [
            {
                "format": "spaghetti-extractor-machine-ir-v3",
                "record_kind": "unit", "id": "unit:call", "status": "qualified",
                "source": {
                    "contract_sha256": "b" * 64,
                    "instruction_bytes_sha256": "c" * 64,
                    "original": {"rva_start": 0x1000, "rva_end": 0x1010},
                },
                "semantics": {
                    "outcome": {
                        "kind": "branch", "true_target_rva": 0x1010,
                        "false_target_rva": 0x1020,
                    },
                    "edge_conditions": [
                        {"target_rva": 0x1010, "condition": {
                            "op": "eq", "args": [response, {"op": "const", "value": 0, "width": 32}],
                        }},
                        {"target_rva": 0x1020, "condition": {
                            "op": "not", "args": [{
                                "op": "eq", "args": [response, {"op": "const", "value": 0, "width": 32}],
                            }],
                        }},
                    ],
                    "memory_events": [], "external_events": [event], "faults": [],
                    "register_writes": [{"register": "eax", "value": response}],
                    "flag_writes": [],
                },
            },
            {
                "format": "spaghetti-extractor-machine-ir-v3",
                "record_kind": "unit", "id": "unit:success", "status": "qualified",
                "source": {
                    "contract_sha256": "d" * 64,
                    "instruction_bytes_sha256": "e" * 64,
                    "original": {"rva_start": 0x1010, "rva_end": 0x1020},
                },
                "semantics": {
                    "outcome": {"kind": "return", "value": {
                        "op": "load", "width": 4,
                        "address": {"op": "reg", "name": "esp", "width": 32},
                    }}, "memory_events": [],
                    "external_events": [], "faults": [],
                    "register_writes": [{"register": "eax", "value": {
                        "op": "const", "value": 11, "width": 32,
                    }}],
                    "flag_writes": [],
                },
            },
            {
                "format": "spaghetti-extractor-machine-ir-v3",
                "record_kind": "unit", "id": "unit:failure", "status": "qualified",
                "source": {
                    "contract_sha256": "f" * 64,
                    "instruction_bytes_sha256": "1" * 64,
                    "original": {"rva_start": 0x1020, "rva_end": 0x1030},
                },
                "semantics": {
                    "outcome": {"kind": "return", "value": {
                        "op": "load", "width": 4,
                        "address": {"op": "reg", "name": "esp", "width": 32},
                    }}, "memory_events": [],
                    "external_events": [], "faults": [],
                    "register_writes": [], "flag_writes": [],
                },
            },
        ]
        machine = root / "machine-ir.jsonl"
        machine.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in units),
            encoding="ascii",
        )
        machine_sha256 = hashlib.sha256(machine.read_bytes()).hexdigest()
        manifest = root / "machine-ir-manifest.json"
        manifest.write_text(json.dumps({
            "format": "spaghetti-extractor-machine-ir-v3",
            "binary": {"sha256": "a" * 64},
            "artifacts": {"machine_ir": {"sha256": machine_sha256}},
        }), encoding="ascii")
        binding = create_component_machine_binding_v1(
            id="service-branch-component",
            binary={"pe_sha256": "a" * 64, "machine_ir_sha256": machine_sha256},
            interface={"id": "service_branch", "sha256": canonical_sha256_v3(interface)},
            unit_ids=["unit:call", "unit:failure", "unit:success"],
            operations=[{
                "operation_id": "run", "entry_unit_ids": ["unit:call"],
                "exit_unit_ids": ["unit:failure", "unit:success"],
                "parameters": ([{"id": "buffer", "projection": {
                    "kind": "bytes_view", "extent_id": "value", "at": "entry",
                    "base": {"kind": "register", "register": "ecx",
                             "width": 32, "at": "entry"},
                }}] if byte_view else []) + [{"id": "value", "projection": {
                    "kind": "register", "register": ("edx" if byte_view else "ecx"),
                    "width": 32, "at": "entry",
                }}],
                "results": [{"id": "result", "projection": {
                    "kind": "register", "register": "eax", "width": 32, "at": "exit",
                }}],
                "state": [], "preserved_state_ids": [], "effects": [],
                "callback_operation_ids": [], "continuation_unit_ids": [],
            }],
            services=[{
                "service_id": "choose", "mediation": "direct",
                "provider": {"kind": "machine_events", "events": [{
                    "unit_id": "unit:call", "event_index": 0,
                    "event_sha256": canonical_sha256_v3(event),
                    "arguments": [
                        {"kind": "register", "register": "ecx", "width": 32,
                         "at": "call"},
                        *([{"kind": "register", "register": "edx", "width": 32,
                            "at": "call"}] if byte_view else []),
                    ],
                    "result": {
                        "kind": "register", "register": "eax", "width": 32, "at": "call",
                    },
                }]},
            }],
        )
        binding_path = root / "binding.json"
        binding_path.write_text(json.dumps(binding), encoding="ascii")
        source_file = root / "service-branch.c"
        source_file.write_text(
            '#include "portable-component-implementation.h"\n\n'
            "uint32_t component_service_branch_run(\n"
            "    spx_service_branch_context_v2 *context, "
            + ("const spx_bytes_view_v2 *buffer, " if byte_view else "")
            + "uint32_t value) {\n"
            f"  uint32_t service_result = context->services->choose(context->services->context, "
            + ("buffer, " if byte_view else "")
            + f"{argument});\n"
            f"  return service_result == UINT32_C(0) ? UINT32_C(11) : {failure};\n"
            "}\n",
            encoding="ascii",
        )
        source_package = root / "source-package"
        build_component_source_package(
            lift_unit_id="service-branch-component",
            files={"service-branch.c": source_file}, shared_inputs={},
            operation_symbols={"run": "component_service_branch_run"},
            out_dir=source_package,
        )
        contract = build_component_semantic_contract(
            interface=interface_path, binding=binding_path, machine_ir=machine,
            machine_ir_manifest=manifest,
        )
        contract_path = root / "semantic-contract.json"
        contract_path.write_text(json.dumps(contract), encoding="ascii")
        profile_path = root / "source-profile.json"
        profile_path.write_text(
            json.dumps(check_component_source_profile(package=source_package)),
            encoding="ascii",
        )
        return {
            "interface": interface_path, "binding": binding_path,
            "machine": machine, "manifest": manifest, "contract": contract_path,
            "source": source_package, "profile": profile_path,
        }

    def _bytes_fixture(self, root: Path) -> dict[str, Path]:
        interface = {
            "format": "spaghetti-extractor-component-interface-ir-v2",
            "id": "first_byte",
            "types": [
                {"id": "u32", "kind": "scalar", "c_type": "uint32_t"},
                {
                    "id": "input_bytes",
                    "kind": "bytes",
                    "access": "read",
                    "extent_parameter_id": "extent",
                    "nul_terminated": False,
                },
            ],
            "state": [],
            "operations": [{
                "id": "read", "kind": "operation",
                "parameters": [
                    {"id": "input", "type_id": "input_bytes"},
                    {"id": "extent", "type_id": "u32"},
                ],
                "results": [{"id": "result", "type_id": "u32"}],
                "effect_ids": [], "allowed_service_ids": [],
                "pre_states": ["ready"], "post_states": ["ready"],
            }],
            "effects": [], "services": [],
            "protocol": {"states": ["ready"], "initial_state": "ready"},
        }
        interface_path = root / "interface.json"
        interface_path.write_text(json.dumps(interface), encoding="ascii")

        def unit(
            identity: str, start: int, end: int, semantics: dict[str, object]
        ) -> dict[str, object]:
            return {
                "format": "spaghetti-extractor-machine-ir-v3",
                "record_kind": "unit", "id": identity, "status": "qualified",
                "source": {
                    "contract_sha256": "b" * 64,
                    "instruction_bytes_sha256": "c" * 64,
                    "original": {"rva_start": start, "rva_end": end},
                },
                "semantics": {
                    "memory_events": [], "external_events": [], "faults": [],
                    "register_writes": [], "flag_writes": [],
                    **semantics,
                },
            }

        units = [
            unit(
                "unit:dispatch", 0x1000, 0x1004,
                {
                    "edge_conditions": [
                        {
                            "condition": {"op": "eq", "args": [
                                {"op": "reg", "name": "edx", "width": 32},
                                {"op": "const", "value": 0, "width": 32},
                            ]},
                            "target_rva": 0x1010,
                        },
                        {
                            "condition": {"op": "not", "args": [{
                                "op": "eq", "args": [
                                    {"op": "reg", "name": "edx", "width": 32},
                                    {"op": "const", "value": 0, "width": 32},
                                ],
                            }]},
                            "target_rva": 0x1020,
                        },
                    ],
                    "outcome": {"kind": "branch"},
                },
            ),
            unit(
                "unit:empty", 0x1010, 0x1014,
                {
                    "register_writes": [{
                        "register": "eax",
                        "value": {"op": "const", "value": 0, "width": 32},
                    }],
                    "outcome": {"kind": "return", "value": {
                        "op": "load", "width": 4,
                        "address": {"op": "reg", "name": "esp", "width": 32},
                    }},
                },
            ),
            unit(
                "unit:first", 0x1020, 0x1024,
                {
                    "register_writes": [{
                        "register": "eax",
                        "value": {
                            "op": "load", "width": 1,
                            "address": {"op": "reg", "name": "ecx", "width": 32},
                        },
                    }],
                    "outcome": {"kind": "return", "value": {
                        "op": "load", "width": 4,
                        "address": {"op": "reg", "name": "esp", "width": 32},
                    }},
                },
            ),
        ]
        machine = root / "machine-ir.jsonl"
        machine.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in units),
            encoding="ascii",
        )
        machine_sha256 = hashlib.sha256(machine.read_bytes()).hexdigest()
        manifest = root / "machine-ir-manifest.json"
        manifest.write_text(json.dumps({
            "format": "spaghetti-extractor-machine-ir-v3",
            "binary": {"sha256": "a" * 64},
            "artifacts": {"machine_ir": {"sha256": machine_sha256}},
        }), encoding="ascii")
        binding = create_component_machine_binding_v1(
            id="first-byte-component",
            binary={"pe_sha256": "a" * 64, "machine_ir_sha256": machine_sha256},
            interface={"id": "first_byte", "sha256": canonical_sha256_v3(interface)},
            unit_ids=["unit:dispatch", "unit:empty", "unit:first"],
            operations=[{
                "operation_id": "read", "entry_unit_ids": ["unit:dispatch"],
                "exit_unit_ids": ["unit:empty", "unit:first"],
                "parameters": [
                    {"id": "extent", "projection": {
                        "kind": "register", "register": "edx", "width": 32,
                        "at": "entry",
                    }},
                    {"id": "input", "projection": {
                        "kind": "bytes_view", "extent_id": "extent", "at": "entry",
                        "base": {"kind": "register", "register": "ecx", "width": 32,
                                 "at": "entry"},
                    }},
                ],
                "results": [{"id": "result", "projection": {
                    "kind": "register", "register": "eax", "width": 32, "at": "exit",
                }}],
                "state": [], "preserved_state_ids": [], "effects": [],
                "callback_operation_ids": [], "continuation_unit_ids": [],
            }],
            services=[],
        )
        binding_path = root / "binding.json"
        binding_path.write_text(json.dumps(binding), encoding="ascii")
        source_file = root / "first-byte.c"
        source_file.write_text(
            '#include "portable-component-implementation.h"\n\n'
            "uint32_t component_first_byte_read(\n"
            "    spx_first_byte_context_v2 *context,\n"
            "    const spx_bytes_view_v2 *input, uint32_t extent) {\n"
            "  uint8_t value = 0;\n"
            "  (void)context;\n"
            "  if (extent == 0) return 0;\n"
            "  if (input->read_u8(input->context, 0, &value) != 0) return 0;\n"
            "  return (uint32_t)value;\n"
            "}\n",
            encoding="ascii",
        )
        source_package = root / "source-package"
        build_component_source_package(
            lift_unit_id="first-byte-component", files={"first-byte.c": source_file},
            shared_inputs={}, operation_symbols={"read": "component_first_byte_read"},
            out_dir=source_package,
        )
        contract_path = root / "semantic-contract.json"
        contract_path.write_text(json.dumps(build_component_semantic_contract(
            interface=interface_path, binding=binding_path, machine_ir=machine,
            machine_ir_manifest=manifest,
        )), encoding="ascii")
        profile_path = root / "source-profile.json"
        profile_path.write_text(json.dumps(
            check_component_source_profile(package=source_package)
        ), encoding="ascii")
        return {
            "interface": interface_path, "binding": binding_path,
            "machine": machine, "manifest": manifest, "contract": contract_path,
            "source": source_package, "profile": profile_path,
        }

    def _state_fixture(
        self,
        root: Path,
        *,
        source_update: str = "context->state.value + amount",
        write_rva: int = 0x3000,
        preserved: bool = False,
    ) -> dict[str, Path]:
        interface = {
            "format": "spaghetti-extractor-component-interface-ir-v2",
            "id": "counter",
            "types": [{"id": "u32", "kind": "scalar", "c_type": "uint32_t"}],
            "state": [{"id": "value", "type_id": "u32", "initial": 0}],
            "operations": [{
                "id": "add", "kind": "operation",
                "parameters": [{"id": "amount", "type_id": "u32"}],
                "results": [{"id": "result", "type_id": "u32"}],
                "effect_ids": [], "allowed_service_ids": [],
                "pre_states": ["ready"], "post_states": ["ready"],
            }],
            "effects": [], "services": [],
            "protocol": {"states": ["ready"], "initial_state": "ready"},
        }
        interface_path = root / "interface.json"
        interface_path.write_text(json.dumps(interface), encoding="ascii")
        state_address = {"op": "const", "value": 0x3000, "width": 32}
        amount = {"op": "reg", "name": "ecx", "width": 32}
        next_value = {
            "op": "add32",
            "args": [
                {"op": "load", "width": 4, "address": state_address},
                amount,
            ],
        }
        unit = {
            "format": "spaghetti-extractor-machine-ir-v3",
            "record_kind": "unit", "id": "unit:add", "status": "qualified",
            "source": {
                "contract_sha256": "b" * 64,
                "instruction_bytes_sha256": "c" * 64,
                "original": {"rva_start": 0x1000, "rva_end": 0x1010},
            },
            "semantics": {
                "outcome": {"kind": "return", "value": {
                    "op": "load", "width": 4,
                    "address": {"op": "reg", "name": "esp", "width": 32},
                }},
                "memory_events": [{
                    "kind": "write", "width": 4,
                    "address": {"op": "const", "value": write_rva, "width": 32},
                    "value": next_value,
                }],
                "external_events": [], "faults": [],
                "register_writes": [{"register": "eax", "value": next_value}],
                "flag_writes": [],
            },
        }
        machine = root / "machine-ir.jsonl"
        machine.write_text(json.dumps(unit, sort_keys=True) + "\n", encoding="ascii")
        machine_sha256 = hashlib.sha256(machine.read_bytes()).hexdigest()
        manifest = root / "machine-ir-manifest.json"
        manifest.write_text(json.dumps({
            "format": "spaghetti-extractor-machine-ir-v3",
            "binary": {"sha256": "a" * 64},
            "artifacts": {"machine_ir": {"sha256": machine_sha256}},
        }), encoding="ascii")
        binding = create_component_machine_binding_v1(
            id="counter-component",
            binary={"pe_sha256": "a" * 64, "machine_ir_sha256": machine_sha256},
            interface={"id": "counter", "sha256": canonical_sha256_v3(interface)},
            unit_ids=["unit:add"],
            operations=[{
                "operation_id": "add", "entry_unit_ids": ["unit:add"],
                "exit_unit_ids": ["unit:add"],
                "parameters": [{"id": "amount", "projection": {
                    "kind": "register", "register": "ecx", "width": 32, "at": "entry",
                }}],
                "results": [{"id": "result", "projection": {
                    "kind": "register", "register": "eax", "width": 32, "at": "exit",
                }}],
                "state": [{
                    "id": "value",
                    "entry": {"kind": "static_slot", "rva": 0x3000, "width": 32, "at": "entry"},
                    "exit": {"kind": "static_slot", "rva": 0x3000, "width": 32, "at": "exit"},
                }],
                "preserved_state_ids": ["value"] if preserved else [],
                "effects": [], "callback_operation_ids": [],
                "continuation_unit_ids": [],
            }],
            services=[],
        )
        binding_path = root / "binding.json"
        binding_path.write_text(json.dumps(binding), encoding="ascii")
        source_file = root / "counter.c"
        source_file.write_text(
            '#include "portable-component-implementation.h"\n\n'
            "uint32_t component_counter_add(\n"
            "    spx_counter_context_v2 *context, uint32_t amount) {\n"
            f"  uint32_t result = {source_update};\n"
            "  context->state.value = result;\n"
            "  return result;\n"
            "}\n",
            encoding="ascii",
        )
        source_package = root / "source-package"
        build_component_source_package(
            lift_unit_id="counter-component", files={"counter.c": source_file},
            shared_inputs={}, operation_symbols={"add": "component_counter_add"},
            out_dir=source_package,
        )
        contract = build_component_semantic_contract(
            interface=interface_path, binding=binding_path, machine_ir=machine,
            machine_ir_manifest=manifest,
        )
        contract_path = root / "semantic-contract.json"
        contract_path.write_text(json.dumps(contract), encoding="ascii")
        profile_path = root / "source-profile.json"
        profile_path.write_text(
            json.dumps(check_component_source_profile(package=source_package)),
            encoding="ascii",
        )
        return {
            "interface": interface_path, "binding": binding_path,
            "machine": machine, "manifest": manifest, "contract": contract_path,
            "source": source_package, "profile": profile_path,
        }

    def test_contract_is_exactly_bound_to_selected_machine_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._fixture(Path(temporary))
            payload = json.loads(paths["contract"].read_text(encoding="ascii"))
            parsed = ComponentSemanticContractV1.parse(payload)
        self.assertEqual(parsed.status, "satisfied")
        self.assertEqual(parsed.payload["operations"][0]["units"][0]["id"], "unit:increment")
        self.assertFalse(parsed.payload["policy"]["operator_expected_outputs_accepted"])

    def test_corrupted_contract_digest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._fixture(Path(temporary))
            payload = json.loads(paths["contract"].read_text(encoding="ascii"))
            payload["operations"][0]["operation_id"] = "changed"
            with self.assertRaisesRegex(ComponentSemanticContractError, "digest"):
                ComponentSemanticContractV1.parse(payload)

    def test_exact_service_binding_produces_all_machine_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._service_fixture(Path(temporary))
            contract = ComponentSemanticContractV1.parse(
                json.loads(paths["contract"].read_text(encoding="ascii"))
            )
            model = build_operation_path_model(
                contract.payload["operations"][0],
                PortableComponentInterfaceV2.parse(
                    json.loads(paths["interface"].read_text(encoding="ascii"))
                ),
                contract.payload["services"],
            )
        self.assertEqual(len(model["paths"]), 2)
        self.assertEqual(model["max_events"], 1)
        self.assertEqual(
            {path["trace"][0]["service_id"] for path in model["paths"]},
            {"choose"},
        )

    def test_byte_view_service_binding_preserves_logical_view_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._service_fixture(Path(temporary), byte_view=True)
            contract = ComponentSemanticContractV1.parse(
                json.loads(paths["contract"].read_text(encoding="ascii"))
            )
            model = build_operation_path_model(
                contract.payload["operations"][0],
                PortableComponentInterfaceV2.parse(
                    json.loads(paths["interface"].read_text(encoding="ascii"))
                ),
                contract.payload["services"],
            )
        for path in model["paths"]:
            self.assertEqual(
                path["trace"][0]["arguments"],
                [
                    {"op": "bytes_address", "name": "buffer", "width": 32},
                    {"op": "parameter", "name": "value"},
                ],
            )

    def test_service_argument_stack_staging_is_a_checked_call_frame(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._service_fixture(Path(temporary))
            contract = ComponentSemanticContractV1.parse(
                json.loads(paths["contract"].read_text(encoding="ascii"))
            )
            operation = contract.payload["operations"][0]
            semantics = operation["units"][0]["semantics"]
            event = semantics["external_events"][0]
            stack_address = {"op": "reg", "name": "esp", "width": 32}
            stack_load = {"op": "load", "width": 4, "address": stack_address}
            stack_write = {
                "kind": "write",
                "width": 4,
                "address": stack_address,
                "value": {"op": "reg", "name": "ecx", "width": 32},
            }
            semantics["memory_events"] = [stack_write]
            semantics["ordered_events"] = [
                {"family": "memory", **stack_write},
                {"family": "external"},
            ]
            event["arguments"] = [stack_load]
            event["stack_inputs"] = [
                {"offset": 0, "width": 4, "value": stack_load}
            ]
            contract.payload["services"][0]["provider"]["events"][0][
                "arguments"
            ] = [{"kind": "stack", "offset": 0, "width": 32, "at": "call"}]

            model = build_operation_path_model(
                operation,
                PortableComponentInterfaceV2.parse(
                    json.loads(paths["interface"].read_text(encoding="ascii"))
                ),
                contract.payload["services"],
            )

        for path in model["paths"]:
            self.assertEqual(
                path["service_argument_stack_writes"],
                [{"offset": 0, "width": 4}],
            )
            self.assertEqual(
                path["trace"][0]["arguments"],
                [{"op": "parameter", "name": "value"}],
            )

    def test_unconsumed_nonnegative_stack_write_remains_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._service_fixture(Path(temporary))
            contract = ComponentSemanticContractV1.parse(
                json.loads(paths["contract"].read_text(encoding="ascii"))
            )
            operation = contract.payload["operations"][0]
            semantics = operation["units"][0]["semantics"]
            stack_write = {
                "kind": "write",
                "width": 4,
                "address": {"op": "reg", "name": "esp", "width": 32},
                "value": {"op": "reg", "name": "ecx", "width": 32},
            }
            semantics["memory_events"] = [stack_write]
            semantics["ordered_events"] = [
                {"family": "memory", **stack_write},
                {"family": "external"},
            ]
            with self.assertRaisesRegex(SemanticPathError, "not consumed"):
                build_operation_path_model(
                    operation,
                    PortableComponentInterfaceV2.parse(
                        json.loads(paths["interface"].read_text(encoding="ascii"))
                    ),
                    contract.payload["services"],
                )

    def test_edge_guard_uses_unit_entry_state_before_register_writes(self) -> None:
        register = {"op": "reg", "name": "ecx", "width": 32}
        one = {"op": "const", "value": 1, "width": 32}
        decremented = {"op": "sub32", "args": [register, one]}
        operation = {
            "operation_id": "run",
            "entry_unit_ids": ["unit:adjust"],
            "exit_unit_ids": ["unit:exit"],
            "parameters": [{
                "id": "value",
                "projection": {
                    "kind": "register",
                    "register": "ecx",
                    "width": 32,
                    "at": "entry",
                },
            }],
            "results": [{
                "id": "result",
                "projection": {
                    "kind": "register",
                    "register": "eax",
                    "width": 32,
                    "at": "exit",
                },
            }],
            "state": [],
            "preserved_state_ids": [],
            "effects": [],
            "callback_operation_ids": [],
            "units": [
                {
                    "id": "unit:adjust",
                    "source": {
                        "original": {"rva_start": 0x1000, "rva_end": 0x1010}
                    },
                    "semantics": {
                        "outcome": {"kind": "jump", "target_rva": 0x1010},
                        "edge_conditions": [{
                            "target_rva": 0x1010,
                            "condition": {
                                "op": "eq",
                                "args": [
                                    decremented,
                                    {"op": "const", "value": 0, "width": 32},
                                ],
                            },
                        }],
                        "memory_events": [],
                        "external_events": [],
                        "faults": [],
                        "register_writes": [{
                            "register": "ecx", "value": decremented,
                        }],
                        "flag_writes": [],
                    },
                },
                {
                    "id": "unit:exit",
                    "source": {
                        "original": {"rva_start": 0x1010, "rva_end": 0x1020}
                    },
                    "semantics": {
                        "outcome": {"kind": "return"},
                        "edge_conditions": [],
                        "memory_events": [],
                        "external_events": [],
                        "faults": [],
                        "register_writes": [{
                            "register": "eax", "value": register,
                        }],
                        "flag_writes": [],
                    },
                },
            ],
        }
        model = build_operation_path_model(
            operation,
            PortableComponentInterfaceV2.parse(_interface()),
            [],
        )

        self.assertEqual(
            model["paths"][0]["guards"],
            [{
                "op": "eq",
                "args": [
                    {
                        "op": "add32",
                        "args": [
                            {"op": "parameter", "name": "value"},
                            {"op": "const", "value": 0xFFFFFFFF, "width": 32},
                        ],
                    },
                    {"op": "const", "value": 0, "width": 32},
                ],
            }],
        )

    def test_service_path_rejects_malformed_machine_event_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._service_fixture(Path(temporary))
            contract = ComponentSemanticContractV1.parse(
                json.loads(paths["contract"].read_text(encoding="ascii"))
            )
            operation = contract.payload["operations"][0]
            operation["units"][0]["semantics"]["external_events"][0][
                "arguments"
            ] = [7]
            with self.assertRaisesRegex(SemanticPathError, "external arguments"):
                build_operation_path_model(
                    operation,
                    PortableComponentInterfaceV2.parse(
                        json.loads(paths["interface"].read_text(encoding="ascii"))
                    ),
                    contract.payload["services"],
                )

    def test_service_path_rejects_current_call_response_as_call_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._service_fixture(Path(temporary))
            contract = ComponentSemanticContractV1.parse(
                json.loads(paths["contract"].read_text(encoding="ascii"))
            )
            operation = contract.payload["operations"][0]
            event = operation["units"][0]["semantics"]["external_events"][0]
            event["register_inputs"]["ecx"] = {
                "op": "call_response",
                "call_index": 0,
                "register": "eax",
                "width": 32,
            }
            with self.assertRaisesRegex(SemanticPathError, "unavailable call response"):
                build_operation_path_model(
                    operation,
                    PortableComponentInterfaceV2.parse(
                        json.loads(paths["interface"].read_text(encoding="ascii"))
                    ),
                    contract.payload["services"],
                )

    def test_state_path_tracks_exact_machine_update(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._state_fixture(Path(temporary))
            contract = ComponentSemanticContractV1.parse(
                json.loads(paths["contract"].read_text(encoding="ascii"))
            )
            model = build_operation_path_model(
                contract.payload["operations"][0],
                PortableComponentInterfaceV2.parse(
                    json.loads(paths["interface"].read_text(encoding="ascii"))
                ),
                contract.payload["services"],
            )
        self.assertEqual(model["state_ids"], ["value"])
        self.assertEqual(model["paths"][0]["state"], {
            "value": {
                "op": "add32",
                "args": [
                    {"op": "state_input", "name": "value"},
                    {"op": "parameter", "name": "amount"},
                ],
            }
        })

    def test_state_path_rejects_write_outside_owned_frame(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._state_fixture(Path(temporary), write_rva=0x4000)
            contract = ComponentSemanticContractV1.parse(
                json.loads(paths["contract"].read_text(encoding="ascii"))
            )
            with self.assertRaisesRegex(SemanticPathError, "outside the checked"):
                build_operation_path_model(
                    contract.payload["operations"][0],
                    PortableComponentInterfaceV2.parse(
                        json.loads(paths["interface"].read_text(encoding="ascii"))
                    ),
                    contract.payload["services"],
                )

    def test_state_path_rejects_false_preservation_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._state_fixture(Path(temporary), preserved=True)
            contract = ComponentSemanticContractV1.parse(
                json.loads(paths["contract"].read_text(encoding="ascii"))
            )
            with self.assertRaisesRegex(SemanticPathViolation, "is modified"):
                build_operation_path_model(
                    contract.payload["operations"][0],
                    PortableComponentInterfaceV2.parse(
                        json.loads(paths["interface"].read_text(encoding="ascii"))
                    ),
                    contract.payload["services"],
                )

if __name__ == "__main__":
    unittest.main()
