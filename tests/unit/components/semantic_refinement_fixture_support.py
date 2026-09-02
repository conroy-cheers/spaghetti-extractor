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
    ProofKernelMachineBinding,
    MachineProjectionV1,
    create_proof_kernel_machine_binding,
)
from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
from spaghetti_extractor.components.refinement import check_component_refinement
from spaghetti_extractor.components.semantic_arithmetic import (
    simplify_logical_arithmetic,
)
from spaghetti_extractor.components.semantic_contract import (
    ComponentSemanticContractError,
    ProofKernelSemanticContract,
    build_proof_kernel_semantic_contract,
)
from spaghetti_extractor.components.semantic_paths import (
    SemanticPathError,
    SemanticPathViolation,
    _expression_key,
    _read_call_projection,
    build_operation_path_model,
)
from spaghetti_extractor.components.semantic_path_execution import (
    _bind_service_result_rule,
)
from spaghetti_extractor.components.semantic_path_model import _State
from spaghetti_extractor.components.semantic_services import BoundServiceEvent
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.components.source_profile import (
    check_component_source_profile,
)


def _interface() -> dict[str, object]:
    return {
        "id": "increment",
        "types": [{"id": "u32", "kind": "scalar", "c_type": "uint32_t"}],
        "state": [],
        "operations": [
            {
                "id": "run",
                "kind": "operation",
                "parameters": [{"id": "value", "type_id": "u32"}],
                "results": [{"id": "result", "type_id": "u32"}],
                "effect_ids": [],
                "allowed_service_ids": [],
                "pre_states": ["ready"],
                "post_states": ["ready"],
            }
        ],
        "effects": [],
        "services": [],
        "protocol": {"states": ["ready"], "initial_state": "ready"},
    }

class SemanticRefinementFixtureMixin:
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
            interface["types"].append(
                {
                    "id": "input",
                    "kind": "scalar",
                    "c_type": parameter_c_type,
                }
            )
            interface["operations"][0]["parameters"][0]["type_id"] = "input"
        interface_path = root / "interface.json"
        interface_path.write_text(json.dumps(interface), encoding="ascii")
        unit = {
            "format": "spaghetti-extractor-machine-ir-v3",
            "record_kind": "unit",
            "id": "unit:increment",
            "status": "qualified",
            "source": {
                "contract_sha256": "b" * 64,
                "instruction_bytes_sha256": "c" * 64,
                "original": {"rva_start": 0x1000, "rva_end": 0x1010},
            },
            "semantics": {
                "outcome": {
                    "kind": "return",
                    "value": {
                        "op": "load",
                        "width": 4,
                        "address": {"op": "reg", "name": "esp", "width": 32},
                    },
                },
                "memory_events": [],
                "external_events": [],
                "faults": [],
                "register_writes": [
                    {
                        "register": "eax",
                        "value": (
                            machine_expression
                            if machine_expression is not None
                            else {
                                "op": "add32",
                                "args": [
                                    {"op": "reg", "name": "ecx", "width": 32},
                                    {"op": "const", "value": 1, "width": 32},
                                ],
                            }
                        ),
                    }
                ],
                "flag_writes": [],
            },
        }
        machine = root / "machine-ir.jsonl"
        machine.write_text(json.dumps(unit, sort_keys=True) + "\n", encoding="ascii")
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
        binding = create_proof_kernel_machine_binding(
            id="increment-component",
            binary={"pe_sha256": "a" * 64, "machine_ir_sha256": machine_sha256},
            interface={"id": "increment", "sha256": canonical_sha256_v3(interface)},
            unit_ids=["unit:increment"],
            operations=[
                {
                    "operation_id": "run",
                    "entry_unit_ids": ["unit:increment"],
                    "exit_unit_ids": ["unit:increment"],
                    "parameters": [
                        {
                            "id": "value",
                            "projection": {
                                "kind": "register",
                                "register": "ecx",
                                "width": 32,
                                "at": "entry",
                            },
                        }
                    ],
                    "results": [
                        {
                            "id": "result",
                            "projection": {
                                "kind": "register",
                                "register": "eax",
                                "width": 32,
                                "at": "exit",
                            },
                        }
                    ],
                    "state": [],
                    "preserved_state_ids": [],
                    "effects": [],
                    "callback_operation_ids": [],
                    "continuation_unit_ids": [],
                }
            ],
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
            lift_unit_id="increment-component",
            files={"increment.c": source_file},
            shared_inputs={},
            operation_symbols={"run": "component_increment_run"},
            out_dir=source_package,
        )
        contract = build_proof_kernel_semantic_contract(
            interface=interface_path,
            binding=binding_path,
            machine_ir=machine,
            machine_ir_manifest=manifest,
        )
        contract_path = root / "semantic-contract.json"
        contract_path.write_text(json.dumps(contract), encoding="ascii")
        profile = check_component_source_profile(package=source_package)
        profile_path = root / "source-profile.json"
        profile_path.write_text(json.dumps(profile), encoding="ascii")
        return {
            "interface": interface_path,
            "binding": binding_path,
            "machine": machine,
            "manifest": manifest,
            "contract": contract_path,
            "source": source_package,
            "profile": profile_path,
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
            "id": "service_branch",
            "types": [
                {"id": "u32", "kind": "scalar", "c_type": "uint32_t"},
                *(
                    [
                        {
                            "id": "bytes",
                            "kind": "bytes",
                            "access": "read",
                            "extent_parameter_id": "value",
                            "nul_terminated": False,
                        }
                    ]
                    if byte_view
                    else []
                ),
            ],
            "state": [],
            "operations": [
                {
                    "id": "run",
                    "kind": "operation",
                    "parameters": (
                        [{"id": "buffer", "type_id": "bytes"}] if byte_view else []
                    )
                    + [{"id": "value", "type_id": "u32"}],
                    "results": [{"id": "result", "type_id": "u32"}],
                    "effect_ids": [],
                    "allowed_service_ids": ["choose"],
                    "pre_states": ["ready"],
                    "post_states": ["ready"],
                }
            ],
            "effects": [],
            "services": [
                {
                    "id": "choose",
                    "parameter_type_ids": (["bytes"] if byte_view else []) + ["u32"],
                    "result_type_id": "u32",
                    "effect_ids": [],
                }
            ],
            "protocol": {"states": ["ready"], "initial_state": "ready"},
        }
        interface_path = root / "interface.json"
        interface_path.write_text(json.dumps(interface), encoding="ascii")
        response = {
            "op": "call_response",
            "call_index": 0,
            "register": "eax",
            "width": 32,
        }
        event = {
            "kind": "external_call",
            "dll": "test.dll",
            "symbol": "choose",
            "instruction_rva": 0x1004,
            "return_rva": 0x1008,
            "target_rva": 0x3000,
            "register_inputs": {
                "ecx": {"op": "reg", "name": "ecx", "width": 32},
                **(
                    {"edx": {"op": "reg", "name": "edx", "width": 32}}
                    if byte_view
                    else {}
                ),
            },
            "flag_inputs": {},
            "arguments": [
                {"op": "reg", "name": "ecx", "width": 32},
                *([{"op": "reg", "name": "edx", "width": 32}] if byte_view else []),
            ],
            "stack_inputs": [],
        }
        units = [
            {
                "format": "spaghetti-extractor-machine-ir-v3",
                "record_kind": "unit",
                "id": "unit:call",
                "status": "qualified",
                "source": {
                    "contract_sha256": "b" * 64,
                    "instruction_bytes_sha256": "c" * 64,
                    "original": {"rva_start": 0x1000, "rva_end": 0x1010},
                },
                "semantics": {
                    "outcome": {
                        "kind": "branch",
                        "true_target_rva": 0x1010,
                        "false_target_rva": 0x1020,
                    },
                    "edge_conditions": [
                        {
                            "target_rva": 0x1010,
                            "condition": {
                                "op": "eq",
                                "args": [
                                    response,
                                    {"op": "const", "value": 0, "width": 32},
                                ],
                            },
                        },
                        {
                            "target_rva": 0x1020,
                            "condition": {
                                "op": "not",
                                "args": [
                                    {
                                        "op": "eq",
                                        "args": [
                                            response,
                                            {"op": "const", "value": 0, "width": 32},
                                        ],
                                    }
                                ],
                            },
                        },
                    ],
                    "memory_events": [],
                    "external_events": [event],
                    "faults": [],
                    "register_writes": [{"register": "eax", "value": response}],
                    "flag_writes": [],
                },
            },
            {
                "format": "spaghetti-extractor-machine-ir-v3",
                "record_kind": "unit",
                "id": "unit:success",
                "status": "qualified",
                "source": {
                    "contract_sha256": "d" * 64,
                    "instruction_bytes_sha256": "e" * 64,
                    "original": {"rva_start": 0x1010, "rva_end": 0x1020},
                },
                "semantics": {
                    "outcome": {
                        "kind": "return",
                        "value": {
                            "op": "load",
                            "width": 4,
                            "address": {"op": "reg", "name": "esp", "width": 32},
                        },
                    },
                    "memory_events": [],
                    "external_events": [],
                    "faults": [],
                    "register_writes": [
                        {
                            "register": "eax",
                            "value": {
                                "op": "const",
                                "value": 11,
                                "width": 32,
                            },
                        }
                    ],
                    "flag_writes": [],
                },
            },
            {
                "format": "spaghetti-extractor-machine-ir-v3",
                "record_kind": "unit",
                "id": "unit:failure",
                "status": "qualified",
                "source": {
                    "contract_sha256": "f" * 64,
                    "instruction_bytes_sha256": "1" * 64,
                    "original": {"rva_start": 0x1020, "rva_end": 0x1030},
                },
                "semantics": {
                    "outcome": {
                        "kind": "return",
                        "value": {
                            "op": "load",
                            "width": 4,
                            "address": {"op": "reg", "name": "esp", "width": 32},
                        },
                    },
                    "memory_events": [],
                    "external_events": [],
                    "faults": [],
                    "register_writes": [],
                    "flag_writes": [],
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
        binding = create_proof_kernel_machine_binding(
            id="service-branch-component",
            binary={"pe_sha256": "a" * 64, "machine_ir_sha256": machine_sha256},
            interface={
                "id": "service_branch",
                "sha256": canonical_sha256_v3(interface),
            },
            unit_ids=["unit:call", "unit:failure", "unit:success"],
            operations=[
                {
                    "operation_id": "run",
                    "entry_unit_ids": ["unit:call"],
                    "exit_unit_ids": ["unit:failure", "unit:success"],
                    "parameters": (
                        [
                            {
                                "id": "buffer",
                                "projection": {
                                    "kind": "bytes_view",
                                    "extent_id": "value",
                                    "at": "entry",
                                    "base": {
                                        "kind": "register",
                                        "register": "ecx",
                                        "width": 32,
                                        "at": "entry",
                                    },
                                },
                            }
                        ]
                        if byte_view
                        else []
                    )
                    + [
                        {
                            "id": "value",
                            "projection": {
                                "kind": "register",
                                "register": ("edx" if byte_view else "ecx"),
                                "width": 32,
                                "at": "entry",
                            },
                        }
                    ],
                    "results": [
                        {
                            "id": "result",
                            "projection": {
                                "kind": "register",
                                "register": "eax",
                                "width": 32,
                                "at": "exit",
                            },
                        }
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
                    "service_id": "choose",
                    "mediation": "direct",
                    "provider": {
                        "kind": "machine_events",
                        "events": [
                            {
                                "unit_id": "unit:call",
                                "event_index": 0,
                                "event_sha256": canonical_sha256_v3(event),
                                "arguments": [
                                    {
                                        "kind": "register",
                                        "register": "ecx",
                                        "width": 32,
                                        "at": "call",
                                    },
                                    *(
                                        [
                                            {
                                                "kind": "register",
                                                "register": "edx",
                                                "width": 32,
                                                "at": "call",
                                            }
                                        ]
                                        if byte_view
                                        else []
                                    ),
                                ],
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
            ],
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
            files={"service-branch.c": source_file},
            shared_inputs={},
            operation_symbols={"run": "component_service_branch_run"},
            out_dir=source_package,
        )
        contract = build_proof_kernel_semantic_contract(
            interface=interface_path,
            binding=binding_path,
            machine_ir=machine,
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
            "interface": interface_path,
            "binding": binding_path,
            "machine": machine,
            "manifest": manifest,
            "contract": contract_path,
            "source": source_package,
            "profile": profile_path,
        }
