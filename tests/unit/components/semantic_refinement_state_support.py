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

class SemanticRefinementStateMixin:
    def _bytes_fixture(self, root: Path) -> dict[str, Path]:
        interface = {
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
            "operations": [
                {
                    "id": "read",
                    "kind": "operation",
                    "parameters": [
                        {"id": "input", "type_id": "input_bytes"},
                        {"id": "extent", "type_id": "u32"},
                    ],
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
        interface_path = root / "interface.json"
        interface_path.write_text(json.dumps(interface), encoding="ascii")

        def unit(
            identity: str, start: int, end: int, semantics: dict[str, object]
        ) -> dict[str, object]:
            return {
                "format": "spaghetti-extractor-machine-ir-v3",
                "record_kind": "unit",
                "id": identity,
                "status": "qualified",
                "source": {
                    "contract_sha256": "b" * 64,
                    "instruction_bytes_sha256": "c" * 64,
                    "original": {"rva_start": start, "rva_end": end},
                },
                "semantics": {
                    "memory_events": [],
                    "external_events": [],
                    "faults": [],
                    "register_writes": [],
                    "flag_writes": [],
                    **semantics,
                },
            }

        units = [
            unit(
                "unit:dispatch",
                0x1000,
                0x1004,
                {
                    "edge_conditions": [
                        {
                            "condition": {
                                "op": "eq",
                                "args": [
                                    {"op": "reg", "name": "edx", "width": 32},
                                    {"op": "const", "value": 0, "width": 32},
                                ],
                            },
                            "target_rva": 0x1010,
                        },
                        {
                            "condition": {
                                "op": "not",
                                "args": [
                                    {
                                        "op": "eq",
                                        "args": [
                                            {"op": "reg", "name": "edx", "width": 32},
                                            {"op": "const", "value": 0, "width": 32},
                                        ],
                                    }
                                ],
                            },
                            "target_rva": 0x1020,
                        },
                    ],
                    "outcome": {"kind": "branch"},
                },
            ),
            unit(
                "unit:empty",
                0x1010,
                0x1014,
                {
                    "register_writes": [
                        {
                            "register": "eax",
                            "value": {"op": "const", "value": 0, "width": 32},
                        }
                    ],
                    "outcome": {
                        "kind": "return",
                        "value": {
                            "op": "load",
                            "width": 4,
                            "address": {"op": "reg", "name": "esp", "width": 32},
                        },
                    },
                },
            ),
            unit(
                "unit:first",
                0x1020,
                0x1024,
                {
                    "register_writes": [
                        {
                            "register": "eax",
                            "value": {
                                "op": "load",
                                "width": 1,
                                "address": {"op": "reg", "name": "ecx", "width": 32},
                            },
                        }
                    ],
                    "outcome": {
                        "kind": "return",
                        "value": {
                            "op": "load",
                            "width": 4,
                            "address": {"op": "reg", "name": "esp", "width": 32},
                        },
                    },
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
            id="first-byte-component",
            binary={"pe_sha256": "a" * 64, "machine_ir_sha256": machine_sha256},
            interface={"id": "first_byte", "sha256": canonical_sha256_v3(interface)},
            unit_ids=["unit:dispatch", "unit:empty", "unit:first"],
            operations=[
                {
                    "operation_id": "read",
                    "entry_unit_ids": ["unit:dispatch"],
                    "exit_unit_ids": ["unit:empty", "unit:first"],
                    "parameters": [
                        {
                            "id": "extent",
                            "projection": {
                                "kind": "register",
                                "register": "edx",
                                "width": 32,
                                "at": "entry",
                            },
                        },
                        {
                            "id": "input",
                            "projection": {
                                "kind": "bytes_view",
                                "extent_id": "extent",
                                "at": "entry",
                                "base": {
                                    "kind": "register",
                                    "register": "ecx",
                                    "width": 32,
                                    "at": "entry",
                                },
                            },
                        },
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
            lift_unit_id="first-byte-component",
            files={"first-byte.c": source_file},
            shared_inputs={},
            operation_symbols={"read": "component_first_byte_read"},
            out_dir=source_package,
        )
        contract_path = root / "semantic-contract.json"
        contract_path.write_text(
            json.dumps(
                build_proof_kernel_semantic_contract(
                    interface=interface_path,
                    binding=binding_path,
                    machine_ir=machine,
                    machine_ir_manifest=manifest,
                )
            ),
            encoding="ascii",
        )
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

    def _state_fixture(
        self,
        root: Path,
        *,
        source_update: str = "context->state.value + amount",
        write_rva: int = 0x3000,
        preserved: bool = False,
        image_base: int | None = None,
        binding_uses_original_va: bool = False,
    ) -> dict[str, Path]:
        interface = {
            "id": "counter",
            "types": [{"id": "u32", "kind": "scalar", "c_type": "uint32_t"}],
            "state": [{"id": "value", "type_id": "u32", "initial": 0}],
            "operations": [
                {
                    "id": "add",
                    "kind": "operation",
                    "parameters": [{"id": "amount", "type_id": "u32"}],
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
        interface_path = root / "interface.json"
        interface_path.write_text(json.dumps(interface), encoding="ascii")
        state_address = {
            "op": "const",
            "value": 0x3000 + (image_base or 0),
            "width": 32,
        }
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
            "record_kind": "unit",
            "id": "unit:add",
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
                "memory_events": [
                    {
                        "kind": "write",
                        "width": 4,
                        "address": {
                            "op": "const",
                            "value": write_rva + (image_base or 0),
                            "width": 32,
                        },
                        "value": next_value,
                    }
                ],
                "external_events": [],
                "faults": [],
                "register_writes": [{"register": "eax", "value": next_value}],
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
        binding_address = 0x3000 + (
            (image_base or 0) if binding_uses_original_va else 0
        )
        binding = create_proof_kernel_machine_binding(
            id="counter-component",
            binary={"pe_sha256": "a" * 64, "machine_ir_sha256": machine_sha256},
            interface={"id": "counter", "sha256": canonical_sha256_v3(interface)},
            unit_ids=["unit:add"],
            operations=[
                {
                    "operation_id": "add",
                    "entry_unit_ids": ["unit:add"],
                    "exit_unit_ids": ["unit:add"],
                    "parameters": [
                        {
                            "id": "amount",
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
                    "state": [
                        {
                            "id": "value",
                            "entry": {
                                "kind": "static_slot",
                                "rva": binding_address,
                                "width": 32,
                                "at": "entry",
                            },
                            "exit": {
                                "kind": "static_slot",
                                "rva": binding_address,
                                "width": 32,
                                "at": "exit",
                            },
                        }
                    ],
                    "preserved_state_ids": ["value"] if preserved else [],
                    "effects": [],
                    "callback_operation_ids": [],
                    "continuation_unit_ids": [],
                }
            ],
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
            lift_unit_id="counter-component",
            files={"counter.c": source_file},
            shared_inputs={},
            operation_symbols={"add": "component_counter_add"},
            out_dir=source_package,
        )
        contract = build_proof_kernel_semantic_contract(
            interface=interface_path,
            binding=binding_path,
            machine_ir=machine,
            machine_ir_manifest=manifest,
            machine_image=(
                None
                if image_base is None
                else {
                    "image_size": 0x10000,
                    "module_interface_sha256": "d" * 64,
                    "pe_sha256": "a" * 64,
                    "preferred_base": image_base,
                }
            ),
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
