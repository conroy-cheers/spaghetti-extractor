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


from .semantic_refinement_fixture_support import SemanticRefinementFixtureMixin
from .semantic_refinement_state_support import SemanticRefinementStateMixin


class SemanticRefinementTests(
    SemanticRefinementFixtureMixin,
    SemanticRefinementStateMixin,
    unittest.TestCase,
):
    def test_constant_unsigned_predicate_selects_only_reachable_ite_arm(self) -> None:
        condition = simplify_logical_arithmetic(
            {
                "op": "ult32",
                "args": [
                    {"op": "const", "value": 25, "width": 32},
                    {"op": "const", "value": 33, "width": 32},
                ],
            }
        )
        self.assertEqual(condition, {"op": "true"})

    def test_unknown_unsigned_predicate_is_not_assumed(self) -> None:
        condition = simplify_logical_arithmetic(
            {
                "op": "ult32",
                "args": [
                    {"op": "parameter", "name": "left"},
                    {"op": "const", "value": 33, "width": 32},
                ],
            }
        )
        self.assertEqual(condition["op"], "ult32")

    def test_failure_preservation_rule_uses_operation_entry_stack(self) -> None:
        entry_esp = {"op": "symbol", "name": "machine_esp", "width": 32}
        entry_word = {"op": "const", "value": 47, "width": 32}
        entry_address = {
            "op": "add32",
            "args": [
                entry_esp,
                {"op": "const", "value": 64, "width": 32},
            ],
        }
        state = _State(
            env={"esp": entry_esp},
            flags={},
            memory={},
            entry_env={"esp": entry_esp},
            entry_flags={},
            entry_memory={_expression_key(entry_address): entry_word},
            guards=[],
            trace=[],
            visited=set(),
            private_stack_writes=set(),
            pending_service_stack_writes=set(),
            service_argument_stack_writes=set(),
        )
        binding = BoundServiceEvent(
            service_id="get_record",
            unit_id="unit:get-record",
            event_index=0,
            event_sha256="7" * 64,
            argument_projections=(),
            argument_expressions=(),
            physical_argument_expressions=(),
            argument_guards=(),
            writebacks=(),
            result=MachineProjectionV1.parse(
                {
                    "kind": "register",
                    "register": "eax",
                    "width": 32,
                    "at": "call",
                }
            ),
            result_rule={
                "kind": "hresult_success_or_preserved_initial",
                "relation_sha256": "8" * 64,
                "variant_id": "default",
                "word_index": 1,
                "failure_value": {
                    "op": "entry_projection",
                    "projection": {
                        "kind": "stack",
                        "offset": 64,
                        "width": 32,
                        "at": "entry",
                    },
                },
            },
            preserved_registers=(),
            stack_pointer_adjustment=None,
        )
        _bind_service_result_rule(
            state=state,
            binding=binding,
            trace_index=3,
            status={"op": "const", "value": 0x80004005, "width": 32},
        )
        self.assertEqual(len(state.guards), 1)
        failure_equality = state.guards[0]["args"][2]
        self.assertEqual(failure_equality["op"], "eq")
        self.assertEqual(failure_equality["args"][0]["op"], "service_result")
        self.assertEqual(failure_equality["args"][0]["index"], 3)
        self.assertEqual(failure_equality["args"][1], entry_word)

    def test_call_projection_reads_argument_prepared_by_prior_unit(self) -> None:
        projection = MachineProjectionV1.parse(
            {
                "kind": "stack",
                "offset": 4,
                "width": 32,
                "at": "call",
            }
        )
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
                "register_inputs": {"esp": {"op": "reg", "name": "esp", "width": 32}},
                "stack_inputs": [],
            },
            {"esp": entry_esp},
            {},
            {_expression_key(address): expected},
            {},
        )
        self.assertEqual(observed, expected)

    def test_call_projection_offsets_a_pointer_argument(self) -> None:
        projection = MachineProjectionV1.parse(
            {
                "kind": "offset",
                "base": {
                    "kind": "stack",
                    "offset": 4,
                    "width": 32,
                    "at": "call",
                },
                "offset_bytes": 4,
                "at": "call",
            }
        )
        pointer = {"op": "const", "value": 0x10203040, "width": 32}
        observed = _read_call_projection(
            projection,
            {
                "register_inputs": {"esp": {"op": "reg", "name": "esp", "width": 32}},
                "stack_inputs": [{"offset": 4, "width": 4, "value": pointer}],
            },
            {"esp": {"op": "symbol", "name": "machine_esp", "width": 32}},
            {},
            {},
            {},
        )
        self.assertEqual(
            observed,
            {
                "op": "add32",
                "args": [pointer, {"op": "const", "value": 4, "width": 32}],
            },
        )

    def test_finite_control_target_becomes_checked_route_paths(self) -> None:
        interface = ProofKernelComponentInterface.parse(
            {
                "id": "selector_dispatch",
                "types": [
                    {"id": "selector", "kind": "scalar", "c_type": "uint8_t"},
                    {"id": "route", "kind": "enum", "c_type": "uint32_t"},
                ],
                "state": [],
                "operations": [
                    {
                        "id": "select",
                        "kind": "operation",
                        "parameters": [{"id": "selector", "type_id": "selector"}],
                        "results": [{"id": "route", "type_id": "route"}],
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
        )
        address = {
            "op": "add32",
            "args": [
                {"op": "const", "value": 0x402000, "width": 32},
                {
                    "op": "mul32",
                    "args": [
                        {
                            "op": "and32",
                            "args": [
                                {"op": "const", "value": 0xFF, "width": 32},
                                {"op": "reg", "name": "eax", "width": 32},
                            ],
                        },
                        {"op": "const", "value": 4, "width": 32},
                    ],
                },
            ],
        }
        unit = {
            "id": "unit:dispatch",
            "status": "qualified",
            "source": {"original": {"rva_start": 0x1000, "rva_end": 0x100A}},
            "semantics": {
                "outcome": {
                    "kind": "indirect_jump",
                    "target": {
                        "op": "load",
                        "width": 4,
                        "address": address,
                    },
                },
                "memory_events": [{"kind": "read", "width": 4, "address": address}],
                "external_events": [],
                "faults": [],
                "flag_writes": [],
                "register_writes": [
                    {
                        "register": "edx",
                        "value": {
                            "op": "and32",
                            "args": [
                                {"op": "const", "value": 0xFF, "width": 32},
                                {"op": "reg", "name": "eax", "width": 32},
                            ],
                        },
                    }
                ],
            },
        }
        operation = {
            "operation_id": "select",
            "entry_unit_ids": ["unit:dispatch"],
            "exit_unit_ids": ["unit:dispatch"],
            "parameters": [
                {
                    "id": "selector",
                    "projection": {
                        "kind": "register",
                        "register": "eax",
                        "width": 8,
                        "at": "entry",
                    },
                }
            ],
            "results": [
                {
                    "id": "route",
                    "projection": {
                        "kind": "finite_control_target",
                        "at": "exit",
                        "unit_id": "unit:dispatch",
                        "selector_parameter_id": "selector",
                        "target_inventory_sha256": "d" * 64,
                        "routes": [
                            {
                                "selector_value": 0,
                                "logical_value": 7,
                                "target_rva": 0x1100,
                                "target_address": 0x401100,
                            },
                            {
                                "selector_value": 1,
                                "logical_value": 9,
                                "target_rva": 0x1200,
                                "target_address": 0x401200,
                            },
                        ],
                    },
                }
            ],
            "state": [],
            "preserved_state_ids": [],
            "effects": [],
            "callback_operation_ids": [],
            "continuation_unit_ids": [],
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





    def test_contract_is_exactly_bound_to_selected_machine_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._fixture(Path(temporary))
            payload = json.loads(paths["contract"].read_text(encoding="ascii"))
            parsed = ProofKernelSemanticContract.parse(payload)
        self.assertEqual(parsed.status, "satisfied")
        self.assertEqual(
            parsed.payload["operations"][0]["units"][0]["id"], "unit:increment"
        )
        self.assertFalse(parsed.payload["policy"]["operator_expected_outputs_accepted"])

    def test_corrupted_contract_digest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._fixture(Path(temporary))
            payload = json.loads(paths["contract"].read_text(encoding="ascii"))
            payload["operations"][0]["operation_id"] = "changed"
            with self.assertRaisesRegex(ComponentSemanticContractError, "digest"):
                ProofKernelSemanticContract.parse(payload)

    def test_exact_service_binding_produces_all_machine_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._service_fixture(Path(temporary))
            contract = ProofKernelSemanticContract.parse(
                json.loads(paths["contract"].read_text(encoding="ascii"))
            )
            model = build_operation_path_model(
                contract.payload["operations"][0],
                ProofKernelComponentInterface.parse(
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
            contract = ProofKernelSemanticContract.parse(
                json.loads(paths["contract"].read_text(encoding="ascii"))
            )
            model = build_operation_path_model(
                contract.payload["operations"][0],
                ProofKernelComponentInterface.parse(
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
            contract = ProofKernelSemanticContract.parse(
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
            event["stack_inputs"] = [{"offset": 0, "width": 4, "value": stack_load}]
            contract.payload["services"][0]["provider"]["events"][0]["arguments"] = [
                {"kind": "stack", "offset": 0, "width": 32, "at": "call"}
            ]

            model = build_operation_path_model(
                operation,
                ProofKernelComponentInterface.parse(
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
            contract = ProofKernelSemanticContract.parse(
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
                    ProofKernelComponentInterface.parse(
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
            "units": [
                {
                    "id": "unit:adjust",
                    "source": {"original": {"rva_start": 0x1000, "rva_end": 0x1010}},
                    "semantics": {
                        "outcome": {"kind": "jump", "target_rva": 0x1010},
                        "edge_conditions": [
                            {
                                "target_rva": 0x1010,
                                "condition": {
                                    "op": "eq",
                                    "args": [
                                        decremented,
                                        {"op": "const", "value": 0, "width": 32},
                                    ],
                                },
                            }
                        ],
                        "memory_events": [],
                        "external_events": [],
                        "faults": [],
                        "register_writes": [
                            {
                                "register": "ecx",
                                "value": decremented,
                            }
                        ],
                        "flag_writes": [],
                    },
                },
                {
                    "id": "unit:exit",
                    "source": {"original": {"rva_start": 0x1010, "rva_end": 0x1020}},
                    "semantics": {
                        "outcome": {"kind": "return"},
                        "edge_conditions": [],
                        "memory_events": [],
                        "external_events": [],
                        "faults": [],
                        "register_writes": [
                            {
                                "register": "eax",
                                "value": register,
                            }
                        ],
                        "flag_writes": [],
                    },
                },
            ],
        }
        model = build_operation_path_model(
            operation,
            ProofKernelComponentInterface.parse(_interface()),
            [],
        )

        self.assertEqual(
            model["paths"][0]["guards"],
            [
                {
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
                }
            ],
        )

    def test_service_path_rejects_malformed_machine_event_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._service_fixture(Path(temporary))
            contract = ProofKernelSemanticContract.parse(
                json.loads(paths["contract"].read_text(encoding="ascii"))
            )
            operation = contract.payload["operations"][0]
            operation["units"][0]["semantics"]["external_events"][0]["arguments"] = [7]
            with self.assertRaisesRegex(SemanticPathError, "external arguments"):
                build_operation_path_model(
                    operation,
                    ProofKernelComponentInterface.parse(
                        json.loads(paths["interface"].read_text(encoding="ascii"))
                    ),
                    contract.payload["services"],
                )

    def test_service_path_rejects_current_call_response_as_call_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._service_fixture(Path(temporary))
            contract = ProofKernelSemanticContract.parse(
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
                    ProofKernelComponentInterface.parse(
                        json.loads(paths["interface"].read_text(encoding="ascii"))
                    ),
                    contract.payload["services"],
                )

    def test_state_path_tracks_exact_machine_update(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._state_fixture(Path(temporary))
            contract = ProofKernelSemanticContract.parse(
                json.loads(paths["contract"].read_text(encoding="ascii"))
            )
            model = build_operation_path_model(
                contract.payload["operations"][0],
                ProofKernelComponentInterface.parse(
                    json.loads(paths["interface"].read_text(encoding="ascii"))
                ),
                contract.payload["services"],
            )
        self.assertEqual(model["state_ids"], ["value"])
        self.assertEqual(
            model["paths"][0]["state"],
            {
                "value": {
                    "op": "add32",
                    "args": [
                        {"op": "state_input", "name": "value"},
                        {"op": "parameter", "name": "amount"},
                    ],
                }
            },
        )

    def test_state_path_relates_loader_rva_to_original_image_address(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._state_fixture(Path(temporary), image_base=0x400000)
            contract = ProofKernelSemanticContract.parse(
                json.loads(paths["contract"].read_text(encoding="ascii"))
            )
            operation = contract.payload["operations"][0]
            self.assertEqual(operation["machine_image"]["preferred_base"], 0x400000)
            model = build_operation_path_model(
                operation,
                ProofKernelComponentInterface.parse(
                    json.loads(paths["interface"].read_text(encoding="ascii"))
                ),
                contract.payload["services"],
            )
        self.assertEqual(
            model["paths"][0]["state"]["value"]["op"],
            "add32",
        )

    def test_state_path_relates_original_image_address_to_loader_rva(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._state_fixture(
                Path(temporary),
                image_base=0x400000,
                binding_uses_original_va=True,
            )
            contract = ProofKernelSemanticContract.parse(
                json.loads(paths["contract"].read_text(encoding="ascii"))
            )
            operation = contract.payload["operations"][0]
            model = build_operation_path_model(
                operation,
                ProofKernelComponentInterface.parse(
                    json.loads(paths["interface"].read_text(encoding="ascii"))
                ),
                contract.payload["services"],
            )
        self.assertEqual(
            model["paths"][0]["state"]["value"]["op"],
            "add32",
        )

    def test_state_path_rejects_write_outside_owned_frame(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._state_fixture(Path(temporary), write_rva=0x4000)
            contract = ProofKernelSemanticContract.parse(
                json.loads(paths["contract"].read_text(encoding="ascii"))
            )
            with self.assertRaisesRegex(SemanticPathError, "outside the checked"):
                build_operation_path_model(
                    contract.payload["operations"][0],
                    ProofKernelComponentInterface.parse(
                        json.loads(paths["interface"].read_text(encoding="ascii"))
                    ),
                    contract.payload["services"],
                )

    def test_state_path_rejects_false_preservation_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._state_fixture(Path(temporary), preserved=True)
            contract = ProofKernelSemanticContract.parse(
                json.loads(paths["contract"].read_text(encoding="ascii"))
            )
            with self.assertRaisesRegex(SemanticPathViolation, "is modified"):
                build_operation_path_model(
                    contract.payload["operations"][0],
                    ProofKernelComponentInterface.parse(
                        json.loads(paths["interface"].read_text(encoding="ascii"))
                    ),
                    contract.payload["services"],
                )


if __name__ == "__main__":
    unittest.main()
