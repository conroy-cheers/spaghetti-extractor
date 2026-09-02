from __future__ import annotations

import json
import shutil
import subprocess
from types import SimpleNamespace
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.boundary._canonical import BoundaryModelError
from spaghetti_extractor.boundary.model import BoundarySchemaV1
from spaghetti_extractor.components.machine_binding import ServiceMachineBindingV1
from spaghetti_extractor.components.machine_binding_schema import (
    ComponentMachineBindingError,
)
from spaghetti_extractor.components.machine_overlay_external_v5 import (
    _external_logical_word_lines,
    _external_service_runtime_helpers,
    _external_service_thunk,
)
from spaghetti_extractor.components.machine_overlay_boundaries_v5 import (
    checked_opaque_resource_projection,
)
from spaghetti_extractor.components.machine_overlay_v5 import (
    _resource_parameter_lines,
)
from spaghetti_extractor.components.semantic_contract import (
    _checked_interface_method_service_v1,
)
from spaghetti_extractor.components.semantic_external_transducers import (
    ComponentSemanticContractError,
    checked_captured_external_target_guard,
)
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header


SHA = "7" * 64


def _stack_word(index: int) -> dict[str, object]:
    address: dict[str, object] = {"op": "reg", "name": "esp", "width": 32}
    if index:
        address = {
            "op": "add32",
            "args": [
                address,
                {"op": "const", "value": index * 4, "width": 32},
            ],
        }
    return {"op": "load", "address": address, "width": 4}

class InterfaceMethodPartialCellTests(unittest.TestCase):
    def test_profile_checked_partial_cell_can_supply_a_total_word_result(self) -> None:
        caller_memory_frame = {
            "status": "complete",
            "model": "pe32-declared-pointer-arguments-v1",
            "arguments": [
                {
                    "argument_index": 0,
                    "role": "interface_resource",
                    "access": "read_write",
                    "extent": "opaque_resource",
                    "retention": "during_call",
                },
                {
                    "argument_index": 1,
                    "role": "caller_memory",
                    "access": "read_write",
                    "extent": "enclosing_object",
                    "retention": "during_call",
                },
            ],
            "assumptions": [],
        }
        receiver = {
            "argument_index": 0,
            "dispatch_slot": 11,
            "lifecycle_effect": "preserve",
            "required_state": "live",
            "view_id": "IFixture",
        }
        cell_relation = {
            "argument_index": 1,
            "extent_words": 2,
            "variants": [
                {
                    "id": "default",
                    "discriminants": [],
                    "input_word_indices": [0],
                    "output_word_indices": [1],
                    "output_condition": "always",
                    "failure_preserved_word_indices": [],
                    "failure_observed_word_indices": [],
                }
            ],
        }
        cell_relation_sha256 = canonical_sha256_v3(cell_relation)
        method = {
            "abi": {
                "callee_cleanup": True,
                "clobbered_registers": ["eax", "ecx", "edx"],
                "preserved_registers": ["ebp", "ebx", "edi", "esi"],
                "template": "pe32-stdcall-v1",
            },
            "argument_words": 3,
            "callback_effect": "none",
            "caller_memory_frame": caller_memory_frame,
            "external_protocol": {
                "kind": "pe32-interface-method",
                "profile_id": "fixture-profile",
                "profile_sha256": SHA,
                "interface_id": "IFixture",
                "method": "GetRecord",
                "slot": 11,
                "offset": 44,
            },
            "local_cells": [cell_relation],
            "out_interfaces": [],
            "receiver_resource": receiver,
        }
        target = {
            "profile_id": "fixture-profile",
            "profile_sha256": SHA,
            "interface_id": "IFixture",
            "method": method,
        }
        method_sha256 = canonical_sha256_v3(target)
        transducers = [
            {"kind": "logical_argument", "parameter_index": 0},
            {
                "kind": "local_cell",
                "cell_id": "record",
                "initial_words": [8, None],
                "local_cell_relation_sha256": cell_relation_sha256,
            },
            {"kind": "constant", "value": 0},
        ]
        result_projection = {
            "kind": "local_cell_word",
            "cell_id": "record",
            "word_index": 1,
        }
        parsed = ServiceMachineBindingV1.parse(
            {
                "service_id": "get_record",
                "mediation": "direct",
                "provider": {
                    "kind": "interface_method",
                    "events": [
                        {
                            "unit_id": "unit:get-record",
                            "event_index": 0,
                        }
                    ],
                    "method_contract_sha256": method_sha256,
                    "argument_transducers": transducers,
                    "result_projection": result_projection,
                },
            },
            "fixture local-cell service",
        )
        self.assertEqual(parsed.provider["result_projection"], result_projection)

        arguments = [_stack_word(index) for index in range(3)]
        provider = _checked_interface_method_service_v1(
            service_id="get_record",
            logical=SimpleNamespace(
                parameter_type_ids=("receiver",),
                result_type_id="word",
            ),
            logical_types={
                "receiver": SimpleNamespace(kind="resource"),
                "word": SimpleNamespace(kind="scalar"),
            },
            target=target,
            method_contract_sha256=method_sha256,
            unit_id="unit:get-record",
            event_index=0,
            machine_event={
                "kind": "indirect_call",
                # Canonical calls may omit a redundant total argument-node
                # projection; the checked ABI frame remains authoritative.
                "arguments": [],
                "stack_inputs": [
                    {"offset": 0, "width": 4, "value": arguments[0]},
                ],
                "target": {
                    "op": "load",
                    "address": {
                        "op": "add32",
                        "args": [
                            {
                                "op": "load",
                                "address": arguments[0],
                                "width": 4,
                            },
                            {"op": "const", "value": 44, "width": 32},
                        ],
                    },
                    "width": 4,
                },
            },
            argument_transducers=transducers,
            result_projection=result_projection,
        )

        event = provider["events"][0]
        self.assertEqual(event["arguments"], [arguments[0]])
        self.assertEqual(len(event["argument_guards"]), 3)
        self.assertEqual(
            event["result"],
            {
                "kind": "memory",
                "address": {
                    "kind": "offset",
                    "base": {
                        "kind": "stack",
                        "offset": 4,
                        "width": 32,
                        "at": "call",
                    },
                    "offset_bytes": 4,
                    "at": "call",
                },
                "width": 32,
                "access": "read_write",
                "at": "call",
            },
        )

        read_only = json.loads(json.dumps(target))
        read_only["method"]["caller_memory_frame"]["arguments"][1]["access"] = "read"
        with self.assertRaisesRegex(
            ValueError, "contradicts the checked caller-memory frame"
        ):
            _checked_interface_method_service_v1(
                service_id="get_record",
                logical=SimpleNamespace(
                    parameter_type_ids=("receiver",), result_type_id="word"
                ),
                logical_types={
                    "receiver": SimpleNamespace(kind="resource"),
                    "word": SimpleNamespace(kind="scalar"),
                },
                target=read_only,
                method_contract_sha256=method_sha256,
                unit_id="unit:get-record",
                event_index=0,
                machine_event={
                    "kind": "indirect_call",
                    "arguments": [],
                    "stack_inputs": [],
                    "target": {
                        "op": "load",
                        "address": {
                            "op": "add32",
                            "args": [
                                {"op": "load", "address": arguments[0], "width": 4},
                                {"op": "const", "value": 44, "width": 32},
                            ],
                        },
                        "width": 4,
                    },
                },
                argument_transducers=transducers,
                result_projection=result_projection,
            )

        success_only = json.loads(json.dumps(target))
        success_only["method"]["local_cells"][0]["variants"][0]["output_condition"] = (
            "hresult_succeeded_eax"
        )
        success_relation = success_only["method"]["local_cells"][0]
        success_transducers = json.loads(json.dumps(transducers))
        success_transducers[1]["local_cell_relation_sha256"] = canonical_sha256_v3(
            success_relation
        )
        with self.assertRaisesRegex(ValueError, "not defined on every call outcome"):
            _checked_interface_method_service_v1(
                service_id="get_record",
                logical=SimpleNamespace(
                    parameter_type_ids=("receiver",), result_type_id="word"
                ),
                logical_types={
                    "receiver": SimpleNamespace(kind="resource"),
                    "word": SimpleNamespace(kind="scalar"),
                },
                target=success_only,
                method_contract_sha256=canonical_sha256_v3(success_only),
                unit_id="unit:get-record",
                event_index=0,
                machine_event={
                    "kind": "indirect_call",
                    "arguments": [],
                    "stack_inputs": [],
                    "target": {
                        "op": "load",
                        "address": {
                            "op": "add32",
                            "args": [
                                {"op": "load", "address": arguments[0], "width": 4},
                                {"op": "const", "value": 44, "width": 32},
                            ],
                        },
                        "width": 4,
                    },
                },
                argument_transducers=success_transducers,
                result_projection=result_projection,
            )

        failure_preserved = json.loads(json.dumps(success_only))
        failure_preserved["method"]["local_cells"][0]["variants"][0][
            "failure_preserved_word_indices"
        ] = [1]
        preserved_relation = failure_preserved["method"]["local_cells"][0]
        preserved_transducers = json.loads(json.dumps(transducers))
        preserved_transducers[1]["initial_words"][1] = {
            "kind": "entry_projection",
            "projection": {
                "kind": "stack",
                "offset": 64,
                "width": 32,
                "at": "entry",
            },
        }
        preserved_transducers[1]["local_cell_relation_sha256"] = canonical_sha256_v3(
            preserved_relation
        )
        preserved_provider = _checked_interface_method_service_v1(
            service_id="get_record",
            logical=SimpleNamespace(
                parameter_type_ids=("receiver",), result_type_id="word"
            ),
            logical_types={
                "receiver": SimpleNamespace(kind="resource"),
                "word": SimpleNamespace(kind="scalar"),
            },
            target=failure_preserved,
            method_contract_sha256=canonical_sha256_v3(failure_preserved),
            unit_id="unit:get-record",
            event_index=0,
            machine_event={
                "kind": "indirect_call",
                "arguments": [],
                "stack_inputs": [],
                "target": {
                    "op": "load",
                    "address": {
                        "op": "add32",
                        "args": [
                            {"op": "load", "address": arguments[0], "width": 4},
                            {"op": "const", "value": 44, "width": 32},
                        ],
                    },
                    "width": 4,
                },
            },
            argument_transducers=preserved_transducers,
            result_projection=result_projection,
        )
        preserved_event = preserved_provider["events"][0]
        self.assertEqual(
            preserved_event["result_rule"]["kind"],
            "hresult_success_or_preserved_initial",
        )
        self.assertEqual(
            preserved_event["result_rule"]["failure_value"]["op"],
            "entry_projection",
        )
        self.assertIn(
            "entry_projection",
            json.dumps(preserved_event["argument_guards"]),
        )
