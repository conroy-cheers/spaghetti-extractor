from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.machine_binding import (
    COMPONENT_MACHINE_BINDING_DECLARATION_V2,
    COMPONENT_MACHINE_BINDING_DECLARATION_V3,
    ComponentMachineBindingError,
    MachineProjectionV1,
    check_component_machine_binding,
    create_component_machine_binding_v1,
    materialize_component_machine_binding,
)


PE_SHA256 = "a" * 64


def _interface() -> dict[str, object]:
    return {
        "format": "spaghetti-extractor-component-interface-ir-v2",
        "id": "counter",
        "types": [
            {"id": "u32", "kind": "scalar", "c_type": "uint32_t"},
        ],
        "state": [{"id": "value", "type_id": "u32", "initial": 0}],
        "operations": [
            {
                "id": "increment",
                "kind": "operation",
                "parameters": [{"id": "amount", "type_id": "u32"}],
                "results": [{"id": "value", "type_id": "u32"}],
                "effect_ids": ["value_written"],
                "allowed_service_ids": ["notify"],
                "pre_states": ["active"],
                "post_states": ["active"],
            }
        ],
        "effects": [
            {
                "id": "value_written",
                "kind": "memory",
                "target_id": "value",
                "operation": "write",
            }
        ],
        "services": [
            {
                "id": "notify",
                "parameter_type_ids": ["u32"],
                "result_type_id": None,
                "effect_ids": [],
            }
        ],
        "protocol": {"initial_state": "active", "states": ["active"]},
    }


def _machine_unit() -> dict[str, object]:
    memory_write = {
        "kind": "write",
        "address": {"op": "const", "value": 0x3000, "width": 32},
        "width": 4,
        "value": {"op": "reg", "name": "eax", "width": 32},
    }
    return {
        "format": "spaghetti-extractor-machine-ir-v3",
        "record_kind": "unit",
        "id": "unit:increment",
        "status": "qualified",
        "source": {
            "original": {"rva_start": 0x1000, "rva_end": 0x1010},
            "contract_sha256": "b" * 64,
            "instruction_bytes_sha256": "c" * 64,
        },
        "semantics": {
            "external_events": [
                {
                    "kind": "internal_call",
                    "target_rva": 0x2000,
                    "return_rva": 0x1010,
                }
            ],
            "memory_events": [memory_write],
        },
    }


def _binding(machine_sha256: str, interface: dict[str, object]) -> dict[str, object]:
    return create_component_machine_binding_v1(
        id="counter",
        binary={"pe_sha256": PE_SHA256, "machine_ir_sha256": machine_sha256},
        interface={"id": "counter", "sha256": canonical_sha256_v3(interface)},
        unit_ids=["unit:increment"],
        operations=[
            {
                "operation_id": "increment",
                "entry_unit_ids": ["unit:increment"],
                "exit_unit_ids": ["unit:increment"],
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
                        "id": "value",
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
                            "rva": 0x3000,
                            "width": 32,
                            "at": "entry",
                        },
                        "exit": {
                            "kind": "static_slot",
                            "rva": 0x3000,
                            "width": 32,
                            "at": "exit",
                        },
                    }
                ],
                "preserved_state_ids": [],
                "effects": [
                    {
                        "effect_id": "value_written",
                        "unit_id": "unit:increment",
                        "family": "memory_event",
                        "index": 0,
                        "fact_sha256": canonical_sha256_v3(
                            _machine_unit()["semantics"]["memory_events"][0]
                        ),
                    }
                ],
                "callback_operation_ids": [],
                "continuation_unit_ids": [],
            }
        ],
        services=[
            {
                "service_id": "notify",
                "provider": {"kind": "external_site", "site_id": "site:notify"},
                "mediation": "direct",
            }
        ],
    )


def _component_call_authority(
    machine_sha256: str,
) -> tuple[dict[str, object], dict[str, object]]:
    resolution_core = {
        "format": "spaghetti-extractor-component-resolution-slice-v1",
        "status": "checked",
        "program_id": "test-program",
        "executes_original_binary": False,
        "permitted_activation_profiles": ["development"],
        "bindings": {},
        "components": [
            {
                "id": "counter",
                "source": {"operations": {"increment": "counter_increment"}},
            },
            {
                "id": "logger",
                "source": {"operations": {"write": "logger_write"}},
            },
        ],
        "groups": [],
        "configurations": [],
    }
    resolution = {
        **resolution_core,
        "resolution_sha256": canonical_sha256_v3(resolution_core),
    }
    call = {
        "target_component_id": "logger",
        "target_rva": 0x2000,
        "target_unit_id": "unit:logger",
        "callsites": [{"source_unit_id": "unit:increment"}],
        "dependency_sha256": "d" * 64,
    }
    catalog_core = {
        "format": "spaghetti-extractor-semantic-component-catalog-v1",
        "bindings": {"machine_ir_sha256": machine_sha256},
        "components": [
            {
                "id": "counter",
                "definition_status": "valid",
                "component_calls": [call],
                "refinement": {
                    "stages": [
                        {
                            "kind": "component_resolution_v2",
                            "resolution_sha256": resolution["resolution_sha256"],
                        }
                    ]
                },
            },
            {
                "id": "logger",
                "definition_status": "valid",
                "component_calls": [],
            },
        ],
    }
    catalog = {
        **catalog_core,
        "catalog_sha256": canonical_sha256_v3(catalog_core),
    }
    return resolution, catalog


class ComponentMachineBindingTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[Path, Path, dict[str, object], dict[str, object]]:
        unit = _machine_unit()
        machine = root / "machine-ir.jsonl"
        machine.write_text(json.dumps(unit, sort_keys=True) + "\n", encoding="ascii")
        digest = hashlib.sha256(machine.read_bytes()).hexdigest()
        manifest = root / "machine-ir-manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "format": "spaghetti-extractor-machine-ir-v3",
                    "binary": {"sha256": PE_SHA256},
                    "artifacts": {"machine_ir": {"sha256": digest}},
                },
                sort_keys=True,
            )
            + "\n",
            encoding="ascii",
        )
        interface = _interface()
        return machine, manifest, interface, _binding(digest, interface)

    def test_declaration_materializes_exact_artifact_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine, manifest, interface, binding = self._fixture(Path(temporary))
            declaration = {
                "format": COMPONENT_MACHINE_BINDING_DECLARATION_V2,
                "id": binding["id"],
                "unit_ids": binding["unit_ids"],
                "operations": binding["operations"],
                "services": binding["services"],
            }
            materialized = materialize_component_machine_binding(
                declaration=declaration,
                interface=interface,
                machine_ir=machine,
                machine_ir_manifest=manifest,
            )

        self.assertEqual(materialized, binding)
        effect = materialized["operations"][0]["effects"][0]
        self.assertEqual(effect["family"], "memory_event")
        self.assertEqual(
            effect["fact_sha256"],
            canonical_sha256_v3(_machine_unit()["semantics"]["memory_events"][0]),
        )

    def test_v3_declaration_omits_retired_callback_operation_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine, manifest, interface, binding = self._fixture(Path(temporary))
            operations = copy.deepcopy(binding["operations"])
            operations[0].pop("callback_operation_ids")
            materialized = materialize_component_machine_binding(
                declaration={
                    "format": COMPONENT_MACHINE_BINDING_DECLARATION_V3,
                    "id": binding["id"],
                    "unit_ids": binding["unit_ids"],
                    "operations": operations,
                    "services": binding["services"],
                },
                interface=interface,
                machine_ir=machine,
                machine_ir_manifest=manifest,
            )

        self.assertEqual(materialized, binding)

    def test_effect_reference_is_bound_to_exact_machine_fact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine, manifest, interface, binding = self._fixture(Path(temporary))
            stale = copy.deepcopy(binding)
            stale["operations"][0]["effects"][0]["fact_sha256"] = "0" * 64
            stale.pop("binding_sha256")
            stale["binding_sha256"] = canonical_sha256_v3(stale)
            receipt = check_component_machine_binding(
                binding=stale,
                interface=interface,
                machine_ir=machine,
                machine_ir_manifest=manifest,
                external_site_ids=("site:notify",),
            )

        self.assertEqual(receipt["status"], "violated")
        self.assertIn(
            "effect_fact_digest_stale",
            {row["code"] for row in receipt["issues"]},
        )

    def test_effect_reference_family_must_match_logical_effect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine, manifest, interface, binding = self._fixture(Path(temporary))
            incompatible = copy.deepcopy(binding)
            effect = incompatible["operations"][0]["effects"][0]
            effect.update(
                family="external_event",
                index=0,
                fact_sha256=canonical_sha256_v3(
                    _machine_unit()["semantics"]["external_events"][0]
                ),
            )
            incompatible.pop("binding_sha256")
            incompatible["binding_sha256"] = canonical_sha256_v3(incompatible)
            receipt = check_component_machine_binding(
                binding=incompatible,
                interface=interface,
                machine_ir=machine,
                machine_ir_manifest=manifest,
                external_site_ids=("site:notify",),
            )

        self.assertEqual(receipt["status"], "violated")
        self.assertIn(
            "effect_machine_family_incompatible",
            {row["code"] for row in receipt["issues"]},
        )

    def test_bounded_bytes_projection_binds_pointer_and_local_extent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine, manifest, interface, _ = self._fixture(Path(temporary))
            interface["types"].append(
                {
                    "id": "input_bytes",
                    "kind": "bytes",
                    "access": "read",
                    "extent_parameter_id": "extent",
                    "nul_terminated": False,
                }
            )
            interface["operations"][0]["parameters"] = [
                {"id": "input", "type_id": "input_bytes"},
                {"id": "extent", "type_id": "u32"},
            ]
            digest = hashlib.sha256(machine.read_bytes()).hexdigest()
            binding = _binding(digest, interface)
            binding["operations"][0]["parameters"] = [
                {
                    "id": "extent",
                    "projection": {
                        "kind": "stack",
                        "offset": 8,
                        "width": 32,
                        "at": "entry",
                    },
                },
                {
                    "id": "input",
                    "projection": {
                        "kind": "bytes_view",
                        "base": {
                            "kind": "stack",
                            "offset": 4,
                            "width": 32,
                            "at": "entry",
                        },
                        "extent_id": "extent",
                        "at": "entry",
                    },
                },
            ]
            binding.pop("binding_sha256")
            binding["binding_sha256"] = canonical_sha256_v3(binding)
            receipt = check_component_machine_binding(
                binding=binding,
                interface=interface,
                machine_ir=machine,
                machine_ir_manifest=manifest,
                external_site_ids=("site:notify",),
            )

        self.assertEqual(receipt["status"], "checked", receipt["issues"])

    def test_bytes_projection_extent_mismatch_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine, manifest, interface, _ = self._fixture(Path(temporary))
            interface["types"].append(
                {
                    "id": "input_bytes",
                    "kind": "bytes",
                    "access": "read",
                    "extent_parameter_id": "extent",
                    "nul_terminated": False,
                }
            )
            interface["operations"][0]["parameters"] = [
                {"id": "input", "type_id": "input_bytes"},
                {"id": "extent", "type_id": "u32"},
            ]
            digest = hashlib.sha256(machine.read_bytes()).hexdigest()
            binding = _binding(digest, interface)
            binding["operations"][0]["parameters"] = [
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
                        "base": {
                            "kind": "register",
                            "register": "ecx",
                            "width": 32,
                            "at": "entry",
                        },
                        "extent_id": "wrong_extent",
                        "at": "entry",
                    },
                },
            ]
            binding.pop("binding_sha256")
            binding["binding_sha256"] = canonical_sha256_v3(binding)
            receipt = check_component_machine_binding(
                binding=binding,
                interface=interface,
                machine_ir=machine,
                machine_ir_manifest=manifest,
                external_site_ids=("site:notify",),
            )

        self.assertEqual(receipt["status"], "violated")
        self.assertIn(
            "bytes_projection_extent_mismatch",
            {row["code"] for row in receipt["issues"]},
        )

    def test_record_projection_checks_every_logical_field(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine, manifest, interface, _ = self._fixture(Path(temporary))
            interface["types"].append(
                {
                    "id": "pair",
                    "kind": "record",
                    "access": "read",
                    "fields": [
                        {"id": "left", "type_id": "u32"},
                        {"id": "right", "type_id": "u32"},
                    ],
                }
            )
            interface["operations"][0]["parameters"] = [
                {"id": "pair", "type_id": "pair"}
            ]
            digest = hashlib.sha256(machine.read_bytes()).hexdigest()
            binding = _binding(digest, interface)
            binding["operations"][0]["parameters"] = [
                {
                    "id": "pair",
                    "projection": {
                        "kind": "record_view",
                        "at": "entry",
                        "fields": [
                            {
                                "id": "left",
                                "projection": {
                                    "kind": "register",
                                    "register": "ecx",
                                    "width": 32,
                                    "at": "entry",
                                },
                            },
                            {
                                "id": "right",
                                "projection": {
                                    "kind": "register",
                                    "register": "edx",
                                    "width": 32,
                                    "at": "entry",
                                },
                            },
                        ],
                    },
                }
            ]
            binding.pop("binding_sha256")
            binding["binding_sha256"] = canonical_sha256_v3(binding)
            receipt = check_component_machine_binding(
                binding=binding,
                interface=interface,
                machine_ir=machine,
                machine_ir_manifest=manifest,
                external_site_ids=("site:notify",),
            )

        self.assertEqual(receipt["status"], "checked", receipt["issues"])

    def test_declaration_cannot_override_generated_artifact_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine, manifest, interface, binding = self._fixture(Path(temporary))
            declaration = {
                "format": COMPONENT_MACHINE_BINDING_DECLARATION_V2,
                "id": binding["id"],
                "unit_ids": binding["unit_ids"],
                "operations": binding["operations"],
                "services": binding["services"],
                "binary": {"pe_sha256": "0" * 64},
            }
            with self.assertRaises(ComponentMachineBindingError):
                materialize_component_machine_binding(
                    declaration=declaration,
                    interface=interface,
                    machine_ir=machine,
                    machine_ir_manifest=manifest,
                )

    def test_machine_service_event_is_bound_to_exact_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine, manifest, interface, binding = self._fixture(Path(temporary))
            declaration = {
                "format": COMPONENT_MACHINE_BINDING_DECLARATION_V2,
                "id": binding["id"],
                "unit_ids": binding["unit_ids"],
                "operations": binding["operations"],
                "services": [
                    {
                        "service_id": "notify",
                        "provider": {
                            "kind": "machine_events",
                            "events": [
                                {
                                    "unit_id": "unit:increment",
                                    "event_index": 0,
                                    "arguments": [
                                        {
                                            "kind": "register",
                                            "register": "ecx",
                                            "width": 32,
                                            "at": "call",
                                        }
                                    ],
                                    "result": None,
                                }
                            ],
                        },
                        "mediation": "direct",
                    }
                ],
            }
            materialized = materialize_component_machine_binding(
                declaration=declaration,
                interface=interface,
                machine_ir=machine,
                machine_ir_manifest=manifest,
            )
            receipt = check_component_machine_binding(
                binding=materialized,
                interface=interface,
                machine_ir=machine,
                machine_ir_manifest=manifest,
            )

        event = materialized["services"][0]["provider"]["events"][0]
        self.assertEqual(
            event["event_sha256"],
            canonical_sha256_v3(_machine_unit()["semantics"]["external_events"][0]),
        )
        self.assertEqual(receipt["status"], "checked", receipt["issues"])

    def test_component_operation_service_is_bound_to_exact_component_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine, manifest, interface, binding = self._fixture(Path(temporary))
            binding = copy.deepcopy(binding)
            binding["services"] = [
                {
                    "service_id": "notify",
                    "provider": {
                        "kind": "component_operation",
                        "component_id": "logger",
                        "operation_id": "write",
                        "events": [
                            {
                                "unit_id": "unit:increment",
                                "event_index": 0,
                                "event_sha256": canonical_sha256_v3(
                                    _machine_unit()["semantics"]["external_events"][0]
                                ),
                                "arguments": [
                                    {
                                        "kind": "register",
                                        "register": "ecx",
                                        "width": 32,
                                        "at": "call",
                                    }
                                ],
                                "result": None,
                            }
                        ],
                    },
                    "mediation": "direct",
                }
            ]
            binding.pop("binding_sha256")
            binding["binding_sha256"] = canonical_sha256_v3(binding)
            resolution, catalog = _component_call_authority(
                hashlib.sha256(machine.read_bytes()).hexdigest()
            )
            receipt = check_component_machine_binding(
                binding=binding,
                interface=interface,
                machine_ir=machine,
                machine_ir_manifest=manifest,
                component_resolution=resolution,
                semantic_component_catalog=catalog,
            )

        self.assertEqual(receipt["status"], "checked", receipt["issues"])
        self.assertEqual(
            receipt["bindings"]["component_resolution_sha256"],
            resolution["resolution_sha256"],
        )
        self.assertEqual(
            receipt["bindings"]["semantic_component_catalog_sha256"],
            catalog["catalog_sha256"],
        )

    def test_component_operation_service_without_call_authority_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine, manifest, interface, binding = self._fixture(Path(temporary))
            binding = copy.deepcopy(binding)
            binding["services"][0]["provider"] = {
                "kind": "component_operation",
                "component_id": "logger",
                "operation_id": "write",
            }
            binding.pop("binding_sha256")
            binding["binding_sha256"] = canonical_sha256_v3(binding)
            receipt = check_component_machine_binding(
                binding=binding,
                interface=interface,
                machine_ir=machine,
                machine_ir_manifest=manifest,
            )

        self.assertEqual(receipt["status"], "incomplete")
        self.assertIn(
            "component_operation_call_authority_missing",
            {row["code"] for row in receipt["issues"]},
        )

    def test_complete_logical_binding_is_independent_of_runtime_lowering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine, manifest, interface, binding = self._fixture(Path(temporary))
            receipt = check_component_machine_binding(
                binding=binding,
                interface=interface,
                machine_ir=machine,
                machine_ir_manifest=manifest,
                external_site_ids=("site:notify",),
            )
        self.assertEqual(receipt["status"], "checked")
        self.assertTrue(receipt["activation_authorized"])
        self.assertTrue(receipt["policy"]["runtime_lowering_is_separate_authority"])

    def test_unknown_external_provider_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine, manifest, interface, binding = self._fixture(Path(temporary))
            receipt = check_component_machine_binding(
                binding=binding,
                interface=interface,
                machine_ir=machine,
                machine_ir_manifest=manifest,
            )
        self.assertEqual(receipt["status"], "incomplete")
        self.assertIn(
            "external_site_provider_unresolved",
            {row["code"] for row in receipt["issues"]},
        )

    def test_scalar_register_profile_authorizes_runtime_lowering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interface = {
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
            unit = _machine_unit()
            unit["id"] = "unit:run"
            unit["semantics"] = {
                "external_events": [], "memory_events": [], "faults": [],
                "register_writes": [], "flag_writes": [],
                "outcome": {
                    "kind": "return",
                    "value": {"op": "load", "width": 4, "address": {
                        "op": "reg", "name": "esp", "width": 32,
                    }},
                },
            }
            machine = root / "machine-ir.jsonl"
            machine.write_text(json.dumps(unit, sort_keys=True) + "\n", encoding="ascii")
            machine_sha256 = hashlib.sha256(machine.read_bytes()).hexdigest()
            manifest = root / "machine-ir-manifest.json"
            manifest.write_text(json.dumps({
                "format": "spaghetti-extractor-machine-ir-v3",
                "binary": {"sha256": PE_SHA256},
                "artifacts": {"machine_ir": {"sha256": machine_sha256}},
            }), encoding="ascii")
            binding = create_component_machine_binding_v1(
                id="increment",
                binary={"pe_sha256": PE_SHA256, "machine_ir_sha256": machine_sha256},
                interface={"id": "increment", "sha256": canonical_sha256_v3(interface)},
                unit_ids=["unit:run"],
                operations=[{
                    "operation_id": "run",
                    "entry_unit_ids": ["unit:run"],
                    "exit_unit_ids": ["unit:run"],
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
            receipt = check_component_machine_binding(
                binding=binding,
                interface=interface,
                machine_ir=machine,
                machine_ir_manifest=manifest,
            )

        self.assertEqual(receipt["status"], "checked")
        self.assertTrue(receipt["activation_authorized"])
        self.assertTrue(receipt["policy"]["logical_machine_binding_checked"])

    def test_placeholder_projection_is_not_a_binding_language_form(self) -> None:
        with self.assertRaisesRegex(ComponentMachineBindingError, "unsupported kind"):
            MachineProjectionV1.parse(
                {"kind": "reviewed-resource-origin", "evidence": "operator-review-required"}
            )

    def test_finite_control_target_routes_are_canonical_and_unique(self) -> None:
        projection = {
            "kind": "finite_control_target",
            "at": "exit",
            "unit_id": "unit:dispatch",
            "selector_parameter_id": "selector",
            "target_inventory_sha256": "d" * 64,
            "routes": [
                {
                    "selector_value": 0,
                    "logical_value": 1,
                    "target_rva": 0x1100,
                    "target_address": 0x401100,
                },
                {
                    "selector_value": 1,
                    "logical_value": 2,
                    "target_rva": 0x1200,
                    "target_address": 0x401200,
                },
            ],
        }
        parsed = MachineProjectionV1.parse(projection)
        self.assertEqual(parsed.to_payload(), projection)

        duplicate = copy.deepcopy(projection)
        duplicate["routes"][1]["selector_value"] = 0
        with self.assertRaisesRegex(
            ComponentMachineBindingError, "selector values must be unique"
        ):
            MachineProjectionV1.parse(duplicate)

        reversed_routes = copy.deepcopy(projection)
        reversed_routes["routes"].reverse()
        with self.assertRaisesRegex(
            ComponentMachineBindingError, "canonically ordered"
        ):
            MachineProjectionV1.parse(reversed_routes)

    def test_result_decoding_unknown_parameter_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine, manifest, interface, binding = self._fixture(Path(temporary))
            result = binding["operations"][0]["results"][0]
            result["decoding"] = {
                "op": "sub32",
                "args": [
                    {"op": "projected_value"},
                    {"op": "bytes_address", "name": "missing"},
                ],
            }
            core = dict(binding)
            core.pop("binding_sha256")
            binding["binding_sha256"] = canonical_sha256_v3(core)
            receipt = check_component_machine_binding(
                binding=binding,
                interface=interface,
                machine_ir=machine,
                machine_ir_manifest=manifest,
                external_site_ids=("site:notify",),
            )
        self.assertEqual(receipt["status"], "violated")
        self.assertIn(
            "result_decoding_references_unknown_parameter",
            {row["code"] for row in receipt["issues"]},
        )

    def test_stale_machine_digest_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine, manifest, interface, binding = self._fixture(Path(temporary))
            binding["binary"]["machine_ir_sha256"] = "f" * 64
            core = dict(binding)
            core.pop("binding_sha256")
            binding["binding_sha256"] = canonical_sha256_v3(core)
            receipt = check_component_machine_binding(
                binding=binding,
                interface=interface,
                machine_ir=machine,
                machine_ir_manifest=manifest,
                external_site_ids=("site:notify",),
            )
        self.assertEqual(receipt["status"], "violated")


if __name__ == "__main__":
    unittest.main()
