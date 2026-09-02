from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.boundary._canonical import BoundaryModelError
from spaghetti_extractor.boundary.model import BoundarySchemaV1
from spaghetti_extractor.components.binding_intent import (
    ComponentMachineBindingIntentV1,
)
from spaghetti_extractor.components.component_c_v5 import (
    render_component_c_headers_v5,
)
from spaghetti_extractor.components.interface_package_v5 import (
    ComponentInterfaceIntentV1,
    compile_component_interface_v5,
)
from spaghetti_extractor.components.machine_binding import ServiceMachineBindingV1
from spaghetti_extractor.components.machine_overlay_v5 import (
    render_component_dispatch_registry_v1,
    render_component_machine_overlay_v5,
)
from spaghetti_extractor.components.normalized_component import (
    NormalizedComponentContract,
    NormalizedMachineBinding,
)
from spaghetti_extractor.external.resolved import bind_launch_policy_v1
from spaghetti_extractor.transfer.model import _Action, _Call, _Node, _Transfer
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header


ROOT = Path(__file__).parents[3]
TESTKIT = {
    "fixtures": ("compiler",),
    "resources": (
        "targets/gnu-hello/intent/interfaces-v5",
        "targets/gnu-hello/intent/bindings-v5",
        "targets/dxball/intent/interfaces-v5",
    ),
}


def _transfer(identity: str, rva: int) -> _Transfer:
    return _Transfer(identity, "a" * 64, "b" * 64, rva, (), (), (), (), ())


def _component_overlay(
    component_id: str,
    *,
    action_by_unit: dict[str, tuple[_Action, ...]] | None = None,
    call_by_unit: dict[str, tuple[_Call, ...]] | None = None,
    resolved_external_environment: dict[str, object] | None = None,
    code_capabilities: dict[str, dict[str, object]] | None = None,
    authority_selectors: dict[str, list[dict[str, str]]] | None = None,
    object_authority_rule_ids: tuple[str, ...] | None = None,
):
    interface = ComponentInterfaceIntentV1.parse(
        json.loads(
            (
                ROOT / f"targets/gnu-hello/intent/interfaces-v5/{component_id}.json"
            ).read_text(encoding="utf-8")
        )
    )
    binding = ComponentMachineBindingIntentV1.parse(
        json.loads(
            (
                ROOT / f"targets/gnu-hello/intent/bindings-v5/{component_id}.json"
            ).read_text(encoding="utf-8")
        )
    )
    bundle = compile_component_interface_v5(interface)
    contract = NormalizedComponentContract.create(
        interface=bundle.interface,
        machine_semantics=[item.semantics for item in binding.operations],
    )
    machine_binding = None
    if authority_selectors is not None:
        artifact_digest = "a" * 64
        machine_binding = NormalizedMachineBinding.create(
            bundle=bundle,
            contract=contract,
            artifacts={
                "pe_sha256": artifact_digest,
                "machine_ir_sha256": artifact_digest,
                "machine_ir_manifest_sha256": artifact_digest,
                "structural_units_sha256": artifact_digest,
                "unit_inventory_sha256": artifact_digest,
                "component_unit_inventory_sha256": artifact_digest,
            },
            operation_authority={
                item.semantics.operation_id: {
                    **dict(item.authority),
                    "object_authority_selectors": authority_selectors.get(
                        item.semantics.operation_id, []
                    ),
                    "service_ids": list(item.semantics.service_ids),
                    "callback_ids": list(item.semantics.callback_ids),
                    "outcome_protocol_ids": list(item.semantics.outcome_protocol_ids),
                }
                for item in binding.operations
            },
        )
    unit_ids = sorted(
        {
            unit_id
            for operation in binding.operations
            for unit_id in operation.semantics.transfer_ids
        }
    )
    transfers = []
    for unit_id in unit_ids:
        match = re.search(r"original-cutpoint-([0-9a-f]{8})", unit_id)
        assert match is not None
        transfer = _transfer(unit_id, int(match.group(1), 16))
        transfers.append(
            _Transfer(
                transfer.identity,
                transfer.contract_sha256,
                transfer.instruction_bytes_sha256,
                transfer.rva_start,
                transfer.nodes,
                transfer.x87_nodes,
                (action_by_unit or {}).get(unit_id, ()),
                (call_by_unit or {}).get(unit_id, ()),
                transfer.x87_operations,
            )
        )
    return render_component_machine_overlay_v5(
        bundle=bundle,
        contract=contract,
        operation_symbols={
            operation.identity: f"test_{component_id.replace('-', '_')}_{operation.identity}"
            for operation in bundle.interface.operations
        },
        transfers=transfers,
        machine_binding=machine_binding,
        object_authority_rule_ids=object_authority_rule_ids,
        resolved_external_environment=(
            _resolved_environment()
            if resolved_external_environment is None
            else resolved_external_environment
        ),
        code_capabilities=code_capabilities,
    )


def _external_contract(
    identity: dict[str, object], *, abi_template: str, argument_words: int
) -> dict[str, object]:
    return {
        "import_kind": "ordinary",
        "identity": identity,
        "descriptor_index": 0,
        "cell_index": 0,
        "iat_rva": 0x2000,
        "contract": {
            "profile_id": "fixture-profile",
            "profile_sha256": "5" * 64,
            "entry_key": "fixture-entry",
            "entry_index": 0,
            "payload": {
                "id": "fixture-contract",
                "abi_template": abi_template,
                "argument_words": argument_words,
                "result_register_relations": [],
            },
        },
        "boundary": {"fixture": True},
    }


def _resolved_environment(
    *contracts: dict[str, object],
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
    rows = list(contracts)
    result: dict[str, object] = {
        "format": "spaghetti-extractor-resolved-external-environment-v1",
        "status": "complete",
        "bindings": {
            "module_interface_sha256": "1" * 64,
            "module_pe_sha256": "2" * 64,
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
    result["resolved_environment_sha256"] = canonical_sha256_v3(result)
    return result


class ComponentMachineOverlayV5Tests(unittest.TestCase):
    def test_scalar_stack_parameter_and_register_result_use_faithful_exit(self) -> None:
        interface = ComponentInterfaceIntentV1.parse(
            json.loads(
                (
                    ROOT / "targets/gnu-hello/intent/interfaces-v5/ascii-to-lower.json"
                ).read_text(encoding="utf-8")
            )
        )
        binding = ComponentMachineBindingIntentV1.parse(
            json.loads(
                (
                    ROOT / "targets/gnu-hello/intent/bindings-v5/ascii-to-lower.json"
                ).read_text(encoding="utf-8")
            )
        )
        bundle = compile_component_interface_v5(interface)
        contract = NormalizedComponentContract.create(
            interface=bundle.interface,
            machine_semantics=[item.semantics for item in binding.operations],
        )
        rendered = render_component_machine_overlay_v5(
            bundle=bundle,
            contract=contract,
            operation_symbols={"convert": "gnu_hello_ascii_to_lower"},
            transfers=(
                _transfer(
                    "semantic-transfer:original-cutpoint-0000933d-0000934a",
                    0x933D,
                ),
                _transfer(
                    "semantic-transfer:original-cutpoint-0000934a-00009352",
                    0x934A,
                ),
            ),
        )
        self.assertEqual(len(rendered.entries), 1)
        self.assertEqual(
            rendered.entries[0]["owned_unit_ids"],
            ["semantic-transfer:original-cutpoint-0000933d-0000934a"],
        )
        self.assertIn("state->esp + UINT32_C(4)", rendered.source)
        self.assertIn("state->eax = ((uint32_t)logical_result)", rendered.source)
        self.assertIn("SPX_FALLTHROUGH, 0x0000934aU", rendered.source)

        registry = render_component_dispatch_registry_v1(
            entries=rendered.entries,
            portable_unit_rvas={
                "semantic-transfer:original-cutpoint-0000933d-0000934a": 0x933D
            },
        )
        self.assertIn("spx_region_override_lookup", registry)
        self.assertIn("const spx_region_override spx_region_overrides[]", registry)
        self.assertIn("const uint32_t spx_region_override_count", registry)
        self.assertNotIn("spx_portable_overrides", registry)
        self.assertNotIn("spx_native_machine_fallback_allowed", registry)
        self.assertNotIn("fallback_on_unimplemented", registry)

    def test_control_result_uses_exact_machine_branch_targets(self) -> None:
        unit_id = "semantic-transfer:original-cutpoint-000011ac-000011b3"
        rendered = _component_overlay(
            "short-option-classifier",
            action_by_unit={unit_id: (_Action("outcome_branch", (0, 0x1200, 0x1300)),)},
        )
        self.assertIn(
            "logical_result != 0U ? UINT32_C(4608) : UINT32_C(4864)",
            rendered.source,
        )
        self.assertIn("(void)rt;", rendered.source)
        self.assertIn("(void)spx_component_read;", rendered.source)
        self.assertIn("SPX_BRANCH", rendered.source)

    def test_finite_control_target_is_total_and_fails_closed(self) -> None:
        rendered = _component_overlay("finite-selector-dispatch")
        self.assertIn("switch ((uint32_t)logical_result)", rendered.source)
        self.assertIn("case UINT32_C(11)", rendered.source)
        self.assertIn("SPX_JUMP, UINT32_C(15128)", rendered.source)
        self.assertIn(
            "default: return (spx_step_result){ SPX_UNIMPLEMENTED, 0U, 0U };",
            rendered.source,
        )

    def test_view_is_resolved_with_checked_extent_and_no_static_context(self) -> None:
        rendered = _component_overlay("bounded-string-length")
        self.assertIn("rt->resolve_reference", rendered.source)
        self.assertIn("argument_maximum", rendered.source)
        self.assertIn("argument_buffer_machine.extent", rendered.source)
        self.assertIn("offset >= view->extent", rendered.source)
        self.assertNotIn("static spx_bounded_string_length_context_v5", rendered.source)

    def test_atomic_object_calls_shared_runtime_directly(self) -> None:
        exit_unit = "semantic-transfer:original-cutpoint-0000105a-0000105c"
        rendered = _component_overlay(
            "startup-atomic-compare-exchange",
            action_by_unit={
                exit_unit: (_Action("outcome_branch", (0, 0x1050, 0x105C)),)
            },
        )
        self.assertIn("spx_runtime_atomic_compare_exchange", rendered.source)
        self.assertIn("spx_runtime_atomic_exchange", rendered.source)
        self.assertIn("UINT32_C(4391716)", rendered.source)
        self.assertIn(
            "logical_result != 0U ? UINT32_C(4176) : UINT32_C(4188)", rendered.source
        )

    def test_component_operation_service_uses_typed_provider_thunk(self) -> None:
        rendered = _component_overlay("ascii-string-compare")
        provider_overlay = _component_overlay("ascii-to-lower")
        provider = "spx_component_logical_ascii_to_lower_convert"
        self.assertIn(f"extern uint32_t {provider}(void *, uint32_t);", rendered.source)
        self.assertIn(
            "spx_ascii_string_compare_services_v5 logical_services",
            rendered.source,
        )
        self.assertIn(f"&service_context, {provider}", rendered.source)
        self.assertEqual(
            rendered.entries[0]["service_bindings"][0]["provider_component_id"],
            "ascii-to-lower",
        )
        self.assertEqual(
            rendered.entries[0]["service_bindings"][0]["abi_sha256"],
            provider_overlay.entries[0]["logical_abi_sha256"],
        )
        unit_rvas = {}
        for entry in (*rendered.entries, *provider_overlay.entries):
            for unit_id in entry["owned_unit_ids"]:
                match = re.search(r"original-cutpoint-([0-9a-f]{8})", unit_id)
                assert match is not None
                unit_rvas[unit_id] = int(match.group(1), 16)
        registry = render_component_dispatch_registry_v1(
            entries=(*rendered.entries, *provider_overlay.entries),
            portable_unit_rvas=unit_rvas,
        )
        self.assertIn("spx_region_override_lookup", registry)

        incompatible = [dict(entry) for entry in rendered.entries]
        incompatible[0]["service_bindings"] = [
            {
                **incompatible[0]["service_bindings"][0],
                "abi_sha256": "0" * 64,
            }
        ]
        with self.assertRaisesRegex(BoundaryModelError, "ABI-incompatible"):
            render_component_dispatch_registry_v1(
                entries=(*incompatible, *provider_overlay.entries),
                portable_unit_rvas=unit_rvas,
            )

    def test_external_service_uses_authorized_call_frame_and_reference_realization(
        self,
    ) -> None:
        unit_id = "semantic-transfer:original-cutpoint-00008d6f-00008d7f"
        site_id = (
            "external-site-v3:"
            "113b3481e724d854f3ba27d44c90758a943de5b69ade25293e7db67512986955"
        )
        call = _Call(
            "external_call",
            0x8D76,
            0,
            None,
            0,
            0x8D7B,
            "msvcrt.dll",
            "memcmp",
            None,
            (),
            (),
            (),
            ((0, 4, 0), (4, 4, 0), (8, 4, 0)),
        )

        def stack_word(offset: int) -> dict[str, object]:
            return {
                "op": "load",
                "width": 4,
                "address": (
                    {"op": "reg", "name": "esp", "width": 32}
                    if offset == 0
                    else {
                        "op": "add32",
                        "args": [
                            {"op": "reg", "name": "esp", "width": 32},
                            {"op": "const", "value": offset, "width": 32},
                        ],
                        "width": 32,
                    }
                ),
            }

        site = {
            "id": site_id,
            "status": "complete",
            "authorizing": True,
            "primary_blocker": None,
            "unit_id": unit_id,
            "event_index": 0,
            "identity": {"dll": "msvcrt.dll", "symbol": "memcmp", "ordinal": None},
            "contract": {
                "arguments": [stack_word(0), stack_word(4), stack_word(8)],
                "machine_contract": {"abi_template": "pe32-cdecl-v1"},
            },
        }
        rendered = _component_overlay(
            "memory-regions-equal",
            call_by_unit={unit_id: (call,)},
            resolved_external_environment=_resolved_environment(
                _external_contract(
                    dict(site["identity"]),
                    abi_template="pe32-cdecl-v1",
                    argument_words=3,
                )
            ),
        )
        source = rendered.source
        self.assertIn(
            "spx_component_external_memory_regions_equal_compare_memory", source
        )
        self.assertIn("spx_machine_reference_v1 physical_argument_0_reference", source)
        self.assertIn("service->runtime->realize_reference", source)
        self.assertIn("call_input.esp -= UINT32_C(12)", source)
        self.assertIn('"msvcrt.dll", "memcmp"', source)
        self.assertIn("spx_invoke_call", source)
        self.assertIn("saved_frame_word_2", source)
        self.assertIn("SPX_EXTERNAL_FAULT", source)

        stale_site = dict(site)
        stale_site["identity"] = {
            "dll": "msvcrt.dll",
            "symbol": "strcmp",
            "ordinal": None,
        }
        with self.assertRaisesRegex(BoundaryModelError, "contract is absent"):
            _component_overlay(
                "memory-regions-equal",
                call_by_unit={unit_id: (call,)},
                resolved_external_environment=_resolved_environment(
                    _external_contract(
                        dict(stale_site["identity"]),
                        abi_template="pe32-cdecl-v1",
                        argument_words=3,
                    )
                ),
            )

    def test_interface_method_service_checks_receiver_and_out_interface(self) -> None:
        raw = json.loads(
            (
                ROOT / "targets/dxball/intent/interfaces-v5/directdraw-init.json"
            ).read_text(encoding="utf-8")
        )
        types = {row["id"]: dict(row) for row in raw["schema"]["types"]}
        types["operation.initialize.function"] = {
            **types["operation.initialize.function"],
            "parameter_type_ids": [],
            "result_type_id": "unit",
        }
        types["service.set_cooperative_level.function"] = {
            **types["service.set_cooperative_level.function"],
            "parameter_type_ids": ["directdraw", "surface"],
        }
        signatures = {row["id"]: dict(row) for row in raw["schema"]["signatures"]}
        signatures["operation.initialize"] = {
            **signatures["operation.initialize"],
            "parameters": [],
            "results": [],
        }
        method_signature = json.loads(
            json.dumps(signatures["service.set_cooperative_level"])
        )
        method_signature["parameters"] = [
            method_signature["parameters"][0],
            {
                "access": "write",
                "extent": {"bytes": None, "kind": "none", "value_id": None},
                "id": "created",
                "interpretation": "resource",
                "nullable": False,
                "provider_domain": "component-environment.directdraw-init",
                "resource_kind": "directdraw_surface",
                "type_id": "surface",
            },
        ]
        signatures["service.set_cooperative_level"] = method_signature
        schema = BoundarySchemaV1.create(
            schema_id="component.interface-method-fixture",
            types=[
                types[name]
                for name in (
                    "directdraw",
                    "operation.initialize.function",
                    "service.set_cooperative_level.function",
                    "status",
                    "surface",
                    "status-underlying",
                    "unit",
                )
            ],
            signatures=[
                signatures["operation.initialize"],
                signatures["service.set_cooperative_level"],
            ],
        )
        operation = json.loads(json.dumps(raw["operations"][0]))
        operation.update(
            {
                "allowed_service_ids": ["set_cooperative_level"],
                "effect_ids": [],
                "lifecycle_bindings": [],
                "projection_entries": [],
                "source_values": [],
            }
        )
        intent = ComponentInterfaceIntentV1.create(
            component_id="interface-method-fixture",
            schema=schema,
            state=[],
            operations=[operation],
            effects=[],
            services=[
                next(
                    row
                    for row in raw["services"]
                    if row["id"] == "set_cooperative_level"
                ),
                {
                    "id": "unused",
                    "signature_id": "service.set_cooperative_level",
                    "effect_ids": [],
                    "interaction_contract_id": "component-service.fixture.unused",
                },
            ],
            protocol_states=["ready"],
            initial_protocol_state="ready",
        )
        bundle = compile_component_interface_v5(intent)
        unit_id = "semantic-transfer:original-cutpoint-0000cdb7-0000cdbd"
        profile_sha256 = "7" * 64
        relation = {
            "argument_index": 2,
            "interface_id": "IFixtureChild",
            "nullable": False,
            "object_size": 4,
            "success_condition": "hresult_succeeded_eax",
            "vtable_size": 12,
            "write_width": 4,
        }
        relation_sha256 = canonical_sha256_v3(relation)
        transducers = [
            {"kind": "logical_argument", "parameter_index": 0},
            {"kind": "constant", "value": 0},
            {
                "kind": "out_interface",
                "parameter_index": 1,
                "out_interface_relation_sha256": relation_sha256,
            },
            {"kind": "constant", "value": 0},
        ]
        method = {
            "argument_words": 4,
            "callback_effect": "none",
            "external_protocol": {
                "kind": "pe32-interface-method",
                "profile_id": "fixture-profile",
                "profile_sha256": profile_sha256,
                "interface_id": "IFixture",
                "method": "CreateChild",
                "slot": 4,
                "offset": 16,
            },
            "receiver_resource": {
                "argument_index": 0,
                "dispatch_slot": 4,
                "lifecycle_effect": "preserve",
                "required_state": "live",
                "view_id": "IFixture",
            },
            "argument_interfaces": [{"argument_index": 0, "interface_id": "IFixture"}],
            "out_interfaces": [relation],
        }
        method_core = {
            "profile_id": "fixture-profile",
            "profile_sha256": profile_sha256,
            "interface_id": "IFixture",
            "method": method,
        }
        method_sha256 = canonical_sha256_v3(method_core)
        parsed_service = ServiceMachineBindingV1.parse(
            {
                "service_id": "set_cooperative_level",
                "mediation": "direct",
                "provider": {
                    "kind": "interface_method",
                    "events": [{"unit_id": unit_id, "event_index": 0}],
                    "method_contract_sha256": method_sha256,
                    "argument_transducers": transducers,
                },
            },
            "fixture interface method",
        )
        self.assertEqual(parsed_service.provider["kind"], "interface_method")
        operation_binding = {
            "id": "initialize",
            "kind": "operation",
            "unit_ids": [unit_id],
            "entry_rvas": [0xCDB7],
            "transfer_ids": [unit_id],
            "effect_ids": [],
            "service_ids": ["set_cooperative_level"],
            "callback_ids": [],
            "outcome_protocol_ids": [],
            "machine_projection": {
                "operation": {
                    "operation_id": "initialize",
                    "entry_unit_ids": [unit_id],
                    "exit_unit_ids": [unit_id],
                    "parameters": [],
                    "results": [],
                    "state": [],
                    "preserved_state_ids": [],
                    "effects": [],
                    "callback_operation_ids": [],
                    "continuation_unit_ids": [],
                },
                "service_bindings": [
                    {
                        "service_id": "set_cooperative_level",
                        "mediation": "direct",
                        "provider": {
                            "kind": "interface_method",
                            "events": [{"unit_id": unit_id, "event_index": 0}],
                            "method_contract_sha256": method_sha256,
                            "argument_transducers": transducers,
                        },
                    }
                ],
            },
            "object_authority_selectors": [],
            "pointer_views": [],
            "relation_receipt_sha256s": [],
            "induction_evidence_sha256": None,
        }
        binding = ComponentMachineBindingIntentV1.create(
            component_id="interface-method-fixture",
            operations=[operation_binding],
        )
        contract = NormalizedComponentContract.create(
            interface=bundle.interface,
            machine_semantics=[binding.operations[0].semantics],
        )
        transfer = _Transfer(
            unit_id,
            "a" * 64,
            "b" * 64,
            0xCDB7,
            (
                _Node("const", immediate=16),
                _Node("reg", aux=2),
                _Node("load", (1,), aux=4),
                _Node("add32", (0, 2)),
                _Node("load", (3,), aux=4),
                _Node("const", immediate=1),
                _Node("const", immediate=2),
                _Node("const", immediate=0),
            ),
            (),
            (),
            (
                _Call(
                    "indirect_call",
                    0xCDBA,
                    0,
                    4,
                    0,
                    0xCDBD,
                    None,
                    None,
                    None,
                    (),
                    (),
                    (1, 5, 6, 7),
                    ((0, 4, 1),),
                ),
            ),
            (),
        )
        rendered = render_component_machine_overlay_v5(
            bundle=bundle,
            contract=contract,
            operation_symbols={"initialize": "fixture_initialize"},
            transfers=(transfer,),
            resolved_external_environment=_resolved_environment(
                interface_catalogs=(
                    {
                        "profile_id": "fixture-profile",
                        "profile_sha256": profile_sha256,
                        "interface_id": "IFixture",
                        "methods": [method],
                    },
                ),
            ),
        )
        self.assertIn("realize_interface_resource", rendered.source)
        self.assertIn("physical_out_interface_1", rendered.source)
        self.assertIn("resolved_out_interface_1", rendered.source)
        self.assertIn("interface_vtable + UINT32_C(16)", rendered.source)
        self.assertIn("SPX_CALL_INDIRECT", rendered.source)
        self.assertRegex(
            rendered.source,
            r"spx_interface_method_fixture_services_v5 logical_services = \{\s*"
            r"&service_context, [^,]+, 0\s*\};",
        )
        self.assertIn(method_sha256, json.dumps(rendered.entries))





if __name__ == "__main__":
    unittest.main()
