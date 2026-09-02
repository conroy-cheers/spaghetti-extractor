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

class ComponentMachineOverlayResourceV5Tests(unittest.TestCase):
    def test_factory_service_uses_checked_hresult_out_interface_cell(self) -> None:
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
        identity = {
            "dll": "fixture-provider.dll",
            "symbol": "CreateFixture",
            "ordinal": None,
        }
        schema = BoundarySchemaV1.create(
            schema_id="component.interface-factory-fixture",
            types=[
                {
                    "id": "directdraw",
                    "kind": "opaque",
                    "nominal_id": "fixture.directdraw",
                },
                {
                    "id": "status-underlying",
                    "kind": "integer",
                    "signed": True,
                    "width_bits": 32,
                },
                {
                    "id": "status",
                    "kind": "enum",
                    "underlying_type_id": "status-underlying",
                    "enumerators": [],
                },
                {"id": "unit", "kind": "void"},
                {
                    "id": "operation.run.function",
                    "kind": "function",
                    "result_type_id": "unit",
                    "parameter_type_ids": [],
                    "variadic": False,
                    "calling_convention": "cdecl",
                },
                {
                    "id": "service.create.function",
                    "kind": "function",
                    "result_type_id": "status",
                    "parameter_type_ids": ["directdraw"],
                    "variadic": False,
                    "calling_convention": "cdecl",
                },
            ],
            signatures=[
                {
                    "id": "operation.run",
                    "function_type_id": "operation.run.function",
                    "parameters": [],
                    "results": [],
                },
                {
                    "id": "service.create",
                    "function_type_id": "service.create.function",
                    "parameters": [
                        {
                            "id": "created",
                            "type_id": "directdraw",
                            "interpretation": "resource",
                            "nullable": False,
                            "access": "write",
                            "extent": {"kind": "none", "bytes": None, "value_id": None},
                            "resource_kind": "fixture_object",
                            "provider_domain": "component-environment.fixture",
                        }
                    ],
                    "results": [
                        {
                            "id": "status",
                            "type_id": "status",
                            "interpretation": "value",
                            "nullable": False,
                            "access": "none",
                            "extent": {"kind": "none", "bytes": None, "value_id": None},
                            "resource_kind": None,
                            "provider_domain": None,
                        }
                    ],
                },
            ],
        )
        intent = ComponentInterfaceIntentV1.create(
            component_id="interface-factory-fixture",
            schema=schema,
            state=[],
            operations=[
                {
                    "id": "run",
                    "signature_id": "operation.run",
                    "source_values": [],
                    "projection_entries": [],
                    "lifecycle_bindings": [],
                    "lifecycle_additional_roots": {"state": []},
                    "checked_interaction_contract_ids": [],
                    "effect_ids": [],
                    "allowed_service_ids": ["create"],
                    "pre_states": ["ready"],
                    "post_states": ["ready"],
                }
            ],
            effects=[
                {
                    "id": "created",
                    "kind": "resource",
                    "operation": "run",
                    "target": None,
                }
            ],
            services=[
                {
                    "id": "create",
                    "signature_id": "service.create",
                    "effect_ids": ["created"],
                    "interaction_contract_id": "component-service.fixture.create",
                }
            ],
            protocol_states=["ready"],
            initial_protocol_state="ready",
        )
        bundle = compile_component_interface_v5(intent)
        unit_id = "semantic-transfer:original-cutpoint-00001000-00001010"
        transducers = [
            {"kind": "constant", "value": 0},
            {
                "kind": "out_interface",
                "parameter_index": 0,
                "out_interface_relation_sha256": relation_sha256,
            },
            {"kind": "constant", "value": 0},
        ]
        service_binding = {
            "service_id": "create",
            "mediation": "direct",
            "provider": {
                "kind": "external_call",
                "events": [{"unit_id": unit_id, "event_index": 0}],
                "identity": identity,
                "argument_transducers": transducers,
            },
        }
        ServiceMachineBindingV1.parse(service_binding, "factory service")
        binding = ComponentMachineBindingIntentV1.create(
            component_id="interface-factory-fixture",
            operations=[
                {
                    "id": "run",
                    "kind": "operation",
                    "unit_ids": [unit_id],
                    "entry_rvas": [0x1000],
                    "transfer_ids": [unit_id],
                    "effect_ids": [],
                    "service_ids": ["create"],
                    "callback_ids": [],
                    "outcome_protocol_ids": [],
                    "object_authority_selectors": [],
                    "pointer_views": [],
                    "relation_receipt_sha256s": [],
                    "induction_evidence_sha256": None,
                    "machine_projection": {
                        "operation": {
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
                        },
                        "service_bindings": [service_binding],
                    },
                }
            ],
        )
        contract = NormalizedComponentContract.create(
            interface=bundle.interface,
            machine_semantics=[binding.operations[0].semantics],
        )
        transfer = _Transfer(
            unit_id,
            "a" * 64,
            "b" * 64,
            0x1000,
            (),
            (),
            (),
            (
                _Call(
                    "external_call",
                    0x1004,
                    0,
                    None,
                    0,
                    0x1009,
                    identity["dll"],
                    identity["symbol"],
                    None,
                    (),
                    (),
                    (0, 0, 0),
                    ((0, 4, 0), (4, 4, 0), (8, 4, 0)),
                ),
            ),
            (),
        )
        external = _external_contract(
            identity, abi_template="pe32-stdcall-v1", argument_words=3
        )
        external["contract"]["payload"].update(
            {
                "out_interface_relations": [relation],
                "result_register_relations": [{"register": "eax", "relation": "exact"}],
            }
        )
        rendered = render_component_machine_overlay_v5(
            bundle=bundle,
            contract=contract,
            operation_symbols={"run": "fixture_run"},
            transfers=(transfer,),
            resolved_external_environment=_resolved_environment(external),
        )
        source = rendered.source
        self.assertIn("spx_resource_v5 * logical_created", source)
        self.assertIn("call_input.esp -= UINT32_C(16)", source)
        self.assertIn("physical_argument_1 = call_input.esp + UINT32_C(12)", source)
        self.assertIn("physical_argument_0 = UINT32_C(0)", source)
        self.assertIn("physical_argument_2 = UINT32_C(0)", source)
        self.assertIn("physical_out_interface_0", source)
        self.assertIn("resolve_interface_resource", source)
        self.assertIn("if ((int32_t)call_output.eax >= INT32_C(0))", source)
        self.assertIn(
            "logical_created->identity = resolved_out_interface_0.identity", source
        )

        compilers = [shutil.which("cc"), shutil.which("i686-w64-mingw32-gcc")]
        if any(compiler is None for compiler in compilers):
            self.skipTest("host and PE32 compilers are required")
        headers = render_component_c_headers_v5(bundle, {"run": "fixture_run"})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, body in headers.items():
                (root / name).write_text(body, encoding="ascii")
            (root / "state-machine-runtime.h").write_text(
                exact_runtime_header(), encoding="ascii"
            )
            source_path = root / "factory-overlay.c"
            source_path.write_text(source, encoding="ascii")
            for index, compiler in enumerate(compilers):
                assert compiler is not None
                subprocess.run(
                    [
                        compiler,
                        "-std=c11",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        "-I",
                        str(root),
                        "-c",
                        str(source_path),
                        "-o",
                        str(root / f"factory-overlay-{index}.o"),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )

        stale_binding = json.loads(json.dumps(service_binding))
        stale_binding["provider"]["argument_transducers"][1][
            "out_interface_relation_sha256"
        ] = "0" * 64
        stale_machine = ComponentMachineBindingIntentV1.create(
            component_id="interface-factory-fixture",
            operations=[
                {
                    **binding.operations[0].to_payload(),
                    "machine_projection": {
                        **binding.operations[0].semantics.machine_projection,
                        "service_bindings": [stale_binding],
                    },
                }
            ],
        )
        stale_contract = NormalizedComponentContract.create(
            interface=bundle.interface,
            machine_semantics=[stale_machine.operations[0].semantics],
        )
        with self.assertRaisesRegex(BoundaryModelError, "relation is incompatible"):
            render_component_machine_overlay_v5(
                bundle=bundle,
                contract=stale_contract,
                operation_symbols={"run": "fixture_run"},
                transfers=(transfer,),
                resolved_external_environment=_resolved_environment(external),
            )

        stale_argument_transfer = _Transfer(
            unit_id,
            "a" * 64,
            "b" * 64,
            0x1000,
            (),
            (),
            (),
            (
                _Call(
                    "external_call",
                    0x1004,
                    0,
                    None,
                    0,
                    0x1009,
                    identity["dll"],
                    identity["symbol"],
                    None,
                    (),
                    (),
                    (0, 1, 0),
                    ((0, 4, 0), (4, 4, 0), (8, 4, 0)),
                ),
            ),
            (),
        )
        with self.assertRaisesRegex(
            BoundaryModelError,
            "logical argument projection disagrees with its stack frame",
        ):
            render_component_machine_overlay_v5(
                bundle=bundle,
                contract=contract,
                operation_symbols={"run": "fixture_run"},
                transfers=(stale_argument_transfer,),
                resolved_external_environment=_resolved_environment(external),
            )

    def test_persistent_reference_state_uses_mapped_slot_and_checked_result(
        self,
    ) -> None:
        call_unit = "semantic-transfer:original-cutpoint-00002b64-00002b6c"
        exit_a = "semantic-transfer:original-cutpoint-00002bce-00002bd3"
        exit_b = "semantic-transfer:original-cutpoint-00002bdf-00002be6"
        site_id = (
            "external-site-v3:"
            "28e4cfa5ebca214f1579d0efdb5ecafe8dccdf5d54848663807e2b11f7b467f6"
        )

        def stack_word(offset: int) -> dict[str, object]:
            address: dict[str, object] = {"op": "reg", "name": "esp", "width": 32}
            if offset:
                address = {
                    "op": "add32",
                    "args": [address, {"op": "const", "value": offset, "width": 32}],
                    "width": 32,
                }
            return {"op": "load", "width": 4, "address": address}

        call = _Call(
            "external_call",
            0x2B67,
            0,
            None,
            0,
            0x2B6C,
            "msvcrt.dll",
            "strrchr",
            None,
            (),
            (),
            (),
            ((0, 4, 0), (4, 4, 0)),
        )
        site = {
            "id": site_id,
            "status": "complete",
            "authorizing": True,
            "primary_blocker": None,
            "unit_id": call_unit,
            "event_index": 0,
            "identity": {"dll": "msvcrt.dll", "symbol": "strrchr", "ordinal": None},
            "contract": {
                "arguments": [stack_word(0), stack_word(4)],
                "machine_contract": {"abi_template": "pe32-cdecl-v1"},
            },
        }
        rendered = _component_overlay(
            "program-name-selection",
            action_by_unit={
                exit_a: (_Action("outcome_return", (0,)),),
                exit_b: (_Action("outcome_return", (0,)),),
            },
            call_by_unit={call_unit: (call,)},
            resolved_external_environment=_resolved_environment(
                _external_contract(
                    dict(site["identity"]),
                    abi_template="pe32-cdecl-v1",
                    argument_words=2,
                )
            ),
            authority_selectors={
                "select": [
                    {
                        "authority_id": "argv_string",
                        "rule_id": "external:process-argv",
                    }
                ],
            },
            object_authority_rule_ids=("external:process-argv",),
        )
        source = rendered.source
        self.assertIn("UINT32_C(4391072)", source)
        self.assertIn("component_state_program_name_old_word", source)
        self.assertIn("component_state_program_name_new_word", source)
        self.assertIn("component_state_restore_fault", source)
        self.assertIn("service_result_reference", source)
        self.assertGreaterEqual(source.count('"external:process-argv"'), 3)
        self.assertIn("call_output.eax, UINT32_C(1), UINT32_C(1)", source)
        self.assertIn("SPX_FALLTHROUGH, 0x00002bceU", source)
        self.assertNotIn("static spx_program_name_selection_context", source)

        with self.assertRaisesRegex(BoundaryModelError, "selector is unresolved"):
            _component_overlay(
                "program-name-selection",
                action_by_unit={
                    exit_a: (_Action("outcome_return", (0,)),),
                    exit_b: (_Action("outcome_return", (0,)),),
                },
                call_by_unit={call_unit: (call,)},
                resolved_external_environment=_resolved_environment(
                    _external_contract(
                        dict(site["identity"]),
                        abi_template="pe32-cdecl-v1",
                        argument_words=2,
                    )
                ),
                authority_selectors={
                    "select": [
                        {
                            "authority_id": "argv_string",
                            "rule_id": "external:process-argv",
                        }
                    ],
                },
                object_authority_rule_ids=("image:other",),
            )

    def test_callback_service_uses_the_linked_code_capability_bridge(self) -> None:
        unit_id = "semantic-transfer:original-cutpoint-00001137-00001144"
        capability_id = (
            "code-capability-v1:"
            "aaa404cf58e58b341a80ff316e8d88fb5d7d3b3748d69578dedb20d2e18f2129"
        )
        site_id = (
            "external-site-v3:"
            "12325277926d47f6a2b0994e2b05207ba9c19427b84dab100751e4307459e418"
        )
        call = _Call(
            "external_call",
            0x113B,
            0,
            None,
            0,
            0x1140,
            "kernel32.dll",
            "SetUnhandledExceptionFilter",
            None,
            (),
            (),
            (),
            ((0, 4, 0),),
        )
        site = {
            "id": site_id,
            "status": "complete",
            "authorizing": True,
            "primary_blocker": None,
            "unit_id": unit_id,
            "event_index": 0,
            "identity": {
                "dll": "kernel32.dll",
                "symbol": "SetUnhandledExceptionFilter",
                "ordinal": None,
            },
            "contract": {
                "arguments": [
                    {
                        "op": "load",
                        "width": 4,
                        "address": {"op": "reg", "name": "esp", "width": 32},
                    }
                ],
                "machine_contract": {"abi_template": "pe32-stdcall-v1"},
            },
        }
        capability = {
            "capability_id": capability_id,
            "protocol_id": "win32-unhandled-exception-filter",
            "target_rva": 0xA9A0,
            "target_word": 0x40A9A0,
            "lifetime": "until_replaced_or_process_exit",
        }
        rendered = _component_overlay(
            "startup-callback-registration",
            call_by_unit={unit_id: (call,)},
            resolved_external_environment=_resolved_environment(
                _external_contract(
                    dict(site["identity"]),
                    abi_template="pe32-stdcall-v1",
                    argument_words=1,
                )
            ),
            code_capabilities={capability_id: capability},
        )
        source = rendered.source
        self.assertIn("spx_native_code_bridge_address", source)
        self.assertIn("struct spx_callback_exception_filter_v5", source)
        self.assertIn("spx_native_code_bridge_address(UINT32_C(43424))", source)
        self.assertIn("logical_argument_0000->physical_word", source)
        self.assertIn(
            "service->callback_result.physical_word = call_output.eax", source
        )
        self.assertIn("logical_result->physical_word", source)
