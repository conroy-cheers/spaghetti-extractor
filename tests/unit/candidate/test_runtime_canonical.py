from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.calls.frame import PhysicalCallFrameV2
from spaghetti_extractor.candidate.behavioral_c import (
    write_spx_behavioral_c_package,
)
from spaghetti_extractor.candidate.formats import (
    MODULE_RUNTIME_PLAN_FORMAT,
    NATIVE_INGRESS_PLAN_FORMAT,
)
from spaghetti_extractor.candidate.native_ingress_runtime import exact_tls_regions
from spaghetti_extractor.candidate.runtime import (
    _bind_dynamic_external_object_rules,
    plan_shared_module_runtime,
    write_shared_module_runtime_package,
    write_shared_module_runtime_package_from_linked_module,
)
from spaghetti_extractor.candidate.runtime_model import (
    CandidateRuntimeError,
    INTERFACE_METHOD_TARGET_TAG,
    NativeExternalRangeRule,
    NativeGuestDispatchDomain,
    NativeObjectAuthorityRule,
    interface_class_catalog,
    interface_method_target_catalog,
)
from spaghetti_extractor.candidate.runtime_external_range_validation import (
    _external_range_rules,
)
from spaghetti_extractor.candidate.module_runtime_plan import (
    NativeExternalSite,
    normalized_external_site_inventory_v2,
)
from spaghetti_extractor.candidate.runtime_plan_validation import (
    expanded_external_sites_v8,
)
from spaghetti_extractor.candidate.runtime_canonical import (
    CanonicalRuntimeError,
    _callback_adapter,
    _callback_capability_index,
    _checked_contract,
    _checked_interface_method_contract,
    _loader_service_index,
    guest_dispatch_from_linked_module_v2,
    plan_module_runtime_from_canonical,
)
from spaghetti_extractor.candidate.runtime_canonical_build import (
    external_service_runtime_blockers_v2,
    external_service_runtime_routes_v2,
    interface_callback_runtime_blockers_v1,
)
from spaghetti_extractor.semantic_objects.object_authority import (
    LoaderRealizedLocatorV2,
    MachineObjectAuthorityV2,
    MachineObjectRuleV2,
)
from spaghetti_extractor.external.formats import (
    RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT,
)
from spaghetti_extractor.external.resolved import bind_launch_policy_v1
from spaghetti_extractor.testkit.transfer_fixture import (
    as_machine_ir_unit,
    transfer_row,
    write_fixture_transfer_plan,
)
from spaghetti_extractor.transfer.formats import (
    MODULE_EXECUTION_CLOSURE_FORMAT,
)
from spaghetti_extractor.transfer.plan import load_executable_transfer_plan
from spaghetti_extractor.util import sha256_file, write_json


def _external_range_rule(
    contract_id: str, instruction_rva: int = 0x1234
) -> NativeExternalRangeRule:
    return NativeExternalRangeRule(
        instruction_rva=instruction_rva,
        target_iat_rva=0x3000,
        target_catalog_index=None,
        interface_class_index=None,
        action="add_result_range",
        argument_base_offset=0,
        argument_count=1,
        register="eax",
        argument=None,
        size_kind="fixed",
        size_value=32,
        size_argument=None,
        size_right_argument=None,
        minimum_size=0,
        nullable=False,
        termination_unit_bytes=0,
        termination_zero_units=0,
        termination_max_units=0,
        pointee_offset=0,
        max_elements=0,
        element_unit_bytes=0,
        element_max_units=0,
        contract_id=contract_id,
    )


def _inputs(root: Path) -> dict[str, Path]:
    machine = root / "machine-ir.jsonl"
    row = transfer_row()
    row["outcome"] = {
        "kind": "indirect_jump",
        "target": {"op": "const", "value": 0x401000, "width": 32},
    }
    second = transfer_row()
    second["id"] = "semantic-transfer:globally-valid-but-not-site-authorized"
    second["contract_sha256"] = "c" * 64
    second["instruction_bytes_sha256"] = "d" * 64
    second["original"] = {"rva_start": 0x2000, "rva_end": 0x2003, "size": 3}
    second["outcome"] = {
        "kind": "return",
        "value": {"op": "reg", "name": "eax", "width": 32},
    }
    machine.write_text(
        "\n".join((
            json.dumps(as_machine_ir_unit(row), sort_keys=True),
            json.dumps(as_machine_ir_unit(second), sort_keys=True),
            "",
        )),
        encoding="utf-8",
    )
    transfer = write_fixture_transfer_plan(machine)
    transfer_payload = json.loads(transfer.read_text(encoding="utf-8"))
    unit = transfer_payload["unit_inventory"][0]
    other_unit = transfer_payload["unit_inventory"][1]

    environment_core = {
        "format": RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT,
        "status": "complete",
        "bindings": {"module_pe_sha256": "1" * 64},
        "target": {},
        "launch_policy": bind_launch_policy_v1(
            {
                "format": "spaghetti-extractor-pe32-launch-assumption-template-v1",
                "schema_version": 1,
            },
            source_sha256="0" * 64,
            filename="fixture-launch.json",
        ),
        "canonical_boundaries": [],
        "interface_method_catalogs": [],
        "machine_import_contracts": [{
            "iat_rva": 0x3000,
            "import_kind": "ordinary",
            "identity": {
                "dll": "fixture-provider.dll",
                "symbol": "fixture_data",
                "ordinal": None,
            },
        }],
        "original_semantic_imports": [{
            "identity": {
                "dll": "kernel32.dll", "symbol": "ExitProcess", "ordinal": None,
            },
            "iat_rva": 0x2000,
            "contract": {},
            "boundary": {},
        }],
        "generated_runtime_support_imports": [{
            "support": "process_termination",
            "identity": {
                "dll": "kernel32.dll", "symbol": "ExitProcess", "ordinal": None,
            },
        }],
        "loader_service_contracts": [],
        "static_authority_bindings": [],
        "checked_exception_protocols": [],
        "blockers": [],
        "authority": "fixture checked environment",
    }
    environment = root / "resolved-external-environment.json"
    write_json(environment, {
        **environment_core,
        "resolved_environment_sha256": canonical_sha256_v3(environment_core),
    })

    closure_core = {
        "format": MODULE_EXECUTION_CLOSURE_FORMAT,
        "status": "complete",
        "authorizes_execution": True,
        "bindings": {
            "executable_transfer_plan_sha256": sha256_file(transfer),
            "resolved_external_environment_sha256": sha256_file(environment),
        },
        "roots": [unit["rva_start"]],
        "reachable_units": [{
            "unit_id": unit["unit_id"], "rva": unit["rva_start"],
        }],
        "reachable_edges": [{
            "source_rva": unit["rva_start"],
            "target_rva": unit["rva_start"],
            "kind": "indirect_internal",
        }],
        "indirect_targets": [{
            "source_rva": unit["rva_start"],
            "site": "terminator",
            "targets": [unit["rva_start"]],
            "external_targets": [],
            "provenance": [],
        }],
        "external_contracts": [],
        "runtime_providers": [],
        "callback_escapes": [],
        "exception_continuations": [],
        "nonlocal_transitions": [],
        "lifecycle_effects": [],
        "witnesses": [],
        "blockers": [],
        "metrics": {
            "reachable_units": 1,
            "reachable_edges": 1,
            "indirect_sites": 1,
            "function_contexts": 0,
        },
        "analysis_policy": {
            "reference_alternative_limit": 64,
            "call_string_limit": 1,
            "maximum_worklist_steps": 1_000_000,
            "boundary_exit_rvas": [],
        },
        "authority": "fixture exact execution closure",
    }
    closure = root / "module-execution-closure.json"
    write_json(closure, {
        **closure_core,
        "closure_sha256": canonical_sha256_v3(closure_core),
    })

    transport = PhysicalCallFrameV2.create(
        subject={
            "kind": "function",
            "id": "fixture-process-entry",
            "image_selector": "fixture.exe",
        },
        transfer_kind="direct",
        target="i686-pc-windows-gnu",
        abi_dialect="pe32-i386-gnu-v1",
        calling_convention="cdecl",
        arguments=[],
        results=[],
        stack={
            "coordinate": "callee-entry-esp",
            "alignment_bytes": 4,
            "cleanup": "caller",
            "cleanup_bytes": 0,
            "reserved_bytes": 0,
        },
        preserved_state=["ebx", "ebp", "esi", "edi"],
        clobbered_state=["eax", "ecx", "edx", "eflags"],
        outcomes=["normal"],
    )
    runtime_features = [
        "code_capability_registry_v1",
        "host_thread_concurrency_v1",
        "loader_lock_safe_bootstrap_v1",
        "outgoing_bridge_pe_tls_state_v1",
        "per_thread_ingress_frame_chain_v1",
        "same_thread_reentrancy_v1",
        "tls_private_stack_v1",
        "transactional_boundary_writeback_v1",
    ]
    authority = MachineObjectAuthorityV2(
        machine_backend="x86-pe32-loader-relative-v2",
        bindings={"module_interface_sha256": "8" * 64},
        rules=[MachineObjectRuleV2(
            identity="fixture-image-data",
            kind="image",
            domain=1,
            object_id=17,
            generation=1,
            extent=0x1000,
            permissions=3,
            lifetime="image",
            locator=LoaderRealizedLocatorV2(
                "image_rva", "fixture.exe", 0x2000
            ),
            interior_pointers=True,
            evidence_sha256="9" * 64,
        ), MachineObjectRuleV2(
            identity="fixture-imported-data",
            kind="external",
            domain=3,
            object_id=18,
            generation=1,
            extent=16,
            permissions=3,
            lifetime="image",
            locator=LoaderRealizedLocatorV2(
                "resolved_data_import", "fixture.exe:iat:00003000", 4
            ),
            interior_pointers=True,
            evidence_sha256="a" * 64,
        ), MachineObjectRuleV2(
            identity="fixture-caller-arguments",
            kind="stack",
            domain=5,
            object_id=19,
            generation=1,
            extent=16,
            permissions=3,
            lifetime="invocation",
            locator=LoaderRealizedLocatorV2(
                "captured_stack", transport.frame_id, 0
            ),
            interior_pointers=True,
            evidence_sha256="b" * 64,
        )],
    )
    authority_path = root / "machine-object-authority.json"
    write_json(authority_path, authority.to_payload())
    ingress_core = {
        "format": NATIVE_INGRESS_PLAN_FORMAT,
        "status": "complete",
        "module": {
            "image_id": "fixture.exe",
            "kind": "executable",
            "image_base": 0x400000,
            "executable_transfer_plan_sha256": sha256_file(transfer),
            "module_execution_closure_sha256": sha256_file(closure),
            "resolved_external_environment_sha256": sha256_file(environment),
            "object_authority_sha256": authority.authority_sha256,
        },
        "ingresses": [{
            "role": "process_entry",
            "target_rva": unit["rva_start"],
            "target_unit_id": unit["unit_id"],
            "bridge_symbol": "spx_ingress_0000",
            "physical_frame_id": transport.frame_id,
            "physical_frame": {"transport": transport.to_payload()},
            "outcome_protocol_id": "fixture-normal",
            "capability_id": None,
            "lifecycle_receipt": {"status": "complete"},
        }],
        "bridges": [{
            "symbol": "spx_ingress_0000",
            "target_rva": unit["rva_start"],
            "target_unit_id": unit["unit_id"],
            "equivalence_class": "fixture-entry",
        }],
        "outcome_protocols": [{
            "id": "fixture-normal", "outcomes": ["normal"],
        }],
        "seh_protocols": [],
        "tls_layout": {
            "runtime_offset": 0,
            "runtime_control_bytes": 0x80000,
            "private_stack_bytes": 0x100000,
            "runtime_regions": exact_tls_regions(
                control_bytes=0x80000, stack_bytes=0x100000,
            ),
        },
        "runtime_requirements": {
            "features": runtime_features,
            "private_stack_bytes": 0x100000,
        },
        "blockers": [],
    }
    ingress = root / "native-ingress-plan.json"
    write_json(ingress, {
        **ingress_core, "plan_sha256": canonical_sha256_v3(ingress_core),
    })

    return {
        "transfer_plan": transfer,
        "execution_closure": closure,
        "resolved_external_environment": environment,
        "native_ingress_plan": ingress,
    }


class CanonicalRuntimeTests(unittest.TestCase):
    def test_checked_external_services_have_generic_runtime_routes(self) -> None:
        obligation_id = f"residual-obligation-v2:{'a' * 64}"
        linked_payload = {
            "residual_obligations": [{
                "obligation_id": obligation_id,
                "class": "checked_external_nonlocal_service",
                "semantic_contract_sha256": "b" * 64,
                "allowed_provider_kinds": ["qualified_runtime"],
                "admitted_domain": {
                    "kind": "checked_external_service_protocol_v1",
                    "contract_sha256": "c" * 64,
                    "identity": {
                        "dll": "kernel32.dll",
                        "symbol": "RtlUnwind",
                        "ordinal": None,
                    },
                    "sites": [{
                        "transfer_id": "semantic-transfer:fixture",
                        "source_rva": 0x1000,
                        "instruction_rva": 0x1004,
                        "call_id": 0,
                    }],
                    "protocol": {
                        "format": (
                            "spaghetti-extractor-checked-external-service-"
                            "protocol-v1"
                        ),
                        "id": "win32-rtl-unwind-v1",
                        "kind": "nonlocal_unwind",
                    },
                },
            }],
        }

        self.assertEqual(
            external_service_runtime_blockers_v2(linked_payload), []
        )
        routes = external_service_runtime_routes_v2(linked_payload)
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0].obligation_id, obligation_id)
        self.assertEqual(
            routes[0].payload()["admitted_domain"]["sites"],
            linked_payload["residual_obligations"][0]["admitted_domain"][
                "sites"
            ],
        )
        self.assertEqual(
            routes[0].payload()["implementation"], "checked_runtime"
        )

        checked = json.loads(json.dumps(linked_payload))
        checked_obligation = checked["residual_obligations"][0]
        checked_obligation["class"] = (
            "checked_external_exception_object_service"
        )
        checked_domain = checked_obligation["admitted_domain"]
        checked_domain["identity"]["symbol"] = "UnhandledExceptionFilter"
        checked_domain["protocol"] = {
            "format": (
                "spaghetti-extractor-checked-external-service-protocol-v1"
            ),
            "id": "win32-unhandled-exception-filter-v1",
            "kind": "unhandled_exception_filter",
            "arguments": {"exception_pointers": 0},
            "behavior": {
                "active_filter": "invoke_once_on_same_thread",
                "fallback": "loader_owned_unhandled_exception_policy",
                "outcome": "normal",
            },
            "object_view": {
                "kind": "win32_exception_pointers_v1",
                "size_bytes": 8,
                "exception_record_pointer_offset": 0,
                "context_pointer_offset": 4,
                "exception_record_view": "checked_exception_record_v1",
                "context_view": "x86_context_v1",
                "root_access": "read",
                "referent_access": "read_write",
                "lifetime": "during_call",
            },
            "registered_filter": {
                "protocol_id": "win32-unhandled-exception-filter",
                "absence": "host_fallback",
                "result_register": "eax",
            },
        }
        checked_routes = external_service_runtime_routes_v2(checked)
        self.assertEqual(len(checked_routes), 1)
        self.assertTrue(checked_routes[0].realized)
        self.assertEqual(
            external_service_runtime_blockers_v2(checked), []
        )

        linked_payload["residual_obligations"][0]["admitted_domain"] = {}
        with self.assertRaisesRegex(
            CanonicalRuntimeError,
            "external-service obligation has no checked protocol",
        ):
            external_service_runtime_blockers_v2(linked_payload)

    def test_loader_services_publish_into_existing_callable_catalog(self) -> None:
        module_handle = {
            "identity": {
                "dll": "kernel32.dll", "symbol": "GetModuleHandleA",
                "ordinal": None,
            },
            "contract": {"payload": {"loader_service": {
                "kind": "module_handle",
                "module_name_argument": 0,
                "nullable_module_name": True,
            }}},
        }
        get_proc_address = {
            "identity": {
                "dll": "kernel32.dll", "symbol": "GetProcAddress",
                "ordinal": None,
            },
            "contract": {"payload": {"loader_service": {
                "kind": "dynamic_export_resolution",
                "module_handle_argument": 0,
                "export_name_argument": 1,
            }}},
        }
        indexed = _loader_service_index({
            "loader_service_contracts": [module_handle, get_proc_address],
        })
        self.assertEqual(
            indexed[("kernel32.dll", "symbol", "GetModuleHandleA")],
            {
                "kind": "module_handle",
                "module_name_argument": 0,
                "nullable_module_name": True,
                "wide_name": False,
                "contract_sha256": canonical_sha256_v3(module_handle),
            },
        )
        self.assertEqual(
            indexed[("kernel32.dll", "symbol", "GetProcAddress")]["kind"],
            "dynamic_export_resolution",
        )
        malformed = json.loads(json.dumps(get_proc_address))
        malformed["contract"]["payload"]["loader_service"][
            "export_name_argument"
        ] = -1
        with self.assertRaisesRegex(
            CanonicalRuntimeError, "invalid export-resolution contract"
        ):
            _loader_service_index({"loader_service_contracts": [malformed]})

    def test_callback_default_and_ignore_values_are_noncallback_sentinels(self) -> None:
        adapter = _callback_adapter(
            protocol={
                "source": {
                    "kind": "argument_word",
                    "argument": 1,
                    "sentinels": [
                        {"kind": "default", "word": 0},
                        {"kind": "ignore", "word": 1},
                    ],
                },
                "signature": {
                    "argument_words": 1,
                    "stack_cleanup_bytes": 0,
                    "result": {"kind": "void"},
                },
                "lifetime": {"kind": "process"},
            },
            escape={"targets": [0x1000]},
        )
        self.assertEqual(
            adapter.source["non_callback_sentinel_words"], [0, 1]
        )

    def test_variadic_import_uses_checked_minimum_prefix_and_raw_suffix(self) -> None:
        forwarding = {
            "kind": "exact_raw_caller_stack_suffix_v1",
            "minimum_argument_words": 2,
            "source": "caller_argument_stack",
            "destination": "same_library_machine_ir_callthrough",
            "extent": "all_words_after_minimum_prefix",
            "word_relation": "exact_u32",
            "order_relation": "preserved",
        }
        checked = _checked_contract(
            row={
                "identity": {
                    "dll": "msvcrt.dll", "symbol": "fprintf",
                    "ordinal": None,
                },
                "contract": {
                    "profile_id": "fixture",
                    "profile_sha256": "a" * 64,
                    "entry_key": "fprintf",
                    "entry_index": 0,
                    "payload": {
                        "id": "fixture:fprintf",
                        "abi_template": "pe32-cdecl-v1",
                        "arity": {
                            "kind": "variadic",
                            "minimum_words": 2,
                        },
                        "minimum_argument_words": 2,
                        "raw_caller_stack_suffix_forwarding": forwarding,
                        "result_register_relations": [],
                        "memory_effect": "none",
                        "memory_footprints": [],
                        "world_effect": "none",
                    },
                },
                "boundary": {},
            },
            call=SimpleNamespace(
                argument_nodes=({"op": "const"}, {"op": "reg"}),
                instruction_rva=0x1234,
            ),
            escape_index={},
        )
        self.assertEqual(checked.arity_kind, "variadic")
        self.assertEqual(checked.argument_words, 2)
        self.assertEqual(checked.raw_caller_stack_suffix_forwarding, forwarding)

    def test_runtime_v7_factors_one_site_target_domain_losslessly(self) -> None:
        def checked(symbol: str):
            return _checked_contract(
                row={
                    "identity": {
                        "dll": "fixture.dll", "symbol": symbol,
                        "ordinal": None,
                    },
                    "contract": {
                        "profile_id": "fixture",
                        "profile_sha256": "a" * 64,
                        "entry_key": symbol,
                        "entry_index": 0,
                        "payload": {
                            "id": f"fixture:{symbol}",
                            "abi_template": "pe32-stdcall-v1",
                            "argument_words": 1,
                            "disposition": "returns",
                            "result_register_relations": [],
                            "memory_effect": "none",
                            "memory_footprints": [],
                            "world_effect": "none",
                        },
                    },
                    "boundary": {},
                },
                call=SimpleNamespace(
                    argument_nodes=(), instruction_rva=0x1234,
                ),
                escape_index={},
            )

        rows = []
        for index, symbol in enumerate(("alpha", "beta")):
            contract = checked(symbol)
            self.assertEqual(
                contract.payload(), contract.payload(copy_json=False)
            )
            identity = ["fixture.dll", "symbol", symbol]
            rows.append(NativeExternalSite(
                id=index,
                transfer_id="semantic-transfer:fixture",
                event_index=0,
                instruction_rva=0x1234,
                return_rva=0x1239,
                source_instruction_sha256="b" * 64,
                site_kind="dynamic_target",
                dll="fixture.dll",
                symbol=symbol,
                ordinal=None,
                disposition="returns_here",
                iat_rva=0x3000 + index * 4,
                transfer_sha256="c" * 64,
                abi_metadata_sha256=canonical_sha256_v3(
                    contract.profile_effect_payload()
                ),
                checked_external_contract=contract,
                target_resolution_evidence={
                    "kind": "resolved-external-environment-v1",
                    "sha256": "d" * 64,
                    "identity": identity,
                    "admitted_domain_sha256": "e" * 64,
                    "admitted_member_sha256": str(index) * 64,
                },
            ))
        catalog, domains, callback_domains, sites, pairs = (
            normalized_external_site_inventory_v2(tuple(rows))
        )
        self.assertEqual(
            (len(catalog), len(domains), len(callback_domains), len(sites), pairs),
            (2, 1, 0, 1, 2),
        )
        payload = {
            "external_target_contracts": catalog,
            "external_contract_domains": domains,
            "callback_target_domains": callback_domains,
            "external_sites": sites,
        }
        expanded = expanded_external_sites_v8(payload)
        self.assertEqual(len(expanded), 2)
        self.assertEqual(
            sorted(row["import"]["symbol"] for row in expanded),
            ["alpha", "beta"],
        )
        stale = json.loads(json.dumps(payload))
        stale["external_contract_domains"][0]["target_contract_ids"][0] = "f" * 64
        with self.assertRaisesRegex(
            CandidateRuntimeError, "external contract domain is stale"
        ):
            expanded_external_sites_v8(stale)

    def test_returning_external_tail_jump_preserves_transfer_and_argument_base(
        self,
    ) -> None:
        checked = _checked_contract(
            row={
                "identity": {
                    "dll": "msvcrt.dll", "symbol": "_unlock",
                    "ordinal": None,
                },
                "contract": {
                    "profile_id": "fixture",
                    "profile_sha256": "a" * 64,
                    "entry_key": "_unlock",
                    "entry_index": 0,
                    "payload": {
                        "id": "fixture:_unlock",
                        "abi_template": "pe32-cdecl-v1",
                        "argument_words": 1,
                        "disposition": "returns",
                        "result_register_relations": [],
                        "memory_effect": "none",
                        "memory_footprints": [],
                        "world_effect": "opaqueResources",
                    },
                },
                "boundary": {},
            },
            call=SimpleNamespace(
                argument_nodes=(), instruction_rva=0x14353,
            ),
            escape_index={},
            tail_jump=True,
        )

        self.assertEqual(checked.transfer_kind, "jump")
        self.assertEqual(checked.disposition, "tail_jump")
        self.assertEqual(checked.profile_disposition, "returns")
        self.assertEqual(checked.argument_base_offset, 4)
        self.assertEqual(
            checked.arguments,
            ({"kind": "captured_stack_word", "offset": 4},),
        )
        self.assertEqual(checked.stack_arguments[0].offset, 4)

    def test_interface_method_domain_binds_live_class_and_output_registration(
        self,
    ) -> None:
        profile_sha256 = "a" * 64
        receiver = {
            "argument_index": 0,
            "view_id": "IFixture",
            "required_state": "live_factory_interface_instance",
            "dispatch_slot": 1,
            "lifecycle_effect": "preserve",
        }
        protocol = {
            "kind": "pe32-interface-method",
            "profile_id": "fixture-interfaces",
            "profile_sha256": profile_sha256,
            "profile_binding": {
                "profile_id": "fixture-interfaces",
                "profile_sha256": profile_sha256,
                "receiver_resource": receiver,
            },
            "interface_id": "IFixture",
            "method": "Clone",
            "slot": 1,
            "offset": 4,
        }
        method = {
            "external_protocol": protocol,
            "profile_binding": protocol["profile_binding"],
            "abi": {
                "template": "pe32-stdcall-v1",
                "preserved_registers": ["ebp", "ebx", "edi", "esi"],
                "clobbered_registers": ["eax", "ecx", "edx"],
                "callee_cleanup": True,
            },
            "argument_words": 2,
            "out_interfaces": [{
                "argument_index": 1,
                "interface_id": "IFixture",
                "write_width": 4,
                "object_size": 4,
                "vtable_size": 8,
                "nullable": True,
                "success_condition": "hresult_succeeded_eax",
            }],
            "receiver_resource": receiver,
            "memory_effect": "same-native-target-effect-v1",
            "memory_footprints": [],
            "world_effect": "same-native-target-effect-v1",
            "callback_effect": "none",
        }
        target_core = {
            "profile_id": "fixture-interfaces",
            "profile_sha256": profile_sha256,
            "interface_id": "IFixture",
            "method": method,
        }
        method_sha256 = canonical_sha256_v3(target_core)
        target = {
            **target_core,
            "method_contract_sha256": method_sha256,
        }
        domain_core = {
            "kind": "checked_indirect_callable_targets_v3",
            "logical_guest_frame": "logical_machine_state_v2",
            "resolved_environment_sha256": "d" * 64,
            "guest_transfer_entry_rvas": [0x1000],
            "external_loader_targets": [],
            "external_interface_targets": [target],
            "selection": {
                "guest": "active_code_capability_address",
                "external": "checked_loader_code_capability",
                "interface": "live_factory_interface_vtable_method_capability",
                "ambiguity": "reject",
                "no_match": "reject",
            },
        }
        domain = NativeGuestDispatchDomain(
            domain_sha256=canonical_sha256_v3(domain_core),
            contract=domain_core,
            authority="linked_semantic_module_v2",
        )
        targets, indexes = interface_method_target_catalog((domain,))
        self.assertEqual(targets, (target,))
        self.assertEqual(indexes, {method_sha256: 1})
        classes, class_indexes = interface_class_catalog((domain,))
        self.assertEqual(
            classes,
            ((profile_sha256, "IFixture", "fixture-interfaces"),),
        )
        self.assertEqual(class_indexes[(profile_sha256, "IFixture")], 1)

        checked = _checked_interface_method_contract(
            target=target,
            call=SimpleNamespace(argument_nodes=(), instruction_rva=0x1234),
            tail_jump=False,
        )
        resolution = {
            "kind": "resolved-external-environment-v1",
            "sha256": "d" * 64,
            "identity": ["fixture-interfaces", "interface", "IFixture::Clone"],
            "admitted_domain_sha256": domain.domain_sha256,
            "admitted_member_sha256": method_sha256,
        }
        site = NativeExternalSite(
            id=0,
            transfer_id="semantic-transfer:fixture",
            event_index=0,
            instruction_rva=0x1234,
            return_rva=0x1239,
            source_instruction_sha256="b" * 64,
            site_kind="dynamic_target",
            dll=None,
            symbol=None,
            ordinal=None,
            disposition="returns_here",
            iat_rva=None,
            transfer_sha256="c" * 64,
            abi_metadata_sha256=canonical_sha256_v3(
                checked.profile_effect_payload()
            ),
            checked_external_contract=checked,
            target_resolution_evidence=resolution,
        )
        catalog, domains, callback_domains, sites, _pairs = (
            normalized_external_site_inventory_v2((site,))
        )
        native_plan = {
            "external_target_contracts": catalog,
            "external_contract_domains": domains,
            "callback_target_domains": callback_domains,
            "external_sites": sites,
            "import_bindings": [],
            "implementation_dispatch_receipt": {
                "reachability": {"status": "complete"},
            },
        }
        rules, authorized, blocked = _external_range_rules(
            native_plan,
            None,
            resolved_environment_sha256="d" * 64,
            guest_dispatch_domains=(domain,),
        )
        self.assertEqual(authorized, (0x1234,))
        self.assertEqual(blocked, ())
        self.assertTrue(all(
            rule.target_catalog_index == INTERFACE_METHOD_TARGET_TAG | 1
            for rule in rules
        ))
        output_rule = next(
            rule for rule in rules
            if rule.action == "add_argument_interface_ranges"
        )
        self.assertEqual(output_rule.interface_class_index, 1)

    def test_interface_callback_method_is_an_exact_runtime_blocker(self) -> None:
        method = {
            "external_protocol": {
                "kind": "pe32-interface-method",
                "interface_id": "IFixture",
                "method": "Enumerate",
            },
            "callback_effect": "explicit",
            "callback_abi": {
                "kind": "generic_callback",
                "argument_words": 2,
                "stack_cleanup_bytes": 8,
                "nullable": False,
                "result": {"kind": "word", "register": "eax"},
            },
            "callback_source": {"kind": "argument_word", "argument": 1},
            "callback_arguments": [{
                "argument_index": 0,
                "kind": "scalar",
            }],
            "callback_lifetime": "during_call",
        }
        target_core = {
            "profile_id": "fixture-interfaces",
            "profile_sha256": "a" * 64,
            "interface_id": "IFixture",
            "method": method,
        }
        target = {
            **target_core,
            "method_contract_sha256": canonical_sha256_v3(target_core),
        }
        contract = {
            "external_interface_targets": [target],
            "guest_transfer_entry_rvas": [],
        }
        domain = NativeGuestDispatchDomain(
            domain_sha256=canonical_sha256_v3(contract),
            contract=contract,
            authority="linked_semantic_module_v2",
        )
        blockers = interface_callback_runtime_blockers_v1(
            domains=(domain,),
            sites=(SimpleNamespace(domain_sha256=domain.domain_sha256),),
        )
        self.assertEqual(len(blockers), 1)
        self.assertEqual(
            blockers[0]["category"],
            "interface_callback_callthrough_runtime_unsupported",
        )
        self.assertEqual(
            blockers[0]["method_contract_sha256"],
            target["method_contract_sha256"],
        )
        self.assertEqual(blockers[0]["site_count"], 1)
        self.assertEqual(
            blockers[0]["admitted_domain_sha256s"],
            [domain.domain_sha256],
        )








if __name__ == "__main__":
    unittest.main()
