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

class CanonicalRuntimeDomainTests(unittest.TestCase):
    def test_v2_guest_dispatch_preserves_shared_admitted_domain_identity(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs = _inputs(Path(temporary))
            _payload, transfers = load_executable_transfer_plan(
                inputs["transfer_plan"], require_complete=True
            )
            source = transfers[0]
            domain_core = {
                "kind": "frame_compatible_transfer_entry_rvas",
                "physical_frame": "logical_machine_state_v2",
                "targets": [source.rva_start],
            }
            domain_sha256 = canonical_sha256_v3(domain_core)
            linked = {
                "admitted_domains": [{
                    **domain_core, "domain_sha256": domain_sha256,
                }],
                "effects": {"indirect_targets": [{
                    "kind": "logical_machine_state_indirect_dispatch_v2",
                    "site_kind": "terminator",
                    "source_transfer_id": source.identity,
                    "instruction_rva": source.rva_start,
                    "admitted_domain": {
                        "kind": "catalog_reference",
                        "domain_sha256": domain_sha256,
                    },
                }]},
            }
            domains, sites = guest_dispatch_from_linked_module_v2(
                transfers=transfers, linked_module=linked
            )

        self.assertEqual(len(domains), 1)
        self.assertEqual(domains[0].domain_sha256, domain_sha256)
        self.assertEqual(domains[0].target_rvas, (source.rva_start,))
        self.assertEqual(domains[0].authority, "linked_semantic_module_v2")
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].domain_sha256, domain_sha256)
        self.assertEqual(sites[0].instruction_rva, source.rva_start)

        stale = dict(linked)
        stale["admitted_domains"] = [dict(linked["admitted_domains"][0])]
        stale["admitted_domains"][0]["targets"] = []
        with self.assertRaisesRegex(
            CanonicalRuntimeError, "domain is stale"
        ):
            guest_dispatch_from_linked_module_v2(
                transfers=transfers, linked_module=stale
            )

    def test_v2_callable_domain_uses_total_checked_external_members(
        self,
    ) -> None:
        call = SimpleNamespace(
            kind="indirect_call", instruction_rva=0x1002, call_index=0,
        )
        transfer = SimpleNamespace(
            identity="semantic-transfer:fixture",
            rva_start=0x1000,
            calls=(call,),
            actions=(),
        )
        contract_sha256 = "a" * 64
        frame_sha256 = "b" * 64
        symbol_id = "external:function-import:fixture"
        domain_core = {
            "kind": "checked_indirect_callable_targets_v3",
            "logical_guest_frame": "logical_machine_state_v2",
            "resolved_environment_sha256": "c" * 64,
            "guest_transfer_entry_rvas": [0x1000],
            "external_loader_targets": [{
                "identity": {
                    "dll": "fixture.dll", "symbol": "invoke",
                    "ordinal": None,
                },
                "import_kind": "ordinary",
                "cell_index": 0,
                "iat_rva": 0x3000,
                "contract_sha256": contract_sha256,
                "physical_frame_id": "fixture-frame",
                "physical_frame_sha256": frame_sha256,
            }],
            "external_interface_targets": [],
            "selection": {
                "guest": "active_code_capability_address",
                "external": "checked_loader_code_capability",
                "interface": (
                    "live_factory_interface_vtable_method_capability"
                ),
                "ambiguity": "reject",
                "no_match": "reject",
            },
        }
        domain_sha256 = canonical_sha256_v3(domain_core)
        effect = {
            "semantic_role": "external_function",
            "symbol_id": symbol_id,
            "identity": domain_core["external_loader_targets"][0]["identity"],
            "contract_sha256": contract_sha256,
            "physical_frame_id": "fixture-frame",
            "physical_frame_sha256": frame_sha256,
            "domain_ids": [domain_sha256],
        }
        linked = {
            "admitted_domains": [{
                **domain_core, "domain_sha256": domain_sha256,
            }],
            "active_symbols": [{
                "symbol_id": symbol_id,
                "kind": "external_function",
                "definition_id": "semantic-definition-v2:fixture",
                "resolution": {
                    "kind": "checked_external_contract",
                    "contract_sha256": contract_sha256,
                },
                "domain_ids": [domain_sha256],
            }],
            "definition_requirements": [{
                "symbol_id": symbol_id,
                "definition_id": "semantic-definition-v2:fixture",
                "allowed_provider_kinds": ["external_environment"],
            }],
            "effects": {
                "external_contracts": [effect],
                "indirect_targets": [{
                    "kind": "checked_indirect_callable_dispatch_v2",
                    "site_kind": "call",
                    "source_transfer_id": transfer.identity,
                    "instruction_rva": call.instruction_rva,
                    "semantic_contract": {
                        "call": {"event_index": call.call_index},
                    },
                    "admitted_domain": {
                        "kind": "catalog_reference",
                        "domain_sha256": domain_sha256,
                    },
                }],
            },
        }

        domains, sites = guest_dispatch_from_linked_module_v2(
            transfers=(transfer,), linked_module=linked
        )
        self.assertEqual(len(sites), 1)
        self.assertEqual(
            domains[0].external_loader_targets,
            tuple(domain_core["external_loader_targets"]),
        )

        stale = json.loads(json.dumps(linked))
        stale["effects"]["external_contracts"] = []
        with self.assertRaisesRegex(
            CanonicalRuntimeError,
            "callable external member is disconnected",
        ):
            guest_dispatch_from_linked_module_v2(
                transfers=(transfer,), linked_module=stale
            )

    def test_external_allocation_locator_binds_one_range_contract(self) -> None:
        rule = NativeObjectAuthorityRule(
            identity="fixture-allocation",
            domain=3,
            object_id=41,
            generation=1,
            extent=16,
            permissions=3,
            lifetime="allocation",
            locator_kind="external_allocation",
            locator_identity="contract:allocator",
            locator_offset=4,
            locator_subject_rva=0,
            interior_pointers=True,
        )
        blockers: list[dict[str, object]] = []
        bound = _bind_dynamic_external_object_rules(
            [rule], (_external_range_rule("contract:allocator"),), blockers
        )
        self.assertEqual(blockers, [])
        self.assertEqual(bound[0].locator_subject_rva, 1)
        self.assertEqual(bound[0].locator_code, 5)

        missing_blockers: list[dict[str, object]] = []
        missing = _bind_dynamic_external_object_rules(
            [rule], (), missing_blockers
        )
        self.assertEqual(missing[0].locator_subject_rva, 0)
        self.assertEqual(
            missing_blockers[0]["category"],
            "runtime_external_allocation_locator_unresolved",
        )

        ambiguous_blockers: list[dict[str, object]] = []
        ambiguous = _bind_dynamic_external_object_rules(
            [rule],
            (
                _external_range_rule("contract:allocator", 0x1234),
                _external_range_rule("contract:allocator", 0x5678),
            ),
            ambiguous_blockers,
        )
        self.assertEqual(ambiguous[0].locator_subject_rva, 0)
        self.assertEqual(
            ambiguous_blockers[0]["matching_range_rules"], 2
        )

        resource_rule = NativeObjectAuthorityRule(
            identity="fixture-resource",
            domain=5,
            object_id=42,
            generation=1,
            extent=8,
            permissions=1,
            lifetime="resource",
            locator_kind="resource",
            locator_identity="contract:resource",
            locator_offset=0,
            locator_subject_rva=0,
            interior_pointers=True,
        )
        resource_blockers: list[dict[str, object]] = []
        resource = _bind_dynamic_external_object_rules(
            [resource_rule],
            (_external_range_rule("contract:resource"),),
            resource_blockers,
        )
        self.assertEqual(resource_blockers, [])
        self.assertEqual(resource[0].locator_subject_rva, 1)
        self.assertEqual(resource[0].locator_code, 6)

    def test_process_entry_without_termination_support_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs = _inputs(Path(temporary))
            environment_path = inputs["resolved_external_environment"]
            environment = json.loads(environment_path.read_text(encoding="utf-8"))
            environment["original_semantic_imports"] = []
            environment["generated_runtime_support_imports"] = []
            environment.pop("resolved_environment_sha256")
            environment["resolved_environment_sha256"] = canonical_sha256_v3(
                environment
            )
            write_json(environment_path, environment)

            closure_path = inputs["execution_closure"]
            closure = json.loads(closure_path.read_text(encoding="utf-8"))
            closure["bindings"]["resolved_external_environment_sha256"] = (
                sha256_file(environment_path)
            )
            closure.pop("closure_sha256")
            closure["closure_sha256"] = canonical_sha256_v3(closure)
            write_json(closure_path, closure)

            ingress_path = inputs["native_ingress_plan"]
            ingress = json.loads(ingress_path.read_text(encoding="utf-8"))
            ingress["module"]["resolved_external_environment_sha256"] = (
                sha256_file(environment_path)
            )
            ingress["module"]["module_execution_closure_sha256"] = (
                sha256_file(closure_path)
            )
            ingress.pop("plan_sha256")
            ingress["plan_sha256"] = canonical_sha256_v3(ingress)
            write_json(ingress_path, ingress)

            plan = plan_module_runtime_from_canonical(**inputs)
            self.assertEqual(plan.status, "incomplete")
            self.assertIn(
                "process_entry_termination_support_missing",
                {row["category"] for row in plan.blockers},
            )

    def test_dynamic_callable_catalog_member_is_not_an_iat_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs = _inputs(Path(temporary))
            environment_path = inputs["resolved_external_environment"]
            environment = json.loads(environment_path.read_text(encoding="utf-8"))
            environment["loader_service_contracts"] = [{
                "identity": {
                    "dll": "kernel32.dll",
                    "symbol": "GetProcAddress",
                    "ordinal": None,
                },
                "contract": {"payload": {"loader_service": {
                    "kind": "dynamic_export_resolution",
                    "module_handle_argument": 0,
                    "export_name_argument": 1,
                }}},
                "boundary": {},
                "resolution_catalog": [{
                    "identity": {
                        "dll": "fixture-provider.dll",
                        "symbol": "fixture_dynamic",
                        "ordinal": None,
                    },
                    "import_kind": "dynamic_export",
                    "dynamic_export_kind": "code",
                    "cell_index": None,
                    "iat_rva": None,
                    "contract": {},
                    "boundary": {},
                }],
            }]
            environment.pop("resolved_environment_sha256")
            environment["resolved_environment_sha256"] = canonical_sha256_v3(
                environment
            )
            write_json(environment_path, environment)

            closure_path = inputs["execution_closure"]
            closure = json.loads(closure_path.read_text(encoding="utf-8"))
            closure["bindings"]["resolved_external_environment_sha256"] = (
                sha256_file(environment_path)
            )
            closure.pop("closure_sha256")
            closure["closure_sha256"] = canonical_sha256_v3(closure)
            write_json(closure_path, closure)

            ingress_path = inputs["native_ingress_plan"]
            ingress = json.loads(ingress_path.read_text(encoding="utf-8"))
            ingress["module"]["resolved_external_environment_sha256"] = (
                sha256_file(environment_path)
            )
            ingress["module"]["module_execution_closure_sha256"] = (
                sha256_file(closure_path)
            )
            ingress.pop("plan_sha256")
            ingress["plan_sha256"] = canonical_sha256_v3(ingress)
            write_json(ingress_path, ingress)

            plan = plan_module_runtime_from_canonical(**inputs)
            self.assertEqual(
                [binding.slot_id for binding in plan.import_bindings],
                ["iat:00002000"],
            )

    def test_runtime_plan_v3_retires_callback_passthrough_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = _inputs(root)
            plan = plan_module_runtime_from_canonical(**inputs)
            transfer = json.loads(
                inputs["transfer_plan"].read_text(encoding="utf-8")
            )
            payload = plan.payload(
                state_machine_sha256=transfer["bindings"]["machine_ir_sha256"]
            )
            self.assertEqual(payload["format"], MODULE_RUNTIME_PLAN_FORMAT)
            for retired_field in (
                "code_capability_passthroughs",
                "semantic_coverage",
                "execution_policy",
                "image_base_policy",
                "relocation_policy",
                "authority",
            ):
                self.assertNotIn(retired_field, payload)
            self.assertNotIn("code_capability_passthroughs", payload["counts"])
            self.assertNotIn("input_transfers", payload["counts"])
            self.assertNotIn("indirect_calls", payload["counts"])

            behavioral = root / "behavioral"
            write_spx_behavioral_c_package(
                transfer_plan=inputs["transfer_plan"], out=behavioral,
            )
            payload["code_capability_passthroughs"] = []
            runtime_plan = root / "module-runtime-plan.json"
            write_json(runtime_plan, payload)
            with self.assertRaisesRegex(
                CandidateRuntimeError, "module-runtime plan fields differ"
            ):
                plan_shared_module_runtime(
                    behavioral_c_package=behavioral,
                    transfer_plan=inputs["transfer_plan"],
                    runtime_plan=runtime_plan,
                    native_ingress_plan=inputs["native_ingress_plan"],
                    execution_closure=inputs["execution_closure"],
                    resolved_external_environment=inputs[
                        "resolved_external_environment"
                    ],
                    object_authority=root / "machine-object-authority.json",
                )
