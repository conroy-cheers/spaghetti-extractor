from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.dependency_graph import (
    ComponentDependencyGraphError,
    build_component_dependency_graph_v3,
    build_component_release_gate_v1,
)
from spaghetti_extractor.components.implementation import (
    ComponentImplementationError,
    adapt_machine_ir_implementation_v3,
    create_blocked_component_implementation_v3,
    create_component_implementation_v3,
)
from spaghetti_extractor.components.interface_ir import PortableComponentInterfaceV2
from spaghetti_extractor.components.machine_binding import (
    create_component_machine_binding_v1,
)
from spaghetti_extractor.components.universal_binding import (
    build_component_machine_binding_v3,
)
from spaghetti_extractor.components.universal_contract import (
    ComponentContractV3,
    UniversalComponentContractError,
    build_component_contract_v3,
)


def _component(
    component_id: str,
    *,
    service: bool = False,
    parameter_type: str = "u32",
) -> tuple[ComponentContractV3, object]:
    types = [{"id": "u32", "kind": "scalar", "c_type": "uint32_t"}]
    if parameter_type != "u32":
        types.append(
            {"id": parameter_type, "kind": "scalar", "c_type": "uint16_t"}
        )
    interface = {
        "format": "spaghetti-extractor-component-interface-ir-v2",
        "id": f"{component_id}_interface",
        "types": types,
        "state": [],
        "operations": [
            {
                "id": "run",
                "kind": "operation",
                "parameters": [{"id": "value", "type_id": parameter_type}],
                "results": [],
                "effect_ids": [],
                "allowed_service_ids": ["next"] if service else [],
                "pre_states": ["ready"],
                "post_states": ["ready"],
            }
        ],
        "effects": [],
        "services": (
            [
                {
                    "id": "next",
                    "parameter_type_ids": ["u32"],
                    "result_type_id": None,
                    "effect_ids": [],
                }
            ]
            if service
            else []
        ),
        "protocol": {"states": ["ready"], "initial_state": "ready"},
    }
    portable = PortableComponentInterfaceV2.parse(interface)
    binding = create_component_machine_binding_v1(
        id=component_id,
        binary={"pe_sha256": "a" * 64, "machine_ir_sha256": "b" * 64},
        interface={"id": portable.identity, "sha256": portable.sha256},
        unit_ids=[f"unit:{component_id}"],
        operations=[
            {
                "operation_id": "run",
                "entry_unit_ids": [f"unit:{component_id}"],
                "exit_unit_ids": [f"unit:{component_id}"],
                "parameters": [
                    {
                        "id": "value",
                        "projection": {
                            "kind": "register",
                            "register": "eax",
                            "width": 32 if parameter_type == "u32" else 16,
                            "at": "entry",
                        },
                    }
                ],
                "results": [],
                "state": [],
                "preserved_state_ids": [],
                "effects": [],
                "callback_operation_ids": [],
                "continuation_unit_ids": [],
            }
        ],
        services=[],
    )
    semantic_core = {
        "format": "spaghetti-extractor-component-semantic-contract-v1",
        "status": "satisfied",
        "component_id": component_id,
        "bindings": {
            "pe_sha256": "a" * 64,
            "machine_ir_sha256": "b" * 64,
            "machine_ir_manifest_sha256": "c" * 64,
            "interface_sha256": portable.sha256,
            "machine_binding_sha256": binding["binding_sha256"],
            "external_sites_sha256": None,
        },
        "operations": [{"operation_id": "run", "callback_operation_ids": []}],
        "services": [],
        "issues": [],
        "policy": {
            "original_binary_executed": False,
            "behavior_is_machine_derived": True,
        },
    }
    semantics = {
        **semantic_core,
        "contract_sha256": canonical_sha256_v3(semantic_core),
    }
    receipt_core = {
        "format": "spaghetti-extractor-component-machine-binding-receipt-v1",
        "status": "checked",
        "activation_authorized": True,
        "bindings": {
            "component_machine_binding_sha256": binding["binding_sha256"],
            "interface_sha256": portable.sha256,
            "machine_ir_sha256": "b" * 64,
            "machine_ir_manifest_sha256": "c" * 64,
            "pe_sha256": "a" * 64,
        },
        "counts": {"units": 1, "operations": 1, "services": 0, "issues": 0},
        "policy": {
            "runtime_lowering_is_separate_authority": True,
            "logical_machine_binding_checked": True,
        },
        "issues": [],
    }
    receipt = {
        **receipt_core,
        "receipt_sha256": canonical_sha256_v3(receipt_core),
    }
    contract = build_component_contract_v3(
        interface=interface,
        machine_binding=binding,
        machine_binding_receipt=receipt,
        semantic_contract=semantics,
    )
    universal_binding = build_component_machine_binding_v3(
        contract=contract,
        machine_binding=binding,
        machine_binding_receipt=receipt,
        semantic_contract=semantics,
    )
    implementation = adapt_machine_ir_implementation_v3(
        implementation_id=f"{component_id}-machine",
        contract=contract,
        machine_binding=universal_binding,
    )
    return contract, implementation


def _activation_plan(
    *,
    fallback_units: int = 0,
    ownership_state: str = "machine_ir_fallback",
) -> dict[str, object]:
    entries = [
        {
            "unit_id": f"unit:{index}",
            "rva": index,
            "implementation_kind": "machine_ir_fallback",
            "dispatch_lookup": "spx_program_lookup",
            "selected_owner": None,
        }
        for index in range(fallback_units)
    ]
    core: dict[str, object] = {
        "format": "spaghetti-extractor-component-activation-plan-v3",
        "status": "checked",
        "configuration_id": "fixture",
        "bindings": {},
        "policy": {},
        "ownership": {},
        "hybrid": {},
        "selections": [
            {
                "id": "component",
                "ownership_state": ownership_state,
            }
        ],
        "entries": entries,
        "counts": {},
        "issues": [],
    }
    return {**core, "activation_plan_sha256": canonical_sha256_v3(core)}


class UniversalComponentTests(unittest.TestCase):
    def test_contract_binds_interface_semantics_and_exact_units(self) -> None:
        contract, _implementation = _component("consumer")

        self.assertEqual(contract.status, "checked")
        self.assertEqual(contract.component_id, "consumer")
        self.assertEqual(contract.interface_id, "consumer_interface")
        self.assertEqual(ComponentContractV3.parse(contract.to_payload()), contract)

        corrupted = contract.to_payload()
        corrupted["operations"][0]["semantic_operation_sha256"] = "f" * 64
        with self.assertRaisesRegex(
            UniversalComponentContractError, "digest is stale"
        ):
            ComponentContractV3.parse(corrupted)

    def test_checked_implementation_is_bound_to_one_contract(self) -> None:
        contract, implementation = _component("consumer")

        self.assertTrue(implementation.authorizing)
        self.assertEqual(implementation.contract_sha256, contract.contract_sha256)
        corrupted = implementation.to_payload()
        corrupted["contract_sha256"] = "f" * 64
        with self.assertRaisesRegex(ComponentImplementationError, "digest is stale"):
            type(implementation).parse(corrupted)

    def test_implementation_kind_must_match_runtime_realization(self) -> None:
        _contract, implementation = _component("consumer")
        corrupted = implementation.to_payload()
        corrupted["realization"] = {"kind": "native_component_runtime"}
        core = dict(corrupted)
        core.pop("implementation_sha256")
        corrupted["implementation_sha256"] = canonical_sha256_v3(core)

        with self.assertRaisesRegex(
            ComponentImplementationError, "contradicts its realization kind"
        ):
            type(implementation).parse(corrupted)

    def test_blocked_implementation_is_reducer_output_only(self) -> None:
        contract, _implementation = _component("consumer")
        with self.assertRaisesRegex(
            ComponentImplementationError, "configuration-reducer output"
        ):
            create_component_implementation_v3(
                implementation_id="authored-blocked",
                contract=contract,
                kind="blocked",
                artifact_kind="none",
                artifact_sha256=None,
                authority_kind="none",
                authority_sha256=None,
                realization={"kind": "none"},
            )

        blocked = create_blocked_component_implementation_v3(
            implementation_id="reduced-blocked",
            contract=contract,
            issues=[{"status": "incomplete", "code": "implementation_missing"}],
        )
        self.assertFalse(blocked.authorizing)
        self.assertEqual(blocked.status, "incomplete")

    def test_implementation_accepts_canonical_namespaced_id(self) -> None:
        contract, _implementation = _component("namespaced")
        implementation = create_component_implementation_v3(
            implementation_id=f"reusable-library-implementation-v1:{'a' * 64}",
            contract=contract,
            kind="portable_c",
            artifact_kind="portable_source_package",
            artifact_sha256="b" * 64,
            authority_kind="component_refinement_receipt",
            authority_sha256="c" * 64,
            realization={"kind": "native_component_runtime"},
        )

        self.assertTrue(implementation.authorizing)

    def test_graph_checks_service_signatures_and_tracks_consumers(self) -> None:
        consumer, consumer_impl = _component("consumer", service=True)
        provider, provider_impl = _component("provider")
        graph = build_component_dependency_graph_v3(
            contracts={"consumer": consumer, "provider": provider},
            implementations={
                "consumer": consumer_impl,
                "provider": provider_impl,
            },
            bindings=[
                {
                    "consumer_component_id": "consumer",
                    "consumer_service_id": "next",
                    "provider_component_id": "provider",
                    "provider_operation_id": "run",
                    "mediation": "direct",
                    "callsite_ids": ["unit:consumer:event:0"],
                }
            ],
        )

        self.assertEqual(graph.status, "checked")
        provider_reverse = next(
            row
            for row in graph.reverse_dependencies
            if row["provider_component_id"] == "provider"
        )
        self.assertFalse(provider_reverse["retirable"])
        self.assertEqual(
            provider_reverse["consumers"][0]["operation_ids"], ["run"]
        )

    def test_missing_and_incompatible_services_fail_closed(self) -> None:
        consumer, consumer_impl = _component("consumer", service=True)
        provider, provider_impl = _component("provider", parameter_type="u16")
        missing = build_component_dependency_graph_v3(
            contracts={"consumer": consumer, "provider": provider},
            implementations={
                "consumer": consumer_impl,
                "provider": provider_impl,
            },
            bindings=[],
        )
        self.assertEqual(missing.status, "incomplete")
        self.assertIn(
            "dependency_service_unresolved",
            {row["code"] for row in missing.issues},
        )

        incompatible = build_component_dependency_graph_v3(
            contracts={"consumer": consumer, "provider": provider},
            implementations={
                "consumer": consumer_impl,
                "provider": provider_impl,
            },
            bindings=[
                {
                    "consumer_component_id": "consumer",
                    "consumer_service_id": "next",
                    "provider_component_id": "provider",
                    "provider_operation_id": "run",
                    "mediation": "direct",
                    "callsite_ids": ["unit:consumer:event:0"],
                }
            ],
        )
        self.assertEqual(incompatible.status, "violated")
        self.assertIn(
            "dependency_contract_incompatible",
            {row["code"] for row in incompatible.issues},
        )

    def test_release_modes_distinguish_hybrid_and_portable(self) -> None:
        contract, machine = _component("component")
        graph = build_component_dependency_graph_v3(
            contracts={"component": contract},
            implementations={"component": machine},
            bindings=[],
        )

        self.assertEqual(
            build_component_release_gate_v1(
                graph=graph, activation_plan=_activation_plan(), mode="hybrid"
            )["status"],
            "ready",
        )
        self.assertEqual(
            build_component_release_gate_v1(
                graph=graph, activation_plan=_activation_plan(), mode="portable"
            )["status"],
            "incomplete",
        )

        portable = create_component_implementation_v3(
            implementation_id="component-portable",
            contract=contract,
            kind="portable_c",
            artifact_kind="component_source_package",
            artifact_sha256="d" * 64,
            authority_kind="component_activation_receipt_v2",
            authority_sha256="e" * 64,
            realization={"kind": "native_component_runtime"},
        )
        portable_graph = build_component_dependency_graph_v3(
            contracts={"component": contract},
            implementations={"component": portable},
            bindings=[],
        )
        self.assertEqual(
            build_component_release_gate_v1(
                graph=portable_graph,
                activation_plan=_activation_plan(
                    ownership_state="portable_replacement"
                ),
                mode="portable",
            )["status"],
            "ready",
        )
        self.assertEqual(
            portable_graph.contracts,
            graph.contracts,
            "implementation swaps must not change consumer contract identities",
        )

        fallback_gate = build_component_release_gate_v1(
            graph=portable_graph,
            activation_plan=_activation_plan(
                fallback_units=1,
                ownership_state="portable_replacement",
            ),
            mode="portable",
        )
        self.assertEqual(fallback_gate["status"], "incomplete")
        self.assertEqual(fallback_gate["counts"]["machine_ir_fallback_units"], 1)

        mismatched = build_component_release_gate_v1(
            graph=graph,
            activation_plan=_activation_plan(
                ownership_state="portable_replacement"
            ),
            mode="hybrid",
        )
        self.assertEqual(mismatched["status"], "violated")
        self.assertIn(
            "component_activation_implementation_kind_mismatch",
            {row["code"] for row in mismatched["issues"]},
        )

    def test_dependency_parser_rejects_stale_graph(self) -> None:
        contract, implementation = _component("component")
        graph = build_component_dependency_graph_v3(
            contracts={"component": contract},
            implementations={"component": implementation},
            bindings=[],
        )
        payload = copy.deepcopy(graph.to_payload())
        payload["implementations"][0]["kind"] = "portable_c"
        with self.assertRaisesRegex(ComponentDependencyGraphError, "digest is stale"):
            type(graph).parse(payload)


if __name__ == "__main__":
    unittest.main()
