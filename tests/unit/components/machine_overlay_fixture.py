from __future__ import annotations
import json
import re
from pathlib import Path
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.binding_intent import (
    ComponentMachineBindingIntentV1,
)
from spaghetti_extractor.components.interface_package_v5 import (
    ComponentInterfaceIntentV1,
    compile_component_interface_v5,
)
from spaghetti_extractor.components.machine_overlay_v5 import (
    render_component_machine_overlay_v5,
)
from spaghetti_extractor.components.normalized_component import (
    NormalizedComponentContract,
    NormalizedMachineBinding,
)
from spaghetti_extractor.external.resolved import bind_launch_policy_v1
from spaghetti_extractor.transfer.model import _Action, _Call, _Transfer
ROOT = Path(__file__).parents[3]
TESTKIT = {
    "fixtures": ("compiler",),
    "resources": (
        "targets/gnu-hello/intent/interfaces-v5",
        "targets/gnu-hello/intent/bindings-v5",
        "targets/dxball/intent/interfaces-v5",
        "targets/jq/intent/interfaces-v5",
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
    external_service_thunk_renderer=None,
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
        match = re.search(r"(?:original-cutpoint|rooted-view)-([0-9a-f]{8})", unit_id)
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
        external_service_thunk_renderer=external_service_thunk_renderer,
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
                "memory_effect": "readOnly",
                "world_effect": "none",
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
