"""Project one checked reusable-library island into direct provider inputs."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from ..components.binding_intent import (
    ComponentMachineBindingIntentV1,
)
from ..components.interface_package_v5 import (
    compile_component_interface_v5,
    write_component_interface_package_v5,
)
from ..transfer.plan import load_executable_transfer_plan
from ..semantic_link.module_v2_codec import LinkedSemanticModuleV2
from ..util import write_json
from .abi_catalog import CATALOG_SEARCH_INDEX_CODEC_V3, CatalogSearchIndexV3
from .abi_records import LibraryAbiProfileV3, ValueLocationV3
from .behavior_pack_v3 import load_reusable_library_behavior_pack_v3
from .v4_adoption_records import (
    CHECKED_LIBRARY_ISLAND_CODEC_V1,
    CheckedLibraryIslandV1,
)
from .v4_release_set import select_library_island_v1


class LibraryProviderBindingError(ValueError):
    """A checked island cannot project exact direct-provider inputs."""


def build_checked_library_provider_binding_v1(
    *,
    linked_semantic_module: LinkedSemanticModuleV2 | Path | str,
    release_hypotheses: Path | str,
    checked_island: CheckedLibraryIslandV1 | Path | str,
    behavior_pack: Path | str,
    catalog_search_index: CatalogSearchIndexV3 | Path | str,
    out_dir: Path | str,
) -> dict[str, object]:
    """Write the canonical interface and machine-binding intent for adoption.

    This phase maps independently checked library recognition to the same
    direct inputs used by an operator-authored component. It deliberately does
    not emit a component contract, machine-binding receipt, implementation, or
    library-specific provider artifact.
    """

    receipt = (
        checked_island
        if isinstance(checked_island, CheckedLibraryIslandV1)
        else CHECKED_LIBRARY_ISLAND_CODEC_V1.read(checked_island)
    )
    pack = load_reusable_library_behavior_pack_v3(behavior_pack)
    release, island = select_library_island_v1(
        release_hypotheses, receipt.island_id
    )
    catalog = (
        catalog_search_index
        if isinstance(catalog_search_index, CatalogSearchIndexV3)
        else CATALOG_SEARCH_INDEX_CODEC_V3.read(catalog_search_index)
    )
    linked = (
        linked_semantic_module
        if isinstance(linked_semantic_module, LinkedSemanticModuleV2)
        else LinkedSemanticModuleV2.load(Path(linked_semantic_module))
    )
    transfer_payload, transfers = load_executable_transfer_plan(
        linked.require_member("transfer_plan"), require_complete=True
    )
    transfer_bindings = transfer_payload["bindings"]
    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    blockers: list[dict[str, object]] = []

    def block(code: str, **details: object) -> None:
        blockers.append({"code": code, **details})

    if receipt.status != "complete":
        block("checked_library_island_incomplete")
    if receipt.hypotheses_sha256 != release.hypotheses_sha256:
        block("checked_library_island_hypotheses_stale")
    if receipt.machine_ir_sha256 != transfer_bindings["machine_ir_sha256"]:
        block("checked_library_island_machine_ir_stale")
    if receipt.target_binary_sha256 != transfer_bindings["pe_sha256"]:
        block("checked_library_island_target_binary_stale")
    if receipt.checked_unit_ids != island.target_unit_ids:
        block("checked_library_island_unit_inventory_stale")
    if receipt.checked_operation_ids != island.operation_ids:
        block("checked_library_island_operation_inventory_stale")
    if (
        receipt.implementation_id != pack.implementation.implementation_id
        or receipt.implementation_sha256
        != pack.implementation.implementation_sha256
    ):
        block("checked_library_island_implementation_stale")
    if set(receipt.checked_operation_ids) != set(
        pack.manifest["operation_symbols"]
    ):
        block("checked_library_island_interface_inventory_stale")

    bundle = compile_component_interface_v5(pack.interface_intent)
    if bundle.interface.state:
        block("stateful_library_machine_projection_requires_authority")
    if bundle.interface.effects:
        block("effectful_library_machine_projection_requires_authority")
    if bundle.interface.services:
        block("serviceful_library_machine_projection_requires_authority")

    functions = {row.function_id: row for row in catalog.functions}
    matches: dict[str, tuple[Any, Any]] = {}
    for match in island.matches:
        function = functions.get(match.catalog_function_id)
        if function is None:
            block("library_catalog_function_missing", function_id=match.catalog_function_id)
            continue
        operation_id = function.operation_id or function.function_id
        if operation_id in matches:
            block("library_operation_match_ambiguous", operation_id=operation_id)
            continue
        matches[operation_id] = (match, function)
    if set(matches) != {item.identity for item in bundle.interface.operations}:
        block("library_operation_inventory_mismatch")

    profiles = {item.profile_id: item for item in catalog.abi_profiles}
    transfers_by_id = {item.identity: item for item in transfers}
    operations: list[dict[str, object]] = []
    for operation in bundle.interface.operations:
        matched = matches.get(operation.identity)
        if matched is None:
            continue
        match, function = matched
        profile = (
            profiles.get(function.abi_profile_id)
            if function.abi_profile_id is not None
            else None
        )
        if profile is None:
            block(
                "library_operation_physical_abi_unresolved",
                operation_id=operation.identity,
            )
            continue
        projection = _operation_projection(
            operation_id=operation.identity,
            profile=profile,
            unit_ids=tuple(match.target_unit_ids),
            transfers=transfers_by_id,
            bundle=bundle,
            block=block,
        )
        if projection is not None:
            operations.append(projection)

    intent = ComponentMachineBindingIntentV1.create(
        component_id=bundle.interface.identity,
        operations=operations,
        blockers=blockers,
    )
    interface_root = output / "interface"
    write_component_interface_package_v5(interface_root, pack.interface_intent)
    write_json(output / "component-machine-binding-intent-v1.json", intent.to_payload())
    CHECKED_LIBRARY_ISLAND_CODEC_V1.write(
        output / "checked-library-island-v1.json", receipt
    )
    return intent.to_payload()


def _operation_projection(
    *,
    operation_id: str,
    profile: LibraryAbiProfileV3,
    unit_ids: tuple[str, ...],
    transfers: Mapping[str, Any],
    bundle: Any,
    block: Any,
) -> dict[str, object] | None:
    if profile.hidden_sret or profile.variadic.kind != "none" or profile.callback_slots:
        block("library_operation_abi_requires_explicit_mapping", operation_id=operation_id)
        return None
    signature_id = next(
        item.signature_id
        for item in bundle.interface.operations
        if item.identity == operation_id
    )
    signature = bundle.intent.schema.signature_index[signature_id]
    if len(profile.arguments) != len(signature.parameters):
        block("library_operation_argument_count_mismatch", operation_id=operation_id)
        return None
    if len(profile.returns) != len(signature.results):
        block("library_operation_result_count_mismatch", operation_id=operation_id)
        return None
    parameters = []
    results = []
    for logical, location in zip(signature.parameters, profile.arguments, strict=True):
        physical = _physical_projection(location, "entry")
        if physical is None:
            block("library_operation_argument_location_unsupported", operation_id=operation_id)
            return None
        parameters.append({"id": logical.identity, "projection": physical})
    for logical, location in zip(signature.results, profile.returns, strict=True):
        physical = _physical_projection(location, "exit")
        if physical is None:
            block("library_operation_result_location_unsupported", operation_id=operation_id)
            return None
        results.append({"id": logical.identity, "projection": physical})
    try:
        ordered_units = sorted(
            (transfers[unit_id] for unit_id in unit_ids),
            key=lambda row: (row.rva_start, row.identity),
        )
    except KeyError as error:
        block("library_operation_machine_unit_missing", operation_id=operation_id)
        return None
    exits = sorted(
        row.identity
        for row in ordered_units
        if _is_operation_exit(row, set(unit_ids), transfers)
    )
    if not exits:
        block("library_operation_exit_not_recovered", operation_id=operation_id)
        return None
    transfer_ids = [item.identity for item in ordered_units]
    operation = next(
        item for item in bundle.interface.operations if item.identity == operation_id
    )
    return {
        "id": operation_id,
        "kind": "operation",
        "unit_ids": transfer_ids,
        "entry_rvas": [ordered_units[0].rva_start],
        "transfer_ids": transfer_ids,
        "effect_ids": list(operation.effect_ids),
        "service_ids": list(operation.allowed_service_ids),
        "callback_ids": [],
        "outcome_protocol_ids": ["normal"],
        "machine_projection": {
            "operation": {
                "operation_id": operation_id,
                "entry_unit_ids": [ordered_units[0].identity],
                "exit_unit_ids": exits,
                "parameters": parameters,
                "results": results,
                "state": [],
                "preserved_state_ids": [],
                "effects": [],
                "callback_operation_ids": [],
                "continuation_unit_ids": [],
            },
            "preserved_unit_inventory": transfer_ids,
            "service_bindings": [],
        },
        "object_authority_selectors": [],
        "pointer_views": [],
        "relation_receipt_sha256s": [],
        "induction_evidence_sha256": None,
    }


def _physical_projection(
    location: ValueLocationV3, phase: str
) -> dict[str, object] | None:
    if location.kind == "register" and location.register is not None:
        return {
            "kind": "register",
            "register": location.register,
            "width": location.width_bits,
            "at": phase,
        }
    if location.kind == "stack" and location.stack_offset is not None:
        return {
            "kind": "stack",
            "offset": location.stack_offset,
            "width": location.width_bits,
            "at": phase,
        }
    return None


def _is_operation_exit(
    transfer: Any,
    unit_ids: set[str],
    transfers: Mapping[str, Any],
) -> bool:
    if not transfer.actions:
        return False
    outcome = transfer.actions[-1]
    if outcome.op == "outcome_return":
        return True
    if outcome.op in {"outcome_indirect", "outcome_nonlocal"}:
        return True
    starts = {row.rva_start: row.identity for row in transfers.values()}
    targets = (
        outcome.args[:1]
        if outcome.op in {"outcome_fallthrough", "outcome_jump"}
        else outcome.args[1:3] if outcome.op == "outcome_branch" else ()
    )
    return any(
        starts.get(target) not in unit_ids for target in targets
    )


__all__ = [
    "LibraryProviderBindingError",
    "build_checked_library_provider_binding_v1",
]
