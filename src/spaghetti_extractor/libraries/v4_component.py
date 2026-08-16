"""Generate ordinary component artifacts from a checked library adoption."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.formats import GENERATED_LIBRARY_COMPONENT_V1_FORMAT
from ..components.machine_binding import (
    COMPONENT_MACHINE_BINDING_DECLARATION_V2,
    check_component_machine_binding,
    materialize_component_machine_binding,
)
from ..components.semantic_contract import build_component_semantic_contract
from ..components.universal_contract import build_component_contract_v3
from ..components.universal_binding import build_component_machine_binding_v3
from .component_implementations import (
    adapt_library_behavior_pack_implementation_v3,
)
from ..util import sha256_file, write_json
from .abi_catalog import CATALOG_SEARCH_INDEX_CODEC_V3, CatalogSearchIndexV3
from .abi_records import LibraryAbiProfileV3, ValueLocationV3
from .matching_support import load_machine_package
from .v4_adoption_records import (
    CHECKED_LIBRARY_ISLAND_CODEC_V1,
    CheckedLibraryIslandV1,
)
from .v4_behavior_pack import load_reusable_library_behavior_pack_v1
from .v4_record_support import canonical_sha256
from .v4_release_set import select_library_island_v1


LIBRARY_COMPONENT_PACKAGE_V1 = GENERATED_LIBRARY_COMPONENT_V1_FORMAT


def build_checked_library_component_v1(
    *,
    machine_ir: Path | str,
    release_hypotheses: Path | str,
    checked_island: CheckedLibraryIslandV1 | Path | str,
    behavior_pack: Path | str,
    catalog_search_index: CatalogSearchIndexV3 | Path | str,
    canonical_external_sites: Path | str | None,
    out_dir: Path | str,
) -> dict[str, Any]:
    """Materialize one component without original execution or handwritten tests."""

    receipt = (
        checked_island
        if isinstance(checked_island, CheckedLibraryIslandV1)
        else CHECKED_LIBRARY_ISLAND_CODEC_V1.read(checked_island)
    )
    pack = load_reusable_library_behavior_pack_v1(behavior_pack)
    release, island = select_library_island_v1(
        release_hypotheses, receipt.island_id
    )
    catalog = (
        catalog_search_index
        if isinstance(catalog_search_index, CatalogSearchIndexV3)
        else CATALOG_SEARCH_INDEX_CODEC_V3.read(catalog_search_index)
    )
    machine = load_machine_package(Path(machine_ir))
    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    issues: list[dict[str, str]] = []

    def issue(code: str, message: str) -> None:
        issues.append({"status": "incomplete", "code": code, "message": message})

    if receipt.status != "complete":
        issue("checked_island_incomplete", "library island authority is incomplete")
    if receipt.hypotheses_sha256 != release.hypotheses_sha256:
        issue("checked_island_stale", "library island hypotheses binding is stale")
    if receipt.machine_ir_sha256 != machine.ir_sha256:
        issue("checked_island_machine_ir_stale", "machine-IR binding is stale")
    machine_binary = machine.manifest.get("binary")
    machine_binary_sha256 = (
        machine_binary.get("sha256")
        if isinstance(machine_binary, Mapping)
        else None
    )
    if receipt.target_binary_sha256 != machine_binary_sha256:
        issue("checked_island_target_stale", "target binary binding is stale")
    if receipt.checked_unit_ids != island.target_unit_ids:
        issue(
            "checked_island_unit_inventory_stale",
            "checked and recognized library units differ",
        )
    if receipt.checked_operation_ids != island.operation_ids:
        issue(
            "checked_island_operation_inventory_stale",
            "checked and recognized library operations differ",
        )
    if (
        receipt.implementation_id != pack.implementation.implementation_id
        or receipt.implementation_sha256
        != pack.implementation.implementation_sha256
    ):
        issue("checked_island_implementation_stale", "behavior-pack binding is stale")

    interface = pack.interface
    operations = interface.operation_index()
    functions = {row.function_id: row for row in catalog.functions}
    profiles = {row.profile_id: row for row in catalog.abi_profiles}
    matches_by_operation: dict[str, Any] = {}
    for match in island.matches:
        function = functions.get(match.catalog_function_id)
        if function is None:
            issue("catalog_function_missing", match.catalog_function_id)
            continue
        operation_id = function.operation_id or function.function_id
        if operation_id in matches_by_operation:
            issue("operation_match_ambiguous", operation_id)
            continue
        matches_by_operation[operation_id] = (match, function)
    if set(matches_by_operation) != set(operations):
        issue(
            "operation_inventory_mismatch",
            "recognized operations differ from the behavior-pack interface",
        )
    if interface.state:
        issue(
            "stateful_library_component_generation_unsupported",
            "automatic state binding requires an explicit reusable mapping",
        )
    if interface.effects:
        issue(
            "effectful_library_component_generation_unsupported",
            "automatic effect binding requires an explicit reusable mapping",
        )
    if interface.services:
        issue(
            "serviceful_library_component_generation_unsupported",
            "automatic service binding requires an explicit reusable mapping",
        )

    operation_bindings = []
    if not issues:
        for operation_id, operation in sorted(operations.items()):
            match, function = matches_by_operation[operation_id]
            profile = profiles.get(function.abi_profile_id or "")
            if profile is None:
                issue("operation_abi_missing", operation_id)
                continue
            binding = _operation_binding(
                operation=operation,
                profile=profile,
                unit_ids=match.target_unit_ids,
                machine=machine,
                issue=issue,
            )
            if binding is not None:
                operation_bindings.append(binding)

    component_id = interface.identity
    declaration = {
        "format": COMPONENT_MACHINE_BINDING_DECLARATION_V2,
        "id": component_id,
        "unit_ids": list(island.target_unit_ids),
        "operations": operation_bindings,
        "services": [],
    }
    write_json(output / "machine-binding-declaration.json", declaration)
    shutil.copyfile(
        pack.root / "portable-interface.json", output / "portable-interface.json"
    )
    shutil.copytree(pack.root / "source-package", output / "source-package")
    CHECKED_LIBRARY_ISLAND_CODEC_V1.write(
        output / "checked-library-island.json", receipt
    )
    machine_binding_receipt: dict[str, Any] | None = None
    semantic_contract: dict[str, Any] | None = None
    universal_contract = None
    universal_binding = None
    universal_implementation = None
    if not issues:
        binding = materialize_component_machine_binding(
            declaration=declaration,
            interface=output / "portable-interface.json",
            machine_ir=machine.ir_path,
            machine_ir_manifest=machine.manifest_path,
        )
        write_json(output / "machine-binding.json", binding)
        machine_binding_receipt = check_component_machine_binding(
            binding=binding,
            interface=output / "portable-interface.json",
            machine_ir=machine.ir_path,
            machine_ir_manifest=machine.manifest_path,
            canonical_external_sites=canonical_external_sites,
        )
        write_json(
            output / "machine-binding-receipt.json", machine_binding_receipt
        )
        if machine_binding_receipt.get("status") != "checked":
            issue(
                "generated_machine_binding_incomplete",
                "generated machine binding did not pass its canonical checker",
            )
        else:
            semantic_contract = build_component_semantic_contract(
                interface=output / "portable-interface.json",
                binding=output / "machine-binding.json",
                machine_ir=machine.ir_path,
                machine_ir_manifest=machine.manifest_path,
                canonical_external_sites=canonical_external_sites,
            )
            write_json(output / "semantic-contract.json", semantic_contract)
            if semantic_contract.get("status") != "satisfied":
                issue(
                    "generated_semantic_contract_incomplete",
                    "machine-derived semantic contract is not satisfied",
                )
            else:
                universal_contract = build_component_contract_v3(
                    interface=output / "portable-interface.json",
                    machine_binding=output / "machine-binding.json",
                    machine_binding_receipt=output / "machine-binding-receipt.json",
                    semantic_contract=output / "semantic-contract.json",
                    out=output,
                )
                universal_binding = build_component_machine_binding_v3(
                    contract=universal_contract,
                    machine_binding=output / "machine-binding.json",
                    machine_binding_receipt=output / "machine-binding-receipt.json",
                    semantic_contract=output / "semantic-contract.json",
                    out=output,
                )
                universal_implementation = (
                    adapt_library_behavior_pack_implementation_v3(
                        implementation_id=(
                            f"{pack.implementation.implementation_id}_portable_c"
                        ),
                        contract=universal_contract,
                        machine_binding=universal_binding,
                        behavior_pack=behavior_pack,
                        checked_island=output / "checked-library-island.json",
                        out=output,
                    )
                )
                if (
                    universal_contract.status != "checked"
                    or not universal_binding.authorizing
                    or not universal_implementation.authorizing
                ):
                    issue(
                        "generated_universal_component_incomplete",
                        "universal contract, binding, or implementation is incomplete",
                    )

    status = "complete" if not issues else "incomplete"
    core: dict[str, Any] = {
        "format": LIBRARY_COMPONENT_PACKAGE_V1,
        "status": status,
        "component_id": component_id,
        "target_id": receipt.target_id,
        "island_id": receipt.island_id,
        "implementation_id": receipt.implementation_id,
        "unit_ids": list(receipt.checked_unit_ids),
        "operation_ids": list(receipt.checked_operation_ids),
        "bindings": {
            "target_binary_sha256": receipt.target_binary_sha256,
            "machine_ir_sha256": receipt.machine_ir_sha256,
            "checked_island_receipt_sha256": receipt.receipt_sha256,
            "behavior_pack_sha256": pack.pack_sha256,
            "interface_sha256": interface.sha256,
            "source_package_sha256": pack.source["implementation_sha256"],
            "machine_binding_receipt_sha256": (
                None
                if machine_binding_receipt is None
                else machine_binding_receipt.get("receipt_sha256")
            ),
            "semantic_contract_sha256": (
                None
                if semantic_contract is None
                else semantic_contract.get("contract_sha256")
            ),
            "universal_contract_sha256": (
                None
                if universal_contract is None
                else universal_contract.contract_sha256
            ),
            "universal_machine_binding_sha256": (
                None
                if universal_binding is None
                else universal_binding.binding_sha256
            ),
            "universal_implementation_sha256": (
                None
                if universal_implementation is None
                else universal_implementation.implementation_sha256
            ),
        },
        "issues": sorted(issues, key=lambda row: row["code"]),
        "policy": {
            "original_binary_executed": False,
            "handwritten_behavior_tests_used": False,
            "component_interface_is_portable": True,
            "candidate_activation_requires_complete_package": True,
        },
    }
    result = {**core, "package_sha256": canonical_sha256(core)}
    write_json(output / "library-component.json", result)
    return result


def _operation_binding(
    *,
    operation: Any,
    profile: LibraryAbiProfileV3,
    unit_ids: tuple[str, ...],
    machine: Any,
    issue: Any,
) -> dict[str, Any] | None:
    if profile.hidden_sret or profile.variadic.kind != "none" or profile.callback_slots:
        issue(
            "operation_abi_profile_requires_explicit_mapping",
            operation.identity,
        )
        return None
    if len(profile.arguments) != len(operation.parameters):
        issue("operation_argument_count_mismatch", operation.identity)
        return None
    if len(profile.returns) != len(operation.results):
        issue("operation_result_count_mismatch", operation.identity)
        return None
    parameters = []
    results = []
    for logical, location in zip(operation.parameters, profile.arguments, strict=True):
        projection = _projection(location, "entry")
        if projection is None:
            issue("operation_argument_location_unsupported", operation.identity)
            return None
        parameters.append({"id": logical.identity, "projection": projection})
    for logical, location in zip(operation.results, profile.returns, strict=True):
        projection = _projection(location, "exit")
        if projection is None:
            issue("operation_result_location_unsupported", operation.identity)
            return None
        results.append({"id": logical.identity, "projection": projection})
    ordered_units = sorted(
        (machine.by_id[unit_id] for unit_id in unit_ids),
        key=lambda row: (row.start, row.end, row.identity),
    )
    exits = tuple(
        row.identity
        for row in ordered_units
        if _is_operation_exit(row.payload, set(unit_ids), machine)
    )
    if not exits:
        issue("operation_exit_not_recovered", operation.identity)
        return None
    return {
        "operation_id": operation.identity,
        "entry_unit_ids": [ordered_units[0].identity],
        "exit_unit_ids": sorted(exits),
        "parameters": parameters,
        "results": results,
        "state": [],
        "preserved_state_ids": [],
        "effects": [],
        "callback_operation_ids": [],
        "continuation_unit_ids": [],
    }


def _projection(location: ValueLocationV3, phase: str) -> dict[str, Any] | None:
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
    payload: Mapping[str, Any], unit_ids: set[str], machine: Any
) -> bool:
    control = payload.get("control")
    semantics = payload.get("semantics")
    outcome = semantics.get("outcome") if isinstance(semantics, Mapping) else None
    if isinstance(outcome, Mapping) and outcome.get("kind") == "return":
        return True
    if not isinstance(control, Mapping):
        return False
    if control.get("has_indirect_target") is True:
        return True
    starts = {row.start: row.identity for row in machine.units}
    targets = control.get("direct_targets")
    return isinstance(targets, list) and any(
        isinstance(target, int) and starts.get(target) not in unit_ids
        for target in targets
    )


__all__ = [
    "LIBRARY_COMPONENT_PACKAGE_V1",
    "build_checked_library_component_v1",
]
