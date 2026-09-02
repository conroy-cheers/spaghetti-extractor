"""Fail-closed activation of one recognized library island.

Identity matching is proposal evidence.  This checker rebinds an operator
intent to the exact island and checks every structural crossing directly
against executable-transfer-plan-v2 and resolved-external-environment-v1.
No parallel external-site or indirect-target authority graph is accepted.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path
from typing import Any

from ..external.resolved import ResolvedExternalEnvironmentV1
from ..semantic_link.module_v2_codec import LinkedSemanticModuleV2
from ..transfer.plan import load_executable_transfer_plan
from ..util import sha256_file
from .abi_catalog import CATALOG_SEARCH_INDEX_CODEC_V3, CatalogSearchIndexV3
from .v4_adoption_records import (
    CHECKED_LIBRARY_ISLAND_CODEC_V1,
    LIBRARY_ADOPTION_INTENT_CODEC_V1,
    REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1,
    CheckedLibraryIslandV1,
    LibraryAdoptionIntentV1,
    ReusableLibraryImplementationV1,
)
from .v4_behavior_manifest import read_library_behavior_pack_declaration
from .v4_identity_records import (
    LibraryIslandIssueV4,
)
from .v4_record_support import stable_id
from .v4_release_set import select_library_island_v1


_CHECKER_ID = "checked-library-island-v1"


def _issue(
    family: str,
    status: str,
    code: str,
    message: str,
    location: str,
) -> LibraryIslandIssueV4:
    return LibraryIslandIssueV4.create(
        family=family,
        status=status,
        code=code,
        message=message,
        location=location,
    )


def _edge_id(
    *, kind: str, direction: str, source: str, target: str, abi_id: str | None
) -> str:
    return stable_id(
        "library-boundary-edge-v4",
        {
            "kind": kind,
            "direction": direction,
            "source": source,
            "target": target,
            "abi_profile_id": abi_id,
        },
    )


def _direct_crossings(
    transfers: tuple[Any, ...], island_ids: set[str]
) -> tuple[tuple[str, str, str, str, str, str | None], ...]:
    starts = {transfer.rva_start: transfer for transfer in transfers}
    edges: dict[str, tuple[str, str, str, str | None]] = {}
    for transfer in transfers:
        if not transfer.actions:
            continue
        outcome = transfer.actions[-1]
        control_targets = (
            outcome.args[:1]
            if outcome.op in {"outcome_fallthrough", "outcome_jump"}
            else outcome.args[1:3] if outcome.op == "outcome_branch" else ()
        )
        targets = [
            *(('control', target, None) for target in control_targets),
            *(
                ('call', call.target_rva, None)
                for call in transfer.calls
                if call.kind == "internal_call"
            ),
        ]
        source_inside = transfer.identity in island_ids
        for kind, target, abi_id in targets:
            destination = starts.get(target)
            destination_inside = destination is not None and destination.identity in island_ids
            if source_inside == destination_inside:
                continue
            direction = "outbound" if source_inside else "inbound"
            destination_id = (
                destination.identity if destination is not None else f"rva:{target:08x}"
            )
            edge = _edge_id(
                kind=kind,
                direction=direction,
                source=transfer.identity,
                target=destination_id,
                abi_id=abi_id,
            )
            edges[edge] = (
                kind, direction, transfer.identity, destination_id, abi_id
            )
    return tuple(
        (edge_id, kind, direction, source, target, abi_id)
        for edge_id, (kind, direction, source, target, abi_id) in sorted(edges.items())
    )


def _external_identity_key(
    *, dll: object, symbol: object, ordinal: object
) -> tuple[str, str, int | None] | None:
    if (
        not isinstance(dll, str)
        or not dll
        or (symbol is None) == (ordinal is None)
        or (symbol is not None and (not isinstance(symbol, str) or not symbol))
        or (
            ordinal is not None
            and (
                not isinstance(ordinal, int)
                or isinstance(ordinal, bool)
                or ordinal < 0
            )
        )
    ):
        return None
    return (dll.lower(), "" if symbol is None else symbol, ordinal)


def _resolved_external_contracts(
    environment: ResolvedExternalEnvironmentV1,
) -> dict[tuple[str, str, int | None], Mapping[str, Any]]:
    result: dict[tuple[str, str, int | None], Mapping[str, Any]] = {}
    for raw in environment.payload["machine_import_contracts"]:
        if not isinstance(raw, Mapping) or not isinstance(
            raw.get("identity"), Mapping
        ):
            raise ValueError("resolved machine-import contract is malformed")
        identity = raw["identity"]
        key = _external_identity_key(
            dll=identity.get("dll"),
            symbol=identity.get("symbol"),
            ordinal=identity.get("ordinal"),
        )
        if (
            key is None
            or key in result
            or not isinstance(raw.get("contract"), Mapping)
            or not isinstance(raw.get("boundary"), Mapping)
        ):
            raise ValueError(
                "resolved machine-import contracts are incomplete or duplicated"
            )
        result[key] = raw
    return result


def _finite_route_index(
    transfer_payload: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    rows = transfer_payload.get("finite_control_routes")
    if not isinstance(rows, list):
        raise ValueError("transfer plan finite-control routes are malformed")
    result: dict[str, Mapping[str, Any]] = {}
    for raw in rows:
        if not isinstance(raw, Mapping) or not isinstance(raw.get("unit_id"), str):
            raise ValueError("transfer plan finite-control route is malformed")
        unit_id = str(raw["unit_id"])
        if unit_id in result:
            raise ValueError("transfer plan finite-control routes are duplicated")
        result[unit_id] = raw
    return result


def check_library_island_v1(
    *,
    target_id: str,
    linked_semantic_module: LinkedSemanticModuleV2 | Path | str,
    release_hypotheses: Path | str,
    island_id: str,
    adoption_intent: LibraryAdoptionIntentV1 | Path | str,
    implementation: ReusableLibraryImplementationV1 | Path | str,
    catalog_search_index: CatalogSearchIndexV3 | Path | str,
    out: Path | str,
) -> CheckedLibraryIslandV1:
    """Check one adoption without executing either the target or candidate."""

    release, island = select_library_island_v1(release_hypotheses, island_id)
    intent = (
        adoption_intent
        if isinstance(adoption_intent, LibraryAdoptionIntentV1)
        else LIBRARY_ADOPTION_INTENT_CODEC_V1.read(adoption_intent)
    )
    implementation_pack_sha256: str | None = None
    if isinstance(implementation, ReusableLibraryImplementationV1):
        checked_implementation = implementation
    elif Path(implementation).is_dir():
        behavior_pack = read_library_behavior_pack_declaration(implementation)
        checked_implementation = behavior_pack.implementation
        implementation_pack_sha256 = behavior_pack.pack_sha256
    else:
        checked_implementation = REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1.read(
            implementation
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
    transfer_path = linked.require_member("transfer_plan")
    resolved_external_environment = linked.require_member(
        "resolved_external_environment"
    )
    transfer_payload, transfers = load_executable_transfer_plan(
        transfer_path, require_complete=True
    )
    transfer_bindings = transfer_payload["bindings"]
    transfers_by_id = {item.identity: item for item in transfers}
    environment = (
        resolved_external_environment
        if isinstance(
            resolved_external_environment, ResolvedExternalEnvironmentV1
        )
        else ResolvedExternalEnvironmentV1.parse(
            json.loads(
                Path(resolved_external_environment).read_text(encoding="utf-8")
            )
        )
    )
    if environment.payload["status"] != "complete":
        raise ValueError("library boundary requires a complete resolved environment")
    external_contracts = _resolved_external_contracts(environment)
    finite_routes = _finite_route_index(transfer_payload)
    issues = [issue for issue in island.issues if issue.family == "identity"]

    if intent.target_id != target_id or island.target_id != target_id:
        issues.append(
            _issue(
                "identity",
                "violated",
                "adoption_target_mismatch",
                "adoption, island, and checked target must have one target identity",
                f"intent:{intent.intent_id}",
            )
        )
    if intent.island_id != island.island_id:
        issues.append(
            _issue(
                "identity",
                "violated",
                "adoption_island_mismatch",
                "adoption selects a different recognized island",
                f"intent:{intent.intent_id}",
            )
        )
    if intent.hypotheses_sha256 != release.hypotheses_sha256:
        issues.append(
            _issue(
                "identity",
                "violated",
                "adoption_hypotheses_stale",
                "adoption was authored against different release hypotheses",
                f"intent:{intent.intent_id}",
            )
        )
    if intent.mode != "adopt" or intent.implementation_id != checked_implementation.implementation_id:
        issues.append(
            _issue(
                "implementation",
                "violated",
                "adoption_implementation_mismatch",
                "checked adoption must select this exact reusable implementation",
                f"intent:{intent.intent_id}",
            )
        )
    if release.target_binary_sha256 != transfer_bindings["pe_sha256"]:
        issues.append(
            _issue(
                "identity",
                "violated",
                "library_transfer_plan_target_stale",
                "recognized library island belongs to another PE",
                f"island:{island.island_id}",
            )
        )
    environment_bindings = environment.payload["bindings"]
    if environment_bindings["module_pe_sha256"] != transfer_bindings["pe_sha256"]:
        issues.append(
            _issue(
                "identity",
                "violated",
                "library_resolved_environment_target_stale",
                "resolved environment belongs to another PE",
                f"island:{island.island_id}",
            )
        )

    missing_units = sorted(set(island.target_unit_ids) - set(transfers_by_id))
    if missing_units:
        issues.append(
            _issue(
                "boundary",
                "violated",
                "island_unit_missing",
                f"machine IR lacks selected units {missing_units!r}",
                f"island:{island.island_id}",
            )
        )
    island_ids = set(island.target_unit_ids)
    direct_crossings = (
        () if missing_units else _direct_crossings(transfers, island_ids)
    )
    boundary_ids = {
        edge_id for edge_id, _kind, _direction, _source, _target, _abi in direct_crossings
    }
    catalog_functions = {row.function_id: row for row in catalog.functions}
    for edge_id, kind, _direction, _source, target, abi_id in direct_crossings:
        if kind == "call" and abi_id is None:
            issues.append(
                _issue(
                    "boundary",
                    "incomplete",
                    "direct_boundary_abi_missing",
                    "direct call crossing lacks a checked machine ABI contract",
                    f"boundary-edge:{edge_id}",
                )
            )

    for unit_id in sorted(island_ids - set(missing_units)):
        transfer = transfers_by_id[unit_id]
        for call in transfer.calls:
            if call.kind != "external_call":
                continue
            key = _external_identity_key(
                dll=call.dll, symbol=call.symbol, ordinal=call.ordinal
            )
            edge_id = stable_id(
                "library-external-call-v1",
                {
                    "unit_id": unit_id,
                    "event_index": call.call_index,
                    "dll": call.dll,
                    "symbol": call.symbol,
                    "ordinal": call.ordinal,
                },
            )
            boundary_ids.add(edge_id)
            if key is None or key not in external_contracts:
                issues.append(
                    _issue(
                        "boundary",
                        "incomplete",
                        "resolved_external_contract_missing",
                        "external crossing has no checked resolved-environment contract",
                        f"unit:{unit_id}/event:{call.call_index}",
                    )
                )

        has_indirect = (
            bool(transfer.actions)
            and transfer.actions[-1].op == "outcome_indirect"
        )
        route = finite_routes.get(unit_id)
        if has_indirect and route is None:
            issues.append(
                _issue(
                    "boundary",
                    "incomplete",
                    "finite_control_route_missing",
                    "indirect island exit lacks a checked finite transfer route",
                    f"unit:{unit_id}",
                )
            )
        elif route is not None:
            boundary_ids.add(str(route["route_inventory_sha256"]))

    island_rvas = {transfers_by_id[unit_id].rva_start for unit_id in island_ids}
    for source in transfers:
        if source.identity in island_ids or not source.actions:
            continue
        if source.actions[-1].op != "outcome_indirect":
            continue
        route = finite_routes.get(source.identity)
        if route is None:
            issues.append(
                _issue(
                    "boundary",
                    "incomplete",
                    "inbound_indirect_universe_unresolved",
                    "an external indirect transfer has no finite route proving it cannot enter the island",
                    f"unit:{source.identity}",
                )
            )
            continue
        targets = {
            int(row["target_rva"])
            for row in route["routes"]
            if isinstance(row, Mapping) and isinstance(row.get("target_rva"), int)
        }
        if targets & island_rvas:
            boundary_ids.add(str(route["route_inventory_sha256"]))

    implementation_operations = {
        mapping.operation_id
        for mapping in checked_implementation.operation_source_mappings
    }
    missing_operations = sorted(set(island.operation_ids) - implementation_operations)
    if checked_implementation.family_id != island.family_id:
        issues.append(
            _issue(
                "implementation",
                "violated",
                "implementation_family_mismatch",
                "implementation belongs to another library family",
                f"implementation:{checked_implementation.implementation_id}",
            )
        )
    if island.release_id not in checked_implementation.compatible_release_ids:
        issues.append(
            _issue(
                "implementation",
                "violated",
                "implementation_release_mismatch",
                "implementation does not cover the recognized release",
                f"implementation:{checked_implementation.implementation_id}",
            )
        )
    if missing_operations:
        issues.append(
            _issue(
                "implementation",
                "incomplete",
                "implementation_operations_missing",
                f"implementation omits island operations {missing_operations!r}",
                f"implementation:{checked_implementation.implementation_id}",
            )
        )
    if checked_implementation.status != "complete":
        issues.extend(checked_implementation.issues)
        if not checked_implementation.issues:
            issues.append(
                _issue(
                    "implementation",
                    "incomplete",
                    "implementation_qualification_incomplete",
                    "implementation has no complete compile/refinement qualification",
                    f"implementation:{checked_implementation.implementation_id}",
                )
            )

    for function_id in island.catalog_function_ids:
        function = catalog_functions.get(function_id)
        if function is None:
            issues.append(
                _issue(
                    "identity",
                    "violated",
                    "catalog_function_missing",
                    "selected function is absent from the bound catalog index",
                    f"catalog-function:{function_id}",
                )
            )
        else:
            issues.append(
                _issue(
                    "boundary",
                    "incomplete",
                    "target_operation_physical_abi_unresolved",
                    "recognized operation lacks physical ABI authority from the linked semantic module",
                    f"catalog-function:{function_id}",
                )
            )

    receipt = CheckedLibraryIslandV1.create(
        target_id=target_id,
        target_binary_sha256=release.target_binary_sha256,
        machine_ir_sha256=str(transfer_bindings["machine_ir_sha256"]),
        island_id=island.island_id,
        hypotheses_sha256=release.hypotheses_sha256,
        implementation_id=checked_implementation.implementation_id,
        implementation_sha256=checked_implementation.implementation_sha256,
        checker_id=_CHECKER_ID,
        checked_unit_ids=island.target_unit_ids,
        checked_operation_ids=island.operation_ids,
        checked_boundary_edge_ids=boundary_ids,
        dependency_sha256s=(
            sha256_file(transfer_path),
            str(transfer_bindings["machine_ir_sha256"]),
            catalog.index_sha256,
            checked_implementation.implementation_sha256,
            implementation_pack_sha256
            or checked_implementation.implementation_sha256,
            intent.intent_sha256,
            environment.identity,
            str(transfer_bindings["finite_control_routes_sha256"]),
        ),
        issues=issues,
    )
    CHECKED_LIBRARY_ISLAND_CODEC_V1.write(out, receipt)
    return receipt


__all__ = ["check_library_island_v1"]
