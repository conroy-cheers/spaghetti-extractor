"""Operator status for release/island-scoped linked-library recognition."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from ..artifacts.formats import LIBRARY_STATUS_V4_FORMAT
from ..libraries.v4_adoption_records import (
    CHECKED_LIBRARY_ISLAND_CODEC_V1,
    LIBRARY_ADOPTION_INTENT_CODEC_V1,
    REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1,
    CheckedLibraryIslandV1,
    LibraryAdoptionIntentV1,
    ReusableLibraryImplementationV1,
)
from ..libraries.v4_behavior_manifest import (
    read_library_behavior_pack_declaration_v1,
)
from ..libraries.abi_catalog import CATALOG_SEARCH_INDEX_CODEC_V3
from ..libraries.v4_record_support import canonical_sha256
from ..libraries.v4_release_set import read_library_release_set_v4
from ..libraries.v4_identity_records import (
    LibraryIslandHypothesisV4,
    LibraryReleaseHypothesesV4,
)
from ..util import write_json


def _issue(status: str, code: str, location: str) -> dict[str, object]:
    return {"status": status, "code": code, "location": location}


def _next_action(issue: dict[str, object]) -> str:
    code = issue.get("code")
    actions = {
        "canonical_boundary_not_checked": (
            "adopt a reusable implementation, then build the island check so "
            "canonical call, return, external-site, and indirect-target boundaries are checked"
        ),
        "maximum_weight_assignment_ambiguous": (
            "inspect the island and add stronger catalog identity evidence such as exact "
            "bytes, relocations, symbols, retained-member structure, or call adjacency"
        ),
        "retained_member_functions_unmatched": (
            "complete target function recovery or correct the catalog member-retention model"
        ),
        "reusable_implementation_unavailable": (
            "author or import a statically qualified reusable behavior pack covering every "
            "operation in the island"
        ),
        "checked_island_receipt_missing": "build the selected island authority check",
        "generated_library_component_missing": (
            "build the selected island check to generate and validate its ordinary component"
        ),
        "generated_library_component_incomplete": (
            "inspect the generated component issues and complete its reusable machine mapping"
        ),
        "generated_library_component_unbound": "regenerate the checked island and component",
        "checked_island_receipt_stale": "regenerate the checked island from current hypotheses",
        "generated_library_component_stale": (
            "regenerate the component from the current checked island and behavior pack"
        ),
    }
    if isinstance(code, str) and code in actions:
        return actions[code]
    family = issue.get("family")
    if family == "identity":
        return "inspect the identity evidence and resolve the reported catalog ambiguity"
    if family == "boundary":
        return "close the reported machine boundary with canonical static evidence"
    if family == "implementation":
        return "provide or repair a statically qualified reusable implementation"
    return "inspect the referenced artifact and regenerate the affected dependency closure"


def _selected_artifact_issues(
    *,
    target_id: str,
    intent: LibraryAdoptionIntentV1,
    release: LibraryReleaseHypothesesV4,
    island: LibraryIslandHypothesisV4,
    receipt: CheckedLibraryIslandV1 | None,
    component: dict[str, object] | None,
) -> list[dict[str, object]]:
    issues: list[dict[str, object]] = []
    location = f"intent:{intent.intent_id}"
    if receipt is None:
        issues.append(_issue("incomplete", "checked_island_receipt_missing", location))
    else:
        expected_receipt = (
            receipt.target_id == target_id
            and receipt.target_binary_sha256 == release.target_binary_sha256
            and receipt.island_id == island.island_id
            and receipt.hypotheses_sha256 == release.hypotheses_sha256
            and receipt.implementation_id == intent.implementation_id
            and receipt.checked_unit_ids == island.target_unit_ids
            and receipt.checked_operation_ids == island.operation_ids
            and receipt.checked_boundary_edge_ids == island.boundary_edge_ids
        )
        if not expected_receipt:
            issues.append(_issue("violated", "checked_island_receipt_stale", location))
        elif receipt.status != "complete":
            issues.extend(issue.to_payload() for issue in receipt.issues)
    if component is None:
        issues.append(_issue("incomplete", "generated_library_component_missing", location))
    elif receipt is None:
        issues.append(_issue("incomplete", "generated_library_component_unbound", location))
    elif component.get("status") != "complete":
        component_issues = component.get("issues")
        if isinstance(component_issues, list) and component_issues:
            issues.extend(dict(row) for row in component_issues if isinstance(row, dict))
        else:
            issues.append(
                _issue("incomplete", "generated_library_component_incomplete", location)
            )
    else:
        bindings = component.get("bindings")
        expected_component = (
            component.get("target_id") == target_id
            and component.get("island_id") == island.island_id
            and component.get("implementation_id") == intent.implementation_id
            and component.get("unit_ids") == list(island.target_unit_ids)
            and component.get("operation_ids") == list(island.operation_ids)
            and isinstance(bindings, dict)
            and bindings.get("target_binary_sha256")
            == release.target_binary_sha256
            and bindings.get("machine_ir_sha256") == receipt.machine_ir_sha256
            and bindings.get("checked_island_receipt_sha256")
            == receipt.receipt_sha256
        )
        if not expected_component:
            issues.append(_issue("violated", "generated_library_component_stale", location))
    return issues


def _load_intents(
    values: Iterable[LibraryAdoptionIntentV1 | Path | str],
) -> tuple[LibraryAdoptionIntentV1, ...]:
    return tuple(
        sorted(
            (
                value
                if isinstance(value, LibraryAdoptionIntentV1)
                else LIBRARY_ADOPTION_INTENT_CODEC_V1.read(value)
                for value in values
            ),
            key=lambda item: item.intent_id,
        )
    )


def _load_receipts(
    values: Iterable[CheckedLibraryIslandV1 | Path | str],
) -> tuple[CheckedLibraryIslandV1, ...]:
    return tuple(
        sorted(
            (
                value
                if isinstance(value, CheckedLibraryIslandV1)
                else CHECKED_LIBRARY_ISLAND_CODEC_V1.read(value)
                for value in values
            ),
            key=lambda item: item.checked_island_id,
        )
    )


def _load_implementations(
    values: Iterable[ReusableLibraryImplementationV1 | Path | str],
) -> tuple[ReusableLibraryImplementationV1, ...]:
    return tuple(
        sorted(
            (
                value
                if isinstance(value, ReusableLibraryImplementationV1)
                else (
                    read_library_behavior_pack_declaration_v1(value).implementation
                    if Path(value).is_dir()
                    else REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1.read(value)
                )
                for value in values
            ),
            key=lambda item: item.implementation_id,
        )
    )


def _load_generated_components(
    values: Iterable[Path | str],
) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for value in values:
        path = Path(value)
        if path.is_dir():
            path /= "library-component.json"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise ValueError(f"cannot read generated library component: {error}") from error
        if not isinstance(payload, dict):
            raise ValueError("generated library component must be an object")
        core = dict(payload)
        if (
            core.pop("package_sha256", None) != canonical_sha256(core)
            or payload.get("format")
            != "spaghetti-extractor-generated-library-component-v1"
        ):
            raise ValueError("generated library component binding is stale")
        island_id = payload.get("island_id")
        if not isinstance(island_id, str) or island_id in result:
            raise ValueError("generated library component island ID is invalid")
        result[island_id] = payload
    return result


def build_library_status_v4(
    *,
    target_id: str,
    release_hypotheses: Path | str,
    catalog_search_index: Path | str | None = None,
    adoption_intents: Iterable[LibraryAdoptionIntentV1 | Path | str] = (),
    checked_islands: Iterable[CheckedLibraryIslandV1 | Path | str] = (),
    generated_components: Iterable[Path | str] = (),
    implementations: Iterable[ReusableLibraryImplementationV1 | Path | str] = (),
    out: Path | str,
) -> dict[str, object]:
    releases = read_library_release_set_v4(release_hypotheses)
    catalog = (
        None
        if catalog_search_index is None
        else CATALOG_SEARCH_INDEX_CODEC_V3.read(catalog_search_index)
    )
    catalog_functions = (
        {} if catalog is None else {row.function_id: row for row in catalog.functions}
    )
    if catalog is not None and any(
        release.catalog_search_index_sha256 != catalog.index_sha256
        for release in releases
    ):
        raise ValueError("library status catalog search index is stale")
    intents = _load_intents(adoption_intents)
    receipts = _load_receipts(checked_islands)
    components_by_island = _load_generated_components(generated_components)
    implementation_rows = _load_implementations(implementations)
    implementations_by_id = {
        implementation.implementation_id: implementation
        for implementation in implementation_rows
    }
    islands = {
        island.island_id: (release, island)
        for release in releases
        for island in release.islands
    }
    receipt_by_island = {receipt.island_id: receipt for receipt in receipts}
    duplicate_receipts = len(receipt_by_island) != len(receipts)
    intent_by_island = {intent.island_id: intent for intent in intents}
    duplicate_intents = len(intent_by_island) != len(intents)
    duplicate_implementations = len(implementations_by_id) != len(implementation_rows)
    violations: list[dict[str, object]] = []
    selection_blockers: list[dict[str, object]] = []
    if duplicate_intents:
        violations.append(
            {
                "status": "violated",
                "code": "duplicate_library_adoption_intent",
                "location": "library-adoption-intents",
            }
        )
    if duplicate_receipts:
        violations.append(
            {
                "status": "violated",
                "code": "duplicate_checked_library_island",
                "location": "checked-library-islands",
            }
        )
    if duplicate_implementations:
        violations.append(
            {
                "status": "violated",
                "code": "duplicate_reusable_library_implementation",
                "location": "reusable-library-implementations",
            }
        )
    selections = []
    for intent in intents:
        release_island = islands.get(intent.island_id)
        receipt = receipt_by_island.get(intent.island_id)
        generated_component = components_by_island.get(intent.island_id)
        issues: list[dict[str, object]] = []
        if intent.target_id != target_id:
            issues.append(
                {
                    "status": "violated",
                    "code": "adoption_target_mismatch",
                    "location": f"intent:{intent.intent_id}",
                }
            )
        if release_island is None:
            issues.append(
                {
                    "status": "violated",
                    "code": "adoption_island_missing",
                    "location": f"intent:{intent.intent_id}",
                }
            )
        else:
            release, selected_island = release_island
            if intent.hypotheses_sha256 != release.hypotheses_sha256:
                issues.append(
                    {
                        "status": "violated",
                        "code": "adoption_hypotheses_stale",
                        "location": f"intent:{intent.intent_id}",
                    }
                )
            if (
                intent.mode == "adopt"
                and intent.implementation_id not in selected_island.implementation_ids
            ):
                issues.append(
                    {
                        "status": "violated",
                        "code": "adoption_implementation_unavailable",
                        "location": f"intent:{intent.intent_id}",
                    }
                )
        if intent.mode == "adopt":
            if release_island is not None:
                release, selected_island = release_island
                issues.extend(
                    _selected_artifact_issues(
                        target_id=target_id,
                        intent=intent,
                        release=release,
                        island=selected_island,
                        receipt=receipt,
                        component=generated_component,
                    )
                )
        selection_status = (
            "violated"
            if any(issue["status"] == "violated" for issue in issues)
            else "incomplete"
            if issues
            else "draft"
            if intent.mode == "draft"
            else "ready"
        )
        selections.append(
            {
                "intent_id": intent.intent_id,
                "island_id": intent.island_id,
                "mode": intent.mode,
                "implementation_id": intent.implementation_id,
                "recipe_id": intent.recipe_id,
                "status": selection_status,
                "issues": issues,
            }
        )
        selection_blockers.extend(issues)
    hypothesis_rows = []
    blockers = list(violations) + selection_blockers
    for release in releases:
        for release_issue in release.issues:
            blockers.append(release_issue.to_payload())
        for island in release.islands:
            intent = intent_by_island.get(island.island_id)
            receipt = receipt_by_island.get(island.island_id)
            generated_component = components_by_island.get(island.island_id)
            effective = receipt if receipt is not None else island
            issues = [issue.to_payload() for issue in effective.issues]
            if (
                intent is not None
                and intent.mode == "adopt"
                and generated_component is not None
                and generated_component.get("status") != "complete"
            ):
                issues.extend(
                    dict(issue)
                    for issue in generated_component.get("issues", [])
                    if isinstance(issue, dict)
                )
            blockers.extend(issues)
            implementation_status = effective.implementation_status
            if intent is not None and intent.mode == "adopt":
                if (
                    generated_component is None
                    or generated_component.get("status") != "complete"
                ):
                    implementation_status = "incomplete"
            overall_status = (
                "violated"
                if "violated"
                in {effective.identity_status, effective.boundary_status, implementation_status}
                else "incomplete"
                if "incomplete"
                in {effective.identity_status, effective.boundary_status, implementation_status}
                else "complete"
            )
            recipes = []
            for implementation_id in island.implementation_ids:
                implementation = implementations_by_id.get(implementation_id)
                if implementation is None:
                    continue
                recipes.append(
                    {
                        "implementation_id": implementation.implementation_id,
                        "recipe_id": implementation.recipe_id,
                        "status": implementation.status,
                    }
                )
            catalog_rows = []
            for function_id in island.catalog_function_ids:
                function = catalog_functions.get(function_id)
                if function is None:
                    continue
                catalog_rows.append(
                    {
                        "function_id": function.function_id,
                        "member_id": function.member_id,
                        "symbols": list(function.symbols),
                        "operation_id": function.operation_id,
                        "abi_profile_id": function.abi_profile_id,
                    }
                )
            hypothesis_rows.append(
                {
                    "id": island.island_id,
                    "family_id": island.family_id,
                    "release_id": island.release_id,
                    "hypotheses_sha256": release.hypotheses_sha256,
                    "target_unit_ids": list(island.target_unit_ids),
                    "member_ids": list(island.member_ids),
                    "catalog_function_ids": list(island.catalog_function_ids),
                    "operation_ids": list(island.operation_ids),
                    "catalog_functions": catalog_rows,
                    "implementation_ids": list(island.implementation_ids),
                    "recipes": sorted(recipes, key=lambda row: str(row["recipe_id"])),
                    "matches": [match.to_payload() for match in island.matches],
                    "identity_status": effective.identity_status,
                    "boundary_status": effective.boundary_status,
                    "implementation_status": implementation_status,
                    "status": overall_status,
                    "adoption": None if intent is None else intent.to_payload(),
                    "generated_component": generated_component,
                    "issues": issues,
                }
            )
    adoption_status = (
        "violated"
        if any(item.get("status") == "violated" for item in violations)
        or any(item["status"] == "violated" for item in selections)
        else "incomplete"
        if any(item["status"] == "incomplete" for item in selections)
        else "ready"
    )
    recognition_status = (
        "not_applicable"
        if not hypothesis_rows
        else "violated"
        if any(row["status"] == "violated" for row in hypothesis_rows)
        else "incomplete"
        if any(row["status"] == "incomplete" for row in hypothesis_rows)
        else "complete"
    )
    unique_blockers = {canonical_sha256(item): item for item in blockers}
    primary_blockers = [
        {**item, "next_action": _next_action(item)}
        for item in unique_blockers.values()
    ]
    core: dict[str, object] = {
        "format": LIBRARY_STATUS_V4_FORMAT,
        "status": adoption_status,
        "adoption_status": adoption_status,
        "recognition_status": recognition_status,
        "target_id": target_id,
        "catalog_search_index_sha256": (
            None if catalog is None else catalog.index_sha256
        ),
        "authorizing": False,
        "executes_original_binary": False,
        "counts": {
            "releases": len(releases),
            "islands": len(hypothesis_rows),
            "identity_complete": sum(row["identity_status"] == "complete" for row in hypothesis_rows),
            "boundary_complete": sum(row["boundary_status"] == "complete" for row in hypothesis_rows),
            "implementation_complete": sum(row["implementation_status"] == "complete" for row in hypothesis_rows),
            "adoption_intents": len(intents),
            "ready_adoptions": sum(row["status"] == "ready" for row in selections),
            "primary_blockers": len(unique_blockers),
        },
        "islands": sorted(hypothesis_rows, key=lambda row: str(row["id"])),
        "selections": sorted(selections, key=lambda row: str(row["intent_id"])),
        "primary_blockers": sorted(
            primary_blockers,
            key=lambda row: (
                0 if row.get("status") == "violated" else 1,
                {"identity": 0, "boundary": 1, "implementation": 2}.get(
                    str(row.get("family")), 3
                ),
                str(row.get("code")),
                str(row.get("location")),
            ),
        ),
        "policy": {
            "identity_match_authorizes_replacement": False,
            "operator_adoption_authorizes_replacement": False,
            "checked_island_receipt_required": True,
            "unselected_units_remain_machine_ir": True,
            "handwritten_behavior_tests_required": False,
        },
    }
    result = {**core, "status_sha256": canonical_sha256(core)}
    write_json(Path(out), result)
    return result


__all__ = ["build_library_status_v4"]
