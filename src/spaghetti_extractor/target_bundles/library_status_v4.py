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
    read_library_behavior_pack_declaration,
)
from ..libraries.abi_catalog import CATALOG_SEARCH_INDEX_CODEC_V3
from ..libraries.v4_record_support import canonical_sha256
from ..libraries.v4_release_set import read_library_release_set_v4
from ..libraries.v4_identity_records import (
    LibraryIslandHypothesisV4,
    LibraryReleaseHypothesesV4,
)
from ..semantic_providers.qualification_v2 import (
    SemanticProviderQualificationV2,
)
from ..util import json_dumps, sha256_file, sha256_text, write_json


def _issue(status: str, code: str, location: str) -> dict[str, object]:
    return {"status": status, "code": code, "location": location}


def _next_action(issue: dict[str, object]) -> str:
    code = issue.get("code")
    field = issue.get("field")
    if code == "abi_required_fact_missing" and isinstance(field, str):
        field_actions = {
            "arguments": (
                "add checked call-site/callee input-location evidence or a pinned "
                "header/debug declaration for this exact library snapshot"
            ),
            "results": (
                "recover the machine result locations and their caller uses, or add a "
                "pinned declaration"
            ),
            "variadic": (
                "reconcile reachable call-site arities with pinned declaration metadata"
            ),
            "preserved_state": (
                "complete checked register preservation across every function return"
            ),
            "stack_cleanup": (
                "classify every reachable return and reconcile its exact stack delta"
            ),
            "calling_convention": (
                "reconcile symbol decoration, argument locations, and return cleanup"
            ),
        }
        return field_actions.get(
            field,
            f"supply checked physical ABI evidence for {field}",
        )
    actions = {
        "abi_constraint_contradiction": (
            "inspect the listed machine, declaration, and match evidence IDs; correct "
            "the contradictory profile rather than choosing one source"
        ),
        "abi_alternative_budget_exceeded": (
            "refine call-site or declaration evidence to reduce the finite ABI alternatives"
        ),
        "abi_fact_ambiguous": (
            "use the matched symbol, return cleanup, and checked call sites to reduce this "
            "field to one physical ABI value"
        ),
        "abi_declaration_match_ambiguous": (
            "make declaration symbol selectors unique within this pinned catalog snapshot"
        ),
        "abi_checked_summary_not_authorizing": (
            "close the referenced checked parametric summary before using this function match"
        ),
        "abi_declaration_or_machine_evidence_required": (
            "add a pinned declaration spec or improve checked machine call-boundary recovery"
        ),
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
        "library_semantic_provider_missing": (
            "build the selected island check and direct semantic-provider qualification"
        ),
        "library_semantic_provider_incomplete": (
            "inspect the direct provider blockers and complete its contextual refinement"
        ),
        "library_semantic_provider_unbound": (
            "regenerate the checked island and direct provider"
        ),
        "checked_island_receipt_stale": "regenerate the checked island from current hypotheses",
        "library_semantic_provider_stale": (
            "regenerate the direct provider from the current island and behavior pack"
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
    provider: SemanticProviderQualificationV2 | None,
    expected_provenance: frozenset[str],
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
    if provider is None:
        issues.append(_issue("incomplete", "library_semantic_provider_missing", location))
    elif receipt is None:
        issues.append(_issue("incomplete", "library_semantic_provider_unbound", location))
    elif provider.payload.get("status") != "complete":
        provider_issues = provider.payload.get("blockers")
        if isinstance(provider_issues, list) and provider_issues:
            issues.extend(dict(row) for row in provider_issues if isinstance(row, dict))
        else:
            issues.append(
                _issue("incomplete", "library_semantic_provider_incomplete", location)
            )
    else:
        dependencies = frozenset(str(item) for item in provider.payload["dependencies"])
        receipt_dependency = (
            "provider-provenance:checked-library-island:"
            + sha256_text(json_dumps(receipt.to_payload()) + "\n")
        )
        required = expected_provenance | {receipt_dependency}
        if not required.issubset(dependencies):
            issues.append(_issue("violated", "library_semantic_provider_stale", location))
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
                    read_library_behavior_pack_declaration(value).implementation
                    if Path(value).is_dir()
                    else REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1.read(value)
                )
                for value in values
            ),
            key=lambda item: item.implementation_id,
        )
    )


def _load_provider_qualifications(
    values: Iterable[Path | str],
) -> dict[tuple[str, ...], SemanticProviderQualificationV2]:
    result: dict[tuple[str, ...], SemanticProviderQualificationV2] = {}
    for value in values:
        path = Path(value)
        if path.is_dir():
            path /= "semantic-provider-qualification.json"
        try:
            provider = SemanticProviderQualificationV2.parse(
                json.loads(path.read_text(encoding="utf-8"))
            )
        except (OSError, ValueError) as error:
            raise ValueError(f"cannot read library semantic provider: {error}") from error
        units = []
        for definition in provider.semantic_slice.payload["definitions"]:
            symbol_id = str(definition["symbol_id"])
            prefix = "original:function:"
            if not symbol_id.startswith(prefix):
                raise ValueError("library semantic provider owns a non-function symbol")
            units.append(symbol_id[len(prefix):])
        key = tuple(sorted(units))
        if not key or key in result:
            raise ValueError("library semantic-provider unit ownership is ambiguous")
        result[key] = provider
    return result


def _implementation_provenance(
    values: Iterable[Path | str],
) -> dict[str, frozenset[str]]:
    result: dict[str, frozenset[str]] = {}
    for value in values:
        if isinstance(value, ReusableLibraryImplementationV1):
            continue
        root = Path(value)
        if not root.is_dir() or not (root / "behavior-pack.json").is_file():
            continue
        declaration = read_library_behavior_pack_declaration(root)
        implementation_id = declaration.implementation.implementation_id
        dependencies = frozenset({
            "provider-provenance:library-behavior-pack:"
            + sha256_file(root / "behavior-pack.json"),
            "provider-provenance:library-source-qualification:"
            + sha256_file(root / "source-qualification-v1.json"),
        })
        if implementation_id in result:
            raise ValueError("reusable library implementation provenance is duplicated")
        result[implementation_id] = dependencies
    return result


def build_library_status_v4(
    *,
    target_id: str,
    release_hypotheses: Path | str,
    catalog_search_index: Path | str | None = None,
    adoption_intents: Iterable[LibraryAdoptionIntentV1 | Path | str] = (),
    checked_islands: Iterable[CheckedLibraryIslandV1 | Path | str] = (),
    provider_qualifications: Iterable[Path | str] = (),
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
    providers_by_units = _load_provider_qualifications(provider_qualifications)
    implementation_values = tuple(implementations)
    implementation_rows = _load_implementations(implementation_values)
    implementation_provenance = _implementation_provenance(
        implementation_values
    )
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
        provider = (
            None
            if release_island is None
            else providers_by_units.get(
                tuple(sorted(release_island[1].target_unit_ids))
            )
        )
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
                        provider=provider,
                        expected_provenance=implementation_provenance.get(
                            intent.implementation_id, frozenset()
                        ),
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
            provider = providers_by_units.get(tuple(sorted(island.target_unit_ids)))
            effective = receipt if receipt is not None else island
            issues = [issue.to_payload() for issue in effective.issues]
            if (
                intent is not None
                and intent.mode == "adopt"
                and provider is not None
                and provider.payload.get("status") != "complete"
            ):
                issues.extend(
                    dict(issue)
                    for issue in provider.payload.get("blockers", [])
                    if isinstance(issue, dict)
                )
            blockers.extend(issues)
            implementation_status = effective.implementation_status
            if intent is not None and intent.mode == "adopt":
                if (
                    provider is None
                    or provider.payload.get("status") != "complete"
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
                    "semantic_provider": (
                        None if provider is None else provider.payload
                    ),
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
