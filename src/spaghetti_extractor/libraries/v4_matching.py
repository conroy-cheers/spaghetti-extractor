"""Checked, island-local V4 linked-library hypothesis synthesis."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ..artifacts.formats import LIBRARY_RELEASE_HYPOTHESES_SET_V4_FORMAT
from ..util import write_json
from .abi_catalog import CATALOG_SEARCH_INDEX_CODEC_V3, CatalogSearchIndexV3
from .abi_records import LibraryFunctionSignatureV3
from .constellations import (
    _match_score,
    _optimal_assignment,
    generate_sparse_candidates,
)
from .signature_graph import TARGET_SIGNATURE_GRAPH_CODEC_V3, TargetSignatureGraphV3
from .span_matching import discover_static_span_matches
from .v4_adoption_records import (
    REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1,
    ReusableLibraryImplementationV1,
)
from .v4_behavior_manifest import read_library_behavior_pack_declaration_v1
from .v4_identity_records import (
    LIBRARY_RELEASE_HYPOTHESES_CODEC_V4,
    LibraryFunctionMatchV4,
    LibraryIslandHypothesisV4,
    LibraryIslandIssueV4,
    LibraryReleaseHypothesesV4,
    LibraryReleaseIssueV4,
)
from .v4_record_support import canonical_sha256, stable_id


_STRONG_EVIDENCE = frozenset(
    {
        "exact_bytes",
        "normalized_bytes",
        "relocation_masked_bytes",
        "relocation_masked_static_span",
        "unit_merkle",
    }
)


@dataclass(frozen=True)
class _Region:
    region_id: str
    rva_start: int
    rva_end: int
    unit_ids: tuple[str, ...]


def _region_id(*, start: int, end: int, units: Iterable[str]) -> str:
    return stable_id(
        "library-target-region-v4",
        {"rva_start": start, "rva_end": end, "unit_ids": sorted(set(units))},
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


def _candidate_rows(
    target: TargetSignatureGraphV3,
    index: CatalogSearchIndexV3,
    target_pe: Path | str,
) -> tuple[
    dict[str, _Region],
    dict[tuple[str, str], set[str]],
    dict[tuple[str, str], str],
]:
    regions: dict[str, _Region] = {}
    evidence: dict[tuple[str, str], set[str]] = defaultdict(set)
    abi_status: dict[tuple[str, str], str] = {}
    target_by_id = {item.function_id: item for item in target.functions}
    sparse, _issues = generate_sparse_candidates(target, index)
    for match in sparse:
        if not _STRONG_EVIDENCE.intersection(match.evidence):
            continue
        function = target_by_id[match.target_function_id]
        region_id = _region_id(
            start=function.rva_start,
            end=function.rva_end,
            units=function.unit_ids,
        )
        regions[region_id] = _Region(
            region_id, function.rva_start, function.rva_end, function.unit_ids
        )
        pair = (region_id, match.catalog_function_id)
        evidence[pair].update(match.evidence)
        abi_status[pair] = match.abi_status
    for match in discover_static_span_matches(
        target_graph=target, search_index=index, target_pe=target_pe
    ):
        region_id = _region_id(
            start=match.target_rva_start,
            end=match.target_rva_end,
            units=match.target_unit_ids,
        )
        regions[region_id] = _Region(
            region_id,
            match.target_rva_start,
            match.target_rva_end,
            match.target_unit_ids,
        )
        evidence[(region_id, match.catalog_function_id)].update(match.evidence)
        abi_status.setdefault((region_id, match.catalog_function_id), "incomplete")
    return regions, evidence, abi_status


def _selected_for_release(
    *,
    family_id: str,
    release_id: str,
    index: CatalogSearchIndexV3,
    regions: dict[str, _Region],
    evidence: dict[tuple[str, str], set[str]],
    abi_status: dict[tuple[str, str], str],
) -> tuple[list[LibraryFunctionMatchV4], set[str]]:
    from .abi_records import FunctionMatchV3

    catalog = {
        item.function_id: item
        for item in index.functions
        if item.family_id == family_id and item.release_id == release_id
    }
    rows = [
        FunctionMatchV3(
            target_function_id=region_id,
            catalog_function_id=catalog_id,
            evidence=tuple(sorted(items)),
            abi_status=abi_status.get((region_id, catalog_id), "incomplete"),
        )
        for (region_id, catalog_id), items in evidence.items()
        if catalog_id in catalog
    ]
    selected, ambiguous = _optimal_assignment(rows)
    result = []
    for row in selected:
        region = regions[row.target_function_id]
        result.append(
            LibraryFunctionMatchV4.create(
                target_function_id=region.region_id,
                target_span_start=region.rva_start,
                target_span_end=region.rva_end,
                target_unit_ids=region.unit_ids,
                catalog_function_id=row.catalog_function_id,
                evidence=row.evidence,
                score=_match_score(row),
            )
        )
    return result, ambiguous


def _island_components(
    selected: Iterable[LibraryFunctionMatchV4],
    catalog: dict[str, LibraryFunctionSignatureV3],
) -> tuple[tuple[LibraryFunctionMatchV4, ...], ...]:
    rows = {item.catalog_function_id: item for item in selected}
    by_symbol = {
        symbol: function.function_id
        for function in catalog.values()
        for symbol in function.symbols
    }
    adjacency: dict[str, set[str]] = {identity: set() for identity in rows}
    by_member: dict[str, set[str]] = defaultdict(set)
    for identity, match in rows.items():
        function = catalog[identity]
        if function.retention_model == "archive_member":
            by_member[function.member_id].add(identity)
        for symbol in (*function.direct_callees, *function.data_refs):
            destination = by_symbol.get(symbol)
            if destination in rows:
                adjacency[identity].add(destination)
                adjacency[destination].add(identity)
    for member_functions in by_member.values():
        for identity in member_functions:
            adjacency[identity].update(member_functions - {identity})
    components = []
    remaining = set(rows)
    while remaining:
        pending = [min(remaining)]
        component: set[str] = set()
        while pending:
            identity = pending.pop()
            if identity in component:
                continue
            component.add(identity)
            remaining.discard(identity)
            pending.extend(adjacency[identity] - component)
        components.append(
            tuple(sorted((rows[identity] for identity in component), key=lambda item: item.match_id))
        )
    return tuple(components)


def _implementation_ids(
    *,
    family_id: str,
    release_id: str,
    operation_ids: set[str],
    implementations: tuple[ReusableLibraryImplementationV1, ...],
) -> tuple[str, ...]:
    return tuple(
        item.implementation_id
        for item in implementations
        if item.status == "complete"
        and item.family_id == family_id
        and release_id in item.compatible_release_ids
        and operation_ids
        <= {mapping.operation_id for mapping in item.operation_source_mappings}
    )


def _release_hash(
    index: CatalogSearchIndexV3, family_id: str, release_id: str
) -> str:
    return canonical_sha256(
        {
            "family_id": family_id,
            "release_id": release_id,
            "functions": [
                item.to_payload()
                for item in index.functions
                if item.family_id == family_id and item.release_id == release_id
            ],
        }
    )


def solve_library_release_hypotheses(
    *,
    target_id: str,
    target_signatures: TargetSignatureGraphV3 | Path | str,
    search_index: CatalogSearchIndexV3 | Path | str,
    target_pe: Path | str,
    out_dir: Path | str,
    implementations: Iterable[ReusableLibraryImplementationV1 | Path | str] = (),
) -> tuple[LibraryReleaseHypothesesV4, ...]:
    """Solve release-scoped, independently adoptable library islands."""

    target = (
        target_signatures
        if isinstance(target_signatures, TargetSignatureGraphV3)
        else TARGET_SIGNATURE_GRAPH_CODEC_V3.read(target_signatures)
    )
    index = (
        search_index
        if isinstance(search_index, CatalogSearchIndexV3)
        else CATALOG_SEARCH_INDEX_CODEC_V3.read(search_index)
    )
    checked_implementations = _load_implementations(implementations)
    regions, evidence, abi_status = _candidate_rows(target, index, target_pe)
    release_keys = sorted(
        {
            (function.family_id, function.release_id)
            for function in index.functions
            if any(pair[1] == function.function_id for pair in evidence)
        }
    )
    provisional: list[tuple[LibraryReleaseHypothesesV4, int, int]] = []
    for family_id, release_id in release_keys:
        catalog = {
            item.function_id: item
            for item in index.functions
            if item.family_id == family_id and item.release_id == release_id
        }
        selected, ambiguous = _selected_for_release(
            family_id=family_id,
            release_id=release_id,
            index=index,
            regions=regions,
            evidence=evidence,
            abi_status=abi_status,
        )
        islands = []
        for component in _island_components(selected, catalog):
            catalog_function_ids = {
                item.catalog_function_id for item in component
            }
            operation_ids = {
                catalog[function_id].operation_id or function_id
                for function_id in catalog_function_ids
            }
            unit_ids = {unit for item in component for unit in item.target_unit_ids}
            member_ids = {
                catalog[identity].member_id for identity in catalog_function_ids
            }
            issues = []
            for item in component:
                if item.target_function_id in ambiguous:
                    issues.append(
                        LibraryIslandIssueV4.create(
                            family="identity",
                            status="incomplete",
                            code="maximum_weight_assignment_ambiguous",
                            message="another injective assignment has the same total identity evidence",
                            location=f"target-region:{item.target_function_id}",
                        )
                    )
            for member_id in sorted(member_ids):
                retained = {
                    function.function_id
                    for function in catalog.values()
                    if function.member_id == member_id
                    and function.retention_model == "archive_member"
                }
                missing = retained - catalog_function_ids
                if missing:
                    issues.append(
                        LibraryIslandIssueV4.create(
                            family="identity",
                            status="incomplete",
                            code="retained_member_functions_unmatched",
                            message=f"archive retention requires unmatched functions {sorted(missing)!r}",
                            location=f"catalog-member:{member_id}",
                        )
                    )
            issues.append(
                LibraryIslandIssueV4.create(
                    family="boundary",
                    status="incomplete",
                    code="canonical_boundary_not_checked",
                    message="canonical target boundary evidence has not yet been checked",
                    location=f"family:{family_id}/release:{release_id}",
                )
            )
            implementation_ids = _implementation_ids(
                family_id=family_id,
                release_id=release_id,
                operation_ids=operation_ids,
                implementations=checked_implementations,
            )
            if not implementation_ids:
                issues.append(
                    LibraryIslandIssueV4.create(
                        family="implementation",
                        status="incomplete",
                        code="reusable_implementation_unavailable",
                        message="no checked implementation covers every island operation",
                        location=f"family:{family_id}/release:{release_id}",
                    )
                )
            islands.append(
                LibraryIslandHypothesisV4.create(
                    target_id=target_id,
                    family_id=family_id,
                    release_id=release_id,
                    target_unit_ids=unit_ids,
                    member_ids=member_ids,
                    catalog_function_ids=catalog_function_ids,
                    operation_ids=operation_ids,
                    matches=component,
                    implementation_ids=implementation_ids,
                    issues=issues,
                )
            )
        if not islands:
            continue
        release = LibraryReleaseHypothesesV4.create(
            target_id=target_id,
            family_id=family_id,
            release_id=release_id,
            target_binary_sha256=target.binary_sha256,
            target_signature_graph_sha256=target.graph_sha256,
            catalog_search_index_sha256=index.index_sha256,
            catalog_release_sha256=_release_hash(index, family_id, release_id),
            islands=islands,
        )
        score = sum(match.score for island in islands for match in island.matches)
        matches = sum(len(island.matches) for island in islands)
        provisional.append((release, score, matches))
    by_family: dict[str, list[tuple[LibraryReleaseHypothesesV4, int, int]]] = defaultdict(list)
    for row in provisional:
        by_family[row[0].family_id].append(row)
    final = []
    for family_id, rows in sorted(by_family.items()):
        best = max((score, count) for _release, score, count in rows)
        tied = sorted(
            release.release_id
            for release, score, count in rows
            if (score, count) == best
        )
        for release, score, count in rows:
            issues = release.issues
            if len(tied) > 1 and (score, count) == best:
                issues = (
                    *issues,
                    LibraryReleaseIssueV4.create(
                        status="incomplete",
                        code="release_assignment_ambiguous",
                        message="multiple releases have the same maximum identity evidence",
                        location=f"family:{family_id}",
                        competing_release_ids=tied,
                    ),
                )
                release = LibraryReleaseHypothesesV4.create(
                    target_id=release.target_id,
                    family_id=release.family_id,
                    release_id=release.release_id,
                    target_binary_sha256=release.target_binary_sha256,
                    target_signature_graph_sha256=release.target_signature_graph_sha256,
                    catalog_search_index_sha256=release.catalog_search_index_sha256,
                    catalog_release_sha256=release.catalog_release_sha256,
                    islands=release.islands,
                    issues=issues,
                )
            final.append(release)
    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    manifest_rows = []
    for release in sorted(final, key=lambda item: (item.family_id, item.release_id)):
        filename = f"release-{canonical_sha256((release.family_id, release.release_id))[:20]}.json"
        LIBRARY_RELEASE_HYPOTHESES_CODEC_V4.write(output / filename, release)
        manifest_rows.append(
            {
                "family_id": release.family_id,
                "release_id": release.release_id,
                "path": filename,
                "hypotheses_sha256": release.hypotheses_sha256,
                "status": release.status,
            }
        )
    manifest_core = {
        "format": LIBRARY_RELEASE_HYPOTHESES_SET_V4_FORMAT,
        "target_id": target_id,
        "target_binary_sha256": target.binary_sha256,
        "target_signature_graph_sha256": target.graph_sha256,
        "catalog_search_index_sha256": index.index_sha256,
        "releases": manifest_rows,
    }
    write_json(
        output / "manifest.json",
        {**manifest_core, "manifest_sha256": canonical_sha256(manifest_core)},
    )
    return tuple(sorted(final, key=lambda item: (item.family_id, item.release_id)))


__all__ = ["solve_library_release_hypotheses"]
