"""Sparse ABI-first candidate generation and constellation inference."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol, Sequence

from .abi_catalog import (
    CATALOG_SEARCH_INDEX_CODEC_V3,
    LIBRARY_ABI_CATALOG_CODEC_V3,
    CatalogSearchIndexV3,
    build_catalog_search_index,
)
from .abi_records import (
    ABI_CATALOG_V3_FORMAT,
    CONSTELLATION_HYPOTHESES_V3_FORMAT,
    CATALOG_SEARCH_INDEX_V3_FORMAT,
    ConstellationHypothesisV3,
    FunctionMatchV3,
    LibraryAbiError,
    LibraryAbiProfileV3,
    LibraryFunctionSignatureV3,
    LibraryIssueV3,
    StrictCodec,
    _array,
    _object,
    _sha256,
    _text,
    canonical_sha256,
    phase_status,
    stable_id,
)
from .signature_graph import (
    TARGET_SIGNATURE_GRAPH_CODEC_V3,
    TargetSignatureGraphV3,
)


class NativeCandidateBackend(Protocol):
    """Optional accelerator.  Returned pairs are always checked in Python."""

    def generate_library_candidates(
        self, target_graph: Mapping[str, Any], search_index: Mapping[str, Any]
    ) -> Iterable[tuple[str, str]]: ...


class NativeExtensionCandidateBackend:
    """Adapter for the optional PyO3 sparse retrieval extension."""

    def __init__(self, module: Any | None = None) -> None:
        if module is None:
            try:
                import spaghetti_extractor_native as module
            except ImportError as error:
                raise LibraryAbiError(
                    "native_library_backend_unavailable",
                    str(error),
                    location="library candidate backend",
                ) from error
        self._module = module

    @staticmethod
    def _catalog_record(function: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "record_id": str(function["id"]),
            # ABI filtering remains in the checked Python layer so signatures
            # with missing ABI evidence still produce identity hypotheses.
            "abi_key": "abi-proposal-only-v3",
            "fixed_anchor_hashes": [
                value
                for value in (function.get("exact_bytes_sha256"),)
                if isinstance(value, str)
            ],
            "normalized_hashes": [
                value
                for value in (function.get("normalized_bytes_sha256"),)
                if isinstance(value, str)
            ],
            "structural_feature_hashes": sorted(
                value
                for value in (
                    function.get("unit_merkle_sha256"),
                    function.get("cfg_sha256"),
                )
                if isinstance(value, str)
            ),
        }

    @staticmethod
    def _target_record(function: Mapping[str, Any]) -> dict[str, Any]:
        return NativeExtensionCandidateBackend._catalog_record(function)

    def generate_library_candidates(
        self, target_graph: Mapping[str, Any], search_index: Mapping[str, Any]
    ) -> Iterable[tuple[str, str]]:
        catalog = [
            self._catalog_record(item)
            for item in search_index.get("functions", [])
            if isinstance(item, Mapping)
        ]
        targets = [
            self._target_record(item)
            for item in target_graph.get("functions", [])
            if isinstance(item, Mapping)
        ]
        for row in self._module.retrieve_library_candidates(catalog, targets):
            yield str(row["target_record_id"]), str(row["catalog_record_id"])


@dataclass(frozen=True)
class ConstellationHypothesisSetV3:
    status: str
    target_graph_sha256: str
    target_machine_ir_sha256: str
    search_index_sha256: str
    hypotheses: tuple[ConstellationHypothesisV3, ...]
    issues: tuple[LibraryIssueV3, ...]
    hypotheses_sha256: str

    @property
    def core_payload(self) -> dict[str, Any]:
        return {
            "format": CONSTELLATION_HYPOTHESES_V3_FORMAT,
            "status": self.status,
            "executes_original_binary": False,
            "bindings": {
                "target_graph_sha256": self.target_graph_sha256,
                "target_machine_ir_sha256": self.target_machine_ir_sha256,
                "search_index_sha256": self.search_index_sha256,
            },
            "hypotheses": [item.to_payload() for item in self.hypotheses],
            "issues": [item.to_payload() for item in self.issues],
            "authority": {
                "rankings_are_diagnostic_only": True,
                "whole_island_activation_required": True,
            },
        }

    def to_payload(self) -> dict[str, Any]:
        return {
            **self.core_payload,
            "hypotheses_sha256": self.hypotheses_sha256,
        }

    @classmethod
    def from_payload(
        cls, value: object, location: str
    ) -> "ConstellationHypothesisSetV3":
        row = _object(
            value,
            {
                "format",
                "status",
                "executes_original_binary",
                "bindings",
                "hypotheses",
                "issues",
                "authority",
                "hypotheses_sha256",
            },
            {},
            location,
        )
        if row["format"] != CONSTELLATION_HYPOTHESES_V3_FORMAT:
            raise LibraryAbiError(
                "wrong_artifact_format",
                "not a v3 constellation hypothesis set",
                location=f"{location}.format",
            )
        if row["executes_original_binary"] is not False:
            raise LibraryAbiError(
                "original_execution_forbidden",
                "constellation matching claims original execution",
                location=f"{location}.executes_original_binary",
            )
        authority = _object(
            row["authority"],
            {"rankings_are_diagnostic_only", "whole_island_activation_required"},
            {},
            f"{location}.authority",
        )
        if (
            authority["rankings_are_diagnostic_only"] is not True
            or authority["whole_island_activation_required"] is not True
        ):
            raise LibraryAbiError(
                "authority_policy_contradiction",
                "hypothesis set attempts to authorize ranking or partial activation",
                location=f"{location}.authority",
            )
        bindings = _object(
            row["bindings"],
            {"target_graph_sha256", "target_machine_ir_sha256", "search_index_sha256"},
            {},
            f"{location}.bindings",
        )
        result = cls(
            status=_text(row["status"], f"{location}.status"),
            target_graph_sha256=_sha256(
                bindings["target_graph_sha256"],
                f"{location}.bindings.target_graph_sha256",
            ),
            target_machine_ir_sha256=_sha256(
                bindings["target_machine_ir_sha256"],
                f"{location}.bindings.target_machine_ir_sha256",
            ),
            search_index_sha256=_sha256(
                bindings["search_index_sha256"],
                f"{location}.bindings.search_index_sha256",
            ),
            hypotheses=tuple(
                ConstellationHypothesisV3.from_payload(
                    item, f"{location}.hypotheses[{index}]"
                )
                for index, item in enumerate(
                    _array(row["hypotheses"], f"{location}.hypotheses")
                )
            ),
            issues=tuple(
                LibraryIssueV3.from_payload(
                    item, f"{location}.issues[{index}]"
                )
                for index, item in enumerate(
                    _array(row["issues"], f"{location}.issues")
                )
            ),
            hypotheses_sha256=_sha256(
                row["hypotheses_sha256"], f"{location}.hypotheses_sha256"
            ),
        )
        if result.status != phase_status(result.issues):
            raise LibraryAbiError(
                "status_contradiction",
                "hypothesis-set status disagrees with its global issues",
                location=f"{location}.status",
            )
        hypothesis_ids = tuple(item.hypothesis_id for item in result.hypotheses)
        if len(set(hypothesis_ids)) != len(hypothesis_ids):
            raise LibraryAbiError(
                "hypothesis_identity_conflict",
                "hypothesis IDs are not unique",
                location=f"{location}.hypotheses",
            )
        if canonical_sha256(result.core_payload) != result.hypotheses_sha256:
            raise LibraryAbiError(
                "stale_hypotheses_hash",
                "hypothesis SHA-256 does not bind its contents",
                location=f"{location}.hypotheses_sha256",
            )
        return result


CONSTELLATION_HYPOTHESIS_SET_CODEC_V3 = StrictCodec(
    lambda value: value.to_payload(), ConstellationHypothesisSetV3.from_payload
)


def _load_target(
    source: Path | str | TargetSignatureGraphV3,
) -> TargetSignatureGraphV3:
    return (
        source
        if isinstance(source, TargetSignatureGraphV3)
        else TARGET_SIGNATURE_GRAPH_CODEC_V3.read(source)
    )


def _load_index(
    source: Path | str | CatalogSearchIndexV3 | Sequence[Path | str],
) -> CatalogSearchIndexV3:
    if isinstance(source, CatalogSearchIndexV3):
        return source
    if isinstance(source, (str, Path)):
        path = Path(source)
        try:
            import json

            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise LibraryAbiError(
                "search_index_read_failed", str(error), location=str(path)
            ) from error
        if isinstance(raw, Mapping) and raw.get("format") == CATALOG_SEARCH_INDEX_V3_FORMAT:
            return CATALOG_SEARCH_INDEX_CODEC_V3.decode(raw, str(path))
        if isinstance(raw, Mapping) and raw.get("format") == ABI_CATALOG_V3_FORMAT:
            LIBRARY_ABI_CATALOG_CODEC_V3.decode(raw, str(path))
    with tempfile.TemporaryDirectory(prefix="spx-library-index-") as temporary:
        return build_catalog_search_index(
            source, Path(temporary) / "catalog-search-index.json"
        )


def _index_map(entries: Iterable[Any]) -> dict[str, tuple[str, ...]]:
    return {entry.key: entry.function_ids for entry in entries}


def _masked_anchor(function: Any) -> tuple[int, int, bytes] | None:
    """Return one deterministic fixed-byte anchor for a catalog signature."""

    if function.masked_bytes_hex is None or function.match_strength != "strong":
        return None
    data = bytes.fromhex(function.masked_bytes_hex)
    mutable = [False] * len(data)
    for offset, width, _kind, _target in function.relocation_holes:
        for index in range(offset, min(offset + width, len(mutable))):
            mutable[index] = True
    runs: list[tuple[int, int]] = []
    start = 0
    while start < len(data):
        while start < len(data) and mutable[start]:
            start += 1
        end = start
        while end < len(data) and not mutable[end]:
            end += 1
        if end - start >= 4:
            runs.append((start, end))
        start = end + 1
    if not runs:
        return None
    offset, end = min(runs, key=lambda item: (-min(item[1] - item[0], 8), item[0]))
    width = min(end - offset, 8)
    return len(data), offset, data[offset : offset + width]


def _relocation_masked_match(target_bytes: str | None, function: Any) -> bool:
    if target_bytes is None or function.masked_bytes_hex is None:
        return False
    target = bytes.fromhex(target_bytes)
    expected = bytes.fromhex(function.masked_bytes_hex)
    if len(target) != len(expected):
        return False
    mutable = bytearray(len(expected))
    for offset, width, _kind, _target in function.relocation_holes:
        if offset + width > len(expected):
            return False
        mutable[offset : offset + width] = b"\1" * width
    return all(mutable[index] or value == target[index] for index, value in enumerate(expected))


def _python_candidate_pairs(
    target: TargetSignatureGraphV3,
    index: CatalogSearchIndexV3,
    *,
    native_complement_only: bool = False,
) -> dict[tuple[str, str], set[str]]:
    normalized = _index_map(index.normalized_hash_index)
    exact = _index_map(index.exact_hash_index)
    unit_merkle = _index_map(index.unit_merkle_index)
    cfg = _index_map(index.cfg_hash_index)
    imports = _index_map(index.import_index)
    strings = _index_map(index.string_index)
    constants = _index_map(index.constant_index)
    catalog_by_id = {item.function_id: item for item in index.functions}
    profiles = {item.profile_id: item for item in index.abi_profiles}
    candidates: dict[tuple[str, str], set[str]] = {}
    masked_anchors: dict[tuple[int, int, bytes], list[str]] = {}
    anchor_shapes: set[tuple[int, int, int]] = set()
    for catalog_function in index.functions:
        anchor = _masked_anchor(catalog_function)
        if anchor is None:
            continue
        masked_anchors.setdefault(anchor, []).append(catalog_function.function_id)
        anchor_shapes.add((anchor[0], anchor[1], len(anchor[2])))
    for function in target.functions:
        strong: dict[str, set[str]] = {}

        def add(rows: Iterable[str], label: str) -> None:
            for catalog_id in rows:
                strong.setdefault(catalog_id, set()).add(label)

        if function.normalized_bytes_sha256 is not None:
            add(normalized.get(function.normalized_bytes_sha256, ()), "normalized_bytes")
        if function.exact_bytes_sha256 is not None:
            add(exact.get(function.exact_bytes_sha256, ()), "exact_bytes")
        add(unit_merkle.get(function.unit_merkle_sha256, ()), "unit_merkle")
        if function.bytes_hex is not None:
            target_bytes = bytes.fromhex(function.bytes_hex)
            for length, offset, width in sorted(anchor_shapes):
                if len(target_bytes) != length or offset + width > length:
                    continue
                key = (length, offset, target_bytes[offset : offset + width])
                for catalog_id in masked_anchors.get(key, ()):
                    if _relocation_masked_match(
                        function.bytes_hex, catalog_by_id[catalog_id]
                    ):
                        add((catalog_id,), "relocation_masked_bytes")
        cfg_bucket = cfg.get(function.cfg_sha256, ())
        if len(cfg_bucket) <= 64:
            add(cfg_bucket, "cfg")
        weak: dict[str, set[str]] = {}
        for value in function.imports:
            for catalog_id in imports.get(value, ()):
                weak.setdefault(catalog_id, set()).add(f"import:{value}")
        for value in function.strings:
            for catalog_id in strings.get(value, ()):
                weak.setdefault(catalog_id, set()).add(f"string:{value}")
        for value in function.constants:
            for catalog_id in constants.get(str(value), ()):
                weak.setdefault(catalog_id, set()).add(f"constant:{value}")
        for catalog_id, evidence in weak.items():
            if catalog_id in strong or len(evidence) >= 2:
                strong.setdefault(catalog_id, set()).update(evidence)
        for catalog_id, evidence in strong.items():
            if native_complement_only:
                catalog_function = catalog_by_id[catalog_id]
                catalog_profile = (
                    profiles.get(catalog_function.abi_profile_id)
                    if catalog_function.abi_profile_id is not None
                    else None
                )
                if (
                    function.abi_profile is not None
                    and catalog_profile is not None
                    and not _abi_difference(function.abi_profile, catalog_profile)
                ):
                    continue
            candidates[(function.function_id, catalog_id)] = evidence
    return candidates


def _abi_difference(
    target: LibraryAbiProfileV3, catalog: LibraryAbiProfileV3
) -> tuple[str, ...]:
    target_payload = target.to_payload()
    catalog_payload = catalog.to_payload()
    differences = []
    for field in (
        "architecture",
        "object_format",
        "calling_convention",
        "stack_cleanup",
        "arguments",
        "returns",
        "hidden_sret",
        "variadic",
        "preserved_registers",
        "callback_slots",
        "structure_layout_ids",
        "boundary_effects",
    ):
        if target_payload[field] != catalog_payload[field]:
            differences.append(field)
    return tuple(differences)


def generate_sparse_candidates(
    target: TargetSignatureGraphV3,
    index: CatalogSearchIndexV3,
    *,
    native_backend: NativeCandidateBackend | None = None,
) -> tuple[tuple[FunctionMatchV3, ...], tuple[LibraryIssueV3, ...]]:
    """Generate sparse candidates; all native proposals are checked in Python."""

    target_by_id = {item.function_id: item for item in target.functions}
    catalog_by_id = {item.function_id: item for item in index.functions}
    if native_backend is None:
        proposals = _python_candidate_pairs(target, index)
    else:
        cfg_buckets = _index_map(index.cfg_hash_index)
        proposals: dict[tuple[str, str], set[str]] = {}
        for raw_target, raw_catalog in native_backend.generate_library_candidates(
            target.to_payload(), index.to_payload()
        ):
            pair = (str(raw_target), str(raw_catalog))
            target_function = target_by_id.get(pair[0])
            catalog_function = catalog_by_id.get(pair[1])
            if target_function is None or catalog_function is None:
                continue
            evidence: set[str] = set()
            if (
                target_function.normalized_bytes_sha256 is not None
                and target_function.normalized_bytes_sha256
                == catalog_function.normalized_bytes_sha256
            ):
                evidence.add("normalized_bytes")
            if target_function.exact_bytes_sha256 == catalog_function.exact_bytes_sha256:
                if target_function.exact_bytes_sha256 is not None:
                    evidence.add("exact_bytes")
            if target_function.unit_merkle_sha256 == catalog_function.unit_merkle_sha256:
                evidence.add("unit_merkle")
            if (
                target_function.cfg_sha256 == catalog_function.cfg_sha256
                and len(cfg_buckets.get(target_function.cfg_sha256, ())) <= 64
            ):
                evidence.add("cfg")
            evidence.update(
                f"import:{value}"
                for value in set(target_function.imports).intersection(
                    catalog_function.imports
                )
            )
            evidence.update(
                f"string:{value}"
                for value in set(target_function.strings).intersection(
                    catalog_function.strings
                )
            )
            evidence.update(
                f"constant:{value}"
                for value in set(target_function.constants).intersection(
                    catalog_function.constants
                )
            )
            strong = evidence.intersection({"normalized_bytes", "exact_bytes", "relocation_masked_bytes", "unit_merkle", "cfg"})
            weak_count = len(evidence - strong)
            if strong or weak_count >= 2:
                proposals[pair] = evidence
        # Native retrieval deliberately excludes unknown ABI partitions.
        # Preserve those candidates through the checked sparse Python path so
        # acceleration can never turn missing evidence into a false negative.
        for pair, evidence in _python_candidate_pairs(
            target, index, native_complement_only=True
        ).items():
            proposals.setdefault(pair, evidence)
    profiles = {item.profile_id: item for item in index.abi_profiles}
    matches: list[FunctionMatchV3] = []
    issues: list[LibraryIssueV3] = []
    for (target_id, catalog_id), evidence in sorted(proposals.items()):
        target_function = target_by_id[target_id]
        catalog_function = catalog_by_id[catalog_id]
        location = f"target-function:{target_id}/catalog-function:{catalog_id}"
        abi_status = "compatible"
        if target_function.abi_profile is None or catalog_function.abi_profile_id is None:
            abi_status = "incomplete"
            issues.append(
                LibraryIssueV3(
                    "incomplete",
                    "function_abi_evidence_missing",
                    "candidate function lacks a complete target or catalog ABI envelope",
                    location,
                )
            )
        else:
            catalog_profile = profiles.get(catalog_function.abi_profile_id)
            if catalog_profile is None:
                abi_status = "incomplete"
                issues.append(
                    LibraryIssueV3(
                        "incomplete",
                        "catalog_abi_profile_missing",
                        "catalog function references no indexed ABI profile",
                        location,
                    )
                )
            else:
                differences = _abi_difference(target_function.abi_profile, catalog_profile)
                if differences:
                    abi_status = "violated"
                    issues.append(
                        LibraryIssueV3(
                            "violated",
                            "function_abi_contradiction",
                            f"ABI fields contradict: {list(differences)!r}",
                            location,
                        )
                    )
        matches.append(
            FunctionMatchV3(
                target_function_id=target_id,
                catalog_function_id=catalog_id,
                evidence=tuple(sorted(evidence)),
                abi_status=abi_status,
            )
        )
    return tuple(matches), tuple(sorted(issues))


def _match_score(match: FunctionMatchV3) -> int:
    score = 0
    for evidence in match.evidence:
        if evidence == "exact_bytes":
            score += 100
        elif evidence == "relocation_masked_bytes":
            score += 90
        elif evidence == "normalized_bytes":
            score += 80
        elif evidence == "unit_merkle":
            score += 70
        elif evidence == "cfg":
            score += 20
        else:
            score += 2
    if match.abi_status == "compatible":
        score += 10
    return score


_IDENTITY_EVIDENCE = frozenset(
    {"exact_bytes", "relocation_masked_bytes", "normalized_bytes", "unit_merkle"}
)


def _hungarian_assignment(
    rows: tuple[str, ...],
    columns: tuple[str, ...],
    weights: Mapping[tuple[str, str], int],
) -> tuple[tuple[tuple[str, str], ...], int]:
    """Deterministic maximum-weight injective assignment with unmatched rows."""

    if not rows:
        return (), 0
    real_columns = len(columns)
    padded_columns = (*columns, *(f"__unmatched__:{row}" for row in rows))
    maximum = max(weights.values(), default=0)
    n = len(rows)
    m = len(padded_columns)
    potentials_rows = [0] * (n + 1)
    potentials_columns = [0] * (m + 1)
    matching = [0] * (m + 1)
    way = [0] * (m + 1)
    for row_index in range(1, n + 1):
        matching[0] = row_index
        column = 0
        minimum = [10**18] * (m + 1)
        used = [False] * (m + 1)
        while True:
            used[column] = True
            current_row = matching[column]
            delta = 10**18
            next_column = 0
            for candidate_column in range(1, m + 1):
                if used[candidate_column]:
                    continue
                identity = padded_columns[candidate_column - 1]
                weight = (
                    weights.get((rows[current_row - 1], identity), 0)
                    if candidate_column <= real_columns
                    else 0
                )
                cost = maximum - weight
                reduced = (
                    cost
                    - potentials_rows[current_row]
                    - potentials_columns[candidate_column]
                )
                if reduced < minimum[candidate_column]:
                    minimum[candidate_column] = reduced
                    way[candidate_column] = column
                if minimum[candidate_column] < delta:
                    delta = minimum[candidate_column]
                    next_column = candidate_column
            for candidate_column in range(m + 1):
                if used[candidate_column]:
                    potentials_rows[matching[candidate_column]] += delta
                    potentials_columns[candidate_column] -= delta
                else:
                    minimum[candidate_column] -= delta
            column = next_column
            if matching[column] == 0:
                break
        while True:
            previous = way[column]
            matching[column] = matching[previous]
            column = previous
            if column == 0:
                break
    selected = tuple(
        sorted(
            (rows[row_index - 1], columns[column_index - 1])
            for column_index, row_index in enumerate(matching[1 : real_columns + 1], 1)
            if row_index != 0
            and weights.get((rows[row_index - 1], columns[column_index - 1]), 0) > 0
        )
    )
    return selected, sum(weights[pair] for pair in selected)


def _assignment_components(
    rows: Iterable[FunctionMatchV3],
) -> tuple[tuple[FunctionMatchV3, ...], ...]:
    by_target: dict[str, set[str]] = {}
    by_catalog: dict[str, set[str]] = {}
    by_pair: dict[tuple[str, str], FunctionMatchV3] = {}
    for row in rows:
        if not _IDENTITY_EVIDENCE.intersection(row.evidence):
            continue
        by_target.setdefault(row.target_function_id, set()).add(row.catalog_function_id)
        by_catalog.setdefault(row.catalog_function_id, set()).add(row.target_function_id)
        by_pair[(row.target_function_id, row.catalog_function_id)] = row
    components: list[tuple[FunctionMatchV3, ...]] = []
    remaining = set(by_target)
    while remaining:
        pending_targets = [min(remaining)]
        targets: set[str] = set()
        catalogs: set[str] = set()
        while pending_targets:
            target_id = pending_targets.pop()
            if target_id in targets:
                continue
            targets.add(target_id)
            remaining.discard(target_id)
            new_catalogs = by_target.get(target_id, set()) - catalogs
            catalogs.update(new_catalogs)
            for catalog_id in new_catalogs:
                pending_targets.extend(by_catalog.get(catalog_id, set()) - targets)
        components.append(
            tuple(
                sorted(
                    (
                        by_pair[(target_id, catalog_id)]
                        for target_id in targets
                        for catalog_id in by_target.get(target_id, set())
                        if catalog_id in catalogs
                    ),
                    key=lambda item: (
                        item.target_function_id,
                        item.catalog_function_id,
                    ),
                )
            )
        )
    return tuple(components)


def _optimal_assignment(
    rows: Iterable[FunctionMatchV3],
) -> tuple[list[FunctionMatchV3], set[str]]:
    selected: list[FunctionMatchV3] = []
    ambiguous_targets: set[str] = set()
    for component in _assignment_components(rows):
        by_pair = {
            (item.target_function_id, item.catalog_function_id): item
            for item in component
        }
        targets = tuple(sorted({item.target_function_id for item in component}))
        catalogs = tuple(sorted({item.catalog_function_id for item in component}))
        weights = {pair: _match_score(item) for pair, item in by_pair.items()}
        assignment, optimum = _hungarian_assignment(targets, catalogs, weights)
        for pair in assignment:
            alternative_weights = dict(weights)
            del alternative_weights[pair]
            alternative, alternative_score = _hungarian_assignment(
                targets, catalogs, alternative_weights
            )
            if alternative_score == optimum:
                ambiguous_targets.add(pair[0])
                ambiguous_targets.update(target for target, _catalog in alternative)
        selected.extend(by_pair[pair] for pair in assignment)
    selected.sort(key=lambda item: (item.target_function_id, item.catalog_function_id))
    return selected, ambiguous_targets


def _hypotheses(
    target: TargetSignatureGraphV3,
    index: CatalogSearchIndexV3,
    matches: Iterable[FunctionMatchV3],
) -> list[ConstellationHypothesisV3]:
    target_by_id = {item.function_id: item for item in target.functions}
    catalog_by_id = {item.function_id: item for item in index.functions}
    groups: dict[tuple[str, str], list[FunctionMatchV3]] = {}
    for match in matches:
        function = catalog_by_id[match.catalog_function_id]
        groups.setdefault((function.family_id, function.release_id), []).append(match)
    results: list[ConstellationHypothesisV3] = []
    for (family_id, release_id), rows in sorted(groups.items()):
        issues: list[LibraryIssueV3] = []
        selected, ambiguous_targets = _optimal_assignment(rows)
        for target_id in sorted(ambiguous_targets):
            issues.append(
                LibraryIssueV3(
                    "incomplete",
                    "function_match_ambiguous",
                    "multiple maximum-weight assignments explain this target function",
                    f"target-function:{target_id}/family:{family_id}/release:{release_id}",
                )
            )
        selected_catalog_ids = {item.catalog_function_id for item in selected}
        for match in selected:
            if match.abi_status == "incomplete":
                issues.append(
                    LibraryIssueV3(
                        "incomplete",
                        "selected_function_abi_incomplete",
                        "identity evidence matched but ABI evidence is incomplete",
                        f"target-function:{match.target_function_id}/catalog-function:{match.catalog_function_id}",
                    )
                )
            elif match.abi_status == "violated":
                issues.append(
                    LibraryIssueV3(
                        "violated",
                        "selected_function_abi_violated",
                        "identity evidence matched but ABI evidence contradicts",
                        f"target-function:{match.target_function_id}/catalog-function:{match.catalog_function_id}",
                    )
                )
        selected_members = {
            catalog_by_id[item.catalog_function_id].member_id for item in selected
        }
        expected_in_members = {
            function.function_id
            for function in index.functions
            if function.family_id == family_id
            and function.release_id == release_id
            and function.member_id in selected_members
            and function.retention_model == "archive_member"
        }
        missing_members = sorted(expected_in_members - selected_catalog_ids)
        if missing_members:
            issues.append(
                LibraryIssueV3(
                    "incomplete",
                    "member_coretention_incomplete",
                    f"selected archive members contain unmatched functions {missing_members!r}",
                    f"family:{family_id}/release:{release_id}",
                )
            )
        target_start = {
            function.rva_start: function.function_id for function in target.functions
        }
        selected_by_target = {
            item.target_function_id: catalog_by_id[item.catalog_function_id]
            for item in selected
        }
        catalog_id_by_symbol = {
            symbol: function.function_id
            for function in index.functions
            if function.family_id == family_id and function.release_id == release_id
            for symbol in function.symbols
        }
        call_edges = 0
        for target_id, catalog_function in selected_by_target.items():
            target_function = target_by_id[target_id]
            target_callees = {
                target_start[rva]
                for rva in target_function.direct_call_rvas
                if rva in target_start
            }
            mapped_catalog_callees = {
                selected_by_target[item].function_id
                for item in target_callees
                if item in selected_by_target
            }
            catalog_callees = {
                catalog_id_by_symbol[symbol]
                for symbol in catalog_function.direct_callees
                if symbol in catalog_id_by_symbol
            }
            call_edges += len(mapped_catalog_callees.intersection(catalog_callees))
        score = sum(_match_score(item) for item in selected) + call_edges * 10
        if not missing_members:
            score += len(selected_members) * 20
        selected.sort(
            key=lambda item: (item.target_function_id, item.catalog_function_id)
        )
        hypothesis_binding = {
            "target_graph_sha256": target.graph_sha256,
            "search_index_sha256": index.index_sha256,
            "family_id": family_id,
            "release_id": release_id,
            "matches": [item.to_payload() for item in selected],
        }
        target_ids = tuple(sorted(item.target_function_id for item in selected))
        results.append(
            ConstellationHypothesisV3(
                hypothesis_id=stable_id("library-constellation-v3", hypothesis_binding),
                family_id=family_id,
                release_id=release_id,
                target_function_ids=target_ids,
                target_unit_ids=tuple(
                    sorted(
                        unit_id
                        for target_id in target_ids
                        for unit_id in target_by_id[target_id].unit_ids
                    )
                ),
                catalog_function_ids=tuple(
                    sorted(item.catalog_function_id for item in selected)
                ),
                member_ids=tuple(sorted(selected_members)),
                matches=tuple(selected),
                diagnostic_score=score,
                status=phase_status(issues),
                issues=tuple(sorted(issues)),
            )
        )
    results.sort(
        key=lambda item: (
            -item.diagnostic_score,
            -len(item.target_function_ids),
            item.family_id,
            item.release_id,
            item.hypothesis_id,
        )
    )
    return results


def match_library_constellations(
    target_signatures: Path | str | TargetSignatureGraphV3,
    search_index_or_catalog_records: (
        Path | str | CatalogSearchIndexV3 | Sequence[Path | str]
    ),
    out: Path | str,
    *,
    native_backend: NativeCandidateBackend | None = None,
) -> ConstellationHypothesisSetV3:
    """Rank globally consistent constellations; rankings never authorize use."""

    target = _load_target(target_signatures)
    index = _load_index(search_index_or_catalog_records)
    if native_backend is None:
        from .native_index import optional_native_library_backend

        native_backend = optional_native_library_backend()
    matches, candidate_issues = generate_sparse_candidates(
        target, index, native_backend=native_backend
    )
    hypotheses = _hypotheses(target, index, matches)
    issues = [*target.issues, *candidate_issues]
    if not hypotheses:
        issues.append(
            LibraryIssueV3(
                "incomplete",
                "no_constellation_hypothesis",
                "no sparse ABI-compatible constellation was found",
                "constellation-set",
            )
        )
    elif len(hypotheses) > 1:
        first, second = hypotheses[:2]
        if (
            first.diagnostic_score == second.diagnostic_score
            and len(first.target_function_ids) == len(second.target_function_ids)
        ):
            issues.append(
                LibraryIssueV3(
                    "incomplete",
                    "constellation_version_ambiguous",
                    "top library releases have indistinguishable global evidence",
                    f"family:{first.family_id}",
                )
            )
    issues.sort()
    placeholder = ConstellationHypothesisSetV3(
        status=phase_status(issues),
        target_graph_sha256=target.graph_sha256,
        target_machine_ir_sha256=target.machine_ir_sha256,
        search_index_sha256=index.index_sha256,
        hypotheses=tuple(hypotheses),
        issues=tuple(issues),
        hypotheses_sha256="0" * 64,
    )
    result = ConstellationHypothesisSetV3(
        **{
            **placeholder.__dict__,
            "hypotheses_sha256": canonical_sha256(placeholder.core_payload),
        }
    )
    CONSTELLATION_HYPOTHESIS_SET_CODEC_V3.write(out, result)
    return result


__all__ = [
    "CONSTELLATION_HYPOTHESIS_SET_CODEC_V3",
    "ConstellationHypothesisSetV3",
    "NativeCandidateBackend",
    "NativeExtensionCandidateBackend",
    "generate_sparse_candidates",
    "match_library_constellations",
]
