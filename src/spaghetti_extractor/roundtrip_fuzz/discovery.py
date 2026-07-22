from __future__ import annotations

import inspect
import json
import os
import shutil
import tempfile
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..relational.contract import stage_a_generate_relation_contract
from ..relational.mapping import stage_a_generate_map
from ..stage_binary import StageAInputError, _parse_stage_a_pe
from ..util import json_dumps, sha256_file, sha256_text, write_json
from .model import ArtifactRef, CaseManifest, ExpectedDisposition


DISCOVERY_RESULT_FORMAT = "stage-a-roundtrip-discovery-v1"
DISCOVERY_COMPARISON_FORMAT = "stage-a-roundtrip-discovery-comparison-v1"
DISCOVERY_CASE_RESULT_FORMAT = "stage-a-roundtrip-discovery-case-v1"
DISCOVERY_FRONTIERS_FORMAT = "stage-a-roundtrip-discovery-case-frontiers-v1"
DISCOVERY_TIMINGS_FORMAT = "stage-a-roundtrip-discovery-case-timings-v1"
DISCOVERY_QUALIFICATION_FORMAT = "stage-a-roundtrip-discovery-qualification-v1"
DISCOVERY_ALGORITHM = "binary-entry-static-v2"
LINKER_MAP_ASSISTED_DISCOVERY_ALGORITHM = "linker-map-assisted-static-v1"
INITIAL_DISCOVERY_TEMPLATES = (
    "straight-line-arithmetic",
    "guarded-branch",
    "bounded-loop",
    "internal-call-stack",
)
_MAPPING_IMPLEMENTATION = Path(inspect.getsourcefile(stage_a_generate_map) or __file__).resolve()
_CONTRACT_IMPLEMENTATION = Path(
    inspect.getsourcefile(stage_a_generate_relation_contract) or __file__
).resolve()


@dataclass(frozen=True)
class DiscoveryInput:
    role: str
    sha256: str

    def to_payload(self) -> dict[str, str]:
        return {"role": self.role, "sha256": self.sha256}


@dataclass(frozen=True)
class DiscoveryArtifact:
    role: str
    path: str
    sha256: str

    def to_payload(self) -> dict[str, str]:
        return {"role": self.role, "path": self.path, "sha256": self.sha256}


class DiscoveryCaseStatus(str, Enum):
    RECOVERED = "recovered"
    DIFFERENT = "different"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True)
class DiscoveryPhaseResult:
    id: str
    status: str
    cache_key: str
    cache_hit: bool
    duration_seconds: float
    artifact: str | None
    artifact_sha256: str | None
    reason_code: str | None

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "cache_key": self.cache_key,
            "cache_hit": self.cache_hit,
            "duration_seconds": self.duration_seconds,
            "artifact": self.artifact,
            "artifact_sha256": self.artifact_sha256,
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True)
class DiscoveryCaseResult:
    case_id: str
    status: DiscoveryCaseStatus
    phases: tuple[DiscoveryPhaseResult, ...]
    artifacts: tuple[DiscoveryArtifact, ...]
    frontiers: tuple[dict[str, Any], ...]
    comparison: dict[str, Any] | None

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": DISCOVERY_CASE_RESULT_FORMAT,
            "case_id": self.case_id,
            "status": self.status.value,
            "phases": [phase.to_payload() for phase in self.phases],
            "artifacts": [artifact.to_payload() for artifact in self.artifacts],
            "frontiers": list(self.frontiers),
            "comparison": self.comparison,
            "trust": {
                "proof_authority": False,
                "closes_stage_a_proof": False,
                "ground_truth_influences_discovery": False,
                "corpus_mapping_hints_withheld": True,
                "anonymous_entry_hints_derived_from_pe": True,
            },
        }


def execute_case_discovery(
    *,
    case: CaseManifest,
    case_root: Path,
    out: Path,
    external_profiles: Sequence[Path] = (),
    force: bool = False,
) -> DiscoveryCaseResult:
    """Recover and assess a relation without exposing generator ground truth.

    The proposal phase receives only the verified PE pair, optional verified
    external profiles. It deliberately does not verify or open corpus linker
    maps. Anonymous entry-root hints are derived from the PE headers inside the
    public proposal path. The known relation proposal is opened only after
    discovery has produced a persistent result. This ordering makes the trust
    boundary observable and testable.
    """

    case_root = Path(case_root).resolve()
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    original = _verified_case_artifact(case, case_root, "original_pe")
    candidate = _verified_case_artifact(case, case_root, "candidate_pe")
    phases: list[DiscoveryPhaseResult] = []
    frontiers: list[dict[str, Any]] = []
    comparison: dict[str, Any] | None = None
    proposal_bundle = out / "proposal"
    discovery_started = time.monotonic()

    discovery_inputs = _binary_discovery_inputs(
        original=original,
        candidate=candidate,
        external_profiles=tuple(Path(path) for path in external_profiles),
    )
    expected_cache_key = _discovery_cache_key(
        discovery_inputs, algorithm=DISCOVERY_ALGORITHM,
    )
    replace_stale = proposal_bundle.exists() and _load_cached_result(
        proposal_bundle, expected_cache_key
    ) is None
    discovery = discover_binary_pair(
        original=original,
        candidate=candidate,
        out=proposal_bundle,
        external_profiles=external_profiles,
        force=force or replace_stale,
    )
    cache = discovery["cache"]
    discovery_report = proposal_bundle / "discovery-result.json"
    phases.append(DiscoveryPhaseResult(
        id="mapping-discovery",
        status=str(discovery["status"]),
        cache_key=str(cache["key"]),
        cache_hit=bool(cache["hit"]),
        duration_seconds=_duration(discovery_started),
        artifact="proposal/discovery-result.json",
        artifact_sha256=sha256_file(discovery_report),
        reason_code=(
            None
            if discovery["status"] == "recovered"
            else _first_frontier_category(discovery)
        ),
    ))
    frontiers.extend(_load_case_frontiers(
        proposal_bundle / "discovery-frontier.json"
    ))
    discovery_recovered = discovery["status"] == "recovered"

    status = DiscoveryCaseStatus.INCOMPLETE
    if discovery_recovered:
        ground_truth = _optional_verified_case_artifact(
            case, case_root, "relation_proposal"
        )
        comparison_started = time.monotonic()
        if ground_truth is None:
            reason_code = "ground_truth_relation_proposal_unavailable"
            comparison_key = _comparison_unavailable_cache_key(
                proposal_bundle / "recovered-proposal.json"
            )
            phases.append(DiscoveryPhaseResult(
                id="semantic-comparison",
                status="incomplete",
                cache_key=comparison_key,
                cache_hit=False,
                duration_seconds=_duration(comparison_started),
                artifact=None,
                artifact_sha256=None,
                reason_code=reason_code,
            ))
            frontiers.append(_case_frontier(
                phase="comparison",
                reason_code=reason_code,
                message="the case does not bind a generator-known relation proposal",
                next_action="add a ground-truth proposal for discovery qualification only",
            ))
        else:
            recovered = proposal_bundle / "recovered-proposal.json"
            comparison_path = out / "semantic-comparison.json"
            comparison_key = _comparison_cache_key(recovered, ground_truth)
            cached_comparison = (
                None
                if force
                else _load_keyed_object(
                    comparison_path,
                    expected_format=DISCOVERY_COMPARISON_FORMAT,
                    cache_key=comparison_key,
                )
            )
            comparison_hit = cached_comparison is not None
            if cached_comparison is None:
                comparison = compare_discovery_proposals(
                    recovered=recovered,
                    ground_truth=ground_truth,
                )
                comparison["cache_key"] = comparison_key
                write_json(comparison_path, comparison)
            else:
                comparison = cached_comparison
            comparison_status = str(comparison["status"])
            reason_code = (
                None
                if comparison_status == "equivalent"
                else "recovered_relation_semantically_different"
            )
            phases.append(DiscoveryPhaseResult(
                id="semantic-comparison",
                status=comparison_status,
                cache_key=comparison_key,
                cache_hit=comparison_hit,
                duration_seconds=_duration(comparison_started),
                artifact="semantic-comparison.json",
                artifact_sha256=sha256_file(comparison_path),
                reason_code=reason_code,
            ))
            if comparison_status == "equivalent":
                status = DiscoveryCaseStatus.RECOVERED
            else:
                status = DiscoveryCaseStatus.DIFFERENT
                frontiers.append(_case_frontier(
                    phase="comparison",
                    reason_code=reason_code or "recovered_relation_semantically_different",
                    message="the recovered relation differs from generator ground truth",
                    next_action=(
                        "inspect missing and extra semantic spans; improve generic "
                        "mapping recovery without consuming fixture metadata"
                    ),
                    details=dict(comparison.get("counts", {})),
                ))

    frontiers.sort(key=lambda item: (
        str(item.get("phase") or ""),
        str(item.get("reason_code") or ""),
        str(item.get("id") or ""),
    ))
    frontier_path = out / "discovery-frontiers.json"
    write_json(frontier_path, {
        "format": DISCOVERY_FRONTIERS_FORMAT,
        "status": "clear" if not frontiers else "incomplete",
        "items": frontiers,
        "trust": {"proof_authority": False, "closes_stage_a_proof": False},
    })
    timing_path = out / "discovery-timings.json"
    write_json(timing_path, {
        "format": DISCOVERY_TIMINGS_FORMAT,
        "case_id": case.id,
        "phases": [phase.to_payload() for phase in phases],
    })
    artifacts = _case_discovery_artifacts(
        out,
        proposal_attempted=True,
        compared=comparison is not None,
    )
    result = DiscoveryCaseResult(
        case_id=case.id,
        status=status,
        phases=tuple(phases),
        artifacts=artifacts,
        frontiers=tuple(frontiers),
        comparison=comparison,
    )
    write_json(out / "discovery-case-result.json", result.to_payload())
    return result


def discover_binary_pair(
    *,
    original: Path,
    candidate: Path,
    out: Path,
    external_profiles: Sequence[Path] = (),
    force: bool = False,
) -> dict[str, Any]:
    """Run public static proposal generation without corpus mapping hints.

    The only control roots supplied to the ordinary mapper are anonymous entry
    roots derived from each PE header. The mapper may recover more blocks and
    direct targets from exact executable bytes, but it cannot consume linker
    symbols, generator labels, semantic programs, or a known relation.
    """

    original = Path(original)
    candidate = Path(candidate)
    profile_paths = tuple(Path(path) for path in external_profiles)
    inputs = _binary_discovery_inputs(
        original=original,
        candidate=candidate,
        external_profiles=profile_paths,
    )
    cache_key = _discovery_cache_key(inputs, algorithm=DISCOVERY_ALGORITHM)
    out = Path(out).resolve()
    cached = _load_cached_result(out, cache_key)
    if cached is not None and not force:
        return {**cached, "cache": {"key": cache_key, "hit": True}}
    if out.exists() and not force:
        raise StageAInputError(
            f"discovery output exists but is not a valid cache entry: {out}; "
            "use --force to replace it"
        )

    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".{out.name}.tmp-", dir=out.parent,
    ) as temporary:
        staging = Path(temporary) / "bundle"
        staging.mkdir()
        original_hints = staging / "anonymous-original-entry.map"
        candidate_hints = staging / "anonymous-candidate-entry.map"
        _write_anonymous_entry_map(original, original_hints)
        _write_anonymous_entry_map(candidate, candidate_hints)
        report = _build_discovery_bundle(
            original=original,
            candidate=candidate,
            linker_map_original=original_hints,
            linker_map_candidate=candidate_hints,
            staging=staging,
            external_profiles=profile_paths,
            inputs=inputs,
            cache_key=cache_key,
            algorithm=DISCOVERY_ALGORITHM,
            consumed_roles=[item.role for item in inputs],
            withheld_roles=[
                "original_linker_map",
                "candidate_linker_map",
                "semantic_program",
                "candidate_semantic_program",
                "relation_proposal",
                "relation_contract",
                "seed",
                "transformation_history",
                "source_labels",
            ],
            extra_artifacts=(
                ("anonymous_original_entry_hints", original_hints),
                ("anonymous_candidate_entry_hints", candidate_hints),
            ),
        )
        if out.exists():
            shutil.rmtree(out)
        os.replace(staging, out)

    return {**report, "cache": {"key": cache_key, "hit": False}}


def discover_linker_map_pair(
    *,
    original: Path,
    candidate: Path,
    linker_map_original: Path,
    linker_map_candidate: Path,
    out: Path,
    external_profiles: Sequence[Path] = (),
    force: bool = False,
) -> dict[str, Any]:
    """Run the public linker-map-assisted proposal path in an isolated bundle.

    This function deliberately has no parameter for a generator relation proposal,
    semantic program, fixture identity, seed, or transformation metadata. The four
    binary/linker-map inputs are untrusted discovery evidence. The emitted proposal
    remains non-authoritative until ordinary Stage A proof checking consumes it.
    """

    inputs = _discovery_inputs(
        original=Path(original),
        candidate=Path(candidate),
        linker_map_original=Path(linker_map_original),
        linker_map_candidate=Path(linker_map_candidate),
        external_profiles=tuple(Path(path) for path in external_profiles),
    )
    cache_key = _discovery_cache_key(
        inputs, algorithm=LINKER_MAP_ASSISTED_DISCOVERY_ALGORITHM,
    )
    out = Path(out).resolve()
    cached = _load_cached_result(out, cache_key)
    if cached is not None and not force:
        return {**cached, "cache": {"key": cache_key, "hit": True}}
    if out.exists() and not force:
        raise StageAInputError(
            f"discovery output exists but is not a valid cache entry: {out}; "
            "use --force to replace it"
        )

    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".{out.name}.tmp-", dir=out.parent,
    ) as temporary:
        staging = Path(temporary) / "bundle"
        staging.mkdir()
        report = _build_discovery_bundle(
            original=Path(original),
            candidate=Path(candidate),
            linker_map_original=Path(linker_map_original),
            linker_map_candidate=Path(linker_map_candidate),
            staging=staging,
            external_profiles=tuple(Path(path) for path in external_profiles),
            inputs=inputs,
            cache_key=cache_key,
            algorithm=LINKER_MAP_ASSISTED_DISCOVERY_ALGORITHM,
            consumed_roles=[item.role for item in inputs],
            withheld_roles=[
                "semantic_program",
                "candidate_semantic_program",
                "relation_proposal",
                "relation_contract",
                "seed",
                "transformation_history",
                "source_labels",
            ],
        )
        if out.exists():
            shutil.rmtree(out)
        os.replace(staging, out)

    return {**report, "cache": {"key": cache_key, "hit": False}}


def _build_discovery_bundle(
    *,
    original: Path,
    candidate: Path,
    linker_map_original: Path,
    linker_map_candidate: Path,
    staging: Path,
    external_profiles: tuple[Path, ...],
    inputs: tuple[DiscoveryInput, ...],
    cache_key: str,
    algorithm: str,
    consumed_roles: Sequence[str],
    withheld_roles: Sequence[str],
    extra_artifacts: Sequence[tuple[str, Path]] = (),
) -> dict[str, Any]:
    proposal_path = staging / "recovered-proposal.json"
    layout_path = staging / "recovered-layout-contract.json"
    relation_path = staging / "recovered-relation-contract.json"
    frontier_path = staging / "discovery-frontier.json"

    proposal_result = stage_a_generate_map(
        original=original,
        candidate=candidate,
        linker_map_original=linker_map_original,
        linker_map_candidate=linker_map_candidate,
        out=proposal_path,
        layout_contract_out=layout_path,
        original_flags="withheld-generator-mapping",
        candidate_flags="withheld-generator-mapping",
    )
    _normalize_proposal_paths(
        proposal_path,
        original_map_name=linker_map_original.name,
        candidate_map_name=linker_map_candidate.name,
    )
    frontier = _frontier_from_proposal_result(proposal_result)
    write_json(frontier_path, frontier)

    relation_result: dict[str, Any] | None = None
    if proposal_result.get("status") == "pass" and not frontier["items"]:
        relation_result = stage_a_generate_relation_contract(
            original=original,
            candidate=candidate,
            mapping=proposal_path,
            external_profile=list(external_profiles) or None,
            out=relation_path,
        )
        if relation_result.get("status") != "generated":
            frontier = _frontier_from_relation_result(relation_result)
            write_json(frontier_path, frontier)

    status = (
        "recovered"
        if relation_result is not None
        and relation_result.get("status") == "generated"
        and not frontier["items"]
        else "incomplete"
    )
    artifact_specs: list[tuple[str, Path]] = [
        ("recovered_relation_proposal", proposal_path),
        ("recovered_layout_contract", layout_path),
        ("discovery_frontier", frontier_path),
        *extra_artifacts,
    ]
    if relation_path.exists():
        artifact_specs.append(("recovered_relation_contract", relation_path))
    artifacts = tuple(
        DiscoveryArtifact(
            role=role,
            path=path.relative_to(staging).as_posix(),
            sha256=sha256_file(path),
        )
        for role, path in artifact_specs
    )
    report = {
        "format": DISCOVERY_RESULT_FORMAT,
        "status": status,
        "algorithm": algorithm,
        "cache_key": cache_key,
        "inputs": [item.to_payload() for item in inputs],
        "artifacts": [item.to_payload() for item in artifacts],
        "frontier": {
            "count": len(frontier["items"]),
            "categories": sorted({item["category"] for item in frontier["items"]}),
        },
        "trust": {
            "proof_authority": False,
            "closes_stage_a_proof": False,
            "proposal_is_untrusted": True,
            "consumed_roles": list(consumed_roles),
            "withheld_roles": list(withheld_roles),
        },
    }
    write_json(staging / "discovery-result.json", report)
    return report


def qualify_discovery_templates(
    *,
    cases: Sequence[tuple[CaseManifest, Path]],
    out: Path,
    templates: Sequence[str] = INITIAL_DISCOVERY_TEMPLATES,
    external_profiles: Sequence[Path] = (),
    force: bool = False,
) -> dict[str, Any]:
    """Produce stable discovery evidence for one positive case per template.

    Template identity is used only by this non-authoritative qualification
    aggregator to select coverage. It is never passed to proposal generation.
    Volatile timings and cache-hit fields are deliberately excluded so reruns
    produce byte-identical qualification evidence.
    """

    requested = tuple(templates)
    if not requested or len(requested) != len(set(requested)):
        raise StageAInputError(
            "discovery qualification templates must be nonempty and unique"
        )
    selected: list[tuple[str, CaseManifest, Path]] = []
    for template in requested:
        candidates = sorted(
            (
                (case.id, case, Path(case_root))
                for case, case_root in cases
                if case.template == template
                and case.expectation.disposition is ExpectedDisposition.PASS
            ),
            key=lambda item: item[0],
        )
        if not candidates:
            raise StageAInputError(
                f"discovery qualification has no positive case for template {template!r}"
            )
        _case_id, case, case_root = candidates[0]
        selected.append((template, case, case_root))

    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    for template, case, case_root in selected:
        case_out = out / "cases" / template
        result = execute_case_discovery(
            case=case,
            case_root=case_root,
            out=case_out,
            external_profiles=external_profiles,
            force=force,
        )
        phases = {
            phase.id: {
                "status": phase.status,
                "cache_key": phase.cache_key,
                "artifact_sha256": phase.artifact_sha256,
                "reason_code": phase.reason_code,
            }
            for phase in result.phases
        }
        stable_roles = {
            "discovery_result",
            "recovered_relation_proposal",
            "recovered_layout_contract",
            "recovered_relation_contract",
            "discovery_frontier",
            "discovery_comparison",
        }
        artifacts = [
            artifact.to_payload()
            for artifact in result.artifacts
            if artifact.role in stable_roles
        ]
        artifact_roles = {artifact["role"] for artifact in artifacts}
        proposal_ready = (
            phases.get("mapping-discovery", {}).get("status") == "recovered"
            and "recovered_relation_contract" in artifact_roles
        )
        comparison_status = (
            None if result.comparison is None else result.comparison.get("status")
        )
        rows.append({
            "template": template,
            "case_id": case.id,
            "status": "ready_for_proof" if proposal_ready else "frontier",
            "proposal_ready": proposal_ready,
            "comparison_status": comparison_status,
            "phases": phases,
            "artifacts": artifacts,
            "proposal_frontier_reason_codes": sorted({
                str(item.get("reason_code") or item.get("category") or "unknown")
                for item in result.frontiers
                if item.get("phase") != "comparison"
            }),
            "comparison_diagnostic_reason_codes": sorted({
                str(item.get("reason_code") or item.get("category") or "unknown")
                for item in result.frontiers
                if item.get("phase") == "comparison"
            }),
            "trust": {
                "proof_authority": False,
                "closes_stage_a_proof": False,
                "ordinary_stage_a_proof_required": True,
            },
        })

    payload = {
        "format": DISCOVERY_QUALIFICATION_FORMAT,
        "status": (
            "qualified_for_proof_handoff"
            if all(row["proposal_ready"] for row in rows)
            else "incomplete"
        ),
        "algorithm": DISCOVERY_ALGORITHM,
        "templates": rows,
        "counts": {
            "required_templates": len(requested),
            "ready_for_proof": sum(bool(row["proposal_ready"]) for row in rows),
            "proposal_frontier": sum(
                not bool(row["proposal_ready"]) for row in rows
            ),
        },
        "trust": {
            "proof_authority": False,
            "closes_stage_a_proof": False,
            "qualification_is_diagnostic": True,
            "ordinary_stage_a_proof_required": True,
        },
    }
    write_json(out / "discovery-qualification.json", payload)
    return payload


def compare_discovery_proposals(
    *,
    recovered: Path,
    ground_truth: Path,
    out: Path | None = None,
) -> dict[str, Any]:
    """Compare proposal meaning while ignoring diagnostic labels and ordering.

    Comparison is intentionally outside discovery. Ground truth can assess a
    recovered proposal after generation, but it cannot influence that proposal.
    Neither equality nor difference has proof authority.
    """

    recovered_path = Path(recovered)
    ground_truth_path = Path(ground_truth)
    recovered_view = _semantic_proposal_view(_read_object(recovered_path))
    expected_view = _semantic_proposal_view(_read_object(ground_truth_path))
    recovered_items = set(recovered_view)
    expected_items = set(expected_view)
    missing = sorted(expected_items - recovered_items)
    extra = sorted(recovered_items - expected_items)
    payload = {
        "format": DISCOVERY_COMPARISON_FORMAT,
        "status": "equivalent" if not missing and not extra else "different",
        "inputs": {
            "recovered_sha256": sha256_file(recovered_path),
            "ground_truth_sha256": sha256_file(ground_truth_path),
        },
        "counts": {
            "recovered": len(recovered_items),
            "ground_truth": len(expected_items),
            "missing": len(missing),
            "extra": len(extra),
        },
        "missing": [_view_item_payload(item) for item in missing],
        "extra": [_view_item_payload(item) for item in extra],
        "trust": {"proof_authority": False, "closes_stage_a_proof": False},
    }
    if out is not None:
        write_json(Path(out), payload)
    return payload


def _discovery_inputs(
    *,
    original: Path,
    candidate: Path,
    linker_map_original: Path,
    linker_map_candidate: Path,
    external_profiles: tuple[Path, ...],
) -> tuple[DiscoveryInput, ...]:
    paths = (
        ("original_pe", original),
        ("candidate_pe", candidate),
        ("original_linker_map", linker_map_original),
        ("candidate_linker_map", linker_map_candidate),
    ) + tuple(
        (f"external_profile_{index}", path)
        for index, path in enumerate(external_profiles)
    )
    result: list[DiscoveryInput] = []
    for role, path in paths:
        if not path.is_file():
            raise StageAInputError(f"discovery {role} is not a file: {path}")
        result.append(DiscoveryInput(role=role, sha256=sha256_file(path)))
    return tuple(result)


def _binary_discovery_inputs(
    *,
    original: Path,
    candidate: Path,
    external_profiles: tuple[Path, ...],
) -> tuple[DiscoveryInput, ...]:
    paths = (
        ("original_pe", original),
        ("candidate_pe", candidate),
    ) + tuple(
        (f"external_profile_{index}", path)
        for index, path in enumerate(external_profiles)
    )
    result: list[DiscoveryInput] = []
    for role, path in paths:
        if not path.is_file():
            raise StageAInputError(f"discovery {role} is not a file: {path}")
        result.append(DiscoveryInput(role=role, sha256=sha256_file(path)))
    return tuple(result)


def _discovery_cache_key(
    inputs: tuple[DiscoveryInput, ...], *, algorithm: str,
) -> str:
    implementation_files = sorted({_MAPPING_IMPLEMENTATION, _CONTRACT_IMPLEMENTATION})
    implementation = [
        {"name": path.name, "sha256": sha256_file(path)}
        for path in implementation_files
        if path.is_file()
    ]
    local_functions = [
        _build_discovery_bundle,
        _normalize_proposal_paths,
        _frontier_from_proposal_result,
        _frontier_from_relation_result,
        _frontier_payload,
    ]
    if algorithm == DISCOVERY_ALGORITHM:
        local_functions.extend((discover_binary_pair, _write_anonymous_entry_map))
    elif algorithm == LINKER_MAP_ASSISTED_DISCOVERY_ALGORITHM:
        local_functions.append(discover_linker_map_pair)
    else:
        raise StageAInputError(f"unsupported discovery algorithm {algorithm!r}")
    implementation.append({
        "name": "roundtrip-discovery-local-functions",
        "sha256": sha256_text("\n\n".join(
            inspect.getsource(function) for function in local_functions
        )),
    })
    return sha256_text(json_dumps({
        "algorithm": algorithm,
        "inputs": [item.to_payload() for item in inputs],
        "implementation": implementation,
    }))


def _write_anonymous_entry_map(binary_path: Path, out: Path) -> None:
    binary = _parse_stage_a_pe(binary_path)
    entry_address = binary.image_base + binary.entrypoint_rva
    out.write_text(
        f"0x{entry_address:08x} discovered_entry\n",
        encoding="ascii",
    )


def _comparison_cache_key(recovered: Path, ground_truth: Path) -> str:
    return sha256_text(json_dumps({
        "algorithm": DISCOVERY_COMPARISON_FORMAT,
        "recovered_sha256": sha256_file(recovered),
        "ground_truth_sha256": sha256_file(ground_truth),
        "semantic_view_source_sha256": sha256_text(
            inspect.getsource(_semantic_proposal_view)
            + inspect.getsource(_span_tuple)
            + inspect.getsource(_root_kind)
        ),
    }))


def _comparison_unavailable_cache_key(recovered: Path) -> str:
    return sha256_text(json_dumps({
        "algorithm": DISCOVERY_COMPARISON_FORMAT,
        "recovered_sha256": sha256_file(recovered),
        "ground_truth": "unavailable",
    }))


def _load_cached_result(out: Path, cache_key: str) -> dict[str, Any] | None:
    report_path = out / "discovery-result.json"
    if not report_path.is_file():
        return None
    try:
        report = _read_object(report_path)
        if (
            report.get("format") != DISCOVERY_RESULT_FORMAT
            or report.get("cache_key") != cache_key
        ):
            return None
        artifacts = report.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            return None
        for artifact in artifacts:
            if not isinstance(artifact, Mapping):
                return None
            path_value = artifact.get("path")
            digest = artifact.get("sha256")
            if not isinstance(path_value, str) or Path(path_value).is_absolute():
                return None
            path = (out / path_value).resolve()
            if out not in path.parents or not path.is_file() or sha256_file(path) != digest:
                return None
        return dict(report)
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def _normalize_proposal_paths(
    path: Path,
    *,
    original_map_name: str = "original.map",
    candidate_map_name: str = "candidate.map",
) -> None:
    payload = _read_object(path)
    original = payload.get("original")
    candidate = payload.get("candidate")
    linker_maps = payload.get("linker_maps")
    if isinstance(original, dict):
        original["path"] = "original.exe"
    if isinstance(candidate, dict):
        candidate["path"] = "candidate.exe"
    if isinstance(linker_maps, dict):
        linker_maps["original"] = original_map_name
        linker_maps["candidate"] = candidate_map_name
    write_json(path, payload)


def _frontier_from_proposal_result(result: Mapping[str, Any]) -> dict[str, Any]:
    raw_issues = result.get("issues")
    issues = list(raw_issues) if isinstance(raw_issues, list) else []
    if result.get("status") != "pass" and not issues:
        issues.append({
            "category": "proposal_generation_incomplete",
            "obligation_id": "mapping:proposal-status",
            "blocker": "the public mapping proposal did not return pass",
            "next_action": "inspect mapping generation diagnostics and add an explicit untrusted hint",
            "details": {"observed_status": result.get("status")},
        })
    return _frontier_payload("mapping", issues)


def _frontier_from_relation_result(result: Mapping[str, Any]) -> dict[str, Any]:
    raw_issues = result.get("issues")
    issues = list(raw_issues) if isinstance(raw_issues, list) else []
    if result.get("status") != "generated" and not issues:
        issues.append({
            "category": "relation_projection_incomplete",
            "obligation_id": "relation_contract:projection-status",
            "blocker": "the recovered proposal could not be projected into a relation contract",
            "next_action": "inspect relation normalization and mapping coverage diagnostics",
            "details": {"observed_status": result.get("status")},
        })
    return _frontier_payload("relation_contract", issues)


def _frontier_payload(phase: str, issues: Sequence[Any]) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for index, raw in enumerate(issues):
        issue = raw if isinstance(raw, Mapping) else {"blocker": str(raw)}
        category = str(issue.get("category") or "unspecified_discovery_ambiguity")
        obligation = str(issue.get("obligation_id") or f"{phase}:{index}")
        details = issue.get("details") if isinstance(issue.get("details"), Mapping) else {}
        location = _issue_location(details)
        stable_id = sha256_text(json_dumps({
            "phase": phase,
            "category": category,
            "obligation": obligation,
            "location": location,
            "details": details,
        }))[:24]
        items.append({
            "id": f"discovery:{stable_id}",
            "phase": phase,
            "category": category,
            "severity": "blocking",
            "obligation_id": obligation,
            "location": location,
            "blocker": str(issue.get("blocker") or "discovery is ambiguous"),
            "next_action": str(
                issue.get("next_action")
                or "provide an explicit untrusted mapping hint and rerun Stage A"
            ),
            "details": dict(details),
        })
    items.sort(key=lambda item: (item["category"], item["obligation_id"], item["id"]))
    return {
        "format": "stage-a-roundtrip-discovery-frontier-v1",
        "status": "clear" if not items else "incomplete",
        "items": items,
        "trust": {"proof_authority": False, "closes_stage_a_proof": False},
    }


def _issue_location(details: Mapping[str, Any]) -> dict[str, Any]:
    for key in ("function", "candidate_function", "rva", "original_rva", "candidate_rva"):
        value = details.get(key)
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            return {"kind": key, "value": value}
    return {"kind": "unknown"}


def _verified_case_artifact(case: CaseManifest, root: Path, role: str) -> Path:
    artifact = _optional_case_artifact(case, role)
    if artifact is None:
        raise StageAInputError(f"round-trip discovery requires case artifact {role}")
    return artifact.verify(root)


def _optional_verified_case_artifact(
    case: CaseManifest, root: Path, role: str,
) -> Path | None:
    artifact = _optional_case_artifact(case, role)
    return None if artifact is None else artifact.verify(root)


def _optional_case_artifact(case: CaseManifest, role: str) -> ArtifactRef | None:
    matches = [artifact for artifact in case.artifacts if artifact.role == role]
    if len(matches) > 1:
        raise StageAInputError(
            f"round-trip discovery case has multiple {role} artifacts"
        )
    return None if not matches else matches[0]


def _load_keyed_object(
    path: Path, *, expected_format: str, cache_key: str,
) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        payload = _read_object(path)
    except StageAInputError:
        return None
    if (
        payload.get("format") != expected_format
        or payload.get("cache_key") != cache_key
    ):
        return None
    return payload


def _load_case_frontiers(path: Path) -> list[dict[str, Any]]:
    payload = _read_object(path)
    raw_items = payload.get("items")
    if not isinstance(raw_items, list):
        raise StageAInputError("discovery frontier artifact must contain an items list")
    result: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_items):
        if not isinstance(raw, Mapping):
            raise StageAInputError(
                f"discovery frontier item {index} must be an object"
            )
        category = str(raw.get("category") or "unspecified_discovery_ambiguity")
        result.append({
            **dict(raw),
            "phase": str(raw.get("phase") or "mapping"),
            "reason_code": category,
            "message": str(raw.get("blocker") or "discovery is incomplete"),
        })
    return result


def _case_frontier(
    *,
    phase: str,
    reason_code: str,
    message: str,
    next_action: str,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    detail_payload = {} if details is None else dict(details)
    stable_id = sha256_text(json_dumps({
        "phase": phase,
        "reason_code": reason_code,
        "details": detail_payload,
    }))[:24]
    return {
        "id": f"discovery:{stable_id}",
        "phase": phase,
        "category": reason_code,
        "reason_code": reason_code,
        "severity": "blocking",
        "message": message,
        "blocker": message,
        "next_action": next_action,
        "details": detail_payload,
    }


def _first_frontier_category(discovery: Mapping[str, Any]) -> str:
    frontier = discovery.get("frontier")
    if isinstance(frontier, Mapping):
        categories = frontier.get("categories")
        if isinstance(categories, list) and categories:
            return str(categories[0])
    return "discovery_incomplete"


def _duration(started: float) -> float:
    return round(max(0.0, time.monotonic() - started), 6)


def _case_discovery_artifacts(
    out: Path, *, proposal_attempted: bool, compared: bool,
) -> tuple[DiscoveryArtifact, ...]:
    paths: list[tuple[str, Path]] = [
        ("discovery_frontiers", out / "discovery-frontiers.json"),
        ("discovery_timings", out / "discovery-timings.json"),
    ]
    if proposal_attempted:
        paths.extend((
            ("discovery_result", out / "proposal" / "discovery-result.json"),
            ("recovered_relation_proposal", out / "proposal" / "recovered-proposal.json"),
            ("recovered_layout_contract", out / "proposal" / "recovered-layout-contract.json"),
            ("discovery_frontier", out / "proposal" / "discovery-frontier.json"),
        ))
        relation = out / "proposal" / "recovered-relation-contract.json"
        if relation.is_file():
            paths.append(("recovered_relation_contract", relation))
    else:
        paths.append(("discovery_result", out / "proposal-unavailable.json"))
    if compared:
        paths.append(("discovery_comparison", out / "semantic-comparison.json"))

    artifacts: list[DiscoveryArtifact] = []
    for role, path in paths:
        if not path.is_file():
            continue
        artifacts.append(DiscoveryArtifact(
            role=role,
            path=path.relative_to(out).as_posix(),
            sha256=sha256_file(path),
        ))
    return tuple(sorted(artifacts, key=lambda artifact: artifact.role))


def _semantic_proposal_view(payload: Mapping[str, Any]) -> tuple[tuple[Any, ...], ...]:
    result: list[tuple[Any, ...]] = []
    blocks = payload.get("blocks")
    if not isinstance(blocks, list):
        raise StageAInputError("discovery proposal must contain a blocks list")
    for index, raw in enumerate(blocks):
        if not isinstance(raw, Mapping):
            raise StageAInputError(f"discovery proposal block {index} must be an object")
        result.append((
            "block",
            str(raw.get("kind") or "code"),
            *_span_tuple(raw.get("original"), f"block {index} original"),
            *_span_tuple(raw.get("candidate"), f"block {index} candidate"),
            bool(raw.get("reachable", False)),
            _root_kind(raw.get("root")),
        ))
    waivers = payload.get("waivers", [])
    if not isinstance(waivers, list):
        raise StageAInputError("discovery proposal waivers must be a list")
    for index, raw in enumerate(waivers):
        if not isinstance(raw, Mapping):
            raise StageAInputError(f"discovery proposal waiver {index} must be an object")
        rva, size = _span_tuple(raw, f"waiver {index}")
        result.append((
            "waiver", str(raw.get("binary") or ""), rva, size,
            str(raw.get("classification") or raw.get("kind") or ""),
        ))
    return tuple(sorted(result))


def _span_tuple(value: Any, context: str) -> tuple[int, int]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} span must be an object")
    rva = value.get("rva", value.get("rva_start"))
    size = value.get("size")
    if not isinstance(rva, int) or isinstance(rva, bool):
        raise StageAInputError(f"{context} rva must be an integer")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise StageAInputError(f"{context} size must be a nonnegative integer")
    return rva, size


def _root_kind(value: Any) -> str:
    if not isinstance(value, Mapping) or not value.get("checked"):
        return ""
    return str(value.get("kind") or "checked")


def _view_item_payload(item: tuple[Any, ...]) -> dict[str, Any]:
    if item[0] == "block":
        return {
            "kind": "block",
            "classification": item[1],
            "original": {"rva": item[2], "size": item[3]},
            "candidate": {"rva": item[4], "size": item[5]},
            "reachable": item[6],
            "root_kind": item[7],
        }
    return {
        "kind": "waiver",
        "binary": item[1],
        "rva": item[2],
        "size": item[3],
        "classification": item[4],
    }


def _read_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read JSON object {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise StageAInputError(f"JSON artifact must be an object: {path}")
    return payload


__all__ = [
    "DISCOVERY_ALGORITHM",
    "DISCOVERY_CASE_RESULT_FORMAT",
    "DISCOVERY_COMPARISON_FORMAT",
    "DISCOVERY_FRONTIERS_FORMAT",
    "DISCOVERY_QUALIFICATION_FORMAT",
    "DISCOVERY_RESULT_FORMAT",
    "DISCOVERY_TIMINGS_FORMAT",
    "INITIAL_DISCOVERY_TEMPLATES",
    "LINKER_MAP_ASSISTED_DISCOVERY_ALGORITHM",
    "DiscoveryCaseResult",
    "DiscoveryCaseStatus",
    "DiscoveryPhaseResult",
    "compare_discovery_proposals",
    "discover_binary_pair",
    "discover_linker_map_pair",
    "execute_case_discovery",
    "qualify_discovery_templates",
]
