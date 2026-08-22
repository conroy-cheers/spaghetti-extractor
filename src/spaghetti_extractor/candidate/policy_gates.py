"""Checked policy reducers for executable and release candidate states.

The authority graph produces reusable facts.  This module deliberately keeps
the policy which consumes those facts separate: an executable hybrid needs a
closed structural universe and a total fallback engine, while stronger ISA and
component qualification belongs to release acceptance. Runtime observations
remain outside both reducers.
"""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Protocol

from ..artifacts.artifact_set import ArtifactRecordV3, canonical_sha256_v3
from ..artifacts.formats import (
    RELEASE_ACCEPTANCE_FORMAT,
    STRUCTURAL_EXECUTABLE_FORMAT,
)
from ..artifacts.io import open_artifact_reader_v3
from ..authority.callbacks import (
    CALLBACK_AUTHORITY_ARTIFACT_KIND_V3,
    CALLBACK_AUTHORITY_CODEC_V3,
)
from ..authority.exceptional_transitions import (
    EXCEPTIONAL_TRANSITION_CODEC_V3,
    EXCEPTIONAL_TRANSITIONS_ARTIFACT_KIND_V3,
)
from ..authority.external_site_records import (
    CANONICAL_EXTERNAL_SITE_CODEC_V3,
    CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
)
from ..authority.isa_qualification import (
    ISA_QUALIFICATION_ARTIFACT_KIND_V3,
    ISA_QUALIFICATION_CODEC_V3,
)
from ..authority.inductive_records import (
    INDUCTIVE_AUTHORITY_ARTIFACT_KIND_V3,
    INDUCTIVE_AUTHORITY_CODEC_V3,
    InductiveAuthorityBodyV3,
)
from ..authority.parametric_summary_records import (
    PARAMETRIC_SCC_SUMMARIES_ARTIFACT_KIND_V3,
    PARAMETRIC_SCC_SUMMARY_CODEC_V3,
)
from ..authority.root_closure import (
    LAUNCH_ROOT_CLOSURE_ARTIFACT_KIND_V3,
)
from ..authority.semantic_index import (
    SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    SEMANTIC_INDEX_CODEC_V3,
)
from ..authority.target_certificate_records import (
    INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
    INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3,
)
from ..components.formats import COMPONENT_RELEASE_GATE_V1_FORMAT
from ..components.lifecycle_records import (
    ComponentActivationPlanRecordV3,
    ComponentLifecycleRecordError,
)
from ..machine_ir.fallback_capability import FallbackCapabilityAnalysis
from .authority.rooted_projection import (
    RootedBehavioralProjectionError,
    RootedBehavioralProjectionV1,
    load_rooted_behavioral_projection_v1,
)


STRUCTURAL_EXECUTABLE_V1 = STRUCTURAL_EXECUTABLE_FORMAT
RELEASE_ACCEPTANCE_V1 = RELEASE_ACCEPTANCE_FORMAT
_ACTIVATION_PLAN_V3 = "spaghetti-extractor-component-activation-plan-v3"
class CandidatePolicyError(ValueError):
    """A policy input is malformed, stale, or incomplete."""


class _DecodedRecord(Protocol):
    status: str
    authorizing: bool


@dataclass(frozen=True)
class PolicyFamilyReceiptV1:
    identity: str
    status: str
    input_sha256: str
    record_count: int
    blocker: str | None

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "status": self.status,
            "input_sha256": self.input_sha256,
            "record_count": self.record_count,
            "blocker": self.blocker,
        }


@dataclass(frozen=True)
class CandidatePolicyReceiptV1:
    format: str
    status: str
    executable: bool
    release_accepted: bool
    bindings: Mapping[str, object]
    families: tuple[PolicyFamilyReceiptV1, ...]
    receipt_sha256: str

    def to_payload(self) -> dict[str, object]:
        return {
            "format": self.format,
            "status": self.status,
            "executable": self.executable,
            "release_accepted": self.release_accepted,
            "bindings": dict(self.bindings),
            "families": [row.to_payload() for row in self.families],
            "receipt_sha256": self.receipt_sha256,
        }


@dataclass(frozen=True)
class _ArtifactFamily:
    kind: str
    decode: Callable[[ArtifactRecordV3], object]
    complete: Callable[[object], bool]


def _authority_complete(value: object) -> bool:
    return (
        getattr(value, "status", None) == "complete"
        and getattr(value, "authorizing", None) is True
    )


def _semantic_complete(value: object) -> bool:
    return getattr(value, "unit_status", None) == "qualified"


_STRUCTURAL_ARTIFACTS = {
    "semantic_index": _ArtifactFamily(
        SEMANTIC_INDEX_ARTIFACT_KIND_V3,
        lambda row: SEMANTIC_INDEX_CODEC_V3.read(row).value,
        _semantic_complete,
    ),
}

_ROOTED_BEHAVIORAL_ARTIFACTS = {
    "callbacks": _ArtifactFamily(
        CALLBACK_AUTHORITY_ARTIFACT_KIND_V3,
        lambda row: CALLBACK_AUTHORITY_CODEC_V3.read(row).value,
        _authority_complete,
    ),
    "exceptional_transitions": _ArtifactFamily(
        EXCEPTIONAL_TRANSITIONS_ARTIFACT_KIND_V3,
        lambda row: EXCEPTIONAL_TRANSITION_CODEC_V3.read(row).value,
        _authority_complete,
    ),
    "external_sites": _ArtifactFamily(
        CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
        lambda row: CANONICAL_EXTERNAL_SITE_CODEC_V3.read(row).value,
        _authority_complete,
    ),
    "target_certificates": _ArtifactFamily(
        INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
        lambda row: INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3.read(row).value,
        _authority_complete,
    ),
}

_STRUCTURAL_AUXILIARY_ARTIFACTS = frozenset({
    "inductive_authority",
    "parametric_summaries",
    "root_closure",
})


def build_structural_executable_receipt(
    *,
    artifacts: Mapping[str, Path | str],
    fallback_capability_analysis: Path | str,
    activation_plan: Path | str,
    machine_ir: Path | str,
    machine_ir_manifest: Path | str,
    rooted_projection: Path | str | Mapping[str, object],
) -> CandidatePolicyReceiptV1:
    """Reduce exact checked facts into the sole whole-candidate execution gate."""

    expected_artifacts = (
        set(_STRUCTURAL_ARTIFACTS)
        | set(_ROOTED_BEHAVIORAL_ARTIFACTS)
        | set(_STRUCTURAL_AUXILIARY_ARTIFACTS)
    )
    unknown = sorted(set(artifacts) - expected_artifacts)
    missing = sorted(expected_artifacts - set(artifacts))
    if unknown or missing:
        raise CandidatePolicyError(
            f"structural policy artifact families differ: missing={missing}, extra={unknown}"
        )
    try:
        projection = load_rooted_behavioral_projection_v1(rooted_projection)
    except RootedBehavioralProjectionError as exc:
        raise CandidatePolicyError(str(exc)) from exc
    families = [
        _check_artifact_family(
            f"structural_universe_{identity}",
            Path(artifacts[identity]),
            specification,
        )
        for identity, specification in sorted(_STRUCTURAL_ARTIFACTS.items())
    ]
    families.append(
        _check_rooted_projection_inputs(
            projection=projection,
            root_closure=Path(artifacts["root_closure"]),
            semantic_index=Path(artifacts["semantic_index"]),
        )
    )
    families.extend(
        _check_rooted_artifact_family(
            f"rooted_behavior_{identity}",
            Path(artifacts[identity]),
            specification,
            projection,
        )
        for identity, specification in sorted(_ROOTED_BEHAVIORAL_ARTIFACTS.items())
    )
    families.append(
        _check_target_induction(
            projection=projection,
            target_certificates=Path(artifacts["target_certificates"]),
            inductive_authority=Path(artifacts["inductive_authority"]),
        )
    )
    families.append(
        _check_rooted_parametric_summaries(
            projection=projection,
            parametric_summaries=Path(artifacts["parametric_summaries"]),
        )
    )
    families.append(
        _check_fallback_analysis(
            Path(fallback_capability_analysis),
            expected_structural_units=projection.structural_unit_count,
        )
    )
    families.append(
        _check_activation_plan(
            Path(activation_plan),
            expected_structural_units=projection.structural_unit_count,
        )
    )
    machine_path = Path(machine_ir)
    manifest_path = Path(machine_ir_manifest)
    manifest = _load_json(manifest_path, "machine-IR manifest")
    activation = _load_json(activation_plan, "component activation plan")
    bindings = {
        "machine_ir_sha256": _file_sha256(machine_path),
        "machine_ir_manifest_sha256": _file_sha256(manifest_path),
        "pe_sha256": _manifest_pe_sha256(manifest),
        "activation_plan_sha256": activation["activation_plan_sha256"],
        "component_authority_receipts": _component_authority_bindings(activation),
        "rooted_behavioral_projection": projection.to_payload(),
    }
    return _finish_policy(STRUCTURAL_EXECUTABLE_V1, families, bindings=bindings)


def build_release_acceptance_receipt(
    *,
    structural_receipt: Path | str | Mapping[str, object],
    isa_qualification: Path | str,
    candidate_binary: Path | str,
    component_release_gate: Path | str | Mapping[str, object],
) -> CandidatePolicyReceiptV1:
    """Add ISA and exact component qualification to execution closure.

    Candidate-only runtime tests are diagnostics and deliberately do not enter
    this reducer.  Adding or removing one cannot change release acceptance.
    """

    structural = _load_json(structural_receipt, "structural executable receipt")
    if (
        structural.get("format") != STRUCTURAL_EXECUTABLE_V1
        or structural.get("status") != "complete"
        or structural.get("executable") is not True
    ):
        raise CandidatePolicyError("release acceptance requires structural executability")
    structural_bindings = _object(
        structural.get("bindings"), "structural receipt bindings"
    )
    try:
        projection = load_rooted_behavioral_projection_v1(
            _object(
                structural_bindings.get("rooted_behavioral_projection"),
                "structural rooted behavioral projection",
            )
        )
    except RootedBehavioralProjectionError as exc:
        raise CandidatePolicyError(str(exc)) from exc
    component_family, component_gate = _check_component_release_gate(
        component_release_gate,
        expected_activation_plan_sha256=structural_bindings.get(
            "activation_plan_sha256"
        ),
        expected_rooted_projection_sha256=projection.projection_sha256,
    )
    families = [
        PolicyFamilyReceiptV1(
            "structural_executable",
            "complete",
            _receipt_digest(structural),
            len(_array(structural.get("families"), "structural receipt families")),
            None,
        ),
        _check_rooted_artifact_family(
            "rooted_behavior_isa_qualification",
            Path(isa_qualification),
            _ArtifactFamily(
                ISA_QUALIFICATION_ARTIFACT_KIND_V3,
                lambda row: ISA_QUALIFICATION_CODEC_V3.read(row).value,
                _authority_complete,
            ),
            projection,
        ),
        component_family,
    ]
    candidate_sha256 = _file_sha256(Path(candidate_binary))
    return _finish_policy(
        RELEASE_ACCEPTANCE_V1,
        families,
        structurally_executable=True,
        bindings={
            **structural_bindings,
            "structural_receipt_sha256": _receipt_digest(structural),
            "component_release_gate_sha256": component_gate["gate_sha256"],
            "component_dependency_graph_sha256": component_gate["graph_sha256"],
            "candidate_sha256": candidate_sha256,
        },
    )


def write_policy_receipt(path: Path | str, receipt: CandidatePolicyReceiptV1) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(receipt.to_payload(), indent=2, sort_keys=True) + "\n",
        encoding="ascii",
    )


def load_policy_receipt(
    value: Path | str | Mapping[str, object],
) -> CandidatePolicyReceiptV1:
    payload = _load_json(value, "candidate policy receipt")
    expected_fields = {
        "format",
        "status",
        "executable",
        "release_accepted",
        "bindings",
        "families",
        "receipt_sha256",
    }
    if set(payload) != expected_fields:
        raise CandidatePolicyError("candidate policy receipt fields are noncanonical")
    format_name = payload.get("format")
    if format_name not in {STRUCTURAL_EXECUTABLE_V1, RELEASE_ACCEPTANCE_V1}:
        raise CandidatePolicyError("candidate policy receipt format is unsupported")
    status = payload.get("status")
    executable = payload.get("executable")
    release_accepted = payload.get("release_accepted")
    if status not in {"complete", "incomplete"}:
        raise CandidatePolicyError("candidate policy receipt status is invalid")
    if not isinstance(executable, bool):
        raise CandidatePolicyError("candidate policy executable state is invalid")
    if format_name == STRUCTURAL_EXECUTABLE_V1 and executable is not (
        status == "complete"
    ):
        raise CandidatePolicyError("structural executable state contradicts status")
    if format_name == RELEASE_ACCEPTANCE_V1 and executable is not True:
        raise CandidatePolicyError(
            "release receipt must preserve prior structural executability"
        )
    if not isinstance(release_accepted, bool) or release_accepted is not (
        status == "complete" and format_name == RELEASE_ACCEPTANCE_V1
    ):
        raise CandidatePolicyError("candidate release state contradicts policy format")
    bindings = dict(_object(payload.get("bindings"), "policy bindings"))
    rows: list[PolicyFamilyReceiptV1] = []
    for raw in _array(payload.get("families"), "policy families"):
        row = _object(raw, "policy family")
        if set(row) != {"id", "status", "input_sha256", "record_count", "blocker"}:
            raise CandidatePolicyError("policy family fields are noncanonical")
        identity = row.get("id")
        family_status = row.get("status")
        digest = row.get("input_sha256")
        count = row.get("record_count")
        blocker = row.get("blocker")
        if not isinstance(identity, str) or not identity:
            raise CandidatePolicyError("policy family ID is invalid")
        if family_status not in {"complete", "incomplete"}:
            raise CandidatePolicyError("policy family status is invalid")
        if not _is_digest(digest):
            raise CandidatePolicyError("policy family digest is invalid")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise CandidatePolicyError("policy family record count is invalid")
        if blocker is not None and (not isinstance(blocker, str) or not blocker):
            raise CandidatePolicyError("policy family blocker is invalid")
        if (family_status == "complete") != (blocker is None):
            raise CandidatePolicyError("policy family blocker contradicts status")
        rows.append(
            PolicyFamilyReceiptV1(
                identity, family_status, str(digest), count, blocker
            )
        )
    families = tuple(sorted(rows, key=lambda row: row.identity))
    if tuple(rows) != families or len({row.identity for row in rows}) != len(rows):
        raise CandidatePolicyError("policy families are duplicated or unsorted")
    if (status == "complete") is not all(
        row.status == "complete" for row in families
    ):
        raise CandidatePolicyError("policy family states contradict policy status")
    observed = _receipt_digest(payload)
    return CandidatePolicyReceiptV1(
        format=str(format_name),
        status=str(status),
        executable=executable,
        release_accepted=release_accepted,
        bindings=bindings,
        families=families,
        receipt_sha256=observed,
    )


def _check_artifact_family(
    identity: str, path: Path, specification: _ArtifactFamily
) -> PolicyFamilyReceiptV1:
    reader = open_artifact_reader_v3(path)
    if reader.manifest.artifact_kind != specification.kind:
        raise CandidatePolicyError(
            f"{identity} artifact kind is {reader.manifest.artifact_kind!r}, "
            f"expected {specification.kind!r}"
        )
    records = tuple(reader.iter_records())
    incomplete: list[str] = []
    for record in records:
        decoded = specification.decode(record)
        if not specification.complete(decoded):
            incomplete.append(record.record_id)
    status = "complete" if records and not incomplete else "incomplete"
    blocker = None
    if not records:
        blocker = "checked artifact has no records"
    elif incomplete:
        blocker = f"{len(incomplete)} records are not complete: {incomplete[:3]!r}"
    return PolicyFamilyReceiptV1(
        identity,
        status,
        reader.manifest_sha256,
        len(records),
        blocker,
    )


def _check_rooted_projection_inputs(
    *,
    projection: RootedBehavioralProjectionV1,
    root_closure: Path,
    semantic_index: Path,
) -> PolicyFamilyReceiptV1:
    root_reader = open_artifact_reader_v3(root_closure)
    semantic_reader = open_artifact_reader_v3(semantic_index)
    if root_reader.manifest.artifact_kind != LAUNCH_ROOT_CLOSURE_ARTIFACT_KIND_V3:
        raise CandidatePolicyError(
            "rooted behavioral projection has the wrong root-closure artifact kind"
        )
    if semantic_reader.manifest.artifact_kind != SEMANTIC_INDEX_ARTIFACT_KIND_V3:
        raise CandidatePolicyError(
            "rooted behavioral projection has the wrong semantic-index artifact kind"
        )
    if (
        root_reader.manifest_sha256 != projection.root_closure_manifest_sha256
        or semantic_reader.manifest_sha256
        != projection.semantic_index_manifest_sha256
    ):
        raise CandidatePolicyError(
            "rooted behavioral projection is bound to different checked inputs"
        )
    return PolicyFamilyReceiptV1(
        "rooted_behavior_scope",
        "complete",
        projection.projection_sha256,
        len(projection.reachable_unit_ids),
        None,
    )


def _check_rooted_artifact_family(
    identity: str,
    path: Path,
    specification: _ArtifactFamily,
    projection: RootedBehavioralProjectionV1,
) -> PolicyFamilyReceiptV1:
    reader = open_artifact_reader_v3(path)
    if reader.manifest.artifact_kind != specification.kind:
        raise CandidatePolicyError(
            f"{identity} artifact kind is {reader.manifest.artifact_kind!r}, "
            f"expected {specification.kind!r}"
        )
    reachable = projection.reachable_unit_id_set
    records = tuple(
        record for record in reader.iter_records() if record.record_id in reachable
    )
    selected_ids = tuple(record.record_id for record in records)
    missing = sorted(reachable - set(selected_ids))
    duplicated = len(selected_ids) != len(set(selected_ids))
    incomplete: list[str] = []
    for record in records:
        decoded = specification.decode(record)
        if getattr(decoded, "record_id", record.record_id) != record.record_id:
            raise CandidatePolicyError(
                f"{identity} record {record.record_id!r} has a stale unit binding"
            )
        if not specification.complete(decoded):
            incomplete.append(record.record_id)
    complete = not missing and not duplicated and not incomplete
    if missing:
        blocker = (
            f"rooted behavioral coverage is missing {len(missing)} reachable "
            f"unit records: {missing[:3]!r}"
        )
    elif duplicated:
        blocker = "rooted behavioral coverage duplicates reachable unit records"
    elif incomplete:
        blocker = (
            f"{len(incomplete)} root-reachable records are not behaviorally "
            f"complete: {incomplete[:3]!r}"
        )
    else:
        blocker = None
    return PolicyFamilyReceiptV1(
        identity,
        "complete" if complete else "incomplete",
        canonical_sha256_v3(
            {
                "artifact_manifest_sha256": reader.manifest_sha256,
                "rooted_projection_sha256": projection.projection_sha256,
                "selected_record_ids": list(selected_ids),
            }
        ),
        len(records),
        blocker,
    )


def _check_target_induction(
    *,
    projection: RootedBehavioralProjectionV1,
    target_certificates: Path,
    inductive_authority: Path,
) -> PolicyFamilyReceiptV1:
    """Require checked induction exactly where rooted target proofs consume it."""

    target_reader = open_artifact_reader_v3(target_certificates)
    if (
        target_reader.manifest.artifact_kind
        != INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3
    ):
        raise CandidatePolicyError(
            "target-induction target certificates have the wrong kind"
        )
    required_cutpoints: set[str] = set()
    reachable = projection.reachable_unit_id_set
    for record in target_reader.iter_records():
        if record.record_id not in reachable:
            continue
        unit = INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3.read(record).value
        for certificate in unit.certificates:
            if not certificate.authorizing:
                continue
            if certificate.evaluation_method != "inductive_finite_values":
                continue
            required_cutpoints.update(
                dependency.record_id
                for dependency in certificate.dependencies
                if dependency.input_name == "inductive_inputs"
            )

    authority_reader = open_artifact_reader_v3(inductive_authority)
    if (
        authority_reader.manifest.artifact_kind
        != INDUCTIVE_AUTHORITY_ARTIFACT_KIND_V3
    ):
        raise CandidatePolicyError(
            "target-induction authority artifact has the wrong kind"
        )
    coverage: dict[str, list[bool]] = {}
    for record in authority_reader.iter_records():
        authority = INDUCTIVE_AUTHORITY_CODEC_V3.read(record).value
        body = InductiveAuthorityBodyV3.parse(authority.body.to_value())
        for report in body.certificate_reports:
            checked = (
                authority.authorizing
                and authority.status == "complete"
                and report.status == "complete"
            )
            for cutpoint in report.member_cutpoints:
                coverage.setdefault(cutpoint, []).append(checked)

    unresolved = sorted(
        cutpoint
        for cutpoint in required_cutpoints
        if coverage.get(cutpoint) != [True]
    )
    complete = not unresolved
    blocker = None
    if unresolved:
        blocker = (
            f"{len(unresolved)} rooted finite-target cutpoints lack one exact "
            f"checked induction certificate: {unresolved[:3]!r}"
        )
    return PolicyFamilyReceiptV1(
        "rooted_behavior_target_induction",
        "complete" if complete else "incomplete",
        canonical_sha256_v3({
            "rooted_projection": projection.projection_sha256,
            "target_certificates": target_reader.manifest_sha256,
            "inductive_authority": authority_reader.manifest_sha256,
            "required_cutpoints": sorted(required_cutpoints),
        }),
        len(required_cutpoints),
        blocker,
    )


def _check_rooted_parametric_summaries(
    *,
    projection: RootedBehavioralProjectionV1,
    parametric_summaries: Path,
) -> PolicyFamilyReceiptV1:
    """Require one checked root-independent summary for every rooted unit."""

    summary_reader = open_artifact_reader_v3(parametric_summaries)
    if (
        summary_reader.manifest.artifact_kind
        != PARAMETRIC_SCC_SUMMARIES_ARTIFACT_KIND_V3
    ):
        raise CandidatePolicyError(
            "rooted parametric summaries have the wrong artifact kind"
        )
    coverage: dict[str, list[bool]] = {}
    for record in summary_reader.iter_records():
        summary = PARAMETRIC_SCC_SUMMARY_CODEC_V3.read(record).value
        checked = summary.status == "complete" and summary.authorizing
        for unit_id in summary.member_unit_ids:
            coverage.setdefault(unit_id, []).append(checked)

    reachable = projection.reachable_unit_ids
    unresolved = tuple(
        unit_id for unit_id in reachable if coverage.get(unit_id) != [True]
    )
    complete = not unresolved
    if unresolved:
        blocker = (
            f"{len(unresolved)} reachable units lack one exact checked "
            f"parametric summary: {list(unresolved[:3])!r}"
        )
    else:
        blocker = None
    return PolicyFamilyReceiptV1(
        "rooted_behavior_parametric_summaries",
        "complete" if complete else "incomplete",
        canonical_sha256_v3(
            {
                "rooted_projection": projection.projection_sha256,
                "parametric_summaries": summary_reader.manifest_sha256,
                "reachable_unit_ids": list(reachable),
            }
        ),
        len(reachable),
        blocker,
    )


def _check_fallback_analysis(
    path: Path, *, expected_structural_units: int
) -> PolicyFamilyReceiptV1:
    payload = _load_json(path, "fallback capability analysis")
    analysis = FallbackCapabilityAnalysis.from_payload(payload)
    complete = (
        analysis.complete
        and analysis.required_units > 0
        and analysis.required_units == expected_structural_units
        and len(analysis.lowerable_unit_ids) == analysis.required_units
        and not analysis.unlowerable_unit_ids
        and not analysis.blockers
    )
    return PolicyFamilyReceiptV1(
        "structural_universe_fallback_execution",
        "complete" if complete else "incomplete",
        canonical_sha256_v3(payload),
        analysis.required_units,
        (
            None
            if complete
            else "structural-universe fallback capability is incomplete or targets another unit inventory"
        ),
    )


def _check_activation_plan(
    path: Path, *, expected_structural_units: int
) -> PolicyFamilyReceiptV1:
    payload = _load_json(path, "component activation plan")
    counts = _object(payload.get("counts"), "activation-plan counts")
    entries = _array(payload.get("entries"), "activation-plan entries")
    try:
        checked_record = ComponentActivationPlanRecordV3.parse(payload)
    except ComponentLifecycleRecordError:
        checked_record = None
    try:
        selected_authority = _component_authority_bindings(payload)
    except CandidatePolicyError:
        selected_authority = {}
    enabled_ids = [
        row.get("id")
        for row in _array(payload.get("selections"), "activation-plan selections")
        if isinstance(row, Mapping)
        and row.get("requested_activation") == "enabled"
        and isinstance(row.get("id"), str)
    ]
    authority_inventory_complete = (
        len(enabled_ids) == len(set(enabled_ids))
        and set(enabled_ids) == set(selected_authority)
    )
    complete = (
        checked_record is not None
        and payload.get("format") == _ACTIVATION_PLAN_V3
        and payload.get("status") == "checked"
        and counts.get("blocked") == 0
        and counts.get("structural_units") == len(entries)
        and len(entries) == expected_structural_units
        and all(
            isinstance(row, Mapping)
            and row.get("implementation_kind")
            in {"portable_replacement", "machine_ir_fallback"}
            for row in entries
        )
        and authority_inventory_complete
    )
    if checked_record is None:
        blocker = "implementation ownership artifact is malformed or stale"
    elif counts.get("blocked") != 0:
        blocker = "implementation ownership contains blocked structural units"
    elif not authority_inventory_complete:
        blocker = "an enabled component has no exact activation authority receipt"
    elif len(entries) != expected_structural_units:
        blocker = "structural-universe implementation ownership targets another unit inventory"
    elif not complete:
        blocker = "implementation ownership is incomplete or nonexclusive"
    else:
        blocker = None
    return PolicyFamilyReceiptV1(
        "structural_universe_implementation_ownership",
        "complete" if complete else "incomplete",
        canonical_sha256_v3(payload),
        len(entries),
        blocker,
    )


def _component_authority_bindings(
    activation: Mapping[str, object],
) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in _array(activation.get("selections"), "activation-plan selections"):
        selection = _object(raw, "activation-plan selection")
        if selection.get("requested_activation") != "enabled":
            continue
        identity = selection.get("id")
        digest = selection.get("activation_receipt_sha256") or selection.get(
            "qualification_sha256"
        )
        if not isinstance(identity, str) or not identity or not _is_digest(digest):
            continue
        if identity in result:
            raise CandidatePolicyError(
                f"activation plan duplicates selected component {identity!r}"
            )
        result[identity] = str(digest)
    return dict(sorted(result.items()))


def _check_component_release_gate(
    value: Path | str | Mapping[str, object],
    *,
    expected_activation_plan_sha256: object,
    expected_rooted_projection_sha256: object,
) -> tuple[PolicyFamilyReceiptV1, dict[str, object]]:
    payload = _load_json(value, "component release gate")
    expected_fields = {
        "format",
        "mode",
        "status",
        "ready",
        "graph_sha256",
        "activation_plan_sha256",
        "rooted_behavioral_projection_sha256",
        "counts",
        "issues",
        "policy",
        "gate_sha256",
    }
    if set(payload) != expected_fields:
        raise CandidatePolicyError("component release gate fields are noncanonical")
    core = dict(payload)
    observed_sha256 = core.pop("gate_sha256")
    if not _is_digest(observed_sha256) or observed_sha256 != canonical_sha256_v3(core):
        raise CandidatePolicyError("component release gate digest is stale")
    if payload.get("format") != COMPONENT_RELEASE_GATE_V1_FORMAT:
        raise CandidatePolicyError("component release gate format is unsupported")
    issues = _array(payload.get("issues"), "component release gate issues")
    counts = _object(payload.get("counts"), "component release gate counts")
    complete = (
        payload.get("mode") == "hybrid"
        and payload.get("status") == "ready"
        and payload.get("ready") is True
        and _is_digest(payload.get("graph_sha256"))
        and payload.get("activation_plan_sha256")
        == expected_activation_plan_sha256
        and payload.get("rooted_behavioral_projection_sha256")
        == expected_rooted_projection_sha256
        and not issues
    )
    if payload.get("activation_plan_sha256") != expected_activation_plan_sha256:
        blocker = "component release gate targets another activation plan"
    elif (
        payload.get("rooted_behavioral_projection_sha256")
        != expected_rooted_projection_sha256
    ):
        blocker = "component release gate targets another rooted behavioral scope"
    elif payload.get("mode") != "hybrid":
        blocker = "candidate release requires the hybrid component gate"
    elif not complete:
        blocker = "component dependency or implementation closure is incomplete"
    else:
        blocker = None
    record_count = sum(
        item
        for item in counts.values()
        if isinstance(item, int) and not isinstance(item, bool) and item >= 0
    )
    return (
        PolicyFamilyReceiptV1(
            "component_contract_closure",
            "complete" if complete else "incomplete",
            str(observed_sha256),
            record_count,
            blocker,
        ),
        payload,
    )


def _finish_policy(
    format_name: str,
    families: list[PolicyFamilyReceiptV1],
    *,
    bindings: Mapping[str, object],
    structurally_executable: bool | None = None,
) -> CandidatePolicyReceiptV1:
    ordered = tuple(sorted(families, key=lambda row: row.identity))
    complete = bool(ordered) and all(row.status == "complete" for row in ordered)
    core = {
        "format": format_name,
        "status": "complete" if complete else "incomplete",
        "executable": complete if structurally_executable is None else structurally_executable,
        "release_accepted": complete if format_name == RELEASE_ACCEPTANCE_V1 else False,
        "bindings": dict(sorted(bindings.items())),
        "families": [row.to_payload() for row in ordered],
    }
    return CandidatePolicyReceiptV1(
        format=format_name,
        status=str(core["status"]),
        executable=bool(core["executable"]),
        release_accepted=bool(core["release_accepted"]),
        bindings=dict(sorted(bindings.items())),
        families=ordered,
        receipt_sha256=canonical_sha256_v3(core),
    )


def _receipt_digest(payload: Mapping[str, object]) -> str:
    expected = payload.get("receipt_sha256")
    if not isinstance(expected, str):
        raise CandidatePolicyError("policy receipt has no digest")
    core = dict(payload)
    core.pop("receipt_sha256")
    if canonical_sha256_v3(core) != expected:
        raise CandidatePolicyError("policy receipt digest is stale")
    return expected


def _load_json(
    value: Path | str | Mapping[str, object], description: str
) -> dict[str, object]:
    if isinstance(value, Mapping):
        return json.loads(json.dumps(value))
    path = Path(value)
    if path.is_dir():
        candidates = sorted(path.glob("*.json"))
        if len(candidates) != 1:
            raise CandidatePolicyError(
                f"{description} directory must contain exactly one JSON receipt"
            )
        path = candidates[0]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CandidatePolicyError(f"cannot read {description}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise CandidatePolicyError(f"{description} must be an object")
    return dict(payload)


def _file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise CandidatePolicyError(f"cannot hash policy input {path}: {exc}") from exc


def _manifest_pe_sha256(manifest: Mapping[str, object]) -> str:
    candidates: list[object] = []
    binary = manifest.get("binary")
    if isinstance(binary, Mapping):
        candidates.append(binary.get("sha256"))
    inputs = manifest.get("inputs")
    if isinstance(inputs, Mapping):
        original = inputs.get("original_pe")
        if isinstance(original, Mapping):
            candidates.append(original.get("sha256"))
    digests = {
        value
        for value in candidates
        if isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    }
    if len(digests) != 1:
        raise CandidatePolicyError("machine-IR manifest has no unique PE binding")
    return next(iter(digests))


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _object(value: object, description: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise CandidatePolicyError(f"{description} must be an object")
    return value


def _array(value: object, description: str) -> list[object]:
    if not isinstance(value, list):
        raise CandidatePolicyError(f"{description} must be an array")
    return value


__all__ = [
    "CandidatePolicyError",
    "CandidatePolicyReceiptV1",
    "PolicyFamilyReceiptV1",
    "RELEASE_ACCEPTANCE_V1",
    "STRUCTURAL_EXECUTABLE_V1",
    "build_release_acceptance_receipt",
    "build_structural_executable_receipt",
    "load_policy_receipt",
    "write_policy_receipt",
]
