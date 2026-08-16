"""Typed candidate view of checked rooted execution authority.

Candidate rendering consumes this view instead of proposal fields embedded in
the machine-IR manifest.  Construction is fail closed: only a complete root
closure, complete finite-target certificates, and complete parametric
summaries can produce a view.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ...artifacts.artifact_set import CanonicalValueV3
from ...artifacts.io import open_artifact_reader_v3
from ...authority.parametric_summary_records import (
    PARAMETRIC_SCC_SUMMARIES_ARTIFACT_KIND_V3,
    PARAMETRIC_SCC_SUMMARY_CODEC_V3,
    ParametricSccSummaryV3,
)
from ...authority.root_closure import (
    LAUNCH_ROOT_CLOSURE_ARTIFACT_KIND_V3,
    LAUNCH_ROOT_CLOSURE_CODEC_V3,
    RootedControlEdgeV3,
)
from ...authority.target_certificate_records import (
    INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3,
    INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
    IndirectTargetCertificateV3,
)


class CandidateExecutionAuthorityError(ValueError):
    """Checked execution artifacts do not form one executable authority view."""


@dataclass(frozen=True, order=True)
class CheckedIndirectDispatchV3:
    exit_id: str
    source_unit_id: str
    source_event_index: int | None
    transfer_kind: str
    target_unit_ids: tuple[str, ...]
    external_targets: tuple[CanonicalValueV3, ...]
    certificate_id: str


@dataclass(frozen=True)
class CandidateExecutionAuthorityV3:
    root_unit_ids: tuple[str, ...]
    reachable_unit_ids: tuple[str, ...]
    edges: tuple[RootedControlEdgeV3, ...]
    indirect_dispatches: tuple[CheckedIndirectDispatchV3, ...]
    summaries: tuple[ParametricSccSummaryV3, ...]
    root_closure_manifest_sha256: str
    target_certificates_manifest_sha256: str
    parametric_summaries_manifest_sha256: str

    def __post_init__(self) -> None:
        reachable = set(self.reachable_unit_ids)
        if (
            not self.root_unit_ids
            or tuple(sorted(set(self.root_unit_ids))) != self.root_unit_ids
            or tuple(sorted(set(self.reachable_unit_ids)))
            != self.reachable_unit_ids
            or not set(self.root_unit_ids) <= reachable
        ):
            raise CandidateExecutionAuthorityError(
                "checked root/reachable inventories are malformed"
            )
        if self.edges != tuple(sorted(set(self.edges))):
            raise CandidateExecutionAuthorityError(
                "checked rooted edges are duplicated or unsorted"
            )
        if any(
            edge.source_unit_id not in reachable
            or edge.target_unit_id not in reachable
            for edge in self.edges
        ):
            raise CandidateExecutionAuthorityError(
                "checked rooted edge leaves the reachable universe"
            )
        if self.indirect_dispatches != tuple(sorted(set(self.indirect_dispatches))):
            raise CandidateExecutionAuthorityError(
                "checked indirect dispatches are duplicated or unsorted"
            )
        coverage: dict[str, int] = {}
        for summary in self.summaries:
            if summary.status != "complete" or not summary.authorizing:
                raise CandidateExecutionAuthorityError(
                    "candidate view contains a non-authorizing parametric summary"
                )
            for unit_id in summary.member_unit_ids:
                if unit_id in reachable:
                    coverage[unit_id] = coverage.get(unit_id, 0) + 1
        unresolved = sorted(
            unit_id for unit_id in reachable if coverage.get(unit_id) != 1
        )
        if unresolved:
            raise CandidateExecutionAuthorityError(
                f"reachable units lack one checked parametric summary: {unresolved[:3]!r}"
            )

    def summary_for_unit(self, unit_id: str) -> ParametricSccSummaryV3:
        rows = tuple(row for row in self.summaries if row.covers_unit(unit_id))
        if len(rows) != 1:
            raise CandidateExecutionAuthorityError(
                f"unit {unit_id!r} does not have one checked summary"
            )
        return rows[0]

    def indirect_dispatch(
        self, source_unit_id: str, event_index: int | None
    ) -> CheckedIndirectDispatchV3 | None:
        rows = tuple(
            row
            for row in self.indirect_dispatches
            if row.source_unit_id == source_unit_id
            and row.source_event_index == event_index
        )
        if len(rows) > 1:
            raise CandidateExecutionAuthorityError(
                f"indirect dispatch {(source_unit_id, event_index)!r} is ambiguous"
            )
        return rows[0] if rows else None

    @property
    def internal_indirect_sites(self) -> frozenset[tuple[str, int]]:
        """Return call sites whose checked finite alternatives are all internal."""

        return frozenset(
            (row.source_unit_id, row.source_event_index)
            for row in self.indirect_dispatches
            if row.transfer_kind == "indirect_call"
            and row.source_event_index is not None
            and row.target_unit_ids
            and not row.external_targets
        )

    @property
    def call_preservation_by_site(self) -> dict[tuple[str, int], frozenset[str]]:
        """Return independently checked nonvolatile preservation by call site."""

        result: dict[tuple[str, int], frozenset[str]] = {}
        for summary in self.summaries:
            for call in summary.call_effects:
                if call.preserved_registers is None:
                    continue
                key = (call.source_unit_id, call.event_index)
                preserved = frozenset(call.preserved_registers)
                if key in result and result[key] != preserved:
                    raise CandidateExecutionAuthorityError(
                        f"checked call preservation for {key!r} is ambiguous"
                    )
                result[key] = preserved
        return result


def load_candidate_execution_authority_v3(
    *,
    root_closure: Path,
    target_certificates: Path,
    parametric_summaries: Path,
) -> CandidateExecutionAuthorityV3:
    root_reader = open_artifact_reader_v3(root_closure)
    target_reader = open_artifact_reader_v3(target_certificates)
    summary_reader = open_artifact_reader_v3(parametric_summaries)
    expected = (
        (
            root_reader.manifest.artifact_kind,
            LAUNCH_ROOT_CLOSURE_ARTIFACT_KIND_V3,
            "root closure",
        ),
        (
            target_reader.manifest.artifact_kind,
            INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
            "target certificates",
        ),
        (
            summary_reader.manifest.artifact_kind,
            PARAMETRIC_SCC_SUMMARIES_ARTIFACT_KIND_V3,
            "parametric summaries",
        ),
    )
    for actual, required, label in expected:
        if actual != required:
            raise CandidateExecutionAuthorityError(
                f"{label} has artifact kind {actual!r}, expected {required!r}"
            )
    root_records = tuple(root_reader.iter_records())
    if len(root_records) != 1:
        raise CandidateExecutionAuthorityError(
            "candidate execution requires exactly one root closure"
        )
    root = LAUNCH_ROOT_CLOSURE_CODEC_V3.read(root_records[0]).value
    if root.status != "complete" or not root.authorizing or root.frontier_ids:
        raise CandidateExecutionAuthorityError(
            "candidate execution requires a complete frontier-free root closure"
        )
    reachable = set(root.reachable_unit_ids)
    certificates: list[IndirectTargetCertificateV3] = []
    certificates_by_id: dict[str, IndirectTargetCertificateV3] = {}
    certificates_by_exit: dict[str, IndirectTargetCertificateV3] = {}
    for source in target_reader.iter_records():
        unit = INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3.read(source).value
        if unit.source_unit_id not in reachable:
            continue
        for certificate in unit.certificates:
            if certificate.status != "complete" or not certificate.authorizing:
                raise CandidateExecutionAuthorityError(
                    f"reachable indirect exit {certificate.exit_id!r} is not checked"
                )
            if not set(certificate.target_unit_ids) <= reachable:
                raise CandidateExecutionAuthorityError(
                    f"checked indirect exit {certificate.exit_id!r} leaves rooted closure"
                )
            if certificate.certificate_id in certificates_by_id:
                raise CandidateExecutionAuthorityError(
                    f"checked indirect certificate {certificate.certificate_id!r} is duplicated"
                )
            if certificate.exit_id in certificates_by_exit:
                raise CandidateExecutionAuthorityError(
                    f"checked indirect exit {certificate.exit_id!r} is ambiguous"
                )
            certificates_by_id[certificate.certificate_id] = certificate
            certificates_by_exit[certificate.exit_id] = certificate
            certificates.append(certificate)
    dispatches = tuple(
        sorted(
            CheckedIndirectDispatchV3(
                row.exit_id,
                row.source_unit_id,
                row.source_event_index,
                row.transfer_kind,
                row.target_unit_ids,
                row.external_targets,
                row.certificate_id,
            )
            for row in certificates
        )
    )
    summaries = []
    for source in summary_reader.iter_records():
        summary = PARAMETRIC_SCC_SUMMARY_CODEC_V3.read(source).value
        if any(unit_id in reachable for unit_id in summary.member_unit_ids):
            summaries.append(summary)
    for edge in root.edges:
        if edge.edge_kind != "recovered_indirect":
            continue
        certificate = certificates_by_id.get(edge.authority_record_id)
        if (
            certificate is None
            or certificate.source_unit_id != edge.source_unit_id
            or edge.target_unit_id not in certificate.target_unit_ids
        ):
            raise CandidateExecutionAuthorityError(
                f"rooted indirect edge {edge.edge_id!r} lacks its exact checked certificate"
            )
    for summary in summaries:
        for indirect_exit in summary.indirect_exits:
            if indirect_exit.source_unit_id not in reachable:
                continue
            certificate = certificates_by_exit.get(indirect_exit.exit_id)
            if (
                certificate is None
                or certificate.source_unit_id != indirect_exit.source_unit_id
                or certificate.target_unit_ids != indirect_exit.target_unit_ids
            ):
                raise CandidateExecutionAuthorityError(
                    f"parametric indirect exit {indirect_exit.exit_id!r} lacks one matching certificate"
                )
    return CandidateExecutionAuthorityV3(
        root_unit_ids=root.root_unit_ids,
        reachable_unit_ids=root.reachable_unit_ids,
        edges=root.edges,
        indirect_dispatches=dispatches,
        summaries=tuple(sorted(summaries, key=lambda row: row.record_id)),
        root_closure_manifest_sha256=root_reader.manifest_sha256,
        target_certificates_manifest_sha256=target_reader.manifest_sha256,
        parametric_summaries_manifest_sha256=summary_reader.manifest_sha256,
    )


__all__ = [
    "CandidateExecutionAuthorityError",
    "CandidateExecutionAuthorityV3",
    "CheckedIndirectDispatchV3",
    "load_candidate_execution_authority_v3",
]
