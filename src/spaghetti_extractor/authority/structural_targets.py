"""Non-authorizing structural target proposals bound to exact v3 records."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from ..artifact_set_v3 import (
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    CanonicalValueV3,
    RecordDependencyV3,
)
from ..phase_framework_v3 import PhaseContextV3, RecordCodecV3, map_units
from ._schema import (
    canonical_json_rows,
    canonical_sort,
    canonical_strings,
    digest,
    fail,
    mapping,
    optional_uint,
    sequence,
    sorted_records,
    strict_object,
    text,
    uint,
)
from .semantic_index import (
    SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    SEMANTIC_INDEX_CODEC_V3,
)


STRUCTURAL_TARGET_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-structural-target-proposal-record-v3"
)
STRUCTURAL_TARGET_UNIT_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-structural-target-unit-record-v3"
)
STRUCTURAL_TARGETS_ARTIFACT_KIND_V3 = "structural-target-proposals-v3"


@dataclass(frozen=True)
class StructuralTargetProposalV3:
    """One proposal for one exact indirect exit; never authority by itself."""

    record_id: str
    source_unit_id: str
    source_rva: int
    source_event_index: int | None
    transfer_kind: str
    status: str
    target_unit_ids: tuple[str, ...]
    external_targets: tuple[CanonicalValueV3, ...]
    proposal_sha256: str | None
    issue_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        text(self.record_id, "structural-target exit ID")
        text(self.source_unit_id, "structural-target source unit ID")
        uint(self.source_rva, "structural-target source RVA")
        optional_uint(
            self.source_event_index, "structural-target source event index"
        )
        if self.transfer_kind not in {"indirect_call", "indirect_jump"}:
            fail(
                "record_schema_mismatch",
                f"structural target has invalid transfer kind {self.transfer_kind!r}",
                "bind the exact indirect call or jump kind",
            )
        if self.status not in {"recovered", "incomplete", "violated"}:
            fail(
                "record_schema_mismatch",
                f"structural target has invalid status {self.status!r}",
                "use recovered, incomplete, or violated",
            )
        if self.target_unit_ids != tuple(sorted(set(self.target_unit_ids))):
            fail(
                "noncanonical_record_order",
                "structural target unit IDs are not sorted and unique",
                "sort and deduplicate target unit IDs",
            )
        for target_unit_id in self.target_unit_ids:
            text(target_unit_id, "structural-target unit ID")
        if self.external_targets != tuple(
            sorted(set(self.external_targets), key=lambda row: row.data)
        ):
            fail(
                "noncanonical_record_order",
                "external targets are not canonically sorted and unique",
                "sort and deduplicate external targets by canonical JSON",
            )
        if self.issue_codes != tuple(sorted(set(self.issue_codes))):
            fail(
                "noncanonical_record_order",
                "structural target issue codes are not sorted and unique",
                "sort and deduplicate issue codes",
            )
        if self.proposal_sha256 is not None:
            digest(self.proposal_sha256, "structural-target proposal SHA-256")
        if self.status == "recovered":
            if (
                not (self.target_unit_ids or self.external_targets)
                or self.proposal_sha256 is None
                or self.issue_codes
            ):
                fail(
                    "fail_open_target_status",
                    f"recovered target {self.record_id!r} lacks complete checked evidence",
                    "mark it incomplete or repair the proposal evidence",
                )
        elif self.target_unit_ids or self.external_targets:
            fail(
                "fail_open_target_status",
                f"non-recovered target {self.record_id!r} retains target authority",
                "clear target sets unless the checked status is recovered",
            )

    @property
    def authorizing(self) -> bool:
        return False


def _encode_structural_target(value: StructuralTargetProposalV3) -> dict[str, Any]:
    return {
        "schema": STRUCTURAL_TARGET_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "source_unit_id": value.source_unit_id,
        "source_rva": value.source_rva,
        "source_event_index": value.source_event_index,
        "transfer_kind": value.transfer_kind,
        "status": value.status,
        "authorizing": False,
        "target_unit_ids": list(value.target_unit_ids),
        "external_targets": canonical_json_rows(value.external_targets),
        "proposal_sha256": value.proposal_sha256,
        "issue_codes": list(value.issue_codes),
    }


def _decode_structural_target(value: Any) -> StructuralTargetProposalV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "source_unit_id",
            "source_rva",
            "source_event_index",
            "transfer_kind",
            "status",
            "authorizing",
            "target_unit_ids",
            "external_targets",
            "proposal_sha256",
            "issue_codes",
        },
        "structural-target proposal record",
    )
    if row["schema"] != STRUCTURAL_TARGET_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not a structural-target-proposal-record-v3",
            "use STRUCTURAL_TARGET_CODEC_V3 with structural target artifacts",
        )
    if row["authorizing"] is not False:
        fail(
            "fail_open_target_status",
            "structural target proposal claims authority",
            "set authorizing to false and use a checked inductive authority record",
        )
    proposal_sha256 = row["proposal_sha256"]
    if proposal_sha256 is not None:
        proposal_sha256 = digest(
            proposal_sha256, "structural-target proposal SHA-256"
        )
    return StructuralTargetProposalV3(
        record_id=text(row["id"], "structural-target exit ID"),
        source_unit_id=text(
            row["source_unit_id"], "structural-target source unit ID"
        ),
        source_rva=uint(row["source_rva"], "structural-target source RVA"),
        source_event_index=optional_uint(
            row["source_event_index"], "structural-target source event index"
        ),
        transfer_kind=text(
            row["transfer_kind"], "structural-target transfer kind"
        ),
        status=text(row["status"], "structural-target status"),
        target_unit_ids=canonical_strings(
            row["target_unit_ids"], "structural-target unit IDs"
        ),
        external_targets=canonical_sort(
            sequence(row["external_targets"], "structural external targets")
        ),
        proposal_sha256=proposal_sha256,
        issue_codes=canonical_strings(
            row["issue_codes"], "structural-target issue codes"
        ),
    )


STRUCTURAL_TARGET_CODEC_V3 = RecordCodecV3[StructuralTargetProposalV3](
    decode=_decode_structural_target,
    encode=_encode_structural_target,
)


@dataclass(frozen=True)
class StructuralTargetUnitV3:
    """All non-authorizing indirect-exit proposals for one exact unit."""

    record_id: str
    source_unit_id: str
    unit_sha256: str
    proposals: tuple[StructuralTargetProposalV3, ...]

    def __post_init__(self) -> None:
        text(self.record_id, "structural-target unit record ID")
        text(self.source_unit_id, "structural-target source unit ID")
        if self.record_id != self.source_unit_id:
            fail(
                "stale_record_id",
                f"structural-target record {self.record_id!r} does not use unit ID {self.source_unit_id!r}",
                "preserve the exact-unit ID in the map_units output",
            )
        digest(self.unit_sha256, "structural-target exact-unit SHA-256")
        if self.proposals != tuple(
            sorted(self.proposals, key=lambda row: row.record_id)
        ) or len({row.record_id for row in self.proposals}) != len(self.proposals):
            fail(
                "noncanonical_record_order",
                f"structural-target exits for {self.source_unit_id!r} are duplicated or unsorted",
                "sort unique exits by their exact stable ID",
            )
        if any(row.source_unit_id != self.source_unit_id for row in self.proposals):
            fail(
                "structural_target_unit_mismatch",
                f"structural-target record {self.record_id!r} contains an exit from another unit",
                "place each exact exit only in its same-unit output record",
            )

    @property
    def authorizing(self) -> bool:
        return False


def _encode_structural_target_unit(value: StructuralTargetUnitV3) -> dict[str, Any]:
    return {
        "schema": STRUCTURAL_TARGET_UNIT_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "source_unit_id": value.source_unit_id,
        "unit_sha256": value.unit_sha256,
        "authorizing": False,
        "proposals": [_encode_structural_target(row) for row in value.proposals],
    }


def _decode_structural_target_unit(value: Any) -> StructuralTargetUnitV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "source_unit_id",
            "unit_sha256",
            "authorizing",
            "proposals",
        },
        "structural-target unit record",
    )
    if row["schema"] != STRUCTURAL_TARGET_UNIT_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not a structural-target-unit-record-v3",
            "use STRUCTURAL_TARGET_UNIT_CODEC_V3 with structural target artifacts",
        )
    if row["authorizing"] is not False:
        fail(
            "fail_open_target_status",
            "structural-target unit record claims authority",
            "set authorizing to false and use checked downstream closure",
        )
    return StructuralTargetUnitV3(
        record_id=text(row["id"], "structural-target unit record ID"),
        source_unit_id=text(
            row["source_unit_id"], "structural-target source unit ID"
        ),
        unit_sha256=digest(
            row["unit_sha256"], "structural-target exact-unit SHA-256"
        ),
        proposals=tuple(
            _decode_structural_target(item)
            for item in sequence(row["proposals"], "structural-target proposals")
        ),
    )


STRUCTURAL_TARGET_UNIT_CODEC_V3 = RecordCodecV3[StructuralTargetUnitV3](
    decode=_decode_structural_target_unit,
    encode=_encode_structural_target_unit,
)


def _bind_hint(
    exact_exit: Mapping[str, Any],
    hint: ArtifactRecordV3 | None,
) -> StructuralTargetProposalV3:
    exit_id = text(exact_exit.get("id"), "exact indirect-exit ID")
    source_unit_id = text(
        exact_exit.get("source_unit_id"), "exact indirect-exit source unit ID"
    )
    source_rva = uint(exact_exit.get("source_rva"), "exact indirect-exit source RVA")
    source_event_index = optional_uint(
        exact_exit.get("source_event_index"), "exact indirect-exit event index"
    )
    transfer_kind = text(exact_exit.get("kind"), "exact indirect-exit kind")
    if hint is None:
        return StructuralTargetProposalV3(
            exit_id,
            source_unit_id,
            source_rva,
            source_event_index,
            transfer_kind,
            "incomplete",
            (),
            (),
            None,
            ("structural_target_proposal_missing",),
        )
    raw = mapping(hint.value.to_value(), "untrusted structural-target hint")
    proposal_sha256 = digest_of_hint(raw)
    expected = {
        "id": exit_id,
        "source_unit_id": source_unit_id,
        "source_rva": source_rva,
        "source_event_index": source_event_index,
        "kind": transfer_kind,
    }
    if any(raw.get(key) != expected_value for key, expected_value in expected.items()):
        return StructuralTargetProposalV3(
            exit_id,
            source_unit_id,
            source_rva,
            source_event_index,
            transfer_kind,
            "violated",
            (),
            (),
            proposal_sha256,
            ("structural_target_proposal_binding_mismatch",),
        )
    raw_targets = raw.get("target_unit_ids")
    raw_external = raw.get("external_targets", [])
    if (
        not isinstance(raw_targets, list)
        or not isinstance(raw_external, list)
        or any(not isinstance(item, str) for item in raw_targets)
        or any(not isinstance(item, Mapping) for item in raw_external)
    ):
        return StructuralTargetProposalV3(
            exit_id,
            source_unit_id,
            source_rva,
            source_event_index,
            transfer_kind,
            "violated",
            (),
            (),
            proposal_sha256,
            ("structural_target_proposal_target_set_malformed",),
        )
    targets = tuple(sorted(set(raw_targets)))
    external = canonical_sort(raw_external)
    recovered = (
        raw.get("status") == "recovered"
        and bool(targets or external)
        and raw.get("failure") is None
    )
    return StructuralTargetProposalV3(
        exit_id,
        source_unit_id,
        source_rva,
        source_event_index,
        transfer_kind,
        "recovered" if recovered else "incomplete",
        targets if recovered else (),
        external if recovered else (),
        proposal_sha256,
        () if recovered else ("structural_target_proposal_incomplete",),
    )


def digest_of_hint(value: Mapping[str, Any]) -> str:
    from ..artifact_set_v3 import canonical_sha256_v3

    return canonical_sha256_v3(value)


def _optional_hint(
    context: PhaseContextV3, exit_id: str
) -> ArtifactRecordV3 | None:
    return context.optional_record("target_hints", exit_id)


def _derive_structural_target_unit(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> StructuralTargetUnitV3:
    semantic_index = SEMANTIC_INDEX_CODEC_V3.read(source).value
    exits = tuple(
        {
            "id": row.exit_id,
            "source_unit_id": semantic_index.record_id,
            "source_rva": semantic_index.rva_start,
            "source_event_index": row.event_index,
            "kind": row.transfer_kind,
            "target_expression": row.target_expression.to_value(),
        }
        for row in semantic_index.indirect_exits
    )
    records = tuple(
        _bind_hint(
            row,
            _optional_hint(
                context, text(row.get("id"), "exact indirect-exit ID")
            ),
        )
        for row in exits
    )
    return StructuralTargetUnitV3(
        record_id=semantic_index.record_id,
        source_unit_id=semantic_index.record_id,
        unit_sha256=semantic_index.unit_sha256,
        proposals=records,
    )


def _transform_structural_target_unit(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> ArtifactRecordV3:
    target_unit = _derive_structural_target_unit(context, source)
    return STRUCTURAL_TARGET_UNIT_CODEC_V3.write(
        target_unit.record_id, target_unit
    )


def check_structural_targets_completeness_v3(
    reader: ArtifactSetReaderV3, context: PhaseContextV3
) -> None:
    outputs = sorted_records(reader.iter_records())
    expected_count = context.manifest("semantic_index").record_count
    if len(outputs) != expected_count:
        fail(
            "incomplete_record_set",
            f"structural target unit count differs: expected={expected_count}, actual={len(outputs)}",
            "rerun the map_units phase over every exact-unit record",
        )
    for output in outputs:
        semantic_index = context.record("semantic_index", output.record_id)
        expected = _derive_structural_target_unit(context, semantic_index)
        submitted = STRUCTURAL_TARGET_UNIT_CODEC_V3.read(output).value
        if submitted != expected:
            fail(
                "structural_target_contradiction",
                f"structural target unit {output.record_id!r} is stale",
                "rerun structural targeting from exact records and current hints",
            )
        expected_dependencies = (
            RecordDependencyV3("semantic_index", output.record_id),
            *(
                RecordDependencyV3("target_hints", proposal.record_id)
                for proposal in expected.proposals
                if proposal.proposal_sha256 is not None
            ),
        )
        expected_dependencies = tuple(sorted(expected_dependencies))
        if output.dependencies != expected_dependencies:
            fail(
                "incomplete_record_dependencies",
                f"structural target unit {output.record_id!r} lacks its local proposal closure",
                "let the map_units phase attach only same-unit exact and hint records",
            )


def flatten_structural_target_proposals_v3(
    records: Iterable[ArtifactRecordV3],
) -> tuple[StructuralTargetProposalV3, ...]:
    """Flatten canonical per-unit target records for downstream consumers."""

    proposals = tuple(
        proposal
        for record in sorted_records(records)
        for proposal in STRUCTURAL_TARGET_UNIT_CODEC_V3.read(record).value.proposals
    )
    if len({row.record_id for row in proposals}) != len(proposals):
        fail(
            "duplicate_structural_target_id",
            "structural-target unit records repeat an exact exit ID",
            "repair the exact unit partition before consuming target proposals",
        )
    return tuple(sorted(proposals, key=lambda row: row.record_id))


STRUCTURAL_TARGETS_PHASE_V3 = map_units(
    name="structural-target-proposals-v3",
    version="2",
    source_input="semantic_index",
    input_artifact_kinds={
        "semantic_index": SEMANTIC_INDEX_ARTIFACT_KIND_V3,
        "target_hints": "target-hints-v3",
    },
    output_artifact_kind=STRUCTURAL_TARGETS_ARTIFACT_KIND_V3,
    transform=_transform_structural_target_unit,
    completeness=check_structural_targets_completeness_v3,
)


__all__ = [
    "STRUCTURAL_TARGET_CODEC_V3",
    "STRUCTURAL_TARGET_RECORD_V3_SCHEMA",
    "STRUCTURAL_TARGET_UNIT_CODEC_V3",
    "STRUCTURAL_TARGET_UNIT_RECORD_V3_SCHEMA",
    "STRUCTURAL_TARGETS_ARTIFACT_KIND_V3",
    "STRUCTURAL_TARGETS_PHASE_V3",
    "StructuralTargetProposalV3",
    "StructuralTargetUnitV3",
    "check_structural_targets_completeness_v3",
    "flatten_structural_target_proposals_v3",
]
