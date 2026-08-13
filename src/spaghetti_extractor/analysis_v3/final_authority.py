"""Final v3-only candidate authorization over checked authority families."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ..artifact_set_v3 import (
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    RecordDependencyV3,
    canonical_sha256_v3,
)
from ..phase_framework_v3 import PhaseContextV3, RecordCodecV3, reduce
from ._schema import (
    digest,
    fail,
    mapping,
    require_record_ids,
    require_stable_id,
    sequence,
    sorted_records,
    stable_id,
    strict_object,
    text,
)
from .authority_common import (
    PrimaryBlockerV3,
    aggregate_blockers_v3,
    blocker_payload_v3,
    canonical_dependencies_v3,
    decode_dependencies_v3,
    encode_dependencies_v3,
    manifest_blocker_v3,
    validate_authority_decision_v3,
)
from .callbacks import (
    CALLBACK_AUTHORITY_ARTIFACT_KIND_V3,
    CALLBACK_AUTHORITY_CODEC_V3,
)
from .exceptional_transitions import (
    EXCEPTIONAL_TRANSITION_CODEC_V3,
    EXCEPTIONAL_TRANSITIONS_ARTIFACT_KIND_V3,
)
from .external_sites import (
    CANONICAL_EXTERNAL_SITE_CODEC_V3,
    CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
)
from .fallback_coverage import (
    FALLBACK_COVERAGE_ARTIFACT_KIND_V3,
    FALLBACK_COVERAGE_CODEC_V3,
    FallbackCoverageRecordV3,
)
from .inductive import (
    INDUCTIVE_AUTHORITY_ARTIFACT_KIND_V3,
    INDUCTIVE_AUTHORITY_CODEC_V3,
)
from .isa_qualification import (
    ISA_QUALIFICATION_ARTIFACT_KIND_V3,
    ISA_QUALIFICATION_CODEC_V3,
    ISAQualificationRecordV3,
)
from .root_closure import (
    LAUNCH_ROOT_CLOSURE_ARTIFACT_KIND_V3,
    LAUNCH_ROOT_CLOSURE_CODEC_V3,
)
from .semantic_index import (
    SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    SEMANTIC_INDEX_CODEC_V3,
    semantic_universe_sha256_v3,
)


FINAL_AUTHORITY_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-final-candidate-authority-record-v3"
)
FINAL_AUTHORITY_ARTIFACT_KIND_V3 = "final-authority-v3"
FINAL_AUTHORITY_SCOPE_V3 = "stage_b_candidate_generation"

_UNIT_FAMILIES = (
    "callbacks",
    "exceptional_transitions",
    "external_sites",
    "fallback_coverage",
    "isa_qualification",
)
_REQUIRED_FAMILIES = (
    "callbacks",
    "exceptional_transitions",
    "external_sites",
    "fallback_coverage",
    "inductive_authority",
    "isa_qualification",
    "root_closure",
    "semantic_index",
)


@dataclass(frozen=True, order=True)
class AuthorityFamilyBindingV3:
    input_name: str
    artifact_kind: str
    artifact_id: str
    manifest_sha256: str
    record_count: int
    record_inventory_sha256: str

    def __post_init__(self) -> None:
        text(self.input_name, "final authority family input")
        text(self.artifact_kind, "final authority family artifact kind")
        text(self.artifact_id, "final authority family artifact ID")
        digest(self.manifest_sha256, "final authority family manifest SHA-256")
        if (
            not isinstance(self.record_count, int)
            or isinstance(self.record_count, bool)
            or self.record_count < 0
        ):
            fail(
                "record_schema_mismatch",
                "final authority family record count is invalid",
                "emit the exact nonnegative checked record count",
            )
        digest(
            self.record_inventory_sha256,
            "final authority family record-inventory SHA-256",
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "input": self.input_name,
            "artifact_kind": self.artifact_kind,
            "artifact_id": self.artifact_id,
            "manifest_sha256": self.manifest_sha256,
            "record_count": self.record_count,
            "record_inventory_sha256": self.record_inventory_sha256,
        }

    @classmethod
    def parse(cls, value: Any) -> "AuthorityFamilyBindingV3":
        row = strict_object(
            value,
            {
                "input",
                "artifact_kind",
                "artifact_id",
                "manifest_sha256",
                "record_count",
                "record_inventory_sha256",
            },
            "final authority family binding",
        )
        return cls(
            input_name=text(row["input"], "final authority family input"),
            artifact_kind=text(
                row["artifact_kind"], "final authority family artifact kind"
            ),
            artifact_id=text(
                row["artifact_id"], "final authority family artifact ID"
            ),
            manifest_sha256=digest(
                row["manifest_sha256"],
                "final authority family manifest SHA-256",
            ),
            record_count=row["record_count"],
            record_inventory_sha256=digest(
                row["record_inventory_sha256"],
                "final authority family record-inventory SHA-256",
            ),
        )


@dataclass(frozen=True)
class FinalAuthorityRecordV3:
    record_id: str
    scope: str
    status: str
    authorizing: bool
    pe_sha256: str | None
    exact_universe_sha256: str | None
    exact_unit_count: int
    exact_unit_inventory_sha256: str
    families: tuple[AuthorityFamilyBindingV3, ...]
    primary_blocker: PrimaryBlockerV3 | None
    dependencies: tuple[RecordDependencyV3, ...]

    def __post_init__(self) -> None:
        if self.scope != FINAL_AUTHORITY_SCOPE_V3:
            fail(
                "record_schema_mismatch",
                f"final authority scope is {self.scope!r}",
                f"use the exact {FINAL_AUTHORITY_SCOPE_V3!r} scope",
            )
        if (
            not isinstance(self.exact_unit_count, int)
            or isinstance(self.exact_unit_count, bool)
            or self.exact_unit_count < 0
        ):
            fail(
                "record_schema_mismatch",
                "final authority exact-unit count is invalid",
                "emit the exact nonnegative checked unit count",
            )
        digest(
            self.exact_unit_inventory_sha256,
            "final authority exact-unit inventory SHA-256",
        )
        if self.families != tuple(sorted(set(self.families))):
            fail(
                "noncanonical_record_order",
                "final authority family bindings are duplicated or unsorted",
                "sort family bindings by exact input name",
            )
        if tuple(row.input_name for row in self.families) != _REQUIRED_FAMILIES:
            fail(
                "incomplete_authority_families",
                "final authority does not bind every required v3 family",
                "bind exactly the registered final-authority inputs",
            )
        identity = {
            "scope": self.scope,
            "families": [row.to_payload() for row in self.families],
            "exact_unit_count": self.exact_unit_count,
            "exact_unit_inventory_sha256": self.exact_unit_inventory_sha256,
        }
        require_stable_id(
            self.record_id,
            "final-authority-v3",
            identity,
            "final candidate authority",
        )
        validate_authority_decision_v3(
            status=self.status,
            authorizing=self.authorizing,
            primary_blocker=self.primary_blocker,
            dependencies=self.dependencies,
            context="final candidate authority",
        )
        if self.status == "complete":
            if (
                self.pe_sha256 is None
                or self.exact_universe_sha256 is None
                or self.exact_unit_count == 0
            ):
                fail(
                    "fail_open_final_authority",
                    "complete final authority lacks an exact nonempty binary universe",
                    "bind the exact PE, exact-unit universe, and unit inventory",
                )
        if self.pe_sha256 is not None:
            digest(self.pe_sha256, "final authority PE SHA-256")
        if self.exact_universe_sha256 is not None:
            digest(
                self.exact_universe_sha256,
                "final authority exact-universe SHA-256",
            )


def _encode_final_authority(value: FinalAuthorityRecordV3) -> dict[str, Any]:
    return {
        "schema": FINAL_AUTHORITY_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "scope": value.scope,
        "status": value.status,
        "authorizing": value.authorizing,
        "binary": {
            "pe_sha256": value.pe_sha256,
            "exact_universe_sha256": value.exact_universe_sha256,
        },
        "exact_unit_count": value.exact_unit_count,
        "exact_unit_inventory_sha256": value.exact_unit_inventory_sha256,
        "families": [row.to_payload() for row in value.families],
        "primary_blocker": blocker_payload_v3(value.primary_blocker),
        "dependencies": encode_dependencies_v3(value.dependencies),
    }


def _decode_final_authority(value: Any) -> FinalAuthorityRecordV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "scope",
            "status",
            "authorizing",
            "binary",
            "exact_unit_count",
            "exact_unit_inventory_sha256",
            "families",
            "primary_blocker",
            "dependencies",
        },
        "final candidate authority",
    )
    if row["schema"] != FINAL_AUTHORITY_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not final candidate authority v3",
            "use FINAL_AUTHORITY_CODEC_V3 with final-authority-v3 artifacts",
        )
    binary = strict_object(
        row["binary"],
        {"pe_sha256", "exact_universe_sha256"},
        "final authority binary binding",
    )
    authorizing = row["authorizing"]
    if not isinstance(authorizing, bool):
        fail(
            "record_schema_mismatch",
            "final authority authorizing field is not Boolean",
            "emit true or false",
        )
    return FinalAuthorityRecordV3(
        record_id=text(row["id"], "final authority record ID"),
        scope=text(row["scope"], "final authority scope"),
        status=text(row["status"], "final authority status"),
        authorizing=authorizing,
        pe_sha256=(
            None
            if binary["pe_sha256"] is None
            else digest(binary["pe_sha256"], "final authority PE SHA-256")
        ),
        exact_universe_sha256=(
            None
            if binary["exact_universe_sha256"] is None
            else digest(
                binary["exact_universe_sha256"],
                "final authority exact-universe SHA-256",
            )
        ),
        exact_unit_count=row["exact_unit_count"],
        exact_unit_inventory_sha256=digest(
            row["exact_unit_inventory_sha256"],
            "final authority exact-unit inventory SHA-256",
        ),
        families=tuple(
            AuthorityFamilyBindingV3.parse(item)
            for item in sequence(row["families"], "final authority families")
        ),
        primary_blocker=(
            None
            if row["primary_blocker"] is None
            else PrimaryBlockerV3.parse(row["primary_blocker"])
        ),
        dependencies=decode_dependencies_v3(row["dependencies"]),
    )


FINAL_AUTHORITY_CODEC_V3 = RecordCodecV3[FinalAuthorityRecordV3](
    decode=_decode_final_authority,
    encode=_encode_final_authority,
)


def _read_inputs(
    context: PhaseContextV3,
) -> dict[str, tuple[ArtifactRecordV3, ...]]:
    return {
        name: sorted_records(context.records(name))
        for name in _REQUIRED_FAMILIES
    }


def _family_bindings(
    context: PhaseContextV3,
    records: Mapping[str, Sequence[ArtifactRecordV3]],
) -> tuple[AuthorityFamilyBindingV3, ...]:
    return tuple(
        AuthorityFamilyBindingV3(
            input_name=name,
            artifact_kind=context.manifest(name).artifact_kind,
            artifact_id=context.manifest(name).artifact_id,
            manifest_sha256=context.manifest(name).manifest_sha256,
            record_count=len(records[name]),
            record_inventory_sha256=canonical_sha256_v3(
                [row.record_id for row in records[name]]
            ),
        )
        for name in _REQUIRED_FAMILIES
    )


def _record_status_blocker(
    *,
    input_name: str,
    record: ArtifactRecordV3,
    status: str,
    authorizing: bool,
    code: str,
) -> PrimaryBlockerV3 | None:
    if status == "complete" and authorizing:
        return None
    return PrimaryBlockerV3(
        "violated" if status == "violated" else "incomplete",
        code,
        input_name,
        record.record_id,
    )


def _check_unit_inventory(
    *,
    input_name: str,
    records: Sequence[ArtifactRecordV3],
    exact_ids: tuple[str, ...],
) -> tuple[list[PrimaryBlockerV3], list[RecordDependencyV3]]:
    actual = {row.record_id for row in records}
    expected = set(exact_ids)
    blockers: list[PrimaryBlockerV3] = []
    dependencies: list[RecordDependencyV3] = []
    for missing in sorted(expected - actual):
        dependency = RecordDependencyV3(input_name, missing)
        dependencies.append(dependency)
        blockers.append(
            PrimaryBlockerV3(
                "incomplete",
                "authority_family_record_missing",
                input_name,
                missing,
            )
        )
    for extra in sorted(actual - expected):
        blockers.append(
            PrimaryBlockerV3(
                "violated",
                "authority_family_record_unknown",
                input_name,
                extra,
            )
        )
    return blockers, dependencies


def _check_inductive_authority(
    records: Sequence[ArtifactRecordV3],
    semantic_by_id: Mapping[str, Any],
) -> list[PrimaryBlockerV3]:
    if not records:
        return [PrimaryBlockerV3("incomplete", "inductive_authority_missing")]
    blockers: list[PrimaryBlockerV3] = []
    covered: dict[str, str] = {}
    for source in records:
        row = INDUCTIVE_AUTHORITY_CODEC_V3.read(source).value
        if row.record_kind != "scc_authority":
            blockers.append(
                PrimaryBlockerV3(
                    "violated",
                    "legacy_inductive_authority_not_accepted",
                    "inductive_authority",
                    source.record_id,
                )
            )
            continue
        blocker = _record_status_blocker(
            input_name="inductive_authority",
            record=source,
            status=row.status,
            authorizing=row.authorizing,
            code="inductive_authority_not_complete",
        )
        if blocker is not None:
            blockers.append(blocker)
        unit_ids = tuple(
            sorted(
                dependency.record_id
                for dependency in source.dependencies
                if dependency.input_name == "semantic_index"
            )
        )
        if not unit_ids:
            blockers.append(
                PrimaryBlockerV3(
                    "violated",
                    "inductive_scc_semantic_inventory_empty",
                    "inductive_authority",
                    source.record_id,
                )
            )
            continue
        if set(unit_ids) - set(semantic_by_id):
            blockers.append(
                PrimaryBlockerV3(
                    "violated",
                    "inductive_scc_unknown_semantic_unit",
                    "inductive_authority",
                    source.record_id,
                )
            )
            continue
        for unit_id in unit_ids:
            previous = covered.setdefault(unit_id, source.record_id)
            if previous != source.record_id:
                blockers.append(
                    PrimaryBlockerV3(
                        "violated",
                        "inductive_scc_semantic_unit_overlap",
                        "inductive_authority",
                        unit_id,
                    )
                )
        body = mapping(row.body.to_value(), "inductive SCC authority")
        if row.status == "complete" and sequence(
            body.get("issues"), "inductive SCC authority issues"
        ):
            blockers.append(
                PrimaryBlockerV3(
                    "violated",
                    "inductive_authority_has_issues",
                    "inductive_authority",
                    source.record_id,
                )
            )
    for missing in sorted(set(semantic_by_id) - set(covered)):
        blockers.append(
            PrimaryBlockerV3(
                "incomplete",
                "inductive_scc_semantic_unit_missing",
                "inductive_authority",
                missing,
            )
        )
    return blockers


def _derive_final_authority(context: PhaseContextV3) -> FinalAuthorityRecordV3:
    records = _read_inputs(context)
    families = _family_bindings(context, records)
    # The final receipt binds each complete input artifact through ``families``
    # and the output manifest. Repeating tens of thousands of record IDs as
    # dependencies would add no authority and would violate bounded records.
    dependencies: list[RecordDependencyV3] = []
    blockers: list[PrimaryBlockerV3] = []
    for name in _REQUIRED_FAMILIES:
        blocker = manifest_blocker_v3(
            context, name, "authority_family_artifact_not_complete"
        )
        if blocker is not None:
            blockers.append(blocker)

    exact_values = tuple(
        SEMANTIC_INDEX_CODEC_V3.read(row).value for row in records["semantic_index"]
    )
    exact_ids = tuple(row.record_id for row in exact_values)
    exact_by_id = {row.record_id: row for row in exact_values}
    exact_binary: tuple[str, str] | None = None
    if not exact_values:
        blockers.append(PrimaryBlockerV3("incomplete", "semantic_index_missing"))
    else:
        pe_sha256s = {row.pe_sha256 for row in exact_values}
        if len(pe_sha256s) != 1:
            blockers.append(
                PrimaryBlockerV3("violated", "semantic_index_binary_mismatch")
            )
        else:
            exact_binary = (
                exact_values[0].pe_sha256,
                semantic_universe_sha256_v3(exact_values),
            )

    for input_name in _UNIT_FAMILIES:
        inventory_blockers, _missing_dependencies = _check_unit_inventory(
            input_name=input_name,
            records=records[input_name],
            exact_ids=exact_ids,
        )
        blockers.extend(inventory_blockers)

    isa_by_id: dict[str, ISAQualificationRecordV3] = {}
    fallback_by_id: dict[str, FallbackCoverageRecordV3] = {}
    for source in records["external_sites"]:
        value = CANONICAL_EXTERNAL_SITE_CODEC_V3.read(source).value
        exact = exact_by_id.get(source.record_id)
        if exact is None or value.unit_sha256 != exact.unit_sha256:
            blockers.append(
                PrimaryBlockerV3(
                    "violated",
                    "external_site_unit_binding_mismatch",
                    "external_sites",
                    source.record_id,
                )
            )
        blocker = _record_status_blocker(
            input_name="external_sites",
            record=source,
            status=value.status,
            authorizing=value.authorizing,
            code="external_site_authority_not_complete",
        )
        if blocker is not None:
            blockers.append(blocker)
        if value.status == "complete" and any(
            site.status != "complete"
            or not site.authorizing
            or site.contract is None
            for site in value.sites
        ):
            blockers.append(
                PrimaryBlockerV3(
                    "violated",
                    "external_site_contract_not_authoritative",
                    "external_sites",
                    source.record_id,
                )
            )

    for source in records["callbacks"]:
        value = CALLBACK_AUTHORITY_CODEC_V3.read(source).value
        exact = exact_by_id.get(source.record_id)
        if exact is None or value.unit_sha256 != exact.unit_sha256:
            blockers.append(
                PrimaryBlockerV3(
                    "violated",
                    "callback_unit_binding_mismatch",
                    "callbacks",
                    source.record_id,
                )
            )
        blocker = _record_status_blocker(
            input_name="callbacks",
            record=source,
            status=value.status,
            authorizing=value.authorizing,
            code="callback_authority_not_complete",
        )
        if blocker is not None:
            blockers.append(blocker)
        if value.status == "complete" and any(
            callback.status != "complete"
            or not callback.authorizing
            or callback.entry_state is None
            for callback in value.callbacks
        ):
            blockers.append(
                PrimaryBlockerV3(
                    "violated",
                    "callback_entry_state_not_authoritative",
                    "callbacks",
                    source.record_id,
                )
            )

    for source in records["exceptional_transitions"]:
        value = EXCEPTIONAL_TRANSITION_CODEC_V3.read(source).value
        exact = exact_by_id.get(source.record_id)
        if exact is None or value.unit_sha256 != exact.unit_sha256:
            blockers.append(
                PrimaryBlockerV3(
                    "violated",
                    "exception_unit_binding_mismatch",
                    "exceptional_transitions",
                    source.record_id,
                )
            )
        blocker = _record_status_blocker(
            input_name="exceptional_transitions",
            record=source,
            status=value.status,
            authorizing=value.authorizing,
            code="exception_authority_not_complete",
        )
        if blocker is not None:
            blockers.append(blocker)
        if value.status == "complete" and any(
            transition.status != "complete"
            or not transition.authorizing
            or transition.guard is None
            for transition in value.transitions
        ):
            blockers.append(
                PrimaryBlockerV3(
                    "violated",
                    "exception_transition_not_authoritative",
                    "exceptional_transitions",
                    source.record_id,
                )
            )

    for source in records["isa_qualification"]:
        value = ISA_QUALIFICATION_CODEC_V3.read(source).value
        isa_by_id[source.record_id] = value
        exact = exact_by_id.get(source.record_id)
        if exact is None or (
            value.unit_sha256 != exact.unit_sha256
            or value.pe_sha256 != exact.pe_sha256
            or value.unit_ir_sha256 != exact.unit_ir_sha256
        ):
            blockers.append(
                PrimaryBlockerV3(
                    "violated",
                    "isa_unit_binding_mismatch",
                    "isa_qualification",
                    source.record_id,
                )
            )
        blocker = _record_status_blocker(
            input_name="isa_qualification",
            record=source,
            status=value.status,
            authorizing=value.authorizing,
            code="isa_authority_not_complete",
        )
        if blocker is not None:
            blockers.append(blocker)

    for source in records["fallback_coverage"]:
        value = FALLBACK_COVERAGE_CODEC_V3.read(source).value
        fallback_by_id[source.record_id] = value
        exact = exact_by_id.get(source.record_id)
        if exact is None or (
            value.unit_sha256 != exact.unit_sha256
            or value.pe_sha256 != exact.pe_sha256
            or value.unit_ir_sha256 != exact.unit_ir_sha256
        ):
            blockers.append(
                PrimaryBlockerV3(
                    "violated",
                    "fallback_unit_binding_mismatch",
                    "fallback_coverage",
                    source.record_id,
                )
            )
        blocker = _record_status_blocker(
            input_name="fallback_coverage",
            record=source,
            status=value.status,
            authorizing=value.authorizing,
            code="fallback_authority_not_complete",
        )
        if blocker is not None:
            blockers.append(blocker)

    for unit_id in sorted(set(isa_by_id) & set(fallback_by_id)):
        isa = isa_by_id[unit_id]
        fallback = fallback_by_id[unit_id]
        if (
            isa.status != "complete"
            or not isa.authorizing
            or fallback.status != "complete"
            or not fallback.authorizing
        ):
            continue
        selected_form_ids = tuple(sorted({row.form_id for row in isa.selections}))
        capability_ids = {row.fallback_capability_id for row in isa.selections}
        if (
            fallback.selected_form_ids != selected_form_ids
            or capability_ids not in ({fallback.capability_id}, set())
        ):
            blockers.append(
                PrimaryBlockerV3(
                    "violated",
                    "isa_fallback_binding_mismatch",
                    "fallback_coverage",
                    unit_id,
                )
            )

    root_records = records["root_closure"]
    checked_closure = None
    if not root_records:
        blockers.append(PrimaryBlockerV3("incomplete", "root_closure_missing"))
    elif len(root_records) != 1:
        blockers.append(
            PrimaryBlockerV3("violated", "root_closure_ambiguous")
        )
    else:
        source = root_records[0]
        closure = LAUNCH_ROOT_CLOSURE_CODEC_V3.read(source).value
        blocker = _record_status_blocker(
            input_name="root_closure",
            record=source,
            status=closure.status,
            authorizing=closure.authorizing,
            code="root_closure_not_complete",
        )
        if blocker is not None:
            blockers.append(blocker)
        # Frontiers are the closure's explicit incomplete evidence. They are
        # not an inventory contradiction. The closure codec and checker bind
        # them to exact decoded exits; this final join only rejects reachable
        # units outside the exact semantic universe.
        inventory_valid = set(closure.reachable_unit_ids) <= set(exact_ids)
        if not inventory_valid:
            blockers.append(
                PrimaryBlockerV3(
                    "violated",
                    "root_closure_inventory_mismatch",
                    "root_closure",
                    source.record_id,
                )
            )
        elif blocker is None:
            checked_closure = closure

    if checked_closure is not None:
        for unit_id in sorted(set(exact_by_id) & set(isa_by_id)):
            exact = exact_by_id[unit_id]
            isa = isa_by_id[unit_id]
            if isa.status != "complete" or not isa.authorizing:
                continue
            expected_selections = tuple(
                (
                    instruction.index,
                    instruction.instruction_sha256,
                    instruction.rva_start,
                    instruction.rva_end,
                )
                for instruction in exact.instructions
            )
            observed_selections = tuple(
                (
                    selection.instruction_index,
                    selection.instruction_sha256,
                    selection.rva_start,
                    selection.rva_end,
                )
                for selection in isa.selections
            )
            if observed_selections != expected_selections:
                blockers.append(
                    PrimaryBlockerV3(
                        "violated",
                        "isa_exact_form_inventory_mismatch",
                        "isa_qualification",
                        unit_id,
                    )
                )

    blockers.extend(
        _check_inductive_authority(
            records["inductive_authority"],
            exact_by_id,
        )
    )
    primary = aggregate_blockers_v3(blockers)
    if primary is not None and primary.dependency is not None:
        dependencies.append(primary.dependency)
    status = "complete" if primary is None else primary.status
    identity = {
        "scope": FINAL_AUTHORITY_SCOPE_V3,
        "families": [row.to_payload() for row in families],
        "exact_unit_count": len(exact_ids),
        "exact_unit_inventory_sha256": canonical_sha256_v3(list(exact_ids)),
    }
    return FinalAuthorityRecordV3(
        record_id=stable_id("final-authority-v3", identity),
        scope=FINAL_AUTHORITY_SCOPE_V3,
        status=status,
        authorizing=status == "complete",
        pe_sha256=None if exact_binary is None else exact_binary[0],
        exact_universe_sha256=None if exact_binary is None else exact_binary[1],
        exact_unit_count=len(exact_ids),
        exact_unit_inventory_sha256=canonical_sha256_v3(list(exact_ids)),
        families=families,
        primary_blocker=primary,
        dependencies=canonical_dependencies_v3(dependencies),
    )


def _transform_final_authority(context: PhaseContextV3) -> ArtifactRecordV3:
    value = _derive_final_authority(context)
    return FINAL_AUTHORITY_CODEC_V3.write(
        value.record_id, value, dependencies=value.dependencies
    )


def check_final_authority_completeness_v3(
    reader: ArtifactSetReaderV3, context: PhaseContextV3
) -> None:
    expected = _derive_final_authority(context)
    outputs = sorted_records(reader.iter_records())
    require_record_ids(outputs, (expected.record_id,), "final candidate authority")
    submitted = FINAL_AUTHORITY_CODEC_V3.read(outputs[0]).value
    if submitted != expected:
        fail(
            "final_authority_contradiction",
            "final candidate authority is stale",
            "rerun the final reduction from exact v3 authority families",
        )
    if outputs[0].dependencies != expected.dependencies:
        fail(
            "incomplete_record_dependencies",
            "final candidate authority has stale record dependencies",
            "let FINAL_AUTHORITY_PHASE_V3 attach the exact family closure",
        )


FINAL_AUTHORITY_PHASE_V3 = reduce(
    name="final-authority-v3",
    version="2",
    input_artifact_kinds={
        "callbacks": CALLBACK_AUTHORITY_ARTIFACT_KIND_V3,
        "exceptional_transitions": EXCEPTIONAL_TRANSITIONS_ARTIFACT_KIND_V3,
        "external_sites": CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
        "fallback_coverage": FALLBACK_COVERAGE_ARTIFACT_KIND_V3,
        "inductive_authority": INDUCTIVE_AUTHORITY_ARTIFACT_KIND_V3,
        "isa_qualification": ISA_QUALIFICATION_ARTIFACT_KIND_V3,
        "root_closure": LAUNCH_ROOT_CLOSURE_ARTIFACT_KIND_V3,
        "semantic_index": SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    },
    output_artifact_kind=FINAL_AUTHORITY_ARTIFACT_KIND_V3,
    transform=_transform_final_authority,
    completeness=check_final_authority_completeness_v3,
    dependency_scope="artifact",
)


__all__ = [
    "FINAL_AUTHORITY_ARTIFACT_KIND_V3",
    "FINAL_AUTHORITY_CODEC_V3",
    "FINAL_AUTHORITY_PHASE_V3",
    "FINAL_AUTHORITY_RECORD_V3_SCHEMA",
    "FINAL_AUTHORITY_SCOPE_V3",
    "AuthorityFamilyBindingV3",
    "FinalAuthorityRecordV3",
    "check_final_authority_completeness_v3",
]
