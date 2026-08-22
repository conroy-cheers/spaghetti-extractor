"""Checked callback authority derived from canonical external-site contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..artifacts.artifact_set import (
    ArtifactRecordV3,
    ArtifactV3Error,
    CanonicalValueV3,
    RecordDependencyV3,
    canonical_sha256_v3,
)
from ..artifacts.io import ArtifactSetReaderV3
from ..artifacts.phases import PhaseContextV3, RecordCodecV3, map_units
from ..artifacts.callback_protocols import callback_protocol_from_machine_contract
from ._schema import (
    digest,
    fail,
    mapping,
    require_record_ids,
    sequence,
    sorted_records,
    strict_object,
    text,
    uint,
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
from .external_site_records import (
    CANONICAL_EXTERNAL_SITE_CODEC_V3,
    CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
    CallbackRequirementV3,
    CanonicalExternalSiteRecordV3,
)
from .incoming_call_frames import (
    INCOMING_CALL_FRAME_CODEC_V3,
    INCOMING_CALL_FRAMES_ARTIFACT_KIND_V3,
)


CALLBACK_EVIDENCE_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-callback-evidence-record-v4"
)
CALLBACK_EVIDENCE_ARTIFACT_KIND_V4 = "callback-evidence-v4"
CALLBACK_EVIDENCE_ARTIFACT_KIND_V3 = CALLBACK_EVIDENCE_ARTIFACT_KIND_V4
CALLBACK_AUTHORITY_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-callback-authority-record-v4"
)
CALLBACK_AUTHORITY_ARTIFACT_KIND_V4 = "callback-authority-v4"
CALLBACK_AUTHORITY_ARTIFACT_KIND_V3 = CALLBACK_AUTHORITY_ARTIFACT_KIND_V4


def derive_callback_entry_state_v3(
    *,
    external_site_id: str,
    requirement: CallbackRequirementV3,
    machine_contract: CanonicalValueV3,
) -> tuple[CanonicalValueV3 | None, PrimaryBlockerV3 | None]:
    """Derive the canonical symbolic PE32 callback entry frame.

    Concrete callback arguments and the external return address are supplied by
    the environment at invocation time.  The checked entry state records their
    exact ABI locations without pretending those values are statically known.
    """

    machine = mapping(machine_contract.to_value(), "callback machine contract")
    protocol = callback_protocol_from_machine_contract(
        machine, context="callback machine contract"
    )
    raw_abi = (
        protocol.signature.to_payload()
        if protocol is not None
        else machine.get("callback_abi")
    )
    if not isinstance(raw_abi, dict):
        return None, PrimaryBlockerV3(
            "incomplete", "callback_entry_abi_missing"
        )
    if canonical_sha256_v3(raw_abi) != requirement.abi_sha256:
        return None, PrimaryBlockerV3(
            "violated", "callback_entry_abi_contradiction"
        )
    kind = raw_abi.get("kind")
    if protocol is None and kind != "generic_callback":
        return None, PrimaryBlockerV3(
            "incomplete", "callback_entry_abi_unsupported"
        )
    argument_words = raw_abi.get("argument_words")
    cleanup_bytes = raw_abi.get("stack_cleanup_bytes")
    nullable = (
        any(
            row.kind == "null"
            for row in (() if protocol.source is None else protocol.source.sentinels)
        )
        if protocol is not None
        else raw_abi.get("nullable")
    )
    if (
        not isinstance(argument_words, int)
        or isinstance(argument_words, bool)
        or argument_words < 0
        or not isinstance(cleanup_bytes, int)
        or isinstance(cleanup_bytes, bool)
        or cleanup_bytes < 0
        or cleanup_bytes % 4 != 0
        or not isinstance(nullable, bool)
    ):
        return None, PrimaryBlockerV3(
            "violated", "callback_entry_abi_malformed"
        )
    frame_id = f"callback-frame:{requirement.callback_id}"
    entry_esp = {
        "kind": "callback_frame_location",
        "frame_id": frame_id,
        "offset": 0,
    }
    return (
        CanonicalValueV3.of(
            {
                "model": "pe32-callback-entry-v1",
                "external_site_id": external_site_id,
                "callback_id": requirement.callback_id,
                "target_unit_id": requirement.target_unit_id,
                "target_rva": requirement.target_rva,
                "lifetime": requirement.lifetime,
                "abi": raw_abi,
                "registers": {"esp": entry_esp},
                "stack": {
                    "frame_id": frame_id,
                    "return_address": {
                        "offset": 0,
                        "value": {
                            "kind": "external_callback_continuation",
                            "callback_id": requirement.callback_id,
                        },
                    },
                    "arguments": [
                        {
                            "index": index,
                            "offset": 4 + index * 4,
                            "width": 4,
                            "value": {
                                "kind": "external_callback_argument",
                                "callback_id": requirement.callback_id,
                                "index": index,
                            },
                        }
                        for index in range(argument_words)
                    ],
                    "callee_cleanup_bytes": cleanup_bytes,
                },
            }
        ),
        None,
    )


@dataclass(frozen=True)
class CallbackEvidenceV3:
    record_id: str
    external_site_id: str
    target_unit_id: str
    target_unit_sha256: str
    target_rva: int
    abi_sha256: str
    lifetime: str
    status: str
    entry_state: CanonicalValueV3 | None
    primary_blocker: PrimaryBlockerV3 | None

    def __post_init__(self) -> None:
        text(self.record_id, "callback evidence ID")
        text(self.external_site_id, "callback evidence external-site ID")
        text(self.target_unit_id, "callback evidence target unit ID")
        digest(self.target_unit_sha256, "callback evidence target unit SHA-256")
        uint(self.target_rva, "callback evidence target RVA")
        digest(self.abi_sha256, "callback evidence ABI SHA-256")
        text(self.lifetime, "callback evidence lifetime")
        if self.status not in {"complete", "incomplete", "violated"}:
            fail(
                "record_schema_mismatch",
                f"callback evidence status is {self.status!r}",
                "use complete, incomplete, or violated",
            )
        if self.status == "complete":
            if self.entry_state is None or self.primary_blocker is not None:
                fail(
                    "fail_open_callback_evidence",
                    "complete callback evidence lacks entry state or has a blocker",
                    "bind exact entry state and clear the blocker",
                )
            if not mapping(
                self.entry_state.to_value(), "callback evidence entry state"
            ):
                fail(
                    "record_schema_mismatch",
                    "complete callback entry state is empty",
                    "bind at least one exact entry-state fact",
                )
        elif self.entry_state is not None or self.primary_blocker is None:
            fail(
                "fail_open_callback_evidence",
                "non-complete callback evidence retains entry authority or lacks a blocker",
                "clear entry state and provide the matching blocker",
            )
        if self.primary_blocker is not None and self.primary_blocker.status != self.status:
            fail(
                "fail_open_callback_evidence",
                "callback evidence blocker disagrees with its status",
                "use one matching fail-closed status",
            )


def _encode_callback_evidence(value: CallbackEvidenceV3) -> dict[str, Any]:
    return {
        "schema": CALLBACK_EVIDENCE_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "external_site_id": value.external_site_id,
        "target_unit_id": value.target_unit_id,
        "target_unit_sha256": value.target_unit_sha256,
        "target_rva": value.target_rva,
        "abi_sha256": value.abi_sha256,
        "lifetime": value.lifetime,
        "status": value.status,
        "entry_state": (
            None if value.entry_state is None else value.entry_state.to_value()
        ),
        "primary_blocker": blocker_payload_v3(value.primary_blocker),
    }


def _decode_callback_evidence(value: Any) -> CallbackEvidenceV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "external_site_id",
            "target_unit_id",
            "target_unit_sha256",
            "target_rva",
            "abi_sha256",
            "lifetime",
            "status",
            "entry_state",
            "primary_blocker",
        },
        "callback evidence",
    )
    if row["schema"] != CALLBACK_EVIDENCE_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not callback-evidence-record-v3",
            "use CALLBACK_EVIDENCE_CODEC_V4 with callback-evidence-v4",
        )
    return CallbackEvidenceV3(
        record_id=text(row["id"], "callback evidence ID"),
        external_site_id=text(
            row["external_site_id"], "callback evidence external-site ID"
        ),
        target_unit_id=text(
            row["target_unit_id"], "callback evidence target unit ID"
        ),
        target_unit_sha256=digest(
            row["target_unit_sha256"], "callback evidence target unit SHA-256"
        ),
        target_rva=uint(row["target_rva"], "callback evidence target RVA"),
        abi_sha256=digest(row["abi_sha256"], "callback evidence ABI SHA-256"),
        lifetime=text(row["lifetime"], "callback evidence lifetime"),
        status=text(row["status"], "callback evidence status"),
        entry_state=(
            None
            if row["entry_state"] is None
            else CanonicalValueV3.of(row["entry_state"])
        ),
        primary_blocker=(
            None
            if row["primary_blocker"] is None
            else PrimaryBlockerV3.parse(row["primary_blocker"])
        ),
    )


CALLBACK_EVIDENCE_CODEC_V3 = RecordCodecV3[CallbackEvidenceV3](
    decode=_decode_callback_evidence,
    encode=_encode_callback_evidence,
)


@dataclass(frozen=True)
class CallbackAuthorityV3:
    callback_id: str
    external_site_id: str
    target_unit_id: str
    target_unit_sha256: str
    target_rva: int
    abi_sha256: str
    lifetime: str
    status: str
    authorizing: bool
    entry_state: CanonicalValueV3 | None
    primary_blocker: PrimaryBlockerV3 | None
    protocol: CanonicalValueV3 | None = None

    def __post_init__(self) -> None:
        text(self.callback_id, "callback authority ID")
        text(self.external_site_id, "callback authority external-site ID")
        text(self.target_unit_id, "callback authority target unit ID")
        digest(self.target_unit_sha256, "callback authority target unit SHA-256")
        uint(self.target_rva, "callback authority target RVA")
        digest(self.abi_sha256, "callback authority ABI SHA-256")
        text(self.lifetime, "callback authority lifetime")
        validate_authority_decision_v3(
            status=self.status,
            authorizing=self.authorizing,
            primary_blocker=self.primary_blocker,
            dependencies=(
                ()
                if self.primary_blocker is None
                or self.primary_blocker.dependency is None
                else (self.primary_blocker.dependency,)
            ),
            context=f"callback authority {self.callback_id!r}",
        )
        if (self.status == "complete") != (self.entry_state is not None):
            fail(
                "fail_open_callback_authority",
                "callback status disagrees with entry-state authority",
                "retain entry state only for a complete callback",
            )
        if self.status == "complete" and self.protocol is None:
            fail(
                "fail_open_callback_authority",
                "complete callback authority has no canonical protocol",
                "bind the callback protocol from the canonical external site",
            )


@dataclass(frozen=True)
class CallbackAuthorityRecordV3:
    record_id: str
    unit_sha256: str
    status: str
    authorizing: bool
    callbacks: tuple[CallbackAuthorityV3, ...]
    primary_blocker: PrimaryBlockerV3 | None
    dependencies: tuple[RecordDependencyV3, ...]

    def __post_init__(self) -> None:
        text(self.record_id, "callback authority source-unit ID")
        digest(self.unit_sha256, "callback authority source-unit SHA-256")
        if self.callbacks != tuple(
            sorted(set(self.callbacks), key=lambda row: row.callback_id)
        ):
            fail(
                "noncanonical_record_order",
                "callback authority rows are duplicated or unsorted",
                "sort and deduplicate callbacks by stable ID",
            )
        validate_authority_decision_v3(
            status=self.status,
            authorizing=self.authorizing,
            primary_blocker=self.primary_blocker,
            dependencies=self.dependencies,
            context=f"callback authority inventory {self.record_id!r}",
        )


def _callback_payload(value: CallbackAuthorityV3) -> dict[str, Any]:
    return {
        "id": value.callback_id,
        "external_site_id": value.external_site_id,
        "target_unit_id": value.target_unit_id,
        "target_unit_sha256": value.target_unit_sha256,
        "target_rva": value.target_rva,
        "abi_sha256": value.abi_sha256,
        "lifetime": value.lifetime,
        "status": value.status,
        "authorizing": value.authorizing,
        "entry_state": (
            None if value.entry_state is None else value.entry_state.to_value()
        ),
        "protocol": (
            None if value.protocol is None else value.protocol.to_value()
        ),
        "primary_blocker": blocker_payload_v3(value.primary_blocker),
    }


def _parse_callback(value: Any) -> CallbackAuthorityV3:
    row = strict_object(
        value,
        {
            "id",
            "external_site_id",
            "target_unit_id",
            "target_unit_sha256",
            "target_rva",
            "abi_sha256",
            "lifetime",
            "status",
            "authorizing",
            "entry_state",
            "protocol",
            "primary_blocker",
        },
        "callback authority",
    )
    authorizing = row["authorizing"]
    if not isinstance(authorizing, bool):
        fail(
            "record_schema_mismatch",
            "callback authorizing field is not Boolean",
            "emit true or false",
        )
    return CallbackAuthorityV3(
        callback_id=text(row["id"], "callback authority ID"),
        external_site_id=text(
            row["external_site_id"], "callback authority external-site ID"
        ),
        target_unit_id=text(
            row["target_unit_id"], "callback authority target unit ID"
        ),
        target_unit_sha256=digest(
            row["target_unit_sha256"], "callback authority target unit SHA-256"
        ),
        target_rva=uint(row["target_rva"], "callback authority target RVA"),
        abi_sha256=digest(row["abi_sha256"], "callback authority ABI SHA-256"),
        lifetime=text(row["lifetime"], "callback authority lifetime"),
        status=text(row["status"], "callback authority status"),
        authorizing=authorizing,
        entry_state=(
            None
            if row["entry_state"] is None
            else CanonicalValueV3.of(row["entry_state"])
        ),
        primary_blocker=(
            None
            if row["primary_blocker"] is None
            else PrimaryBlockerV3.parse(row["primary_blocker"])
        ),
        protocol=(
            None
            if row["protocol"] is None
            else CanonicalValueV3.of(row["protocol"])
        ),
    )


def _encode_callback_record(value: CallbackAuthorityRecordV3) -> dict[str, Any]:
    return {
        "schema": CALLBACK_AUTHORITY_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "unit_sha256": value.unit_sha256,
        "status": value.status,
        "authorizing": value.authorizing,
        "callbacks": [_callback_payload(row) for row in value.callbacks],
        "primary_blocker": blocker_payload_v3(value.primary_blocker),
        "dependencies": encode_dependencies_v3(value.dependencies),
    }


def _decode_callback_record(value: Any) -> CallbackAuthorityRecordV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "unit_sha256",
            "status",
            "authorizing",
            "callbacks",
            "primary_blocker",
            "dependencies",
        },
        "callback authority record",
    )
    if row["schema"] != CALLBACK_AUTHORITY_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not callback-authority-record-v4",
            "use CALLBACK_AUTHORITY_CODEC_V4 with callback-authority-v4",
        )
    authorizing = row["authorizing"]
    if not isinstance(authorizing, bool):
        fail(
            "record_schema_mismatch",
            "callback inventory authorizing field is not Boolean",
            "emit true or false",
        )
    return CallbackAuthorityRecordV3(
        record_id=text(row["id"], "callback authority source-unit ID"),
        unit_sha256=digest(
            row["unit_sha256"], "callback authority source-unit SHA-256"
        ),
        status=text(row["status"], "callback authority inventory status"),
        authorizing=authorizing,
        callbacks=tuple(
            _parse_callback(item)
            for item in sequence(row["callbacks"], "callback authority rows")
        ),
        primary_blocker=(
            None
            if row["primary_blocker"] is None
            else PrimaryBlockerV3.parse(row["primary_blocker"])
        ),
        dependencies=decode_dependencies_v3(row["dependencies"]),
    )


CALLBACK_AUTHORITY_CODEC_V3 = RecordCodecV3[CallbackAuthorityRecordV3](
    decode=_decode_callback_record,
    encode=_encode_callback_record,
)


def _record_or_none(
    context: PhaseContextV3, input_name: str, record_id: str
) -> ArtifactRecordV3 | None:
    try:
        return context.record(input_name, record_id)
    except ArtifactV3Error as exc:
        if exc.code == "missing_record":
            return None
        raise


def _checked_callback(
    context: PhaseContextV3,
    *,
    external_site_id: str,
    requirement: CallbackRequirementV3,
    machine_contract: CanonicalValueV3,
) -> tuple[CallbackAuthorityV3, tuple[RecordDependencyV3, ...]]:
    evidence_dependency = RecordDependencyV3(
        "callback_evidence", requirement.callback_id
    )
    target_dependency = RecordDependencyV3(
        "incoming_call_frames", requirement.target_unit_id
    )
    dependencies = (evidence_dependency, target_dependency)
    target_source = _record_or_none(
        context, target_dependency.input_name, target_dependency.record_id
    )
    evidence_source = _record_or_none(
        context, evidence_dependency.input_name, evidence_dependency.record_id
    )
    target_sha256 = "0" * 64
    machine = mapping(machine_contract.to_value(), "callback machine contract")
    raw_protocol = machine.get("callback_protocol")
    protocol = (
        CanonicalValueV3.of(raw_protocol)
        if isinstance(raw_protocol, dict)
        else None
    )
    expected_entry_state, entry_blocker = derive_callback_entry_state_v3(
        external_site_id=external_site_id,
        requirement=requirement,
        machine_contract=machine_contract,
    )
    blocker: PrimaryBlockerV3 | None
    if target_source is None:
        blocker = PrimaryBlockerV3(
            "violated",
            "callback_target_unit_missing",
            target_dependency.input_name,
            target_dependency.record_id,
        )
    elif (
        manifest_blocker := manifest_blocker_v3(
            context,
            target_dependency.input_name,
            "incoming_call_frames_artifact_not_complete",
            target_dependency,
        )
    ) is not None:
        blocker = manifest_blocker
    else:
        target = INCOMING_CALL_FRAME_CODEC_V3.read(target_source).value
        target_sha256 = target.unit_sha256
        if target.rva_start != requirement.target_rva:
            blocker = PrimaryBlockerV3(
                "violated",
                "callback_target_rva_contradiction",
                target_dependency.input_name,
                target_dependency.record_id,
            )
        elif protocol is None:
            blocker = PrimaryBlockerV3(
                "incomplete", "callback_protocol_missing"
            )
        elif entry_blocker is not None:
            blocker = entry_blocker
        elif evidence_source is None:
            blocker = PrimaryBlockerV3(
                "incomplete",
                "callback_evidence_missing",
                evidence_dependency.input_name,
                evidence_dependency.record_id,
            )
        elif (
            manifest_blocker := manifest_blocker_v3(
                context,
                evidence_dependency.input_name,
                "callback_evidence_artifact_not_complete",
                evidence_dependency,
            )
        ) is not None:
            blocker = manifest_blocker
        else:
            evidence = CALLBACK_EVIDENCE_CODEC_V3.read(evidence_source).value
            binding_matches = (
                evidence.record_id == requirement.callback_id
                and evidence.external_site_id == external_site_id
                and evidence.target_unit_id == requirement.target_unit_id
                and evidence.target_unit_sha256 == target.unit_sha256
                and evidence.target_rva == requirement.target_rva
                and evidence.abi_sha256 == requirement.abi_sha256
                and evidence.lifetime == requirement.lifetime
            )
            if not binding_matches:
                blocker = PrimaryBlockerV3(
                    "violated",
                    "callback_evidence_binding_contradiction",
                    evidence_dependency.input_name,
                    evidence_dependency.record_id,
                )
            elif evidence.status != "complete":
                blocker = PrimaryBlockerV3(
                    "violated" if evidence.status == "violated" else "incomplete",
                    (
                        evidence.primary_blocker.code
                        if evidence.primary_blocker is not None
                        else "callback_evidence_incomplete"
                    ),
                    evidence_dependency.input_name,
                    evidence_dependency.record_id,
                )
            elif evidence.entry_state != expected_entry_state:
                blocker = PrimaryBlockerV3(
                    "violated",
                    "callback_entry_state_contradiction",
                    evidence_dependency.input_name,
                    evidence_dependency.record_id,
                )
            else:
                blocker = None
    complete = blocker is None
    entry_state = None
    if complete:
        assert evidence_source is not None
        evidence = CALLBACK_EVIDENCE_CODEC_V3.read(evidence_source).value
        entry_state = evidence.entry_state
    return (
        CallbackAuthorityV3(
            callback_id=requirement.callback_id,
            external_site_id=external_site_id,
            target_unit_id=requirement.target_unit_id,
            target_unit_sha256=target_sha256,
            target_rva=requirement.target_rva,
            abi_sha256=requirement.abi_sha256,
            lifetime=requirement.lifetime,
            status="complete" if complete else blocker.status,
            authorizing=complete,
            entry_state=entry_state,
            primary_blocker=blocker,
            protocol=protocol if complete else None,
        ),
        dependencies,
    )


def _derive_callback_record(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> CallbackAuthorityRecordV3:
    external = CANONICAL_EXTERNAL_SITE_CODEC_V3.read(source).value
    dependencies = [RecordDependencyV3("external_sites", source.record_id)]
    blockers: list[PrimaryBlockerV3] = []
    manifest_blocker = manifest_blocker_v3(
        context,
        "external_sites",
        "canonical_external_sites_artifact_not_complete",
        dependencies[0],
    )
    if manifest_blocker is not None:
        blockers.append(manifest_blocker)
    if external.status != "complete":
        blockers.append(
            PrimaryBlockerV3(
                "violated" if external.status == "violated" else "incomplete",
                "canonical_external_sites_not_complete",
                "external_sites",
                source.record_id,
            )
        )
    callbacks: list[CallbackAuthorityV3] = []
    for site in external.sites:
        if site.status != "complete" or site.contract is None:
            continue
        for requirement in site.contract.callbacks:
            callback, exact_dependencies = _checked_callback(
                context,
                external_site_id=site.site_id,
                requirement=requirement,
                machine_contract=site.contract.machine_contract,
            )
            callbacks.append(callback)
            dependencies.extend(exact_dependencies)
            if callback.primary_blocker is not None:
                blockers.append(callback.primary_blocker)
    primary = aggregate_blockers_v3(blockers)
    status = "complete" if primary is None else primary.status
    return CallbackAuthorityRecordV3(
        record_id=external.record_id,
        unit_sha256=external.unit_sha256,
        status=status,
        authorizing=status == "complete",
        callbacks=tuple(sorted(callbacks, key=lambda row: row.callback_id)),
        primary_blocker=primary,
        dependencies=canonical_dependencies_v3(dependencies),
    )


def _transform_callbacks(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> ArtifactRecordV3:
    value = _derive_callback_record(context, source)
    return CALLBACK_AUTHORITY_CODEC_V3.write(
        source.record_id, value, dependencies=value.dependencies
    )


def check_callback_authority_completeness_v3(
    reader: ArtifactSetReaderV3, context: PhaseContextV3
) -> None:
    external_records = sorted_records(context.records("external_sites"))
    outputs = sorted_records(reader.iter_records())
    require_record_ids(
        outputs,
        (row.record_id for row in external_records),
        "callback authority inventories",
    )
    expected_evidence_ids: set[str] = set()
    for source, output in zip(external_records, outputs, strict=True):
        expected = _derive_callback_record(context, source)
        submitted = CALLBACK_AUTHORITY_CODEC_V3.read(output).value
        if submitted != expected:
            fail(
                "callback_authority_contradiction",
                f"callback authority {output.record_id!r} is stale",
                "rerun callback authority from canonical external sites",
            )
        if output.dependencies != expected.dependencies:
            fail(
                "incomplete_record_dependencies",
                f"callback authority {output.record_id!r} has stale dependencies",
                "let CALLBACK_AUTHORITY_PHASE_V3 attach exact dependencies",
            )
        expected_evidence_ids.update(row.callback_id for row in expected.callbacks)
    evidence_records = sorted_records(context.records("callback_evidence"))
    unknown = sorted({row.record_id for row in evidence_records} - expected_evidence_ids)
    if unknown:
        fail(
            "unknown_callback_evidence",
            f"callback evidence names absent requirements {unknown!r}",
            "remove stale evidence or regenerate it from canonical external sites",
        )


CALLBACK_AUTHORITY_PHASE_V3 = map_units(
    name="callback-authority-v4",
    version="1",
    source_input="external_sites",
    input_artifact_kinds={
        "callback_evidence": CALLBACK_EVIDENCE_ARTIFACT_KIND_V3,
        "external_sites": CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
        "incoming_call_frames": INCOMING_CALL_FRAMES_ARTIFACT_KIND_V3,
    },
    output_artifact_kind=CALLBACK_AUTHORITY_ARTIFACT_KIND_V3,
    transform=_transform_callbacks,
    completeness=check_callback_authority_completeness_v3,
)
CALLBACK_AUTHORITY_PHASE_V4 = CALLBACK_AUTHORITY_PHASE_V3
CALLBACK_AUTHORITY_CODEC_V4 = CALLBACK_AUTHORITY_CODEC_V3
CallbackAuthorityV4 = CallbackAuthorityV3
CallbackAuthorityRecordV4 = CallbackAuthorityRecordV3


__all__ = [
    "CALLBACK_AUTHORITY_ARTIFACT_KIND_V3",
    "CALLBACK_AUTHORITY_ARTIFACT_KIND_V4",
    "CALLBACK_AUTHORITY_CODEC_V3",
    "CALLBACK_AUTHORITY_CODEC_V4",
    "CALLBACK_AUTHORITY_PHASE_V3",
    "CALLBACK_AUTHORITY_PHASE_V4",
    "CALLBACK_AUTHORITY_RECORD_V3_SCHEMA",
    "CALLBACK_EVIDENCE_ARTIFACT_KIND_V3",
    "CALLBACK_EVIDENCE_ARTIFACT_KIND_V4",
    "CALLBACK_EVIDENCE_CODEC_V3",
    "CALLBACK_EVIDENCE_RECORD_V3_SCHEMA",
    "CallbackAuthorityRecordV3",
    "CallbackAuthorityRecordV4",
    "CallbackAuthorityV3",
    "CallbackAuthorityV4",
    "CallbackEvidenceV3",
    "derive_callback_entry_state_v3",
    "check_callback_authority_completeness_v3",
]
