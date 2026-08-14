"""Generate fail-closed external-site evidence from native v3 authority inputs.

The generator is intentionally conservative.  It selects exactly one checked
profile for the canonical call identity, preserves that profile's complete
machine-effect contract, and requires exact event-side argument expressions.
Control-only disposition bindings are treated as extraction provenance rather
than confused with the semantic environment profile.  The canonical
external-site phase remains the authority checker and replays every binding in
the emitted record.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..authority._schema import AnalysisV3Error, mapping
from ..authority.authority_common import (
    PrimaryBlockerV3,
    aggregate_blockers_v3,
)
from ..authority.external_site_records import (
    EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
    EXTERNAL_PROFILE_CODEC_V3,
    EXTERNAL_SITE_EVIDENCE_ARTIFACT_KIND_V3,
    EXTERNAL_SITE_EVIDENCE_CODEC_V3,
    CallbackRequirementV3,
    ExternalContractV3,
    ExternalProfileV3,
    ExternalSiteEvidenceV3,
    external_site_id_v3,
)
from ..authority.external_abi import (
    ExternalArgumentRecoveryV3Error,
    recover_external_arguments_v3,
)
from ..authority.semantic_index import (
    SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    SEMANTIC_INDEX_CODEC_V3,
    IndirectExitOccurrenceV3,
    SemanticIndexRecordV3,
)
from ..authority.target_certificate_records import (
    INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3,
    INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
    IndirectTargetCertificateV3,
)
from ..authority.transition_records import (
    TRANSITION_SUMMARIES_ARTIFACT_KIND_V3,
    TRANSITION_SUMMARY_CODEC_V3,
    TransitionSummaryRecordV3,
)
from ..artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactDependencyV3,
    ArtifactInputReaderV3,
    ArtifactRecordV3,
    ArtifactSetManifestV3,
    ArtifactSetWriterV3,
    CanonicalValueV3,
    RecordDependencyV3,
    canonical_sha256_v3,
    open_artifact_reader_v3,
)
from ..control_disposition_profile import CONTROL_DISPOSITION_PROFILE_ID


_EFFECT_INVENTORIES = (
    "memory_footprints",
    "out_interface_relations",
    "out_pointer_relations",
    "result_register_relations",
)


class StandardExternalSiteEvidenceV3Error(ValueError):
    """The exact inputs cannot be reconciled into one evidence artifact."""


@dataclass(frozen=True)
class _ProfileIndex:
    exact: Mapping[tuple[str, str, bytes], ExternalProfileV3]
    by_identity: Mapping[bytes, tuple[ExternalProfileV3, ...]]


def _require_kind(reader: ArtifactInputReaderV3, expected: str, label: str) -> None:
    actual = reader.manifest.artifact_kind
    if actual != expected:
        raise StandardExternalSiteEvidenceV3Error(
            f"{label} has artifact kind {actual!r}, expected {expected!r}"
        )


def _binary_binding(reader: ArtifactInputReaderV3, label: str) -> ArtifactBindingV3:
    bindings = tuple(
        row
        for row in reader.manifest.bindings
        if row.name == "binary" and row.kind == "pe32"
    )
    if len(bindings) != 1:
        raise StandardExternalSiteEvidenceV3Error(
            f"{label} must contain exactly one binary/pe32 binding"
        )
    return bindings[0]


def _dependency(name: str, reader: ArtifactInputReaderV3) -> ArtifactDependencyV3:
    return ArtifactDependencyV3(
        name=name,
        artifact_kind=reader.manifest.artifact_kind,
        artifact_id=reader.manifest.artifact_id,
        manifest_sha256=reader.manifest_sha256,
    )


def _input_status_blocker(
    reader: ArtifactInputReaderV3, *, code: str
) -> PrimaryBlockerV3 | None:
    if reader.manifest.status == "complete":
        return None
    return PrimaryBlockerV3(
        "violated" if reader.manifest.status == "violated" else "incomplete",
        code,
    )


def _identity(target: Mapping[str, Any]) -> Mapping[str, Any] | None:
    imported = target.get("import")
    candidate = imported if isinstance(imported, Mapping) else target
    dll = candidate.get("dll")
    symbol = candidate.get("symbol")
    ordinal = candidate.get("ordinal")
    if isinstance(dll, str) and dll:
        has_symbol = isinstance(symbol, str) and bool(symbol)
        has_ordinal = isinstance(ordinal, int) and not isinstance(ordinal, bool)
        if has_symbol != has_ordinal:
            return {
                "kind": "import",
                "dll": dll.lower(),
                "symbol": symbol if has_symbol else None,
                "ordinal": ordinal if has_ordinal else None,
            }
    protocol = target.get("external_protocol")
    if isinstance(protocol, Mapping) and protocol:
        return {"kind": "protocol", "protocol": dict(protocol)}
    return None


def _profile_binding_candidates(
    event: Mapping[str, Any], target: Mapping[str, Any]
) -> tuple[Any, ...]:
    result: list[Any] = []
    abi = event.get("abi_contract")
    if isinstance(abi, Mapping) and "profile_binding" in abi:
        result.append(abi["profile_binding"])
    if "profile_binding" in target:
        result.append(target["profile_binding"])
    protocol = target.get("external_protocol")
    if isinstance(protocol, Mapping) and "profile_binding" in protocol:
        result.append(protocol["profile_binding"])
    return tuple(result)


def _parse_profile_binding(
    event: Mapping[str, Any], target: Mapping[str, Any]
) -> tuple[tuple[str, str] | None, PrimaryBlockerV3 | None]:
    candidates = _profile_binding_candidates(event, target)
    if not candidates:
        return None, None
    normalized: list[tuple[str, str]] = []
    for raw in candidates:
        if not isinstance(raw, Mapping):
            return None, PrimaryBlockerV3(
                "violated", "external_profile_binding_malformed"
            )
        profile_id = raw.get("profile_id")
        profile_sha256 = raw.get("profile_sha256")
        if not isinstance(profile_id, str) or not profile_id:
            return None, PrimaryBlockerV3(
                "incomplete", "external_profile_id_missing"
            )
        if (
            not isinstance(profile_sha256, str)
            or len(profile_sha256) != 64
            or any(character not in "0123456789abcdef" for character in profile_sha256)
        ):
            return None, PrimaryBlockerV3(
                "incomplete", "external_profile_sha256_missing"
            )
        normalized.append((profile_id, profile_sha256))
    if len(set(normalized)) != 1:
        return None, PrimaryBlockerV3(
            "violated", "external_profile_binding_contradiction"
        )
    return normalized[0], None


def _required_list(
    value: Mapping[str, Any], field: str, *, prefix: str
) -> tuple[list[Any] | None, PrimaryBlockerV3 | None]:
    if field not in value:
        return None, PrimaryBlockerV3("incomplete", f"{prefix}_{field}_missing")
    raw = value[field]
    if not isinstance(raw, list):
        return None, PrimaryBlockerV3("violated", f"{prefix}_{field}_malformed")
    return raw, None


def _required_text(
    value: Mapping[str, Any], field: str, *, prefix: str
) -> tuple[str | None, PrimaryBlockerV3 | None]:
    if field not in value:
        return None, PrimaryBlockerV3("incomplete", f"{prefix}_{field}_missing")
    raw = value[field]
    if not isinstance(raw, str) or not raw:
        return None, PrimaryBlockerV3("violated", f"{prefix}_{field}_malformed")
    return raw, None


def _abi_template(
    abi: Mapping[str, Any]
) -> tuple[str | None, PrimaryBlockerV3 | None]:
    values = [abi[field] for field in ("template", "abi_template") if field in abi]
    if not values:
        return None, PrimaryBlockerV3("incomplete", "external_abi_template_missing")
    if any(not isinstance(value, str) or not value for value in values):
        return None, PrimaryBlockerV3("violated", "external_abi_template_malformed")
    if len(set(values)) != 1:
        return None, PrimaryBlockerV3(
            "violated", "external_abi_template_contradiction"
        )
    return str(values[0]), None


def _callbacks(
    event: Mapping[str, Any], *, site_id: str, callback_effect: str
) -> tuple[tuple[CallbackRequirementV3, ...], PrimaryBlockerV3 | None]:
    raw, blocker = _required_list(
        event, "callback_requirements", prefix="external"
    )
    if blocker is not None:
        return (), blocker
    assert raw is not None
    callbacks: list[CallbackRequirementV3] = []
    try:
        for ordinal, value in enumerate(raw):
            if not isinstance(value, Mapping):
                return (), PrimaryBlockerV3(
                    "violated", "external_callback_requirement_malformed"
                )
            required = {
                "target_unit_id",
                "target_rva",
                "abi_sha256",
                "lifetime",
            }
            if set(value) != required:
                missing = required - set(value)
                return (), PrimaryBlockerV3(
                    "incomplete" if missing else "violated",
                    (
                        "external_callback_requirement_missing"
                        if missing
                        else "external_callback_requirement_malformed"
                    ),
                )
            callbacks.append(
                CallbackRequirementV3.create(
                    site_id=site_id,
                    ordinal=ordinal,
                    target_unit_id=value["target_unit_id"],
                    target_rva=value["target_rva"],
                    abi_sha256=value["abi_sha256"],
                    lifetime=value["lifetime"],
                )
            )
    except (AnalysisV3Error, TypeError, ValueError):
        return (), PrimaryBlockerV3(
            "violated", "external_callback_requirement_malformed"
        )
    result = tuple(sorted(set(callbacks)))
    if callback_effect == "none" and result:
        return (), PrimaryBlockerV3(
            "violated", "external_callback_effect_contradiction"
        )
    if callback_effect == "registers" and not result:
        return (), PrimaryBlockerV3(
            "incomplete", "external_callback_requirement_missing"
        )
    return result, None


def _load_profiles(
    reader: ArtifactInputReaderV3,
) -> _ProfileIndex:
    result: dict[tuple[str, str, bytes], ExternalProfileV3] = {}
    by_identity: dict[bytes, list[ExternalProfileV3]] = {}
    for source in reader.iter_records():
        profile = EXTERNAL_PROFILE_CODEC_V3.read(source).value
        if source.record_id != profile.record_id:
            raise StandardExternalSiteEvidenceV3Error(
                f"external profile envelope {source.record_id!r} disagrees with "
                f"record identity {profile.record_id!r}"
            )
        key = (profile.profile_id, profile.profile_sha256, profile.identity.data)
        if key in result:
            raise StandardExternalSiteEvidenceV3Error(
                "external profile artifact repeats an exact profile binding"
            )
        result[key] = profile
        by_identity.setdefault(profile.identity.data, []).append(profile)
    return _ProfileIndex(
        exact=result,
        by_identity={
            key: tuple(
                sorted(
                    values,
                    key=lambda row: (
                        row.profile_id,
                        row.profile_sha256,
                        row.record_id,
                    ),
                )
            )
            for key, values in by_identity.items()
        },
    )


def _select_profile(
    *,
    identity: CanonicalValueV3,
    binding: tuple[str, str] | None,
    profiles: _ProfileIndex,
) -> tuple[ExternalProfileV3 | None, PrimaryBlockerV3 | None]:
    candidates = profiles.by_identity.get(identity.data, ())
    if binding is not None and binding[0] != CONTROL_DISPOSITION_PROFILE_ID:
        exact = profiles.exact.get((binding[0], binding[1], identity.data))
        if exact is None:
            return None, PrimaryBlockerV3(
                "violated", "external_profile_binding_contradiction"
            )
        return exact, None
    if not candidates:
        return None, PrimaryBlockerV3("incomplete", "external_profile_missing")
    if len(candidates) != 1:
        return None, PrimaryBlockerV3(
            "incomplete", "external_profile_identity_ambiguous"
        )
    return candidates[0], None


def _contract(
    *,
    event: Mapping[str, Any],
    target: Mapping[str, Any],
    site_id: str,
    identity: CanonicalValueV3,
    transfer_kind: str,
    profiles: _ProfileIndex,
    profile_reader: ArtifactInputReaderV3,
) -> tuple[
    ExternalContractV3 | None,
    PrimaryBlockerV3 | None,
    RecordDependencyV3 | None,
]:
    blockers: list[PrimaryBlockerV3] = []
    abi_raw = event.get("abi_contract", {})
    if not isinstance(abi_raw, Mapping):
        return None, PrimaryBlockerV3("violated", "external_abi_contract_malformed"), None
    abi = abi_raw

    binding, blocker = _parse_profile_binding(event, target)
    if blocker is not None:
        blockers.append(blocker)

    profile, profile_blocker = _select_profile(
        identity=identity,
        binding=binding,
        profiles=profiles,
    )
    if profile_blocker is not None:
        blockers.append(profile_blocker)
    profile_dependency = (
        None
        if profile is None
        else RecordDependencyV3("external_profiles", profile.record_id)
    )
    if profile_reader.manifest.status != "complete":
        blockers.append(
            PrimaryBlockerV3(
                (
                    "violated"
                    if profile_reader.manifest.status == "violated"
                    else "incomplete"
                ),
                "external_profile_artifact_not_complete",
                "external_profiles",
                None if profile is None else profile.record_id,
            )
        )

    profile_machine: Mapping[str, Any] = {}
    if profile is not None:
        profile_machine = mapping(
            profile.machine_contract.to_value(), "external profile machine contract"
        )

    supplied_template: str | None = None
    if "template" in abi or "abi_template" in abi:
        supplied_template, blocker = _abi_template(abi)
        if blocker is not None:
            blockers.append(blocker)
    profile_template = profile_machine.get("abi_template")
    if not isinstance(profile_template, str) or not profile_template:
        blockers.append(
            PrimaryBlockerV3("incomplete", "external_profile_abi_template_missing")
        )
    elif supplied_template is not None and supplied_template != profile_template:
        blockers.append(
            PrimaryBlockerV3("violated", "external_profile_contract_contradiction")
        )

    words_raw = (
        profile.argument_words
        if "argument_words" not in abi and profile is not None
        else abi.get("argument_words")
    )
    if words_raw is None:
        words: int | None = None
        blockers.append(
            PrimaryBlockerV3("incomplete", "external_argument_words_missing")
        )
    elif (
        not isinstance(words_raw, int)
        or isinstance(words_raw, bool)
        or not 0 <= words_raw <= 256
    ):
        words = None
        blockers.append(
            PrimaryBlockerV3("violated", "external_argument_words_malformed")
        )
    else:
        words = words_raw

    arguments: tuple[dict[str, Any], ...] | None = None
    if words is not None and isinstance(profile_template, str):
        try:
            arguments = recover_external_arguments_v3(
                event,
                transfer_kind=transfer_kind,
                abi_template=profile_template,
                argument_words=words,
            )
        except ExternalArgumentRecoveryV3Error as exc:
            blockers.append(PrimaryBlockerV3(exc.status, exc.code))

    disposition_raw = (
        profile_machine.get("disposition")
        if "disposition" not in abi
        else abi.get("disposition")
    )
    if not isinstance(disposition_raw, str) or not disposition_raw:
        disposition = None
        blockers.append(
            PrimaryBlockerV3("incomplete", "external_disposition_missing")
        )
    else:
        disposition = disposition_raw
    if disposition == "terminates":
        disposition = "noreturn"
    elif disposition is not None and disposition not in {
        "returns",
        "tail_jump",
        "noreturn",
    }:
        blockers.append(
            PrimaryBlockerV3("violated", "external_disposition_unsupported")
        )

    memory_effect = (
        profile.memory_effect
        if "memory_effect" not in abi and profile is not None
        else abi.get("memory_effect")
    )
    world_effect = (
        profile.world_effect
        if "world_effect" not in abi and profile is not None
        else abi.get("world_effect")
    )
    callback_raw = (
        profile.callback_effect
        if "callback_effect" not in abi and profile is not None
        else abi.get("callback_effect")
    )
    if not isinstance(memory_effect, str) or not memory_effect:
        blockers.append(
            PrimaryBlockerV3("incomplete", "external_memory_effect_missing")
        )
        memory_effect = None
    if not isinstance(world_effect, str) or not world_effect:
        blockers.append(
            PrimaryBlockerV3("incomplete", "external_world_effect_missing")
        )
        world_effect = None
    if not isinstance(callback_raw, str) or not callback_raw:
        blockers.append(
            PrimaryBlockerV3("incomplete", "external_callback_effect_missing")
        )
        callback_raw = None
    callback_effect = (
        None
        if callback_raw is None
        else {
            "explicit": "registers",
            "registers": "registers",
            "none": "none",
        }.get(callback_raw)
    )
    if callback_raw is not None and callback_effect is None:
        blockers.append(
            PrimaryBlockerV3("violated", "external_callback_effect_unsupported")
        )
    if profile is not None:
        for field in _EFFECT_INVENTORIES:
            if field not in abi:
                continue
            inventory = abi[field]
            if not isinstance(inventory, list):
                blockers.append(
                    PrimaryBlockerV3(
                        "violated", f"external_{field}_malformed"
                    )
                )
            elif inventory != profile_machine.get(field, []):
                blockers.append(
                    PrimaryBlockerV3(
                        "violated", "external_profile_contract_contradiction"
                    )
                )

    callbacks: tuple[CallbackRequirementV3, ...] = ()
    if callback_effect is not None:
        if callback_effect == "none" and "callback_requirements" not in event:
            callbacks = ()
        else:
            callbacks, blocker = _callbacks(
                event, site_id=site_id, callback_effect=callback_effect
            )
            if blocker is not None:
                blockers.append(blocker)

    if profile is not None:
        contradictions = (
            transfer_kind not in profile.allowed_transfers
            or (
                disposition is not None
                and disposition not in profile.allowed_dispositions
            )
            or (words is not None and words != profile.argument_words)
            or (
                memory_effect is not None
                and memory_effect != profile.memory_effect
            )
            or (
                world_effect is not None
                and world_effect != profile.world_effect
            )
            or (
                callback_effect is not None
                and callback_effect != profile.callback_effect
            )
        )
        if contradictions:
            blockers.append(
                PrimaryBlockerV3(
                    "violated",
                    "external_profile_contract_contradiction",
                    "external_profiles",
                    profile.record_id,
                )
            )

    primary = aggregate_blockers_v3(blockers)
    if primary is not None:
        return None, primary, profile_dependency
    assert profile is not None
    assert words is not None
    assert arguments is not None
    assert disposition is not None
    assert memory_effect is not None
    assert world_effect is not None
    assert callback_effect is not None
    return (
        ExternalContractV3.create(
            identity=mapping(identity.to_value(), "external identity"),
            transfer_kind=transfer_kind,
            disposition=disposition,
            profile_id=profile.profile_id,
            profile_sha256=profile.profile_sha256,
            argument_words=words,
            arguments=arguments,
            memory_effect=memory_effect,
            world_effect=world_effect,
            callback_effect=callback_effect,
            machine_contract=mapping(
                profile.machine_contract.to_value(),
                "external profile machine contract",
            ),
            callbacks=callbacks,
        ),
        None,
        profile_dependency,
    )


def _site_record(
    *,
    exact: SemanticIndexRecordV3,
    event: Mapping[str, Any],
    event_index: int,
    alternative_index: int,
    target: Mapping[str, Any],
    transfer_kind: str,
    profiles: _ProfileIndex,
    profile_reader: ArtifactInputReaderV3,
    dependencies: Sequence[RecordDependencyV3],
    inherited_blockers: Sequence[PrimaryBlockerV3],
) -> ArtifactRecordV3:
    event_sha256 = canonical_sha256_v3(event)
    target_sha256 = canonical_sha256_v3(target)
    site_id = external_site_id_v3(
        exact.record_id, event_index, alternative_index, target
    )
    raw_identity = _identity(target)
    if raw_identity is None:
        identity = CanonicalValueV3.of(
            {"kind": "invalid", "target_sha256": target_sha256}
        )
        blockers = [
            *inherited_blockers,
            PrimaryBlockerV3("violated", "external_identity_missing"),
        ]
        contract = None
        profile_dependency = None
    else:
        identity = CanonicalValueV3.of(raw_identity)
        contract, contract_blocker, profile_dependency = _contract(
            event=event,
            target=target,
            site_id=site_id,
            identity=identity,
            transfer_kind=transfer_kind,
            profiles=profiles,
            profile_reader=profile_reader,
        )
        blockers = list(inherited_blockers)
        if contract_blocker is not None:
            blockers.append(contract_blocker)
    exact_dependencies = list(dependencies)
    if profile_dependency is not None:
        exact_dependencies.append(profile_dependency)
    primary = aggregate_blockers_v3(blockers)
    if primary is not None:
        contract = None
    evidence = ExternalSiteEvidenceV3(
        record_id=site_id,
        unit_id=exact.record_id,
        unit_sha256=exact.unit_sha256,
        event_index=event_index,
        event_sha256=event_sha256,
        alternative_index=alternative_index,
        target_sha256=target_sha256,
        identity=identity,
        status="complete" if primary is None else primary.status,
        contract=contract,
        primary_blocker=primary,
    )
    return EXTERNAL_SITE_EVIDENCE_CODEC_V3.write(
        evidence.record_id,
        evidence,
        dependencies=tuple(sorted(set(exact_dependencies))),
    )


def _external_events(
    summary: TransitionSummaryRecordV3,
) -> tuple[Mapping[str, Any], ...]:
    result: list[Mapping[str, Any]] = []
    for row in summary.exits:
        if row.source_kind != "external_event":
            continue
        value = row.exact_record.to_value()
        if not isinstance(value, Mapping):
            raise StandardExternalSiteEvidenceV3Error(
                f"transition summary {summary.record_id!r} has a malformed external event"
            )
        result.append(value)
    return tuple(result)


def _indirect_certificate(
    *,
    exact: SemanticIndexRecordV3,
    event_index: int,
    kind: str,
    target_reader: ArtifactInputReaderV3,
) -> IndirectTargetCertificateV3 | None:
    if target_reader.manifest.status == "violated":
        return None
    occurrence: IndirectExitOccurrenceV3 | None = next(
        (
            row
            for row in exact.indirect_exits
            if row.event_index == event_index and row.transfer_kind == kind
        ),
        None,
    )
    if occurrence is None:
        raise StandardExternalSiteEvidenceV3Error(
            f"unit {exact.record_id!r} has no exact indirect occurrence for event {event_index}"
        )
    source = target_reader.find_record(exact.record_id)
    if source is None:
        return None
    unit = INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3.read(source).value
    certificate = next(
        (row for row in unit.certificates if row.exit_id == occurrence.exit_id),
        None,
    )
    if certificate is None or certificate.status != "complete" or not certificate.authorizing:
        return None
    if (
        certificate.source_unit_id != exact.record_id
        or certificate.source_unit_sha256 != exact.unit_sha256
        or certificate.source_rva != exact.rva_start
        or certificate.source_event_index != event_index
        or certificate.transfer_kind != kind
        or certificate.target_expression != occurrence.target_expression
    ):
        raise StandardExternalSiteEvidenceV3Error(
            f"target certificate for {occurrence.exit_id!r} contradicts the semantic index"
        )
    return certificate


def generate_standard_external_site_evidence_v3(
    *,
    semantic_index_path: Path,
    transition_summaries_path: Path,
    target_certificates_path: Path,
    external_profiles_path: Path,
    output_directory: Path,
) -> ArtifactSetManifestV3:
    """Emit exact, fail-closed ``external-site-evidence-v3`` records."""

    semantic = open_artifact_reader_v3(semantic_index_path)
    transitions = open_artifact_reader_v3(transition_summaries_path)
    targets = open_artifact_reader_v3(target_certificates_path)
    profiles_reader = open_artifact_reader_v3(external_profiles_path)
    for reader, expected, label in (
        (semantic, SEMANTIC_INDEX_ARTIFACT_KIND_V3, "semantic index"),
        (transitions, TRANSITION_SUMMARIES_ARTIFACT_KIND_V3, "transition summaries"),
        (
            targets,
            INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
            "target certificates",
        ),
        (profiles_reader, EXTERNAL_PROFILE_ARTIFACT_KIND_V3, "external profiles"),
    ):
        _require_kind(reader, expected, label)
    bindings = tuple(
        _binary_binding(reader, label)
        for reader, label in (
            (semantic, "semantic index"),
            (transitions, "transition summaries"),
            (targets, "target certificates"),
            (profiles_reader, "external profiles"),
        )
    )
    if len(set(bindings)) != 1:
        raise StandardExternalSiteEvidenceV3Error(
            "external-site evidence inputs bind different PE32 binaries"
        )
    binary_binding = bindings[0]
    profiles = _load_profiles(profiles_reader)

    records: list[ArtifactRecordV3] = []
    seen_sites: set[str] = set()
    semantic_status = _input_status_blocker(
        semantic, code="semantic_index_artifact_not_complete"
    )
    transition_status = _input_status_blocker(
        transitions, code="transition_summary_artifact_not_complete"
    )
    for semantic_source in sorted(
        semantic.iter_records(), key=lambda row: row.record_id
    ):
        exact = SEMANTIC_INDEX_CODEC_V3.read(semantic_source).value
        summary_source = transitions.find_record(exact.record_id)
        if summary_source is None:
            raise StandardExternalSiteEvidenceV3Error(
                f"transition summaries omit semantic unit {exact.record_id!r}"
            )
        summary = TRANSITION_SUMMARY_CODEC_V3.read(summary_source).value
        unit_blockers = [
            blocker
            for blocker in (semantic_status, transition_status)
            if blocker is not None
        ]
        if (
            summary.record_id != exact.record_id
            or summary.unit_sha256 != exact.unit_sha256
            or summary.pe_sha256 != exact.pe_sha256
            or summary.unit_ir_sha256 != exact.unit_ir_sha256
        ):
            unit_blockers.append(
                PrimaryBlockerV3(
                    "violated", "transition_summary_unit_contradiction"
                )
            )
        elif summary.status != "complete":
            unit_blockers.append(
                PrimaryBlockerV3("incomplete", "transition_summary_incomplete")
            )
        if exact.unit_status != "qualified":
            unit_blockers.append(
                PrimaryBlockerV3("incomplete", "semantic_unit_not_qualified")
            )
        base_dependencies = (
            RecordDependencyV3("semantic_index", exact.record_id),
            RecordDependencyV3("transition_summaries", exact.record_id),
        )
        for event_index, event in enumerate(_external_events(summary)):
            kind = event.get("kind")
            alternatives: tuple[tuple[int, Mapping[str, Any]], ...]
            dependencies = base_dependencies
            if kind in {"external_call", "external_jump"}:
                alternatives = ((0, event),)
                transfer_kind = "jump" if kind == "external_jump" else "call"
            elif kind in {"indirect_call", "indirect_jump"}:
                certificate = _indirect_certificate(
                    exact=exact,
                    event_index=event_index,
                    kind=str(kind),
                    target_reader=targets,
                )
                if certificate is None:
                    continue
                alternatives = tuple(
                    (index, mapping(value.to_value(), "external target"))
                    for index, value in enumerate(certificate.external_targets)
                )
                dependencies = (
                    *base_dependencies,
                    RecordDependencyV3("target_certificates", exact.record_id),
                )
                transfer_kind = "jump" if kind == "indirect_jump" else "call"
            else:
                continue
            for alternative_index, target in alternatives:
                record = _site_record(
                    exact=exact,
                    event=event,
                    event_index=event_index,
                    alternative_index=alternative_index,
                    target=target,
                    transfer_kind=transfer_kind,
                    profiles=profiles,
                    profile_reader=profiles_reader,
                    dependencies=dependencies,
                    inherited_blockers=unit_blockers,
                )
                if record.record_id in seen_sites:
                    raise StandardExternalSiteEvidenceV3Error(
                        f"external-site identity {record.record_id!r} is duplicated"
                    )
                seen_sites.add(record.record_id)
                records.append(record)

    return ArtifactSetWriterV3(
        artifact_kind=EXTERNAL_SITE_EVIDENCE_ARTIFACT_KIND_V3,
        bindings=(binary_binding,),
        dependencies=(
            _dependency("external_profiles", profiles_reader),
            _dependency("semantic_index", semantic),
            _dependency("target_certificates", targets),
            _dependency("transition_summaries", transitions),
        ),
        # The producer completed even when individual evidence is incomplete.
        # Keeping the artifact complete preserves per-site diagnostics.
        status="complete",
    ).write(output_directory, sorted(records, key=lambda row: row.record_id))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate fail-closed standard external-site evidence for analysis v3"
    )
    parser.add_argument("--semantic-index", type=Path, required=True)
    parser.add_argument("--transition-summaries", type=Path, required=True)
    parser.add_argument("--target-certificates", type=Path, required=True)
    parser.add_argument("--external-profiles", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    generate_standard_external_site_evidence_v3(
        semantic_index_path=arguments.semantic_index,
        transition_summaries_path=arguments.transition_summaries,
        target_certificates_path=arguments.target_certificates,
        external_profiles_path=arguments.external_profiles,
        output_directory=arguments.out,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "StandardExternalSiteEvidenceV3Error",
    "generate_standard_external_site_evidence_v3",
    "main",
]
