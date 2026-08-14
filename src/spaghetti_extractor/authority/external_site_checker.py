"""Reconstruct and check canonical external-site authority."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..artifact_set_v3 import (
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    ArtifactV3Error,
    CanonicalValueV3,
    RecordDependencyV3,
    canonical_sha256_v3,
)
from ..phase_framework_v3 import PhaseContextV3, map_units
from ._schema import (
    digest,
    fail,
    mapping,
    require_record_ids,
    sorted_records,
    stable_id,
    strict_object,
    text,
    uint,
)
from .authority_common import (
    PrimaryBlockerV3,
    aggregate_blockers_v3,
    canonical_dependencies_v3,
    manifest_blocker_v3,
)
from .external_abi import (
    CONTROL_DISPOSITION_PROFILE_ID,
    ExternalArgumentRecoveryV3Error,
    recover_external_arguments_v3,
)
from .external_site_records import (
    CANONICAL_EXTERNAL_SITE_CODEC_V3,
    CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
    EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
    EXTERNAL_PROFILE_CODEC_V3,
    EXTERNAL_SITE_EVIDENCE_ARTIFACT_KIND_V3,
    EXTERNAL_SITE_EVIDENCE_CODEC_V3,
    CallbackRequirementV3,
    CanonicalExternalSiteRecordV3,
    CanonicalExternalSiteV3,
    ExternalContractV3,
    ExternalProfileV3,
    _site_identity_payload,
)
from .identities import indirect_exit_id_v3
from .semantic_index import SEMANTIC_INDEX_CODEC_V3, SemanticIndexRecordV3
from .target_certificate_records import (
    INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3,
    INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
)
from .transition_records import (
    TRANSITION_SUMMARY_CODEC_V3,
    TransitionSummaryRecordV3,
)


@dataclass(frozen=True)
class _ExpectedSite:
    site_id: str
    unit_id: str
    event_index: int
    alternative_index: int
    event_sha256: str
    target_sha256: str
    identity: CanonicalValueV3
    transfer_kind: str
    event: Mapping[str, Any]
    callbacks: tuple[CallbackRequirementV3, ...]
    forced_blocker: PrimaryBlockerV3 | None = None


def _identity(value: Mapping[str, Any]) -> Mapping[str, Any]:
    imported = value.get("import")
    candidate = imported if isinstance(imported, Mapping) else value
    dll = candidate.get("dll")
    symbol = candidate.get("symbol")
    ordinal = candidate.get("ordinal")
    if isinstance(dll, str) and bool(dll):
        has_symbol = isinstance(symbol, str) and bool(symbol)
        has_ordinal = isinstance(ordinal, int) and not isinstance(ordinal, bool)
        if has_symbol != has_ordinal:
            return {
                "kind": "import",
                "dll": dll.lower(),
                "symbol": symbol if has_symbol else None,
                "ordinal": ordinal if has_ordinal else None,
            }
    protocol = value.get("external_protocol")
    if isinstance(protocol, Mapping) and protocol:
        return {"kind": "protocol", "protocol": dict(protocol)}
    fail(
        "external_identity_missing",
        "external event or target has no canonical import/protocol identity",
        "bind exactly one import symbol/ordinal or an external_protocol object",
    )


def _expected_callbacks(
    event: Mapping[str, Any], *, site_id: str
) -> tuple[CallbackRequirementV3, ...]:
    raw = event.get("callback_requirements", [])
    if not isinstance(raw, list):
        fail(
            "record_schema_mismatch",
            "external event callback requirements are not an array",
            "emit exact callback requirement objects",
        )
    result: list[CallbackRequirementV3] = []
    for ordinal, item in enumerate(raw):
        row = strict_object(
            item,
            {"target_unit_id", "target_rva", "abi_sha256", "lifetime"},
            "machine callback requirement",
        )
        result.append(
            CallbackRequirementV3.create(
                site_id=site_id,
                ordinal=ordinal,
                target_unit_id=text(row["target_unit_id"], "callback target unit ID"),
                target_rva=uint(row["target_rva"], "callback target RVA"),
                abi_sha256=digest(row["abi_sha256"], "callback ABI SHA-256"),
                lifetime=text(row["lifetime"], "callback lifetime"),
            )
        )
    return tuple(result)


def _expected_site(
    *,
    exact: SemanticIndexRecordV3,
    event: Mapping[str, Any],
    event_index: int,
    alternative_index: int,
    target: Mapping[str, Any],
    transfer_kind: str,
) -> _ExpectedSite:
    event_sha256 = canonical_sha256_v3(event)
    target_sha256 = canonical_sha256_v3(target)
    site_id = stable_id(
        "external-site-v3",
        _site_identity_payload(
            exact.record_id, event_index, alternative_index, target_sha256
        ),
    )
    try:
        identity = CanonicalValueV3.of(_identity(target))
        callbacks = _expected_callbacks(event, site_id=site_id)
        blocker = None
    except ArtifactV3Error as exc:
        identity = CanonicalValueV3.of({"kind": "invalid", "target_sha256": target_sha256})
        callbacks = ()
        blocker = PrimaryBlockerV3("violated", exc.code)
    return _ExpectedSite(
        site_id,
        exact.record_id,
        event_index,
        alternative_index,
        event_sha256,
        target_sha256,
        identity,
        transfer_kind,
        event,
        callbacks,
        blocker,
    )


def _indirect_exit_id(
    exact: SemanticIndexRecordV3, event: Mapping[str, Any], index: int
) -> str:
    return indirect_exit_id_v3(
        {
            "source_unit_id": exact.record_id,
            "source_rva": exact.rva_start,
            "source_event_index": index,
            "kind": event.get("kind"),
            "target_expression": event.get("target"),
        }
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


def _expected_sites(
    context: PhaseContextV3,
    exact: SemanticIndexRecordV3,
    summary: TransitionSummaryRecordV3,
) -> tuple[
    tuple[_ExpectedSite, ...],
    tuple[PrimaryBlockerV3, ...],
    tuple[RecordDependencyV3, ...],
]:
    events = tuple(
        row.exact_record.to_value()
        for row in summary.exits
        if row.source_kind == "external_event"
    )
    expected: list[_ExpectedSite] = []
    blockers: list[PrimaryBlockerV3] = []
    dependencies: list[RecordDependencyV3] = []
    for event_index, raw in enumerate(events):
        if not isinstance(raw, Mapping):
            blockers.append(
                PrimaryBlockerV3("violated", "external_event_malformed")
            )
            continue
        event = raw
        kind = event.get("kind")
        if kind in {"external_call", "external_jump"}:
            expected.append(
                _expected_site(
                    exact=exact,
                    event=event,
                    event_index=event_index,
                    alternative_index=0,
                    target=event,
                    transfer_kind="jump" if kind == "external_jump" else "call",
                )
            )
        elif kind in {"indirect_call", "indirect_jump"}:
            exit_id = _indirect_exit_id(exact, event, event_index)
            dependency = RecordDependencyV3("target_certificates", exact.record_id)
            dependencies.append(dependency)
            if context.manifest(dependency.input_name).status == "violated":
                blockers.append(
                    PrimaryBlockerV3(
                        "violated",
                        "indirect_target_certificate_artifact_not_complete",
                        dependency.input_name,
                        dependency.record_id,
                    )
                )
                continue
            source = _record_or_none(
                context, "target_certificates", exact.record_id
            )
            if source is None:
                blockers.append(
                    PrimaryBlockerV3(
                        "incomplete",
                        "indirect_target_certificate_missing",
                        dependency.input_name,
                        dependency.record_id,
                    )
                )
                continue
            target_set = INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3.read(source).value
            target = next(
                (
                    certificate
                    for certificate in target_set.certificates
                    if certificate.exit_id == exit_id
                ),
                None,
            )
            if target is None:
                blockers.append(
                    PrimaryBlockerV3(
                        "incomplete",
                        "indirect_target_certificate_missing",
                        dependency.input_name,
                        dependency.record_id,
                    )
                )
                continue
            if (
                target.source_unit_id != exact.record_id
                or target.source_unit_sha256 != exact.unit_sha256
                or target.source_rva != exact.rva_start
                or target.source_event_index != event_index
                or target.transfer_kind != kind
                or target.target_expression
                != next(
                    row.target_expression
                    for row in exact.indirect_exits
                    if row.exit_id == exit_id
                )
            ):
                blockers.append(
                    PrimaryBlockerV3(
                        "violated",
                        "indirect_target_certificate_binding_contradiction",
                        dependency.input_name,
                        dependency.record_id,
                    )
                )
                continue
            if target.status != "complete" or not target.authorizing:
                blockers.append(
                    PrimaryBlockerV3(
                        "violated" if target.status == "violated" else "incomplete",
                        (
                            target.primary_blocker.code
                            if target.primary_blocker is not None
                            else "indirect_target_certificate_not_complete"
                        ),
                        dependency.input_name,
                        dependency.record_id,
                    )
                )
                continue
            for alternative_index, external in enumerate(target.external_targets):
                target_row = mapping(
                    external.to_value(), "recovered external target"
                )
                expected.append(
                    _expected_site(
                        exact=exact,
                        event=event,
                        event_index=event_index,
                        alternative_index=alternative_index,
                        target=target_row,
                        transfer_kind="jump" if kind == "indirect_jump" else "call",
                    )
                )
    return (
        tuple(sorted(expected, key=lambda row: row.site_id)),
        tuple(blockers),
        canonical_dependencies_v3(dependencies),
    )


def _contract_blocker(
    expected: _ExpectedSite, contract: ExternalContractV3
) -> PrimaryBlockerV3 | None:
    if contract.identity != expected.identity or contract.transfer_kind != expected.transfer_kind:
        return PrimaryBlockerV3("violated", "external_contract_identity_contradiction")
    abi = expected.event.get("abi_contract")
    if isinstance(abi, Mapping):
        words = abi.get("argument_words")
        if isinstance(words, int) and not isinstance(words, bool):
            if contract.argument_words != words:
                return PrimaryBlockerV3("violated", "external_contract_abi_contradiction")
        binding = abi.get("profile_binding")
        if (
            isinstance(binding, Mapping)
            and binding.get("profile_id") != CONTROL_DISPOSITION_PROFILE_ID
            and (
                contract.profile_id != binding.get("profile_id")
                or contract.profile_sha256 != binding.get("profile_sha256")
            )
        ):
            return PrimaryBlockerV3(
                "violated", "external_contract_profile_contradiction"
            )
        callback_effect = abi.get("callback_effect")
        if callback_effect is None and abi.get("world_effect") == "callbackRegistration":
            callback_effect = "registers"
        if callback_effect == "explicit":
            callback_effect = "registers"
        if callback_effect is not None and contract.callback_effect != callback_effect:
            return PrimaryBlockerV3(
                "violated", "external_contract_callback_contradiction"
            )
    machine_contract = mapping(
        contract.machine_contract.to_value(), "external machine contract"
    )
    abi_template = machine_contract.get("abi_template")
    if not isinstance(abi_template, str):
        return PrimaryBlockerV3(
            "violated", "external_contract_abi_contradiction"
        )
    try:
        expected_arguments = tuple(
            CanonicalValueV3.of(row)
            for row in recover_external_arguments_v3(
                expected.event,
                transfer_kind=expected.transfer_kind,
                abi_template=abi_template,
                argument_words=contract.argument_words,
            )
        )
    except ExternalArgumentRecoveryV3Error as exc:
        return PrimaryBlockerV3(exc.status, exc.code)
    if contract.arguments != expected_arguments:
        return PrimaryBlockerV3(
            "violated", "external_contract_argument_contradiction"
        )
    if contract.callbacks != expected.callbacks:
        return PrimaryBlockerV3(
            "violated", "external_contract_callback_requirement_contradiction"
        )
    return None


def _profile_dependency(contract: ExternalContractV3) -> RecordDependencyV3:
    return RecordDependencyV3(
        "external_profiles",
        stable_id(
            "external-profile-v3",
            {
                "profile_id": contract.profile_id,
                "profile_sha256": contract.profile_sha256,
                "identity": contract.identity.to_value(),
            },
        ),
    )


def _profile_blocker(
    contract: ExternalContractV3, profile: ExternalProfileV3
) -> PrimaryBlockerV3 | None:
    if (
        profile.profile_id != contract.profile_id
        or profile.profile_sha256 != contract.profile_sha256
        or profile.identity != contract.identity
        or contract.transfer_kind not in profile.allowed_transfers
        or contract.disposition not in profile.allowed_dispositions
        or profile.argument_words != contract.argument_words
        or profile.memory_effect != contract.memory_effect
        or profile.world_effect != contract.world_effect
        or profile.callback_effect != contract.callback_effect
        or profile.machine_contract != contract.machine_contract
    ):
        return PrimaryBlockerV3(
            "violated", "external_profile_contract_contradiction"
        )
    return None


def _checked_site(
    context: PhaseContextV3,
    exact: SemanticIndexRecordV3,
    expected: _ExpectedSite,
) -> tuple[CanonicalExternalSiteV3, tuple[RecordDependencyV3, ...]]:
    dependency = RecordDependencyV3("external_site_evidence", expected.site_id)
    if expected.forced_blocker is not None:
        blocker = PrimaryBlockerV3(
            expected.forced_blocker.status,
            expected.forced_blocker.code,
            dependency.input_name,
            dependency.record_id,
        )
        return (
            CanonicalExternalSiteV3(
                expected.site_id,
                expected.unit_id,
                expected.event_index,
                expected.alternative_index,
                expected.event_sha256,
                expected.target_sha256,
                expected.identity,
                blocker.status,
                False,
                None,
                blocker,
            ),
            (dependency,),
        )
    source = _record_or_none(context, dependency.input_name, dependency.record_id)
    if source is None:
        blocker = PrimaryBlockerV3(
            "incomplete",
            "external_site_evidence_missing",
            dependency.input_name,
            dependency.record_id,
        )
        return (
            CanonicalExternalSiteV3(
                expected.site_id,
                expected.unit_id,
                expected.event_index,
                expected.alternative_index,
                expected.event_sha256,
                expected.target_sha256,
                expected.identity,
                "incomplete",
                False,
                None,
                blocker,
            ),
            (dependency,),
        )
    manifest_blocker = manifest_blocker_v3(
        context,
        dependency.input_name,
        "external_site_evidence_artifact_not_complete",
        dependency,
    )
    if manifest_blocker is not None:
        return (
            CanonicalExternalSiteV3(
                expected.site_id,
                expected.unit_id,
                expected.event_index,
                expected.alternative_index,
                expected.event_sha256,
                expected.target_sha256,
                expected.identity,
                manifest_blocker.status,
                False,
                None,
                manifest_blocker,
            ),
            (dependency,),
        )
    evidence = EXTERNAL_SITE_EVIDENCE_CODEC_V3.read(source).value
    binding_matches = (
        evidence.record_id == expected.site_id
        and evidence.unit_id == expected.unit_id
        and evidence.unit_sha256 == exact.unit_sha256
        and evidence.event_index == expected.event_index
        and evidence.event_sha256 == expected.event_sha256
        and evidence.alternative_index == expected.alternative_index
        and evidence.target_sha256 == expected.target_sha256
        and evidence.identity == expected.identity
    )
    if not binding_matches:
        blocker = PrimaryBlockerV3(
            "violated",
            "external_site_evidence_binding_contradiction",
            dependency.input_name,
            dependency.record_id,
        )
    elif evidence.status != "complete":
        blocker = PrimaryBlockerV3(
            "violated" if evidence.status == "violated" else "incomplete",
            (
                evidence.primary_blocker.code
                if evidence.primary_blocker is not None
                else "external_site_evidence_incomplete"
            ),
            dependency.input_name,
            dependency.record_id,
        )
    else:
        assert evidence.contract is not None
        proposed = _contract_blocker(expected, evidence.contract)
        if proposed is not None:
            blocker = PrimaryBlockerV3(
                proposed.status,
                proposed.code,
                dependency.input_name,
                dependency.record_id,
            )
        else:
            profile_dependency = _profile_dependency(evidence.contract)
            profile_source = _record_or_none(
                context,
                profile_dependency.input_name,
                profile_dependency.record_id,
            )
            if profile_source is None:
                blocker = PrimaryBlockerV3(
                    "incomplete",
                    "external_profile_missing",
                    profile_dependency.input_name,
                    profile_dependency.record_id,
                )
            elif (
                manifest_blocker := manifest_blocker_v3(
                    context,
                    profile_dependency.input_name,
                    "external_profile_artifact_not_complete",
                    profile_dependency,
                )
            ) is not None:
                blocker = manifest_blocker
            else:
                profile = EXTERNAL_PROFILE_CODEC_V3.read(profile_source).value
                proposed = _profile_blocker(evidence.contract, profile)
                blocker = (
                    None
                    if proposed is None
                    else PrimaryBlockerV3(
                        proposed.status,
                        proposed.code,
                        profile_dependency.input_name,
                        profile_dependency.record_id,
                    )
                )
    complete = blocker is None
    exact_dependencies = [dependency]
    if evidence.contract is not None and binding_matches and evidence.status == "complete":
        exact_dependencies.append(_profile_dependency(evidence.contract))
    return (
        CanonicalExternalSiteV3(
            expected.site_id,
            expected.unit_id,
            expected.event_index,
            expected.alternative_index,
            expected.event_sha256,
            expected.target_sha256,
            expected.identity,
            "complete" if complete else blocker.status,
            complete,
            evidence.contract if complete else None,
            blocker,
        ),
        canonical_dependencies_v3(exact_dependencies),
    )


def _derive_external_record(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> CanonicalExternalSiteRecordV3:
    exact = SEMANTIC_INDEX_CODEC_V3.read(source).value
    summary_source = context.record("transition_summaries", exact.record_id)
    summary = TRANSITION_SUMMARY_CODEC_V3.read(summary_source).value
    dependencies = [
        RecordDependencyV3("semantic_index", exact.record_id),
        RecordDependencyV3("transition_summaries", summary.record_id),
    ]
    blockers: list[PrimaryBlockerV3] = []
    for input_name, dependency, code in (
        (
            "semantic_index",
            dependencies[0],
            "semantic_index_artifact_not_complete",
        ),
        (
            "transition_summaries",
            dependencies[1],
            "transition_summary_artifact_not_complete",
        ),
    ):
        manifest_blocker = manifest_blocker_v3(
            context, input_name, code, dependency
        )
        if manifest_blocker is not None:
            blockers.append(manifest_blocker)
    if summary.unit_sha256 != exact.unit_sha256:
        blockers.append(
            PrimaryBlockerV3(
                "violated",
                "transition_summary_unit_contradiction",
                "transition_summaries",
                summary.record_id,
            )
        )
    elif summary.status != "complete":
        blockers.append(
            PrimaryBlockerV3(
                "incomplete",
                "transition_summary_incomplete",
                "transition_summaries",
                summary.record_id,
            )
        )
    expected, structural_blockers, structural_dependencies = _expected_sites(
        context, exact, summary
    )
    blockers.extend(structural_blockers)
    dependencies.extend(structural_dependencies)
    sites: list[CanonicalExternalSiteV3] = []
    for row in expected:
        site, site_dependencies = _checked_site(context, exact, row)
        sites.append(site)
        dependencies.extend(site_dependencies)
        if site.primary_blocker is not None:
            blockers.append(site.primary_blocker)
    primary = aggregate_blockers_v3(blockers)
    status = "complete" if primary is None else primary.status
    return CanonicalExternalSiteRecordV3(
        record_id=exact.record_id,
        unit_sha256=exact.unit_sha256,
        status=status,
        authorizing=status == "complete",
        sites=tuple(sorted(sites, key=lambda row: row.site_id)),
        primary_blocker=primary,
        dependencies=canonical_dependencies_v3(dependencies),
    )


def _transform_external_sites(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> ArtifactRecordV3:
    value = _derive_external_record(context, source)
    return CANONICAL_EXTERNAL_SITE_CODEC_V3.write(
        source.record_id, value, dependencies=value.dependencies
    )


def check_canonical_external_sites_completeness_v3(
    reader: ArtifactSetReaderV3, context: PhaseContextV3
) -> None:
    exact_records = sorted_records(context.records("semantic_index"))
    outputs = sorted_records(reader.iter_records())
    require_record_ids(
        outputs,
        (row.record_id for row in exact_records),
        "canonical external-site inventories",
    )
    expected_evidence_ids: set[str] = set()
    for source, output in zip(exact_records, outputs, strict=True):
        expected = _derive_external_record(context, source)
        submitted = CANONICAL_EXTERNAL_SITE_CODEC_V3.read(output).value
        if submitted != expected:
            fail(
                "canonical_external_site_contradiction",
                f"external-site inventory {output.record_id!r} is stale",
                "rerun canonical external-site analysis from exact inputs",
            )
        if output.dependencies != expected.dependencies:
            fail(
                "incomplete_record_dependencies",
                f"external-site inventory {output.record_id!r} has stale dependencies",
                "let CANONICAL_EXTERNAL_SITES_PHASE_V3 attach exact dependencies",
            )
        expected_evidence_ids.update(site.site_id for site in expected.sites)
    evidence_records = sorted_records(context.records("external_site_evidence"))
    unknown = sorted({row.record_id for row in evidence_records} - expected_evidence_ids)
    if unknown:
        fail(
            "unknown_external_site_evidence",
            f"external-site evidence names absent exact sites {unknown!r}",
            "remove stale evidence or regenerate it from exact external events",
        )


CANONICAL_EXTERNAL_SITES_PHASE_V3 = map_units(
    name="canonical-external-sites-v3",
    version="3",
    source_input="semantic_index",
    input_artifact_kinds={
        "external_profiles": EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
        "external_site_evidence": EXTERNAL_SITE_EVIDENCE_ARTIFACT_KIND_V3,
        "semantic_index": "semantic-index-v3",
        "target_certificates": INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
        "transition_summaries": "transition-summaries-v3",
    },
    output_artifact_kind=CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
    transform=_transform_external_sites,
    completeness=check_canonical_external_sites_completeness_v3,
    unit_aligned_inputs=("target_certificates", "transition_summaries"),
)


__all__ = [
    "CANONICAL_EXTERNAL_SITES_PHASE_V3",
    "check_canonical_external_sites_completeness_v3",
]
