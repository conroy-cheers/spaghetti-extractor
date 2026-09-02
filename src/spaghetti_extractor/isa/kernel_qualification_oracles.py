"""Oracle observations, consensus, and per-form ISA qualification."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import copy
from dataclasses import replace
import hashlib
from typing import Any

from .kernel_qualification import (
    BackendBinding,
    BackendRole,
    CorpusBinding,
    GeneratorBinding,
    ISAFormQualification,
    ISAKernelQualificationError,
    ISAOracleConsensus,
    ISAOracleObservation,
    ISAProfileBinding,
    ISA_FORM_QUALIFICATION_FORMAT,
    ISA_ORACLE_CONSENSUS_FORMAT,
    ISA_ORACLE_OBSERVATION_FORMAT,
    MismatchDiagnostic,
    ObservationAvailability,
    OracleSuiteBinding,
    QualificationStatus,
    SemanticKernelBinding,
    _ROLE_ORDER,
    _backend_payload,
    _comparison_diagnostics,
    _corpus_payload,
    _diagnostic_key,
    _diagnostic_payload,
    _enum,
    _exact_fields,
    _generator_payload,
    _incomplete_backend_diagnostic,
    _kernel_payload,
    _missing_backend_diagnostic,
    _normalize_json,
    _object,
    _objects,
    _ordered_diagnostics,
    _parse_backend,
    _parse_corpus,
    _parse_counts,
    _parse_diagnostic,
    _parse_generator,
    _parse_kernel,
    _parse_profile,
    _parse_suite,
    _parse_trust,
    _profile_payload,
    _qualification_layers_payload,
    _require_shared,
    _sha256,
    _status,
    _status_counts,
    _string,
    _suite_payload,
    _trust_payload,
    _validate_common_bindings,
    _validate_qualification_layers,
    canonical_json_bytes,
)


_UNICORN_PARTIAL_X87_STATUS_BACKEND_V1 = "unicorn-x86-32-batch-v2"
_X87_EXCEPTION_STATUS_BITS_V1 = 0x003F


def _pairwise_capability_projection_v1(
    reference: ISAOracleObservation,
    observed: ISAOracleObservation,
) -> tuple[ISAOracleObservation, ISAOracleObservation]:
    """Project two results to fields claimed by both concrete backends.

    Unicorn's v2 x87 engine does not reliably implement the six accrued
    exception-status flags.  Its backend identity therefore claims every
    normalized output except those bits.  This affects only the independent
    Bochs/Unicorn agreement check: the subsequent Bochs/Lean comparison keeps
    the full architecturally defined status word, so no ISA behavior is waived.
    """

    unicorn_rows = tuple(
        row for row in (reference, observed)
        if row.backend.role is BackendRole.UNICORN
    )
    if (
        len(unicorn_rows) != 1
        or unicorn_rows[0].backend.id
        != _UNICORN_PARTIAL_X87_STATUS_BACKEND_V1
    ):
        return reference, observed

    def projected(row: ISAOracleObservation) -> ISAOracleObservation:
        if row.result is None:
            return row
        result = copy.deepcopy(dict(row.result))
        final_state = result.get("final_state")
        x87 = (
            final_state.get("x87")
            if isinstance(final_state, Mapping) else None
        )
        status = x87.get("status_word") if isinstance(x87, Mapping) else None
        if not isinstance(status, int) or isinstance(status, bool):
            return row
        x87["status_word"] = status & ~_X87_EXCEPTION_STATUS_BITS_V1
        digest = hashlib.sha256(canonical_json_bytes(result)).hexdigest()
        return replace(row, result=result, result_sha256=digest)

    return projected(reference), projected(observed)

def build_oracle_observation(
    *,
    form_id: str,
    case_id: str,
    profile: ISAProfileBinding,
    semantic_kernel: SemanticKernelBinding,
    corpus: CorpusBinding,
    generator: GeneratorBinding,
    backend: BackendBinding,
    availability: ObservationAvailability,
    result: Mapping[str, Any] | None,
    detail: str = "",
) -> ISAOracleObservation:
    """Build one canonical backend observation bound to all cache identities."""
    form_id = _string(form_id, "oracle observation.form_id")
    case_id = _string(case_id, "oracle observation.case_id")
    _validate_common_bindings(
        profile=profile,
        semantic_kernel=semantic_kernel,
        generator=generator,
    )
    if not isinstance(corpus, CorpusBinding):
        raise ISAKernelQualificationError(
            "corpus must be a CorpusBinding"
        )
    _corpus_payload(_parse_corpus(_corpus_payload(corpus), "corpus"))
    if not isinstance(backend, BackendBinding):
        raise ISAKernelQualificationError(
            "backend must be a BackendBinding"
        )
    _backend_payload(backend)
    if not isinstance(availability, ObservationAvailability):
        raise ISAKernelQualificationError(
            "oracle observation availability is unsupported"
        )
    detail = _string(
        detail, "oracle observation.detail", allow_empty=True
    )
    if availability is ObservationAvailability.COMPLETE:
        if result is None:
            raise ISAKernelQualificationError(
                "complete oracle observation requires a result"
            )
        normalized = _object(
            _normalize_json(result, "oracle observation.result"),
            "oracle observation.result",
        )
        result_value: Mapping[str, Any] | None = dict(normalized)
        result_sha256 = hashlib.sha256(
            canonical_json_bytes(result_value)
        ).hexdigest()
    else:
        if result is not None:
            raise ISAKernelQualificationError(
                "incomplete oracle observation must not carry a result"
            )
        if not detail:
            raise ISAKernelQualificationError(
                "incomplete oracle observation requires detail"
            )
        result_value = None
        result_sha256 = None
    return ISAOracleObservation(
        form_id=form_id,
        case_id=case_id,
        profile=profile,
        semantic_kernel=semantic_kernel,
        corpus=corpus,
        generator=generator,
        backend=backend,
        availability=availability,
        result=result_value,
        result_sha256=result_sha256,
        detail=detail,
    )


def parse_oracle_observation(value: Any) -> ISAOracleObservation:
    payload = _object(value, "ISA oracle observation")
    _exact_fields(
        payload,
        {
            "format",
            "form_id",
            "case_id",
            "profile",
            "semantic_kernel",
            "corpus",
            "generator",
            "backend",
            "availability",
            "result",
            "result_sha256",
            "detail",
            "trust",
        },
        "ISA oracle observation",
    )
    if payload.get("format") != ISA_ORACLE_OBSERVATION_FORMAT:
        raise ISAKernelQualificationError(
            "unsupported ISA oracle observation format"
        )
    observation = build_oracle_observation(
        form_id=payload.get("form_id"),
        case_id=payload.get("case_id"),
        profile=_parse_profile(
            payload.get("profile"), "ISA oracle observation.profile"
        ),
        semantic_kernel=_parse_kernel(
            payload.get("semantic_kernel"),
            "ISA oracle observation.semantic_kernel",
        ),
        corpus=_parse_corpus(
            payload.get("corpus"), "ISA oracle observation.corpus"
        ),
        generator=_parse_generator(
            payload.get("generator"), "ISA oracle observation.generator"
        ),
        backend=_parse_backend(
            payload.get("backend"), "ISA oracle observation.backend"
        ),
        availability=_enum(
            ObservationAvailability,
            payload.get("availability"),
            "ISA oracle observation.availability",
        ),
        result=payload.get("result"),
        detail=_string(
            payload.get("detail"),
            "ISA oracle observation.detail",
            allow_empty=True,
        ),
    )
    declared_digest = payload.get("result_sha256")
    if observation.result_sha256 != declared_digest:
        raise ISAKernelQualificationError(
            "ISA oracle observation result SHA-256 is inconsistent"
        )
    _parse_trust(payload.get("trust"), "ISA oracle observation.trust")
    return observation


def serialize_oracle_observation(
    value: ISAOracleObservation,
) -> dict[str, Any]:
    if not isinstance(value, ISAOracleObservation):
        raise ISAKernelQualificationError(
            "oracle observation must be an ISAOracleObservation"
        )
    payload = {
        "format": value.format,
        "form_id": value.form_id,
        "case_id": value.case_id,
        "profile": _profile_payload(value.profile),
        "semantic_kernel": _kernel_payload(value.semantic_kernel),
        "corpus": _corpus_payload(value.corpus),
        "generator": _generator_payload(value.generator),
        "backend": _backend_payload(value.backend),
        "availability": value.availability.value,
        "result": (
            _normalize_json(value.result, "oracle observation.result")
            if value.result is not None
            else None
        ),
        "result_sha256": value.result_sha256,
        "detail": value.detail,
        "trust": _trust_payload(value.trust),
    }
    if parse_oracle_observation(payload) != value:
        raise ISAKernelQualificationError(
            "oracle observation is not a valid typed instance"
        )
    return payload


def build_oracle_consensus(
    *,
    form_id: str,
    case_id: str,
    profile: ISAProfileBinding,
    semantic_kernel: SemanticKernelBinding,
    corpus: CorpusBinding,
    generator: GeneratorBinding,
    oracle_suite: OracleSuiteBinding,
    observations: Iterable[ISAOracleObservation],
) -> ISAOracleConsensus:
    """Classify one case using the strict Bochs/Unicorn/Lean consensus rule."""
    _validate_common_bindings(
        profile=profile,
        semantic_kernel=semantic_kernel,
        generator=generator,
        oracle_suite=oracle_suite,
    )
    if not isinstance(corpus, CorpusBinding):
        raise ISAKernelQualificationError(
            "corpus must be a CorpusBinding"
        )
    _parse_corpus(_corpus_payload(corpus), "corpus")
    form_id = _string(form_id, "oracle consensus.form_id")
    case_id = _string(case_id, "oracle consensus.case_id")
    raw_rows = tuple(observations)
    if any(not isinstance(row, ISAOracleObservation) for row in raw_rows):
        raise ISAKernelQualificationError(
            "oracle consensus observations must be ISAOracleObservation values"
        )
    rows = tuple(
        sorted(raw_rows, key=lambda row: _ROLE_ORDER[row.backend.role])
    )
    if len({row.backend.role for row in rows}) != len(rows):
        raise ISAKernelQualificationError(
            "oracle consensus contains duplicate backend roles"
        )
    suite_by_role = {backend.role: backend for backend in oracle_suite.backends}
    for row in rows:
        _require_shared(row.form_id, form_id, "observation form ID")
        _require_shared(row.case_id, case_id, "observation case ID")
        _require_shared(row.profile, profile, "observation profile")
        _require_shared(
            row.semantic_kernel, semantic_kernel, "observation semantic kernel"
        )
        _require_shared(row.corpus, corpus, "observation corpus")
        _require_shared(row.generator, generator, "observation generator")
        _require_shared(
            row.backend,
            suite_by_role[row.backend.role],
            "observation backend",
        )
    by_role = {row.backend.role: row for row in rows}
    diagnostics: list[MismatchDiagnostic] = []
    missing = [
        backend
        for backend in oracle_suite.backends
        if backend.role not in by_role
    ]
    if missing:
        status = QualificationStatus.INCOMPLETE
        diagnostics.extend(
            _missing_backend_diagnostic(
                form_id=form_id, case_id=case_id, backend=backend
            )
            for backend in missing
        )
    elif any(
        row.availability is not ObservationAvailability.COMPLETE for row in rows
    ):
        status = QualificationStatus.INCOMPLETE
        diagnostics.extend(
            _incomplete_backend_diagnostic(row)
            for row in rows
            if row.availability is not ObservationAvailability.COMPLETE
        )
    else:
        bochs = by_role[BackendRole.BOCHS]
        unicorn = by_role[BackendRole.UNICORN]
        lean = by_role[BackendRole.LEAN]
        external_bochs, external_unicorn = (
            _pairwise_capability_projection_v1(bochs, unicorn)
        )
        if external_bochs.result_sha256 != external_unicorn.result_sha256:
            status = QualificationStatus.DISPUTED
            diagnostics.extend(
                _comparison_diagnostics(
                    code="external_oracle_disagreement",
                    form_id=form_id,
                    case_id=case_id,
                    reference=external_bochs,
                    observed=external_unicorn,
                    message=(
                        "Bochs and Unicorn disagree on an architecturally "
                        "defined output"
                    ),
                )
            )
        elif bochs.result_sha256 != lean.result_sha256:
            status = QualificationStatus.VETOED
            diagnostics.extend(
                _comparison_diagnostics(
                    code="lean_semantics_mismatch",
                    form_id=form_id,
                    case_id=case_id,
                    reference=bochs,
                    observed=lean,
                    message=(
                        "Lean semantics differ from the agreeing external "
                        "Bochs and Unicorn observations"
                    ),
                )
            )
        else:
            status = QualificationStatus.QUALIFIED
    ordered_diagnostics = tuple(sorted(diagnostics, key=_diagnostic_key))
    return ISAOracleConsensus(
        form_id=form_id,
        case_id=case_id,
        profile=profile,
        semantic_kernel=semantic_kernel,
        corpus=corpus,
        generator=generator,
        oracle_suite=oracle_suite,
        observations=rows,
        status=status,
        diagnostics=ordered_diagnostics,
    )


def parse_oracle_consensus(value: Any) -> ISAOracleConsensus:
    payload = _object(value, "ISA oracle consensus")
    _exact_fields(
        payload,
        {
            "format",
            "form_id",
            "case_id",
            "profile",
            "semantic_kernel",
            "corpus",
            "generator",
            "oracle_suite",
            "observations",
            "status",
            "diagnostics",
            "trust",
        },
        "ISA oracle consensus",
    )
    if payload.get("format") != ISA_ORACLE_CONSENSUS_FORMAT:
        raise ISAKernelQualificationError(
            "unsupported ISA oracle consensus format"
        )
    consensus = build_oracle_consensus(
        form_id=payload.get("form_id"),
        case_id=payload.get("case_id"),
        profile=_parse_profile(
            payload.get("profile"), "ISA oracle consensus.profile"
        ),
        semantic_kernel=_parse_kernel(
            payload.get("semantic_kernel"),
            "ISA oracle consensus.semantic_kernel",
        ),
        corpus=_parse_corpus(
            payload.get("corpus"), "ISA oracle consensus.corpus"
        ),
        generator=_parse_generator(
            payload.get("generator"), "ISA oracle consensus.generator"
        ),
        oracle_suite=_parse_suite(
            payload.get("oracle_suite"), "ISA oracle consensus.oracle_suite"
        ),
        observations=tuple(
            parse_oracle_observation(row)
            for row in _objects(
                payload.get("observations"),
                "ISA oracle consensus.observations",
            )
        ),
    )
    declared_status = _enum(
        QualificationStatus,
        payload.get("status"),
        "ISA oracle consensus.status",
    )
    if consensus.status is not declared_status:
        raise ISAKernelQualificationError(
            "ISA oracle consensus status is inconsistent"
        )
    declared_diagnostics = tuple(
        _parse_diagnostic(row, f"ISA oracle consensus.diagnostics[{index}]")
        for index, row in enumerate(
            _objects(
                payload.get("diagnostics"),
                "ISA oracle consensus.diagnostics",
            )
        )
    )
    _ordered_diagnostics(
        declared_diagnostics, "ISA oracle consensus.diagnostics"
    )
    if consensus.diagnostics != declared_diagnostics:
        raise ISAKernelQualificationError(
            "ISA oracle consensus diagnostics are inconsistent"
        )
    _parse_trust(payload.get("trust"), "ISA oracle consensus.trust")
    return consensus


def serialize_oracle_consensus(
    value: ISAOracleConsensus,
) -> dict[str, Any]:
    if not isinstance(value, ISAOracleConsensus):
        raise ISAKernelQualificationError(
            "oracle consensus must be an ISAOracleConsensus"
        )
    payload = {
        "format": value.format,
        "form_id": value.form_id,
        "case_id": value.case_id,
        "profile": _profile_payload(value.profile),
        "semantic_kernel": _kernel_payload(value.semantic_kernel),
        "corpus": _corpus_payload(value.corpus),
        "generator": _generator_payload(value.generator),
        "oracle_suite": _suite_payload(value.oracle_suite),
        "observations": [
            serialize_oracle_observation(row) for row in value.observations
        ],
        "status": value.status.value,
        "diagnostics": [
            _diagnostic_payload(row) for row in value.diagnostics
        ],
        "trust": _trust_payload(value.trust),
    }
    if parse_oracle_consensus(payload) != value:
        raise ISAKernelQualificationError(
            "oracle consensus is not a valid typed instance"
        )
    return payload


def build_form_qualification(
    *,
    form_id: str,
    semantic_form: str,
    profile: ISAProfileBinding,
    semantic_kernel: SemanticKernelBinding,
    generator: GeneratorBinding,
    oracle_suite: OracleSuiteBinding,
    corpora: Iterable[CorpusBinding],
    consensuses: Iterable[ISAOracleConsensus],
) -> ISAFormQualification:
    form_id = _string(form_id, "form qualification.form_id")
    semantic_form = _string(
        semantic_form, "form qualification.semantic_form"
    )
    _validate_common_bindings(
        profile=profile,
        semantic_kernel=semantic_kernel,
        generator=generator,
        oracle_suite=oracle_suite,
    )
    raw_corpora = tuple(corpora)
    if any(not isinstance(row, CorpusBinding) for row in raw_corpora):
        raise ISAKernelQualificationError(
            "form qualification corpora must be CorpusBinding values"
        )
    corpus_rows = tuple(
        sorted(set(raw_corpora), key=lambda row: (row.id, row.sha256))
    )
    if not corpus_rows:
        raise ISAKernelQualificationError(
            "form qualification corpora must not be empty"
        )
    corpus_ids = [row.id for row in corpus_rows]
    if len(corpus_ids) != len(set(corpus_ids)):
        raise ISAKernelQualificationError(
            "form qualification corpus IDs must be unique"
        )
    raw_rows = tuple(consensuses)
    if any(not isinstance(row, ISAOracleConsensus) for row in raw_rows):
        raise ISAKernelQualificationError(
            "form qualification consensuses must be ISAOracleConsensus values"
        )
    rows = tuple(
        sorted(
            raw_rows,
            key=lambda row: (row.corpus.id, row.case_id, row.sha256()),
        )
    )
    identities = [(row.corpus.id, row.case_id) for row in rows]
    if len(identities) != len(set(identities)):
        raise ISAKernelQualificationError(
            "form qualification contains duplicate corpus case identities"
        )
    corpus_set = set(corpus_rows)
    for row in rows:
        _require_shared(row.form_id, form_id, "consensus form ID")
        _require_shared(row.profile, profile, "consensus profile")
        _require_shared(
            row.semantic_kernel, semantic_kernel, "consensus semantic kernel"
        )
        _require_shared(row.generator, generator, "consensus generator")
        _require_shared(row.oracle_suite, oracle_suite, "consensus oracle suite")
        if row.corpus not in corpus_set:
            raise ISAKernelQualificationError(
                "consensus corpus is absent from the form corpus inventory"
            )
    if rows:
        status = _status(row.status for row in rows)
        diagnostics = tuple(
            sorted(
                (
                    diagnostic
                    for row in rows
                    for diagnostic in row.diagnostics
                ),
                key=_diagnostic_key,
            )
        )
    else:
        status = QualificationStatus.INCOMPLETE
        diagnostics = (
            MismatchDiagnostic(
                code="no_conformance_cases",
                form_id=form_id,
                case_id=None,
                json_path="$",
                reference_backend_id=None,
                observed_backend_id=None,
                reference_result_sha256=None,
                observed_result_sha256=None,
                expected={"minimum_consensus_cases": 1},
                observed={"consensus_cases": 0},
                source_locations=(),
                message="semantic form has no multi-oracle conformance cases",
            ),
        )
    counts = _status_counts(
        (row.status for row in rows), total_name="consensus_cases"
    )
    return ISAFormQualification(
        form_id=form_id,
        semantic_form=semantic_form,
        profile=profile,
        semantic_kernel=semantic_kernel,
        generator=generator,
        oracle_suite=oracle_suite,
        corpora=corpus_rows,
        consensuses=rows,
        status=status,
        diagnostics=diagnostics,
        counts=counts,
    )


def parse_form_qualification(value: Any) -> ISAFormQualification:
    payload = _object(value, "ISA form qualification")
    artifact_format = payload.get("format")
    _exact_fields(
        payload,
        {
            "format",
            "form_id",
            "semantic_form",
            "profile",
            "semantic_kernel",
            "generator",
            "oracle_suite",
            "corpora",
            "consensuses",
            "consensus_sha256s",
            "status",
            "diagnostics",
            "counts",
            "trust",
            "qualification_layers",
        },
        "ISA form qualification",
    )
    if artifact_format != ISA_FORM_QUALIFICATION_FORMAT:
        raise ISAKernelQualificationError(
            "unsupported ISA form qualification format"
        )
    result = build_form_qualification(
        form_id=payload.get("form_id"),
        semantic_form=payload.get("semantic_form"),
        profile=_parse_profile(
            payload.get("profile"), "ISA form qualification.profile"
        ),
        semantic_kernel=_parse_kernel(
            payload.get("semantic_kernel"),
            "ISA form qualification.semantic_kernel",
        ),
        generator=_parse_generator(
            payload.get("generator"), "ISA form qualification.generator"
        ),
        oracle_suite=_parse_suite(
            payload.get("oracle_suite"),
            "ISA form qualification.oracle_suite",
        ),
        corpora=tuple(
            _parse_corpus(row, f"ISA form qualification.corpora[{index}]")
            for index, row in enumerate(
                _objects(
                    payload.get("corpora"), "ISA form qualification.corpora"
                )
            )
        ),
        consensuses=tuple(
            parse_oracle_consensus(row)
            for row in _objects(
                payload.get("consensuses"),
                "ISA form qualification.consensuses",
            )
        ),
    )
    declared_hashes = payload.get("consensus_sha256s")
    if not isinstance(declared_hashes, list):
        raise ISAKernelQualificationError(
            "ISA form qualification.consensus_sha256s must be a list"
        )
    hashes = tuple(
        _sha256(row, f"ISA form qualification.consensus_sha256s[{index}]")
        for index, row in enumerate(declared_hashes)
    )
    if hashes != tuple(row.sha256() for row in result.consensuses):
        raise ISAKernelQualificationError(
            "ISA form qualification consensus hashes are inconsistent"
        )
    if result.status is not _enum(
        QualificationStatus,
        payload.get("status"),
        "ISA form qualification.status",
    ):
        raise ISAKernelQualificationError(
            "ISA form qualification status is inconsistent"
        )
    diagnostics = tuple(
        _parse_diagnostic(row, f"ISA form qualification.diagnostics[{index}]")
        for index, row in enumerate(
            _objects(
                payload.get("diagnostics"),
                "ISA form qualification.diagnostics",
            )
        )
    )
    _ordered_diagnostics(diagnostics, "ISA form qualification.diagnostics")
    if diagnostics != result.diagnostics:
        raise ISAKernelQualificationError(
            "ISA form qualification diagnostics are inconsistent"
        )
    counts = _parse_counts(
        payload.get("counts"),
        "ISA form qualification.counts",
        total_name="consensus_cases",
    )
    if counts != result.counts:
        raise ISAKernelQualificationError(
            "ISA form qualification counts are inconsistent"
        )
    expected_layers = _qualification_layers_payload(
        structural_status=result.structural_status,
        structural_statuses=(result.structural_status,),
        structural_diagnostics=result.structural_diagnostics,
        structural_total_name="required_forms",
        concrete_oracle_status=result.concrete_oracle_status,
        concrete_oracle_counts=result.counts,
        concrete_oracle_diagnostics=result.concrete_oracle_diagnostics,
    )
    _validate_qualification_layers(
        payload.get("qualification_layers"),
        expected=expected_layers,
        context="ISA form qualification.qualification_layers",
        structural_total_name="required_forms",
        concrete_oracle_total_name="consensus_cases",
    )
    _parse_trust(payload.get("trust"), "ISA form qualification.trust")
    return replace(result, format=artifact_format)


def serialize_form_qualification(
    value: ISAFormQualification,
) -> dict[str, Any]:
    if not isinstance(value, ISAFormQualification):
        raise ISAKernelQualificationError(
            "form qualification must be an ISAFormQualification"
        )
    payload = {
        "format": value.format,
        "form_id": value.form_id,
        "semantic_form": value.semantic_form,
        "profile": _profile_payload(value.profile),
        "semantic_kernel": _kernel_payload(value.semantic_kernel),
        "generator": _generator_payload(value.generator),
        "oracle_suite": _suite_payload(value.oracle_suite),
        "corpora": [_corpus_payload(row) for row in value.corpora],
        "consensuses": [
            serialize_oracle_consensus(row) for row in value.consensuses
        ],
        "consensus_sha256s": [row.sha256() for row in value.consensuses],
        "status": value.status.value,
        "diagnostics": [
            _diagnostic_payload(row) for row in value.diagnostics
        ],
        "counts": dict(value.counts),
        "trust": _trust_payload(value.trust),
    }
    if value.format != ISA_FORM_QUALIFICATION_FORMAT:
        raise ISAKernelQualificationError(
            "form qualification has an unsupported format"
        )
    payload["qualification_layers"] = _qualification_layers_payload(
        structural_status=value.structural_status,
        structural_statuses=(value.structural_status,),
        structural_diagnostics=value.structural_diagnostics,
        structural_total_name="required_forms",
        concrete_oracle_status=value.concrete_oracle_status,
        concrete_oracle_counts=value.counts,
        concrete_oracle_diagnostics=value.concrete_oracle_diagnostics,
    )
    if parse_form_qualification(payload) != value:
        raise ISAKernelQualificationError(
            "form qualification is not a valid typed instance"
        )
    return payload
