"""Qualification derivation from conformance reports and requirements."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .conformance import (
    BackendKind,
    BackendObservation,
    GPR_NAMES,
    ISAConformanceCorpus,
    ISAConformanceError,
    ISAConformanceReport,
    InstructionTestCase,
    ObservationStatus,
    X87Mask,
    isa_conformance_corpus_sha256,
    parse_isa_conformance_corpus,
    parse_isa_conformance_report,
)
from .kernel_qualification import (
    BackendBinding,
    BackendRole,
    BinaryQualificationRequirements,
    CorpusBinding,
    GeneratorBinding,
    ISAKernelQualification,
    ISAKernelQualificationError,
    ISAKernelSelection,
    ISAOracleConsensus,
    ISAOracleObservation,
    ISAProfileBinding,
    ISA_KERNEL_SELECTION_REQUIREMENTS_FORMAT,
    ObservationAvailability,
    OracleSuiteBinding,
    SemanticKernelBinding,
    _exact_fields,
    _object,
    _objects,
    _parse_trust,
    _sha256,
    _string,
    _trust_payload,
    _validate_common_bindings,
)
from .kernel_qualification_artifacts import (
    _parse_requirement,
    _requirement_payload,
    build_isa_kernel_qualification,
    parse_kernel_qualification,
    select_isa_kernel_qualification,
)
from .kernel_qualification_oracles import (
    build_form_qualification,
    build_oracle_consensus,
    build_oracle_observation,
)

def _backend_binding(
    backend_id: str, oracle_suite: OracleSuiteBinding
) -> BackendBinding:
    for backend in oracle_suite.backends:
        if backend_id == backend.id:
            return backend
    raise ISAKernelQualificationError(
        f"backend {backend_id!r} is absent from the declared oracle suite"
    )


def _profile_matches_case(
    profile: ISAProfileBinding, case: InstructionTestCase
) -> bool:
    return (
        profile.architecture == case.profile.architecture
        and profile.cpu == case.profile.cpu
        and profile.execution_mode == case.profile.execution_mode
        and profile.environment == case.profile.environment
        and profile.features == case.profile.features
    )


def _masked_bytes(value: bytes, mask: bytes) -> list[int]:
    if len(value) != len(mask):
        raise ISAKernelQualificationError(
            "observation and defined-output mask lengths disagree"
        )
    return [
        observed_byte & mask_byte
        for observed_byte, mask_byte in zip(value, mask, strict=True)
    ]


def _effective_x87_mask(
    requested: X87Mask,
    architectural: X87Mask | None,
) -> X87Mask:
    if architectural is None:
        return requested
    return X87Mask(
        control_word=requested.control_word & architectural.control_word,
        status_word=requested.status_word & architectural.status_word,
        tag_word=requested.tag_word & architectural.tag_word,
        last_opcode=requested.last_opcode & architectural.last_opcode,
        instruction_pointer=(
            requested.instruction_pointer & architectural.instruction_pointer
        ),
        data_pointer=requested.data_pointer & architectural.data_pointer,
        registers=tuple(
            bytes(left & right for left, right in zip(a, b, strict=True))
            for a, b in zip(
                requested.registers, architectural.registers, strict=True
            )
        ),
    )


def _has_defined_machine_output(
    case: InstructionTestCase,
    *,
    x87_mask: X87Mask | None = None,
) -> bool:
    masks = case.defined_outputs
    effective_x87 = masks.x87 if x87_mask is None else x87_mask
    return any(
        (
            *(getattr(masks.gprs, register) for register in GPR_NAMES),
            masks.eip,
            masks.eflags,
            masks.fs.selector,
            masks.fs.base,
            effective_x87.control_word,
            effective_x87.status_word,
            effective_x87.tag_word,
            effective_x87.last_opcode,
            effective_x87.instruction_pointer,
            effective_x87.data_pointer,
            *(byte for register in effective_x87.registers for byte in register),
            *(byte for region in masks.memory for byte in region.mask),
        )
    )


def _normalized_complete_result(
    case: InstructionTestCase,
    observation: BackendObservation,
    *,
    x87_definedness: X87Mask | None = None,
) -> dict[str, Any]:
    if observation.actual is None:
        raise ISAKernelQualificationError(
            "complete conformance observation has no control outcome"
        )
    result: dict[str, Any] = {
        "control": observation.actual.control.value,
        "fault": observation.actual.fault.value,
        "final_state": None,
        "memory": None,
    }
    effective_x87 = _effective_x87_mask(
        case.defined_outputs.x87, x87_definedness
    )
    if not _has_defined_machine_output(case, x87_mask=effective_x87):
        return result
    if observation.final_state is None:
        if observation.memory is not None:
            raise ISAKernelQualificationError(
                "conformance observation has memory without final state"
            )
        return result
    if observation.memory is None:
        raise ISAKernelQualificationError(
            "conformance observation has final state without memory"
        )
    state = observation.final_state
    masks = case.defined_outputs
    result["final_state"] = {
        "gprs": {
            register: (
                getattr(state.gprs, register)
                & getattr(masks.gprs, register)
            )
            for register in GPR_NAMES
        },
        "eip": state.eip & masks.eip,
        "eflags": state.eflags & masks.eflags,
        "fs": {
            "selector": state.fs.selector & masks.fs.selector,
            "base": state.fs.base & masks.fs.base,
        },
        "x87": {
            "control_word": state.x87.control_word & effective_x87.control_word,
            "status_word": state.x87.status_word & effective_x87.status_word,
            "tag_word": state.x87.tag_word & effective_x87.tag_word,
            "last_opcode": state.x87.last_opcode & effective_x87.last_opcode,
            "instruction_pointer": (
                state.x87.instruction_pointer
                & effective_x87.instruction_pointer
            ),
            "data_pointer": state.x87.data_pointer & effective_x87.data_pointer,
            "registers": [
                _masked_bytes(register, mask)
                for register, mask in zip(
                    state.x87.registers,
                    effective_x87.registers,
                    strict=True,
                )
            ],
        },
    }
    observed_memory = {row.address: row.data for row in observation.memory}
    normalized_memory: list[dict[str, Any]] = []
    for mask in masks.memory:
        observed = observed_memory.get(mask.address)
        if observed is None:
            normalized_memory.append(
                {
                    "address": mask.address,
                    "mask_length": len(mask.mask),
                    "observed_length": None,
                    "bytes": None,
                }
            )
            continue
        normalized_memory.append(
            {
                "address": mask.address,
                "mask_length": len(mask.mask),
                "observed_length": len(observed),
                "bytes": [
                    observed[index] & mask.mask[index]
                    for index in range(min(len(observed), len(mask.mask)))
                ],
            }
        )
    result["memory"] = normalized_memory
    return result


def observations_from_conformance_report(
    *,
    corpus: ISAConformanceCorpus | Mapping[str, Any],
    report: ISAConformanceReport | Mapping[str, Any],
    form_ids_by_case: Mapping[str, str],
    profile: ISAProfileBinding,
    semantic_kernel: SemanticKernelBinding,
    generator: GeneratorBinding,
    oracle_suite: OracleSuiteBinding,
    x87_definedness_by_case: Mapping[str, X87Mask] | None = None,
) -> tuple[ISAOracleObservation, ...]:
    """Normalize an existing report into strict consensus observations.

    Complete report observations are compared by their actual masked machine
    output.  Their legacy ``match``/``mismatch`` status against the corpus
    expectation does not alter the direct multi-oracle comparison.
    """
    try:
        typed_corpus = (
            corpus
            if isinstance(corpus, ISAConformanceCorpus)
            else parse_isa_conformance_corpus(corpus)
        )
        typed_report = (
            parse_isa_conformance_report(
                report.to_payload(corpus=typed_corpus), corpus=typed_corpus
            )
            if isinstance(report, ISAConformanceReport)
            else parse_isa_conformance_report(report, corpus=typed_corpus)
        )
    except ISAConformanceError as exc:
        raise ISAKernelQualificationError(
            f"invalid ISA conformance input: {exc}"
        ) from exc
    case_ids = tuple(case.id for case in typed_corpus.cases)
    definedness = (
        {} if x87_definedness_by_case is None else x87_definedness_by_case
    )
    if not set(definedness).issubset(set(case_ids)):
        raise ISAKernelQualificationError(
            "x87 definedness names a case outside the qualification corpus"
        )
    if set(form_ids_by_case) != set(case_ids):
        raise ISAKernelQualificationError(
            "semantic-form mapping must contain exactly every corpus case"
        )
    if any(
        not isinstance(case_id, str)
        or not isinstance(form_id, str)
        or not form_id
        for case_id, form_id in form_ids_by_case.items()
    ):
        raise ISAKernelQualificationError(
            "semantic-form mapping must contain non-empty string IDs"
        )
    if any(
        not _profile_matches_case(profile, case) for case in typed_corpus.cases
    ):
        raise ISAKernelQualificationError(
            "qualification profile does not match every corpus case"
        )
    _validate_common_bindings(
        profile=profile,
        semantic_kernel=semantic_kernel,
        generator=generator,
        oracle_suite=oracle_suite,
    )
    declared_backend = _backend_binding(
        typed_report.backend.id, oracle_suite
    )
    if typed_report.backend.version != declared_backend.version:
        raise ISAKernelQualificationError(
            "conformance report backend version differs from the oracle suite"
        )
    expected_kind = (
        BackendKind.SEMANTIC_MODEL
        if declared_backend.role is BackendRole.LEAN
        else BackendKind.EMULATOR
    )
    if typed_report.backend.kind is not expected_kind:
        raise ISAKernelQualificationError(
            "conformance report backend kind differs from its oracle-suite role"
        )
    corpus_binding = CorpusBinding(
        id=typed_corpus.id, sha256=typed_report.input_sha256
    )
    cases_by_id = {case.id: case for case in typed_corpus.cases}
    rows: list[ISAOracleObservation] = []
    for observation in typed_report.observations:
        if observation.status in {
            ObservationStatus.MATCH,
            ObservationStatus.MISMATCH,
        }:
            availability = ObservationAvailability.COMPLETE
            result = _normalized_complete_result(
                cases_by_id[observation.case_id],
                observation,
                x87_definedness=definedness.get(observation.case_id),
            )
            detail = observation.detail
        elif observation.status is ObservationStatus.UNSUPPORTED:
            availability = ObservationAvailability.UNSUPPORTED
            result = None
            detail = observation.detail
        else:
            availability = ObservationAvailability.ERROR
            result = None
            detail = observation.detail
        rows.append(
            build_oracle_observation(
                form_id=form_ids_by_case[observation.case_id],
                case_id=observation.case_id,
                profile=profile,
                semantic_kernel=semantic_kernel,
                corpus=corpus_binding,
                generator=generator,
                backend=declared_backend,
                availability=availability,
                result=result,
                detail=detail,
            )
        )
    return tuple(rows)


def consensuses_from_conformance_reports(
    *,
    corpus: ISAConformanceCorpus | Mapping[str, Any],
    reports: Iterable[ISAConformanceReport | Mapping[str, Any]],
    form_ids_by_case: Mapping[str, str],
    profile: ISAProfileBinding,
    semantic_kernel: SemanticKernelBinding,
    generator: GeneratorBinding,
    oracle_suite: OracleSuiteBinding,
    x87_definedness_by_case: Mapping[str, X87Mask] | None = None,
) -> tuple[ISAOracleConsensus, ...]:
    """Join up to three backend reports into one consensus per corpus case."""
    typed_corpus = (
        corpus
        if isinstance(corpus, ISAConformanceCorpus)
        else parse_isa_conformance_corpus(corpus)
    )
    observations: list[ISAOracleObservation] = []
    for report in reports:
        observations.extend(
            observations_from_conformance_report(
                corpus=typed_corpus,
                report=report,
                form_ids_by_case=form_ids_by_case,
                profile=profile,
                semantic_kernel=semantic_kernel,
                generator=generator,
                oracle_suite=oracle_suite,
                x87_definedness_by_case=x87_definedness_by_case,
            )
        )
    by_case: dict[str, list[ISAOracleObservation]] = {
        case.id: [] for case in typed_corpus.cases
    }
    for observation in observations:
        by_case[observation.case_id].append(observation)
    corpus_binding = CorpusBinding(
        id=typed_corpus.id,
        sha256=(
            observations[0].corpus.sha256
            if observations
            else isa_conformance_corpus_sha256(typed_corpus)
        ),
    )
    return tuple(
        build_oracle_consensus(
            form_id=form_ids_by_case[case.id],
            case_id=case.id,
            profile=profile,
            semantic_kernel=semantic_kernel,
            corpus=corpus_binding,
            generator=generator,
            oracle_suite=oracle_suite,
            observations=by_case[case.id],
        )
        for case in typed_corpus.cases
    )


def build_isa_kernel_qualification_from_reports(
    *,
    corpus: ISAConformanceCorpus | Mapping[str, Any],
    reports: Iterable[ISAConformanceReport | Mapping[str, Any]],
    form_ids_by_case: Mapping[str, str],
    semantic_forms_by_id: Mapping[str, str],
    profile: ISAProfileBinding,
    semantic_kernel: SemanticKernelBinding,
    generator: GeneratorBinding,
    oracle_suite: OracleSuiteBinding,
    required_form_ids: Iterable[str] | None = None,
    x87_definedness_by_case: Mapping[str, X87Mask] | None = None,
) -> ISAKernelQualification:
    """Build kernel qualification directly from a backend report triplet.

    ``reports`` may omit a backend; the resulting form is then incomplete.
    Duplicate backend reports are rejected by consensus construction.
    """
    typed_corpus = (
        corpus
        if isinstance(corpus, ISAConformanceCorpus)
        else parse_isa_conformance_corpus(corpus)
    )
    consensuses = consensuses_from_conformance_reports(
        corpus=typed_corpus,
        reports=reports,
        form_ids_by_case=form_ids_by_case,
        profile=profile,
        semantic_kernel=semantic_kernel,
        generator=generator,
        oracle_suite=oracle_suite,
        x87_definedness_by_case=x87_definedness_by_case,
    )
    required = tuple(
        sorted(
            set(form_ids_by_case.values())
            if required_form_ids is None
            else {
                _string(form_id, "required form ID")
                for form_id in required_form_ids
            }
        )
    )
    if not required:
        raise ISAKernelQualificationError(
            "kernel report qualification requires at least one form"
        )
    if set(semantic_forms_by_id) != set(required):
        raise ISAKernelQualificationError(
            "semantic-form catalog must contain exactly every required form"
        )
    if any(
        not isinstance(form_id, str)
        or not isinstance(semantic_form, str)
        or not semantic_form
        for form_id, semantic_form in semantic_forms_by_id.items()
    ):
        raise ISAKernelQualificationError(
            "semantic-form catalog must contain non-empty string bindings"
        )
    corpus_binding = CorpusBinding(
        typed_corpus.id, isa_conformance_corpus_sha256(typed_corpus)
    )
    by_form: dict[str, list[ISAOracleConsensus]] = {
        form_id: [] for form_id in required
    }
    for consensus in consensuses:
        if consensus.form_id in by_form:
            by_form[consensus.form_id].append(consensus)
    forms = tuple(
        build_form_qualification(
            form_id=form_id,
            semantic_form=semantic_forms_by_id[form_id],
            profile=profile,
            semantic_kernel=semantic_kernel,
            generator=generator,
            oracle_suite=oracle_suite,
            corpora=(corpus_binding,),
            consensuses=by_form[form_id],
        )
        for form_id in required
    )
    return build_isa_kernel_qualification(
        profile=profile,
        semantic_kernel=semantic_kernel,
        generator=generator,
        oracle_suite=oracle_suite,
        corpora=(corpus_binding,),
        required_form_ids=required,
        forms=forms,
    )


def parse_binary_qualification_requirements(
    value: Any,
) -> BinaryQualificationRequirements:
    payload = _object(value, "ISA kernel selection requirements")
    _exact_fields(
        payload,
        {
            "format",
            "binary",
            "profile_id",
            "semantic_kernel_id",
            "forms",
            "trust",
        },
        "ISA kernel selection requirements",
    )
    if payload.get("format") != ISA_KERNEL_SELECTION_REQUIREMENTS_FORMAT:
        raise ISAKernelQualificationError(
            "unsupported ISA kernel selection requirements format"
        )
    binary = _object(
        payload.get("binary"), "ISA kernel selection requirements.binary"
    )
    _exact_fields(
        binary, {"id", "sha256"}, "ISA kernel selection requirements.binary"
    )
    forms = tuple(
        _parse_requirement(
            row, f"ISA kernel selection requirements.forms[{index}]"
        )
        for index, row in enumerate(
            _objects(
                payload.get("forms"),
                "ISA kernel selection requirements.forms",
            )
        )
    )
    if not forms or tuple(row.form_id for row in forms) != tuple(
        sorted({row.form_id for row in forms})
    ):
        raise ISAKernelQualificationError(
            "ISA kernel selection requirement forms must be non-empty, unique, "
            "and ordered"
        )
    binary_sha256 = _sha256(
        binary.get("sha256"),
        "ISA kernel selection requirements.binary.sha256",
    )
    if any(
        location.image_sha256 != binary_sha256
        for form in forms
        for location in form.source_locations
    ):
        raise ISAKernelQualificationError(
            "ISA kernel selection requirements contain a foreign image location"
        )
    _parse_trust(
        payload.get("trust"), "ISA kernel selection requirements.trust"
    )
    return BinaryQualificationRequirements(
        binary_id=_string(
            binary.get("id"), "ISA kernel selection requirements.binary.id"
        ),
        binary_sha256=binary_sha256,
        profile_id=_string(
            payload.get("profile_id"),
            "ISA kernel selection requirements.profile_id",
        ),
        semantic_kernel_id=_string(
            payload.get("semantic_kernel_id"),
            "ISA kernel selection requirements.semantic_kernel_id",
        ),
        forms=forms,
    )


def serialize_binary_qualification_requirements(
    value: BinaryQualificationRequirements,
) -> dict[str, Any]:
    if not isinstance(value, BinaryQualificationRequirements):
        raise ISAKernelQualificationError(
            "requirements must be BinaryQualificationRequirements"
        )
    payload = {
        "format": value.format,
        "binary": {"id": value.binary_id, "sha256": value.binary_sha256},
        "profile_id": value.profile_id,
        "semantic_kernel_id": value.semantic_kernel_id,
        "forms": [_requirement_payload(row) for row in value.forms],
        "trust": _trust_payload(value.trust),
    }
    if parse_binary_qualification_requirements(payload) != value:
        raise ISAKernelQualificationError(
            "kernel selection requirements are not a valid typed instance"
        )
    return payload


def select_isa_kernel_qualification_from_requirements(
    *,
    requirements: BinaryQualificationRequirements | Mapping[str, Any],
    qualification: ISAKernelQualification | Mapping[str, Any],
) -> ISAKernelSelection:
    """Fail-closed adapter used by the qualification-selection CLI."""
    typed_requirements = (
        requirements
        if isinstance(requirements, BinaryQualificationRequirements)
        else parse_binary_qualification_requirements(requirements)
    )
    typed_qualification = (
        qualification
        if isinstance(qualification, ISAKernelQualification)
        else parse_kernel_qualification(qualification)
    )
    if typed_requirements.profile_id != typed_qualification.profile.id:
        raise ISAKernelQualificationError(
            "selection requirements profile does not match qualification"
        )
    if (
        typed_requirements.semantic_kernel_id
        != typed_qualification.semantic_kernel.id
    ):
        raise ISAKernelQualificationError(
            "selection requirements semantic kernel does not match qualification"
        )
    return select_isa_kernel_qualification(
        binary_id=typed_requirements.binary_id,
        binary_sha256=typed_requirements.binary_sha256,
        requirements=typed_requirements.forms,
        qualification=typed_qualification,
    )
