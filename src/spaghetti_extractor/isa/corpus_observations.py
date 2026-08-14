"""Executor adaptation and raw-observation consensus for generated ISA corpora."""

from __future__ import annotations

from . import conformance
from .conformance import (
    CaseExpectation,
    FaultClass,
    ISAConformanceCorpus,
    ISAConformanceError,
    ISAConformanceReport,
    InstructionTestCase,
    MemoryMask,
    ObservationStatus,
    ObservedMemoryRegion,
)
from .corpus_generator import (
    BoundaryMachineStateCase,
    ExecutorCorpusAdapter,
    GeneratedISACorpus,
    ISACorpusGenerationError,
    RawBackendCaseObservation,
    RawBackendObservationSet,
    RawConsensusCase,
    RawConsensusStatus,
    RawObservationConsensus,
    generated_isa_corpus_sha256,
)

def _neutral_memory_expectation(
    case: BoundaryMachineStateCase,
) -> tuple[ObservedMemoryRegion, ...]:
    result: list[ObservedMemoryRegion] = []
    for mask in case.defined_outputs.memory:
        source = next(
            (
                region
                for region in case.memory
                if region.address <= mask.address
                and mask.address + len(mask.mask)
                <= region.address + len(region.data)
            ),
            None,
        )
        if source is None:
            raise ISACorpusGenerationError(
                f"{case.id} output mask is not contained in mapped memory"
            )
        offset = mask.address - source.address
        result.append(
            ObservedMemoryRegion(
                address=mask.address,
                data=source.data[offset : offset + len(mask.mask)],
            )
        )
    return tuple(result)


def generated_corpus_executor_input(
    generated: GeneratedISACorpus,
) -> ExecutorCorpusAdapter:
    """Adapt differential inputs to current runners with non-authoritative expectations."""
    if not isinstance(generated, GeneratedISACorpus):
        raise ISAConformanceError("generated must be a GeneratedISACorpus")
    digest = generated_isa_corpus_sha256(generated)
    cases: list[InstructionTestCase] = []
    for generated_case in generated.cases:
        faulting = generated_case.expected.fault is not FaultClass.NONE
        cases.append(
            InstructionTestCase(
                id=generated_case.id,
                instruction_bytes=generated_case.instruction_bytes,
                profile=generated_case.profile,
                image_base=generated_case.image_base,
                initial_state=generated_case.initial_state,
                memory=generated_case.memory,
                defined_outputs=generated_case.defined_outputs,
                expected=CaseExpectation(
                    final_state=None if faulting else generated_case.initial_state,
                    memory=(
                        None
                        if faulting
                        else _neutral_memory_expectation(generated_case)
                    ),
                    control=generated_case.expected.control,
                    fault=generated_case.expected.fault,
                ),
            )
        )
    corpus = ISAConformanceCorpus(
        id="generated-executor-" + digest,
        cases=tuple(cases),
    )
    # Existing runner entry points validate through this serializer.
    conformance.serialize_isa_conformance_corpus(corpus)
    return ExecutorCorpusAdapter(
        generated_corpus_sha256=digest,
        corpus=corpus,
    )


def extract_raw_executor_observations(
    generated: GeneratedISACorpus,
    report: ISAConformanceReport,
) -> RawBackendObservationSet:
    """Preserve runner actuals while discarding neutral expectation status."""
    adapter = generated_corpus_executor_input(generated)
    if not isinstance(report, ISAConformanceReport):
        raise ISAConformanceError("report must be an ISAConformanceReport")
    conformance.serialize_isa_conformance_report(report, corpus=adapter.corpus)
    observations = tuple(
        RawBackendCaseObservation(
            case_id=observation.case_id,
            complete=(
                observation.status
                in {ObservationStatus.MATCH, ObservationStatus.MISMATCH}
                and observation.actual is not None
            ),
            final_state=observation.final_state,
            memory=observation.memory,
            actual=observation.actual,
            detail=observation.detail,
        )
        for observation in report.observations
    )
    return RawBackendObservationSet(
        backend_id=report.backend.id,
        generated_corpus_sha256=adapter.generated_corpus_sha256,
        observations=observations,
    )


def _raw_memory_agrees(
    masks: tuple[MemoryMask, ...],
    left: tuple[ObservedMemoryRegion, ...],
    right: tuple[ObservedMemoryRegion, ...],
) -> bool:
    left_by_range = {
        (region.address, len(region.data)): region.data for region in left
    }
    right_by_range = {
        (region.address, len(region.data)): region.data for region in right
    }
    expected_ranges = {(mask.address, len(mask.mask)) for mask in masks}
    if set(left_by_range) != expected_ranges or set(right_by_range) != expected_ranges:
        return False
    return all(
        conformance._masked_bytes_match(
            left_by_range[(mask.address, len(mask.mask))],
            right_by_range[(mask.address, len(mask.mask))],
            mask.mask,
        )
        for mask in masks
    )


def _raw_case_agrees(
    case: BoundaryMachineStateCase,
    left: RawBackendCaseObservation,
    right: RawBackendCaseObservation,
) -> bool:
    if not left.complete or not right.complete or left.actual != right.actual:
        return False
    if left.final_state is None or right.final_state is None:
        return (
            left.final_state is None
            and right.final_state is None
            and left.memory is None
            and right.memory is None
            and left.actual is not None
            and left.actual.fault is not FaultClass.NONE
        )
    if left.memory is None or right.memory is None:
        return False
    return conformance._machine_state_matches(
        left.final_state, right.final_state, case.defined_outputs
    ) and _raw_memory_agrees(
        case.defined_outputs.memory, left.memory, right.memory
    )


def compare_raw_executor_observations(
    generated: GeneratedISACorpus,
    *reports: ISAConformanceReport,
) -> RawObservationConsensus:
    """Compare backend actuals pointwise; neutral match statuses are irrelevant."""
    if len(reports) < 2:
        raise ISAConformanceError("raw consensus requires at least two backends")
    extracted = tuple(
        extract_raw_executor_observations(generated, report) for report in reports
    )
    backend_ids = tuple(item.backend_id for item in extracted)
    if len(backend_ids) != len(set(backend_ids)):
        raise ISAConformanceError("raw consensus requires unique backend IDs")
    cases_by_id = {case.id: case for case in generated.cases}
    result: list[RawConsensusCase] = []
    for case_id in (case.id for case in generated.cases):
        observations = tuple(
            next(row for row in item.observations if row.case_id == case_id)
            for item in extracted
        )
        if any(not row.complete for row in observations):
            status = RawConsensusStatus.INCOMPLETE
        elif all(
            _raw_case_agrees(cases_by_id[case_id], observations[0], row)
            for row in observations[1:]
        ):
            status = RawConsensusStatus.AGREED
        else:
            status = RawConsensusStatus.DISAGREED
        result.append(
            RawConsensusCase(case_id=case_id, status=status, backends=backend_ids)
        )
    return RawObservationConsensus(
        generated_corpus_sha256=generated_isa_corpus_sha256(generated),
        cases=tuple(result),
    )
