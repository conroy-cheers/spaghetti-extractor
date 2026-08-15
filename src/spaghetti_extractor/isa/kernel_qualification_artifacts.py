"""Kernel qualification and binary-selection artifact handling."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from typing import Any

from .kernel_qualification import (
    BinaryFormRequirement,
    CorpusBinding,
    GeneratorBinding,
    ISAFormQualification,
    ISAKernelQualification,
    ISAKernelQualificationError,
    ISAKernelSelection,
    ISAProfileBinding,
    ISA_KERNEL_QUALIFICATION_FORMAT,
    ISA_KERNEL_SELECTION_FORMAT,
    MismatchDiagnostic,
    OracleSuiteBinding,
    QualificationStatus,
    SelectedFormQualification,
    SemanticKernelBinding,
    SourceLocation,
    _corpus_payload,
    _diagnostic_key,
    _diagnostic_payload,
    _enum,
    _exact_fields,
    _generator_payload,
    _kernel_payload,
    _location_payload,
    _object,
    _objects,
    _optional_sha256,
    _ordered_diagnostics,
    _ordered_locations,
    _parse_corpus,
    _parse_counts,
    _parse_diagnostic,
    _parse_generator,
    _parse_kernel,
    _parse_location,
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
)
from .kernel_qualification_oracles import (
    parse_form_qualification,
    serialize_form_qualification,
)

def build_kernel_qualification(
    *,
    profile: ISAProfileBinding,
    semantic_kernel: SemanticKernelBinding,
    generator: GeneratorBinding,
    oracle_suite: OracleSuiteBinding,
    corpora: Iterable[CorpusBinding],
    required_form_ids: Iterable[str],
    forms: Iterable[ISAFormQualification],
) -> ISAKernelQualification:
    """Build a complete form inventory for one semantic-kernel revision."""
    _validate_common_bindings(
        profile=profile,
        semantic_kernel=semantic_kernel,
        generator=generator,
        oracle_suite=oracle_suite,
    )
    raw_corpora = tuple(corpora)
    if any(not isinstance(row, CorpusBinding) for row in raw_corpora):
        raise ISAKernelQualificationError(
            "kernel qualification corpora must be CorpusBinding values"
        )
    corpus_rows = tuple(
        sorted(set(raw_corpora), key=lambda row: (row.id, row.sha256))
    )
    if not corpus_rows:
        raise ISAKernelQualificationError(
            "kernel qualification corpora must not be empty"
        )
    if len({row.id for row in corpus_rows}) != len(corpus_rows):
        raise ISAKernelQualificationError(
            "kernel qualification corpus IDs must be unique"
        )
    form_ids = tuple(
        _string(form_id, "kernel qualification required form ID")
        for form_id in required_form_ids
    )
    if not form_ids or form_ids != tuple(sorted(set(form_ids))):
        raise ISAKernelQualificationError(
            "kernel qualification required form IDs must be non-empty, unique, "
            "and ordered"
        )
    raw_forms = tuple(forms)
    if any(not isinstance(row, ISAFormQualification) for row in raw_forms):
        raise ISAKernelQualificationError(
            "kernel qualification forms must be ISAFormQualification values"
        )
    form_rows = tuple(sorted(raw_forms, key=lambda row: row.form_id))
    if tuple(row.form_id for row in form_rows) != form_ids:
        raise ISAKernelQualificationError(
            "kernel qualification must contain exactly every required form"
        )
    corpus_set = set(corpus_rows)
    for row in form_rows:
        _require_shared(row.profile, profile, "form profile")
        _require_shared(
            row.semantic_kernel, semantic_kernel, "form semantic kernel"
        )
        _require_shared(row.generator, generator, "form generator")
        _require_shared(row.oracle_suite, oracle_suite, "form oracle suite")
        if not set(row.corpora).issubset(corpus_set):
            raise ISAKernelQualificationError(
                "form qualification uses an undeclared corpus"
            )
    status = _status(row.status for row in form_rows)
    diagnostics = tuple(
        sorted(
            (
                diagnostic
                for row in form_rows
                for diagnostic in row.diagnostics
            ),
            key=_diagnostic_key,
        )
    )
    counts = _status_counts(
        (row.status for row in form_rows), total_name="required_forms"
    )
    return ISAKernelQualification(
        profile=profile,
        semantic_kernel=semantic_kernel,
        generator=generator,
        oracle_suite=oracle_suite,
        corpora=corpus_rows,
        required_form_ids=form_ids,
        forms=form_rows,
        status=status,
        diagnostics=diagnostics,
        counts=counts,
    )


def build_isa_kernel_qualification(
    *,
    profile: ISAProfileBinding,
    semantic_kernel: SemanticKernelBinding,
    generator: GeneratorBinding,
    oracle_suite: OracleSuiteBinding,
    corpora: Iterable[CorpusBinding],
    required_form_ids: Iterable[str],
    forms: Iterable[ISAFormQualification],
) -> ISAKernelQualification:
    """Public builder used by ``spaghetti-extractor-build-isa-kernel-qualification``."""
    return build_kernel_qualification(
        profile=profile,
        semantic_kernel=semantic_kernel,
        generator=generator,
        oracle_suite=oracle_suite,
        corpora=corpora,
        required_form_ids=required_form_ids,
        forms=forms,
    )


def parse_kernel_qualification(value: Any) -> ISAKernelQualification:
    payload = _object(value, "ISA kernel qualification")
    artifact_format = payload.get("format")
    _exact_fields(
        payload,
        {
            "format",
            "profile",
            "semantic_kernel",
            "generator",
            "oracle_suite",
            "corpora",
            "required_form_ids",
            "forms",
            "form_sha256s",
            "status",
            "diagnostics",
            "counts",
            "trust",
            "qualification_layers",
        },
        "ISA kernel qualification",
    )
    if artifact_format != ISA_KERNEL_QUALIFICATION_FORMAT:
        raise ISAKernelQualificationError(
            "unsupported ISA kernel qualification format"
        )
    required_value = payload.get("required_form_ids")
    if not isinstance(required_value, list):
        raise ISAKernelQualificationError(
            "ISA kernel qualification.required_form_ids must be a list"
        )
    result = build_kernel_qualification(
        profile=_parse_profile(
            payload.get("profile"), "ISA kernel qualification.profile"
        ),
        semantic_kernel=_parse_kernel(
            payload.get("semantic_kernel"),
            "ISA kernel qualification.semantic_kernel",
        ),
        generator=_parse_generator(
            payload.get("generator"), "ISA kernel qualification.generator"
        ),
        oracle_suite=_parse_suite(
            payload.get("oracle_suite"),
            "ISA kernel qualification.oracle_suite",
        ),
        corpora=tuple(
            _parse_corpus(row, f"ISA kernel qualification.corpora[{index}]")
            for index, row in enumerate(
                _objects(
                    payload.get("corpora"),
                    "ISA kernel qualification.corpora",
                )
            )
        ),
        required_form_ids=required_value,
        forms=tuple(
            parse_form_qualification(row)
            for row in _objects(
                payload.get("forms"), "ISA kernel qualification.forms"
            )
        ),
    )
    hashes_value = payload.get("form_sha256s")
    if not isinstance(hashes_value, list):
        raise ISAKernelQualificationError(
            "ISA kernel qualification.form_sha256s must be a list"
        )
    hashes = tuple(
        _sha256(row, f"ISA kernel qualification.form_sha256s[{index}]")
        for index, row in enumerate(hashes_value)
    )
    if hashes != tuple(row.sha256() for row in result.forms):
        raise ISAKernelQualificationError(
            "ISA kernel qualification form hashes are inconsistent"
        )
    if result.status is not _enum(
        QualificationStatus,
        payload.get("status"),
        "ISA kernel qualification.status",
    ):
        raise ISAKernelQualificationError(
            "ISA kernel qualification status is inconsistent"
        )
    diagnostics = tuple(
        _parse_diagnostic(
            row, f"ISA kernel qualification.diagnostics[{index}]"
        )
        for index, row in enumerate(
            _objects(
                payload.get("diagnostics"),
                "ISA kernel qualification.diagnostics",
            )
        )
    )
    _ordered_diagnostics(diagnostics, "ISA kernel qualification.diagnostics")
    if diagnostics != result.diagnostics:
        raise ISAKernelQualificationError(
            "ISA kernel qualification diagnostics are inconsistent"
        )
    counts = _parse_counts(
        payload.get("counts"),
        "ISA kernel qualification.counts",
        total_name="required_forms",
    )
    if counts != result.counts:
        raise ISAKernelQualificationError(
            "ISA kernel qualification counts are inconsistent"
        )
    expected_layers = _qualification_layers_payload(
            structural_status=result.structural_status,
            structural_statuses=(
                row.structural_status for row in result.forms
            ),
            structural_diagnostics=result.structural_diagnostics,
            structural_total_name="required_forms",
            concrete_oracle_status=result.concrete_oracle_status,
            concrete_oracle_counts=_status_counts(
                (row.concrete_oracle_status for row in result.forms),
                total_name="required_forms",
            ),
            concrete_oracle_diagnostics=result.concrete_oracle_diagnostics,
        )
    _validate_qualification_layers(
            payload.get("qualification_layers"),
            expected=expected_layers,
            context="ISA kernel qualification.qualification_layers",
            structural_total_name="required_forms",
            concrete_oracle_total_name="required_forms",
        )
    _parse_trust(payload.get("trust"), "ISA kernel qualification.trust")
    return replace(result, format=artifact_format)


def serialize_kernel_qualification(
    value: ISAKernelQualification,
) -> dict[str, Any]:
    if not isinstance(value, ISAKernelQualification):
        raise ISAKernelQualificationError(
            "kernel qualification must be an ISAKernelQualification"
        )
    payload = {
        "format": value.format,
        "profile": _profile_payload(value.profile),
        "semantic_kernel": _kernel_payload(value.semantic_kernel),
        "generator": _generator_payload(value.generator),
        "oracle_suite": _suite_payload(value.oracle_suite),
        "corpora": [_corpus_payload(row) for row in value.corpora],
        "required_form_ids": list(value.required_form_ids),
        "forms": [serialize_form_qualification(row) for row in value.forms],
        "form_sha256s": [row.sha256() for row in value.forms],
        "status": value.status.value,
        "diagnostics": [
            _diagnostic_payload(row) for row in value.diagnostics
        ],
        "counts": dict(value.counts),
        "trust": _trust_payload(value.trust),
    }
    if value.format != ISA_KERNEL_QUALIFICATION_FORMAT:
        raise ISAKernelQualificationError(
            "kernel qualification has an unsupported format"
        )
    payload["qualification_layers"] = _qualification_layers_payload(
            structural_status=value.structural_status,
            structural_statuses=(
                row.structural_status for row in value.forms
            ),
            structural_diagnostics=value.structural_diagnostics,
            structural_total_name="required_forms",
            concrete_oracle_status=value.concrete_oracle_status,
            concrete_oracle_counts=_status_counts(
                (row.concrete_oracle_status for row in value.forms),
                total_name="required_forms",
            ),
            concrete_oracle_diagnostics=value.concrete_oracle_diagnostics,
        )
    if parse_kernel_qualification(payload) != value:
        raise ISAKernelQualificationError(
            "kernel qualification is not a valid typed instance"
        )
    return payload


def _parse_requirement(value: Any, context: str) -> BinaryFormRequirement:
    payload = _object(value, context)
    _exact_fields(
        payload, {"form_id", "semantic_form", "source_locations"}, context
    )
    locations = tuple(
        _parse_location(row, f"{context}.source_locations[{index}]")
        for index, row in enumerate(
            _objects(payload.get("source_locations"), f"{context}.source_locations")
        )
    )
    _ordered_locations(
        locations, f"{context}.source_locations", allow_empty=False
    )
    image_hashes: dict[str, str] = {}
    for location in locations:
        previous = image_hashes.setdefault(
            location.image_id, location.image_sha256
        )
        if previous != location.image_sha256:
            raise ISAKernelQualificationError(
                f"{context} uses multiple hashes for image {location.image_id!r}"
            )
    return BinaryFormRequirement(
        form_id=_string(payload.get("form_id"), f"{context}.form_id"),
        semantic_form=_string(
            payload.get("semantic_form"), f"{context}.semantic_form"
        ),
        source_locations=locations,
    )


def _requirement_payload(value: BinaryFormRequirement) -> dict[str, Any]:
    return {
        "form_id": value.form_id,
        "semantic_form": value.semantic_form,
        "source_locations": [
            _location_payload(location) for location in value.source_locations
        ],
    }


def _parse_selected_form(
    value: Any, context: str, *, layered: bool
) -> SelectedFormQualification:
    payload = _object(value, context)
    _exact_fields(
        payload,
        {
            "form_id",
            "semantic_form",
            "source_locations",
            "qualification_sha256",
            "status",
            "diagnostics",
        }
        | ({"qualification_layers"} if layered else set()),
        context,
    )
    locations = tuple(
        _parse_location(row, f"{context}.source_locations[{index}]")
        for index, row in enumerate(
            _objects(payload.get("source_locations"), f"{context}.source_locations")
        )
    )
    _ordered_locations(
        locations, f"{context}.source_locations", allow_empty=False
    )
    diagnostics = tuple(
        _parse_diagnostic(row, f"{context}.diagnostics[{index}]")
        for index, row in enumerate(
            _objects(payload.get("diagnostics"), f"{context}.diagnostics")
        )
    )
    _ordered_diagnostics(diagnostics, f"{context}.diagnostics")
    form_id = _string(payload.get("form_id"), f"{context}.form_id")
    if any(
        diagnostic.form_id != form_id
        or diagnostic.source_locations != locations
        for diagnostic in diagnostics
    ):
        raise ISAKernelQualificationError(
            f"{context} diagnostics are not localized to the selected form"
        )
    result = SelectedFormQualification(
        form_id=form_id,
        semantic_form=_string(
            payload.get("semantic_form"), f"{context}.semantic_form"
        ),
        source_locations=locations,
        qualification_sha256=_optional_sha256(
            payload.get("qualification_sha256"),
            f"{context}.qualification_sha256",
        ),
        status=_enum(
            QualificationStatus, payload.get("status"), f"{context}.status"
        ),
        diagnostics=diagnostics,
    )
    if layered:
        expected_layers = _qualification_layers_payload(
            structural_status=result.structural_status,
            structural_statuses=(result.structural_status,),
            structural_diagnostics=result.structural_diagnostics,
            structural_total_name="required_forms",
            concrete_oracle_status=result.concrete_oracle_status,
            concrete_oracle_counts=_status_counts(
                (result.concrete_oracle_status,),
                total_name="required_forms",
            ),
            concrete_oracle_diagnostics=result.concrete_oracle_diagnostics,
        )
        _validate_qualification_layers(
            payload.get("qualification_layers"),
            expected=expected_layers,
            context=f"{context}.qualification_layers",
            structural_total_name="required_forms",
            concrete_oracle_total_name="required_forms",
        )
    return result


def _selected_form_payload(
    value: SelectedFormQualification, *, layered: bool
) -> dict[str, Any]:
    payload = {
        "form_id": value.form_id,
        "semantic_form": value.semantic_form,
        "source_locations": [
            _location_payload(location) for location in value.source_locations
        ],
        "qualification_sha256": value.qualification_sha256,
        "status": value.status.value,
        "diagnostics": [
            _diagnostic_payload(diagnostic)
            for diagnostic in value.diagnostics
        ],
    }
    if layered:
        payload["qualification_layers"] = _qualification_layers_payload(
            structural_status=value.structural_status,
            structural_statuses=(value.structural_status,),
            structural_diagnostics=value.structural_diagnostics,
            structural_total_name="required_forms",
            concrete_oracle_status=value.concrete_oracle_status,
            concrete_oracle_counts=_status_counts(
                (value.concrete_oracle_status,),
                total_name="required_forms",
            ),
            concrete_oracle_diagnostics=value.concrete_oracle_diagnostics,
        )
    return payload


def _localized(
    diagnostic: MismatchDiagnostic,
    locations: tuple[SourceLocation, ...],
) -> MismatchDiagnostic:
    return replace(diagnostic, source_locations=locations)


def _missing_form_diagnostic(
    requirement: BinaryFormRequirement,
) -> MismatchDiagnostic:
    return MismatchDiagnostic(
        code="missing_required_form",
        form_id=requirement.form_id,
        case_id=None,
        json_path="$",
        reference_backend_id=None,
        observed_backend_id=None,
        reference_result_sha256=None,
        observed_result_sha256=None,
        expected={
            "form_id": requirement.form_id,
            "semantic_form": requirement.semantic_form,
        },
        observed=None,
        source_locations=requirement.source_locations,
        message="required binary form is absent from kernel qualification",
    )


def _semantic_form_diagnostic(
    requirement: BinaryFormRequirement,
    observed: ISAFormQualification,
) -> MismatchDiagnostic:
    return MismatchDiagnostic(
        code="semantic_form_binding_mismatch",
        form_id=requirement.form_id,
        case_id=None,
        json_path="$.semantic_form",
        reference_backend_id=None,
        observed_backend_id=None,
        reference_result_sha256=None,
        observed_result_sha256=None,
        expected=requirement.semantic_form,
        observed=observed.semantic_form,
        source_locations=requirement.source_locations,
        message="required form ID resolves to a different semantic form",
    )


def build_kernel_selection(
    *,
    binary_id: str,
    binary_sha256: str,
    requirements: Iterable[BinaryFormRequirement],
    qualification: ISAKernelQualification,
) -> ISAKernelSelection:
    """Select and localize qualification evidence for one exact binary."""
    binary_id = _string(binary_id, "kernel selection.binary_id")
    binary_sha256 = _sha256(
        binary_sha256, "kernel selection.binary_sha256"
    )
    if not isinstance(qualification, ISAKernelQualification):
        raise ISAKernelQualificationError(
            "qualification must be an ISAKernelQualification"
        )
    raw_requirements = tuple(requirements)
    if any(not isinstance(row, BinaryFormRequirement) for row in raw_requirements):
        raise ISAKernelQualificationError(
            "requirements must be BinaryFormRequirement values"
        )
    requirement_rows = tuple(
        sorted(raw_requirements, key=lambda row: row.form_id)
    )
    if not requirement_rows:
        raise ISAKernelQualificationError(
            "kernel selection requirements must not be empty"
        )
    if tuple(row.form_id for row in requirement_rows) != tuple(
        sorted({row.form_id for row in requirement_rows})
    ):
        raise ISAKernelQualificationError(
            "kernel selection requirement form IDs must be unique"
        )
    for row in requirement_rows:
        _parse_requirement(
            _requirement_payload(row),
            f"kernel selection requirement {row.form_id}",
        )
        if any(
            location.image_sha256 != binary_sha256
            for location in row.source_locations
        ):
            raise ISAKernelQualificationError(
                "kernel selection source location does not bind the selected binary"
            )
    forms_by_id = {row.form_id: row for row in qualification.forms}
    selected: list[SelectedFormQualification] = []
    for requirement in requirement_rows:
        form = forms_by_id.get(requirement.form_id)
        if form is None:
            diagnostics = (_missing_form_diagnostic(requirement),)
            selected.append(
                SelectedFormQualification(
                    form_id=requirement.form_id,
                    semantic_form=requirement.semantic_form,
                    source_locations=requirement.source_locations,
                    qualification_sha256=None,
                    status=QualificationStatus.INCOMPLETE,
                    diagnostics=diagnostics,
                )
            )
            continue
        if form.semantic_form != requirement.semantic_form:
            diagnostics = (_semantic_form_diagnostic(requirement, form),)
            selected.append(
                SelectedFormQualification(
                    form_id=requirement.form_id,
                    semantic_form=requirement.semantic_form,
                    source_locations=requirement.source_locations,
                    qualification_sha256=form.sha256(),
                    status=QualificationStatus.INCOMPLETE,
                    diagnostics=diagnostics,
                )
            )
            continue
        diagnostics = tuple(
            sorted(
                (
                    _localized(diagnostic, requirement.source_locations)
                    for diagnostic in form.diagnostics
                ),
                key=_diagnostic_key,
            )
        )
        selected.append(
            SelectedFormQualification(
                form_id=requirement.form_id,
                semantic_form=requirement.semantic_form,
                source_locations=requirement.source_locations,
                qualification_sha256=form.sha256(),
                status=form.status,
                diagnostics=diagnostics,
            )
        )
    selected_rows = tuple(selected)
    status = _status(row.status for row in selected_rows)
    diagnostics = tuple(
        sorted(
            (
                diagnostic
                for row in selected_rows
                for diagnostic in row.diagnostics
            ),
            key=_diagnostic_key,
        )
    )
    return ISAKernelSelection(
        binary_id=binary_id,
        binary_sha256=binary_sha256,
        profile=qualification.profile,
        semantic_kernel=qualification.semantic_kernel,
        kernel_qualification_sha256=qualification.sha256(),
        required_form_ids=tuple(row.form_id for row in requirement_rows),
        selected_forms=selected_rows,
        status=status,
        diagnostics=diagnostics,
        counts=_status_counts(
            (row.status for row in selected_rows), total_name="required_forms"
        ),
    )


def select_isa_kernel_qualification(
    *,
    binary_id: str,
    binary_sha256: str,
    requirements: Iterable[BinaryFormRequirement],
    qualification: ISAKernelQualification,
) -> ISAKernelSelection:
    """Public builder used by ``spaghetti-extractor-select-isa-kernel-qualification``."""
    return build_kernel_selection(
        binary_id=binary_id,
        binary_sha256=binary_sha256,
        requirements=requirements,
        qualification=qualification,
    )


def parse_kernel_selection(value: Any) -> ISAKernelSelection:
    payload = _object(value, "ISA kernel selection")
    artifact_format = payload.get("format")
    _exact_fields(
        payload,
        {
            "format",
            "binary",
            "profile",
            "semantic_kernel",
            "kernel_qualification_sha256",
            "required_form_ids",
            "selected_forms",
            "status",
            "diagnostics",
            "counts",
            "trust",
            "qualification_layers",
        },
        "ISA kernel selection",
    )
    if artifact_format != ISA_KERNEL_SELECTION_FORMAT:
        raise ISAKernelQualificationError(
            "unsupported ISA kernel selection format"
        )
    binary = _object(payload.get("binary"), "ISA kernel selection.binary")
    _exact_fields(binary, {"id", "sha256"}, "ISA kernel selection.binary")
    required_value = payload.get("required_form_ids")
    if not isinstance(required_value, list):
        raise ISAKernelQualificationError(
            "ISA kernel selection.required_form_ids must be a list"
        )
    required_form_ids = tuple(
        _string(row, f"ISA kernel selection.required_form_ids[{index}]")
        for index, row in enumerate(required_value)
    )
    if (
        not required_form_ids
        or required_form_ids != tuple(sorted(set(required_form_ids)))
    ):
        raise ISAKernelQualificationError(
            "ISA kernel selection required form IDs must be non-empty, unique, "
            "and ordered"
        )
    selected = tuple(
        _parse_selected_form(
            row,
            f"ISA kernel selection.selected_forms[{index}]",
            layered=True,
        )
        for index, row in enumerate(
            _objects(
                payload.get("selected_forms"),
                "ISA kernel selection.selected_forms",
            )
        )
    )
    if tuple(row.form_id for row in selected) != required_form_ids:
        raise ISAKernelQualificationError(
            "ISA kernel selection must contain exactly every required form"
        )
    expected_status = _status(row.status for row in selected)
    status = _enum(
        QualificationStatus,
        payload.get("status"),
        "ISA kernel selection.status",
    )
    if status is not expected_status:
        raise ISAKernelQualificationError(
            "ISA kernel selection status is inconsistent"
        )
    diagnostics = tuple(
        _parse_diagnostic(row, f"ISA kernel selection.diagnostics[{index}]")
        for index, row in enumerate(
            _objects(
                payload.get("diagnostics"),
                "ISA kernel selection.diagnostics",
            )
        )
    )
    _ordered_diagnostics(diagnostics, "ISA kernel selection.diagnostics")
    expected_diagnostics = tuple(
        sorted(
            (
                diagnostic
                for row in selected
                for diagnostic in row.diagnostics
            ),
            key=_diagnostic_key,
        )
    )
    if diagnostics != expected_diagnostics:
        raise ISAKernelQualificationError(
            "ISA kernel selection diagnostics are inconsistent"
        )
    counts = _parse_counts(
        payload.get("counts"),
        "ISA kernel selection.counts",
        total_name="required_forms",
    )
    if counts != _status_counts(
        (row.status for row in selected), total_name="required_forms"
    ):
        raise ISAKernelQualificationError(
            "ISA kernel selection counts are inconsistent"
        )
    _parse_trust(payload.get("trust"), "ISA kernel selection.trust")
    binary_sha256 = _sha256(
        binary.get("sha256"), "ISA kernel selection.binary.sha256"
    )
    if any(
        location.image_sha256 != binary_sha256
        for row in selected
        for location in row.source_locations
    ):
        raise ISAKernelQualificationError(
            "ISA kernel selection source location does not bind its binary"
        )
    result = ISAKernelSelection(
        binary_id=_string(binary.get("id"), "ISA kernel selection.binary.id"),
        binary_sha256=binary_sha256,
        profile=_parse_profile(
            payload.get("profile"), "ISA kernel selection.profile"
        ),
        semantic_kernel=_parse_kernel(
            payload.get("semantic_kernel"),
            "ISA kernel selection.semantic_kernel",
        ),
        kernel_qualification_sha256=_sha256(
            payload.get("kernel_qualification_sha256"),
            "ISA kernel selection.kernel_qualification_sha256",
        ),
        required_form_ids=required_form_ids,
        selected_forms=selected,
        status=status,
        diagnostics=diagnostics,
        counts=counts,
        format=artifact_format,
    )
    expected_layers = _qualification_layers_payload(
            structural_status=result.structural_status,
            structural_statuses=(
                row.structural_status for row in result.selected_forms
            ),
            structural_diagnostics=result.structural_diagnostics,
            structural_total_name="required_forms",
            concrete_oracle_status=result.concrete_oracle_status,
            concrete_oracle_counts=_status_counts(
                (
                    row.concrete_oracle_status
                    for row in result.selected_forms
                ),
                total_name="required_forms",
            ),
            concrete_oracle_diagnostics=result.concrete_oracle_diagnostics,
        )
    _validate_qualification_layers(
            payload.get("qualification_layers"),
            expected=expected_layers,
            context="ISA kernel selection.qualification_layers",
            structural_total_name="required_forms",
            concrete_oracle_total_name="required_forms",
        )
    return result


def serialize_kernel_selection(
    value: ISAKernelSelection,
) -> dict[str, Any]:
    if not isinstance(value, ISAKernelSelection):
        raise ISAKernelQualificationError(
            "kernel selection must be an ISAKernelSelection"
        )
    payload = {
        "format": value.format,
        "binary": {"id": value.binary_id, "sha256": value.binary_sha256},
        "profile": _profile_payload(value.profile),
        "semantic_kernel": _kernel_payload(value.semantic_kernel),
        "kernel_qualification_sha256": value.kernel_qualification_sha256,
        "required_form_ids": list(value.required_form_ids),
        "selected_forms": [
            _selected_form_payload(row, layered=True)
            for row in value.selected_forms
        ],
        "status": value.status.value,
        "diagnostics": [
            _diagnostic_payload(row) for row in value.diagnostics
        ],
        "counts": dict(value.counts),
        "trust": _trust_payload(value.trust),
    }
    if value.format != ISA_KERNEL_SELECTION_FORMAT:
        raise ISAKernelQualificationError(
            "kernel selection has an unsupported format"
        )
    payload["qualification_layers"] = _qualification_layers_payload(
            structural_status=value.structural_status,
            structural_statuses=(
                row.structural_status for row in value.selected_forms
            ),
            structural_diagnostics=value.structural_diagnostics,
            structural_total_name="required_forms",
            concrete_oracle_status=value.concrete_oracle_status,
            concrete_oracle_counts=_status_counts(
                (
                    row.concrete_oracle_status
                    for row in value.selected_forms
                ),
                total_name="required_forms",
            ),
            concrete_oracle_diagnostics=value.concrete_oracle_diagnostics,
        )
    if parse_kernel_selection(payload) != value:
        raise ISAKernelQualificationError(
            "kernel selection is not a valid typed instance"
        )
    return payload
