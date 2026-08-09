"""Narrow artifact worker for checked ISA qualification aggregation."""

from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path
from typing import Any

from .isa_conformance import (
    parse_isa_conformance_corpus,
    parse_isa_conformance_report,
)
from .isa_corpus_generator import parse_generated_isa_corpus
from .isa_kernel_qualification import (
    BackendBinding,
    BackendRole,
    GeneratorBinding,
    ISAProfileBinding,
    OracleSuiteBinding,
    SemanticKernelBinding,
    build_isa_kernel_qualification_from_reports,
    serialize_kernel_qualification,
)
from .isa_semantic_forms import lean_semantic_form_id
from .stage_binary import StageAInputError
from .util import sha256_file, write_json


ISA_LEAN_FORM_CROSSWALK_FORMAT = "stage-a-isa-lean-form-crosswalk-v1"


def _read_json(path: Path, context: str) -> Mapping[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read {context} {path}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    return value


def load_isa_semantic_kernel_binding(path: Path) -> SemanticKernelBinding:
    payload = _read_json(path, "ISA semantic-kernel binding")
    if payload.get("format") != "stage-a-isa-semantic-kernel-binding-v1":
        raise StageAInputError("unsupported ISA semantic-kernel binding format")
    try:
        return SemanticKernelBinding(
            id=str(payload["id"]),
            decoder_sha256=str(payload["decoder_sha256"]),
            semantics_sha256=str(payload["semantics_sha256"]),
            lean_version=str(payload["lean_version"]),
        )
    except KeyError as exc:
        raise StageAInputError(
            f"ISA semantic-kernel binding omits {exc.args[0]}"
        ) from exc


def _lean_form_crosswalk(
    *,
    corpus: Mapping[str, Any],
    lean_forms: Mapping[str, Any],
    generated_corpus: Mapping[str, Any] | None,
) -> tuple[dict[str, str], dict[str, str], dict[str, Any]]:
    typed_corpus = parse_isa_conformance_corpus(corpus)
    if lean_forms.get("format") != "stage-a-lean-isa-semantic-forms-v1":
        raise StageAInputError("unsupported Lean semantic-form artifact")
    if lean_forms.get("corpus_id") != typed_corpus.id:
        raise StageAInputError("Lean semantic forms name the wrong corpus")
    classifier_sha256 = lean_forms.get("classifier_sha256")
    if (
        not isinstance(classifier_sha256, str)
        or len(classifier_sha256) != 64
        or any(ch not in "0123456789abcdef" for ch in classifier_sha256)
    ):
        raise StageAInputError("Lean semantic forms have an invalid classifier hash")
    rows = lean_forms.get("cases")
    if not isinstance(rows, list) or any(not isinstance(row, Mapping) for row in rows):
        raise StageAInputError("Lean semantic-form cases must be objects")
    case_ids = [case.id for case in typed_corpus.cases]
    if [row.get("case_id") for row in rows] != case_ids:
        raise StageAInputError(
            "Lean semantic forms must classify every corpus case exactly once"
        )
    forms_by_case: dict[str, str] = {}
    semantic_forms_by_id: dict[str, str] = {}
    crosswalk_rows: list[dict[str, Any]] = []
    catalog_forms_by_case: dict[str, str] = {}
    if generated_corpus is not None:
        typed_generated = parse_generated_isa_corpus(generated_corpus)
        catalog_forms_by_case = {
            case.id: case.form_id for case in typed_generated.cases
        }
        if set(catalog_forms_by_case) != set(case_ids):
            raise StageAInputError(
                "generated ISA corpus does not bind every executor case"
            )
    for row in rows:
        case_id = row.get("case_id")
        semantic_form = row.get("semantic_form")
        if not isinstance(case_id, str) or not isinstance(semantic_form, str):
            raise StageAInputError("Lean semantic-form row is malformed")
        form_id = lean_semantic_form_id(
            semantic_form,
            classifier_sha256=classifier_sha256,
        )
        previous = semantic_forms_by_id.setdefault(form_id, semantic_form)
        if previous != semantic_form:
            raise StageAInputError("Lean semantic-form identity collision")
        forms_by_case[case_id] = form_id
        crosswalk_rows.append(
            {
                "case_id": case_id,
                "catalog_form_id": catalog_forms_by_case.get(case_id),
                "form_id": form_id,
                "semantic_form": semantic_form,
            }
        )
    crosswalk = {
        "format": ISA_LEAN_FORM_CROSSWALK_FORMAT,
        "corpus_id": typed_corpus.id,
        "classifier_sha256": classifier_sha256,
        "cases": crosswalk_rows,
        "trust": {
            "role": "lean_classifier_derived_isa_crosswalk",
            "proof_authority": False,
            "closes_stage_a_proof": False,
        },
    }
    return forms_by_case, semantic_forms_by_id, crosswalk


def build_isa_kernel_qualification(
    *,
    corpus: Path,
    lean_forms: Path,
    bochs_report: Path,
    unicorn_report: Path,
    lean_report: Path,
    semantic_kernel: Path,
    out: Path,
    crosswalk_out: Path | None = None,
    generated_corpus: Path | None = None,
) -> dict[str, Any]:
    corpus_payload = _read_json(corpus, "ISA executor corpus")
    typed_corpus = parse_isa_conformance_corpus(corpus_payload)
    reports = [
        parse_isa_conformance_report(
            _read_json(path, f"{label} ISA report"), corpus=typed_corpus
        )
        for label, path in (
            ("Bochs", bochs_report),
            ("Unicorn", unicorn_report),
            ("Lean", lean_report),
        )
    ]
    form_ids, semantic_forms, crosswalk = _lean_form_crosswalk(
        corpus=corpus_payload,
        lean_forms=_read_json(lean_forms, "Lean semantic forms"),
        generated_corpus=(
            None
            if generated_corpus is None
            else _read_json(generated_corpus, "generated ISA corpus")
        ),
    )
    first_profile = typed_corpus.cases[0].profile
    if any(case.profile != first_profile for case in typed_corpus.cases):
        raise StageAInputError("ISA corpus mixes qualification profiles")
    profile = ISAProfileBinding(
        id="pe32-i686-v1",
        architecture=first_profile.architecture,
        cpu=first_profile.cpu,
        execution_mode=first_profile.execution_mode,
        environment=first_profile.environment,
        features=first_profile.features,
    )
    backends = [
        BackendBinding(role=role, id=report.backend.id, version=report.backend.version)
        for role, report in (
            (BackendRole.BOCHS, reports[0]),
            (BackendRole.UNICORN, reports[1]),
            (BackendRole.LEAN, reports[2]),
        )
    ]
    if len({report.backend.id for report in reports}) != 3:
        raise StageAInputError("ISA qualification reports reuse a backend identity")
    qualification = build_isa_kernel_qualification_from_reports(
        corpus=typed_corpus,
        reports=reports,
        form_ids_by_case=form_ids,
        semantic_forms_by_id=semantic_forms,
        profile=profile,
        semantic_kernel=load_isa_semantic_kernel_binding(semantic_kernel),
        generator=GeneratorBinding(
            id="stage-a-generic-isa-corpus-generator",
            version="v1",
        ),
        oracle_suite=OracleSuiteBinding(tuple(backends)),
    )
    write_json(out, serialize_kernel_qualification(qualification))
    if crosswalk_out is not None:
        write_json(crosswalk_out, crosswalk)
    return {
        "format": "stage-a-isa-kernel-qualification-result-v1",
        "status": qualification.status.value,
        "out": str(out),
        "sha256": sha256_file(out),
        "crosswalk_out": str(crosswalk_out) if crosswalk_out is not None else None,
        "counts": dict(qualification.counts),
        "proof_authority": False,
        "closes_stage_a_proof": False,
    }


__all__ = [
    "build_isa_kernel_qualification",
    "load_isa_semantic_kernel_binding",
]
