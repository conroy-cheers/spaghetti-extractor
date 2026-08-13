"""Deterministic, checked partitioning for cached ISA oracle campaigns."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping, Sequence

from .isa_conformance import (
    ISAConformanceCorpus,
    ISAConformanceError,
    ISAConformanceReport,
    ObservationStatus,
    ReportCounts,
    ReportQualification,
    ReportTrust,
    isa_conformance_corpus_sha256,
    parse_isa_conformance_report,
    serialize_isa_conformance_report,
)
from .isa_semantic_forms import lean_semantic_form_classifier_sha256


LEAN_SEMANTIC_FORMS_FORMAT = "stage-a-lean-isa-semantic-forms-v1"


def _shard_for_case(case_id: str, shard_count: int) -> int:
    digest = hashlib.sha256(case_id.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % shard_count


def partition_isa_conformance_corpus(
    corpus: ISAConformanceCorpus,
    *,
    shard_index: int,
    shard_count: int,
) -> ISAConformanceCorpus:
    """Return one stable hash shard of a complete conformance corpus."""

    if not isinstance(corpus, ISAConformanceCorpus):
        raise ISAConformanceError("corpus must be an ISAConformanceCorpus")
    if (
        isinstance(shard_count, bool)
        or not isinstance(shard_count, int)
        or shard_count <= 0
    ):
        raise ISAConformanceError("shard_count must be a positive integer")
    if (
        isinstance(shard_index, bool)
        or not isinstance(shard_index, int)
        or not 0 <= shard_index < shard_count
    ):
        raise ISAConformanceError("shard_index must identify one corpus shard")
    cases = tuple(
        case
        for case in corpus.cases
        if _shard_for_case(case.id, shard_count) == shard_index
    )
    if not cases:
        raise ISAConformanceError(
            f"ISA corpus shard {shard_index} of {shard_count} is empty"
        )
    return ISAConformanceCorpus(
        id=f"{corpus.id}:sha256-{shard_index:03d}-of-{shard_count:03d}",
        cases=cases,
    )


def lean_semantic_forms_payload(
    corpus: ISAConformanceCorpus,
    semantic_forms_by_id: Mapping[str, str],
    *,
    x87_definedness_by_id: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Bind Lean-owned form and definedness facts to every corpus case."""

    case_ids = [case.id for case in corpus.cases]
    if set(semantic_forms_by_id) != set(case_ids):
        raise ISAConformanceError(
            "Lean semantic forms must bind every corpus case exactly once"
        )
    definedness = {} if x87_definedness_by_id is None else x87_definedness_by_id
    if not set(definedness).issubset(set(case_ids)):
        raise ISAConformanceError(
            "Lean x87 definedness names a case outside the exact corpus"
        )
    rows = []
    for case_id in case_ids:
        semantic_form = semantic_forms_by_id[case_id]
        if not isinstance(semantic_form, str) or not semantic_form:
            raise ISAConformanceError("Lean semantic form must be nonempty")
        row = {
            "case_id": case_id,
            "semantic_form": semantic_form,
            "x87_defined_outputs": definedness.get(case_id),
        }
        rows.append(row)
    return {
        "format": LEAN_SEMANTIC_FORMS_FORMAT,
        "corpus_id": corpus.id,
        "classifier_sha256": lean_semantic_form_classifier_sha256(),
        "cases": rows,
        "trust": {
            "role": "isa_conformance_evidence_only",
            "proof_authority": False,
            "closes_stage_a_proof": False,
        },
    }


def _parse_lean_semantic_forms(
    corpus: ISAConformanceCorpus,
    value: Mapping[str, Any],
) -> tuple[dict[str, str], dict[str, Mapping[str, Any]]]:
    if set(value) != {
        "format",
        "corpus_id",
        "classifier_sha256",
        "cases",
        "trust",
    }:
        raise ISAConformanceError("Lean semantic-form artifact has invalid fields")
    if value.get("format") != LEAN_SEMANTIC_FORMS_FORMAT:
        raise ISAConformanceError("unsupported Lean semantic-form artifact format")
    if value.get("corpus_id") != corpus.id:
        raise ISAConformanceError("Lean semantic forms bind the wrong corpus")
    if value.get("classifier_sha256") != lean_semantic_form_classifier_sha256():
        raise ISAConformanceError("Lean semantic forms bind the wrong classifier")
    trust = value.get("trust")
    if not isinstance(trust, Mapping) or trust != {
        "role": "isa_conformance_evidence_only",
        "proof_authority": False,
        "closes_stage_a_proof": False,
    }:
        raise ISAConformanceError("Lean semantic forms have invalid trust metadata")
    raw_rows = value.get("cases")
    if not isinstance(raw_rows, list):
        raise ISAConformanceError("Lean semantic-form cases must be a list")
    result: dict[str, str] = {}
    definedness: dict[str, Mapping[str, Any]] = {}
    for row in raw_rows:
        if not isinstance(row, Mapping) or frozenset(row) not in {
            frozenset({"case_id", "semantic_form"}),
            frozenset(
                {"case_id", "semantic_form", "x87_defined_outputs"}
            ),
        }:
            raise ISAConformanceError("Lean semantic-form row is malformed")
        case_id = row.get("case_id")
        semantic_form = row.get("semantic_form")
        if (
            not isinstance(case_id, str)
            or not isinstance(semantic_form, str)
            or not semantic_form
            or case_id in result
        ):
            raise ISAConformanceError("Lean semantic-form row is ambiguous")
        result[case_id] = semantic_form
        x87_defined = row.get("x87_defined_outputs")
        if x87_defined is not None:
            if not isinstance(x87_defined, Mapping):
                raise ISAConformanceError(
                    "Lean x87 definedness must be an object or null"
                )
            definedness[case_id] = x87_defined
    if set(result) != {case.id for case in corpus.cases}:
        raise ISAConformanceError(
            "Lean semantic forms do not cover the exact shard corpus"
        )
    return result, definedness


def merge_isa_conformance_shards(
    corpus: ISAConformanceCorpus,
    *,
    shard_corpora: Sequence[ISAConformanceCorpus],
    shard_reports: Sequence[Mapping[str, Any]],
) -> ISAConformanceReport:
    """Validate and merge exact shard reports into one canonical report."""

    if len(shard_corpora) != len(shard_reports) or not shard_corpora:
        raise ISAConformanceError("ISA shard corpora and reports must correspond")
    observations = {}
    backend = None
    for shard, payload in zip(shard_corpora, shard_reports, strict=True):
        report = parse_isa_conformance_report(payload, corpus=shard)
        if backend is None:
            backend = report.backend
        elif report.backend != backend:
            raise ISAConformanceError("ISA shard reports use different backends")
        for observation in report.observations:
            if observation.case_id in observations:
                raise ISAConformanceError("ISA shard reports overlap")
            observations[observation.case_id] = observation
    expected_ids = [case.id for case in corpus.cases]
    if set(observations) != set(expected_ids):
        raise ISAConformanceError("ISA shard reports do not cover the full corpus")
    ordered = tuple(observations[case_id] for case_id in expected_ids)
    counts = ReportCounts(
        cases=len(ordered),
        matched=sum(row.status is ObservationStatus.MATCH for row in ordered),
        mismatched=sum(
            row.status is ObservationStatus.MISMATCH for row in ordered
        ),
        unsupported=sum(
            row.status is ObservationStatus.UNSUPPORTED for row in ordered
        ),
        errors=sum(row.status is ObservationStatus.ERROR for row in ordered),
    )
    qualification = (
        ReportQualification.VETOED
        if counts.mismatched
        else ReportQualification.UNQUALIFIED
        if counts.unsupported or counts.errors
        else ReportQualification.QUALIFIED
    )
    assert backend is not None
    report = ISAConformanceReport(
        corpus_id=corpus.id,
        input_sha256=isa_conformance_corpus_sha256(corpus),
        backend=backend,
        qualification=qualification,
        observations=ordered,
        counts=counts,
        trust=ReportTrust(),
    )
    return parse_isa_conformance_report(
        serialize_isa_conformance_report(report, corpus=corpus),
        corpus=corpus,
    )


def merge_lean_semantic_form_shards(
    corpus: ISAConformanceCorpus,
    *,
    shard_corpora: Sequence[ISAConformanceCorpus],
    shard_payloads: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Validate and merge exact Lean semantic-form shard artifacts."""

    if len(shard_corpora) != len(shard_payloads) or not shard_corpora:
        raise ISAConformanceError("Lean semantic-form shards must correspond")
    merged: dict[str, str] = {}
    merged_definedness: dict[str, Mapping[str, Any]] = {}
    for shard, payload in zip(shard_corpora, shard_payloads, strict=True):
        shard_forms, shard_definedness = _parse_lean_semantic_forms(shard, payload)
        for case_id, semantic_form in shard_forms.items():
            if case_id in merged:
                raise ISAConformanceError("Lean semantic-form shards overlap")
            merged[case_id] = semantic_form
        for case_id, evidence in shard_definedness.items():
            if case_id in merged_definedness:
                raise ISAConformanceError("Lean x87-definedness shards overlap")
            merged_definedness[case_id] = evidence
    return lean_semantic_forms_payload(
        corpus,
        merged,
        x87_definedness_by_id=merged_definedness,
    )


__all__ = [
    "LEAN_SEMANTIC_FORMS_FORMAT",
    "lean_semantic_forms_payload",
    "merge_isa_conformance_shards",
    "merge_lean_semantic_form_shards",
    "partition_isa_conformance_corpus",
]
