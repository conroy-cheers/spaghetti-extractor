"""Project checked form qualification into exact v3 instruction evidence.

The expensive ISA oracle campaign is form-scoped.  This adapter binds those
checked form results back to every exact semantic-index occurrence.  It grants
no authority itself: the v3 ISA phase replays every binding and rejects any
missing, stale, disputed, or mismatched occurrence.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping, Sequence

from .analysis_v3.isa_qualification import (
    ISA_QUALIFICATION_EVIDENCE_ARTIFACT_KIND_V3,
    ISA_QUALIFICATION_EVIDENCE_CODEC_V3,
    ISAOracleObservationV3,
    ISAQualificationEvidenceV3,
    isa_occurrence_id_v3,
    isa_qualification_sha256_v3,
)
from .analysis_v3.semantic_index import SEMANTIC_INDEX_CODEC_V3
from .artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactRecordV3,
    ArtifactSetWriterV3,
    canonical_json_bytes_v3,
    canonical_sha256_v3,
    open_artifact_reader_v3,
)
from .machine_ir_isa_requirements_v2 import (
    parse_machine_ir_isa_requirements_v2,
)
from .machine_ir_isa_selection_v2 import (
    build_machine_ir_isa_selection_certificate_v2,
    parse_machine_ir_isa_selection_certificate_v2,
)


ISA_EVIDENCE_PROJECTION_V3_FORMAT = (
    "spaghetti-extractor-isa-evidence-projection-v3"
)
FALLBACK_CAPABILITY_ID_V3 = "machine-ir-fallback-v3"


class ISAEvidenceProjectionV3Error(ValueError):
    """ISA qualification inputs are stale, incomplete, or contradictory."""


def _load(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ISAEvidenceProjectionV3Error(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ISAEvidenceProjectionV3Error(f"{label} must be an object")
    return value


def emit_isa_evidence_v3(
    *,
    requirements_path: Path,
    selection_authority_path: Path,
    semantic_index_path: Path,
    output_directory: Path,
) -> dict[str, Any]:
    requirements_payload = _load(requirements_path, "ISA requirements")
    authority_payload = _load(selection_authority_path, "ISA selection authority")
    requirements = parse_machine_ir_isa_requirements_v2(requirements_payload)
    certificate = parse_machine_ir_isa_selection_certificate_v2(
        build_machine_ir_isa_selection_certificate_v2(
            requirements=requirements,
            authority=authority_payload,
        )
    )
    semantic = open_artifact_reader_v3(semantic_index_path)
    binary_bindings = tuple(
        row
        for row in semantic.manifest.bindings
        if row.name == "binary" and row.kind == "pe32"
    )
    if len(binary_bindings) != 1:
        raise ISAEvidenceProjectionV3Error(
            "semantic index must have exactly one PE32 binding"
        )
    binary_binding: ArtifactBindingV3 = binary_bindings[0]
    if (
        requirements.binary_sha256 != binary_binding.sha256
        or certificate.binary_sha256 != binary_binding.sha256
    ):
        raise ISAEvidenceProjectionV3Error(
            "ISA qualification and semantic index bind different PE bytes"
        )

    semantic_rows = {
        record.record_id: SEMANTIC_INDEX_CODEC_V3.read(record).value
        for record in semantic.iter_records()
    }
    if len(semantic_rows) != semantic.manifest.record_count:
        raise ISAEvidenceProjectionV3Error("semantic index repeats unit IDs")
    occurrences = requirements.payload.get("occurrences")
    if not isinstance(occurrences, list):
        raise ISAEvidenceProjectionV3Error("ISA requirements omit occurrences")
    occurrence_by_span: dict[tuple[int, int], Mapping[str, Any]] = {}
    for raw in occurrences:
        if not isinstance(raw, Mapping):
            raise ISAEvidenceProjectionV3Error("ISA occurrence is malformed")
        key = (int(raw.get("rva", -1)), int(raw.get("byte_length", -1)))
        if key in occurrence_by_span:
            raise ISAEvidenceProjectionV3Error("ISA occurrence span is duplicated")
        occurrence_by_span[key] = raw

    selected_forms = {str(row["form_id"]): row for row in certificate.forms}
    fallback_by_form = dict(certificate.fallback_capability_ids)
    observation = ISAOracleObservationV3(
        oracle_id="checked-isa-selection-authority-v2",
        verdict="qualified",
        observation_sha256=certificate.selection_authority_sha256,
    )
    records: list[ArtifactRecordV3] = []
    missing: list[dict[str, Any]] = []
    expected_identities: set[tuple[str, int]] = set()
    expected_spans: set[tuple[int, int]] = set()
    for unit_id, unit in sorted(semantic_rows.items()):
        for instruction in unit.instructions:
            key = (unit_id, instruction.index)
            expected_identities.add(key)
            span = (
                instruction.rva_start,
                instruction.rva_end - instruction.rva_start,
            )
            expected_spans.add(span)
            raw = occurrence_by_span.get(span)
            if raw is None:
                missing.append({"unit_id": unit_id, "instruction_index": instruction.index})
                continue
            rva_start = int(raw.get("rva", -1))
            byte_length = int(raw.get("byte_length", -1))
            if (
                rva_start != instruction.rva_start
                or rva_start + byte_length != instruction.rva_end
            ):
                raise ISAEvidenceProjectionV3Error(
                    f"ISA occurrence span contradicts semantic index for {key!r}"
                )
            form_id = str(raw.get("form_id"))
            selected = selected_forms.get(form_id)
            if selected is None or selected.get("status") != "qualified":
                missing.append(
                    {
                        "unit_id": unit_id,
                        "instruction_index": instruction.index,
                        "form_id": form_id,
                        "reason": "form_not_qualified",
                    }
                )
                continue
            qualification_sha256 = selected.get("qualification_sha256")
            if not isinstance(qualification_sha256, str):
                raise ISAEvidenceProjectionV3Error(
                    f"qualified ISA form {form_id!r} lacks a qualification digest"
                )
            if fallback_by_form.get(form_id) is None:
                raise ISAEvidenceProjectionV3Error(
                    f"qualified ISA form {form_id!r} lacks fallback capability"
                )
            semantic_form_id = (
                "semantic-form:"
                + canonical_sha256_v3(str(selected["semantic_form"]))
            )
            record_id = isa_occurrence_id_v3(
                unit_id, instruction.index, instruction.instruction_sha256
            )
            provisional = ISAQualificationEvidenceV3(
                record_id=record_id,
                unit_id=unit_id,
                unit_sha256=unit.unit_sha256,
                pe_sha256=unit.pe_sha256,
                unit_ir_sha256=unit.unit_ir_sha256,
                instruction_index=instruction.index,
                instruction_sha256=instruction.instruction_sha256,
                rva_start=instruction.rva_start,
                rva_end=instruction.rva_end,
                decoded_form_id=form_id,
                selected_form_id=form_id,
                semantic_form=semantic_form_id,
                classifier_sha256=str(
                    requirements.payload["binding"]["classifier_sha256"]
                ),
                semantic_kernel_sha256=str(certificate.kernel["semantics_sha256"]),
                fallback_capability_id=FALLBACK_CAPABILITY_ID_V3,
                qualification_sha256="0" * 64,
                oracle_observations=(observation,),
            )
            evidence = replace(
                provisional,
                qualification_sha256=isa_qualification_sha256_v3(provisional),
            )
            records.append(
                ISA_QUALIFICATION_EVIDENCE_CODEC_V3.write(record_id, evidence)
            )
    unexpected = sorted(set(occurrence_by_span) - expected_spans)
    if unexpected:
        raise ISAEvidenceProjectionV3Error(
            f"ISA requirements contain unknown semantic spans: {unexpected[:8]!r}"
        )

    output_directory = Path(output_directory)
    output_directory.mkdir(parents=True, exist_ok=False)
    manifest = ArtifactSetWriterV3(
        artifact_kind=ISA_QUALIFICATION_EVIDENCE_ARTIFACT_KIND_V3,
        bindings=(binary_binding,),
    ).write(output_directory / "artifact", records)
    metadata = {
        "format": ISA_EVIDENCE_PROJECTION_V3_FORMAT,
        "status": (
            "complete"
            if not missing and certificate.status == "qualified"
            else "incomplete"
        ),
        "artifact_id": manifest.artifact_id,
        "artifact_kind": manifest.artifact_kind,
        "record_ids": [row.record_id for row in records],
        "counts": {
            "semantic_occurrences": len(expected_identities),
            "evidence_records": len(records),
            "missing_occurrences": len(missing),
        },
        "missing": missing,
        "requirements_sha256": certificate.requirements_sha256,
        "selection_authority_sha256": certificate.selection_authority_sha256,
    }
    (output_directory / "metadata.json").write_bytes(
        canonical_json_bytes_v3(metadata)
    )
    return metadata


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument("--selection-authority", type=Path, required=True)
    parser.add_argument("--semantic-index", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    emit_isa_evidence_v3(
        requirements_path=args.requirements,
        selection_authority_path=args.selection_authority,
        semantic_index_path=args.semantic_index,
        output_directory=args.out,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
