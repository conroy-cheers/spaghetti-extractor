"""Nix-worker entry points for generated ISA qualification artifacts."""

from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path
from typing import Any

from .isa_catalog import (
    ISAFormCatalog,
    XEDInstructionCatalog,
    parse_isa_catalog,
    serialize_xed_instruction_catalog,
)
from .isa_campaign import (
    build_isa_qualification_campaign,
    serialize_isa_qualification_campaign,
)
from .isa_conformance import (
    ISAConformanceError,
    parse_isa_conformance_corpus,
    serialize_isa_conformance_corpus,
)
from .isa_corpus_generator import (
    generate_boundary_isa_corpus,
    generated_corpus_executor_input,
    serialize_generated_isa_corpus,
)
from .isa_catalog_enrichment import (
    SIDE_ISA_CATALOG_ENRICHMENT_FORMAT,
    resolved_isa_catalog,
)
from .isa_kernel_qualification import (
    BinaryFormRequirement,
    BinaryQualificationRequirements,
    ISAKernelQualification,
    ISAKernelQualificationError,
    ISAKernelSelection,
    SemanticKernelBinding,
    SourceLocation,
    parse_kernel_qualification,
    parse_kernel_selection,
    select_isa_kernel_qualification_from_requirements,
    serialize_kernel_qualification,
    serialize_kernel_selection,
)
from .isa_qualification_worker import (
    build_isa_kernel_qualification,
    load_isa_semantic_kernel_binding,
)
from .extraction.isa_requirements import (
    ISARequirementInventory,
)
from .isa_side_adapter import SIDE_ISA_EXECUTABLE_CATALOG_PROPOSAL_FORMAT
from .stage_binary import StageAInputError
from .util import sha256_bytes, sha256_file, write_json


ISA_GENERATED_CORPUS_MANIFEST_FORMAT = "stage-a-generated-isa-corpus-manifest-v1"


def _read_json(path: Path, context: str) -> Mapping[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read {context} {path}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    return value


def _canonical_sha256(value: Any) -> str:
    return sha256_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _catalog_summary(catalog: XEDInstructionCatalog) -> dict[str, Any]:
    dispositions: dict[str, int] = {}
    categories: dict[str, int] = {}
    isa_sets: dict[str, int] = {}
    alias_count = 0
    for row in catalog.templates:
        dispositions[row.disposition.value] = (
            dispositions.get(row.disposition.value, 0) + 1
        )
        categories[row.category] = categories.get(row.category, 0) + 1
        isa_sets[row.isa_set] = isa_sets.get(row.isa_set, 0) + 1
        alias_count += len(row.table_indices) - 1
    return {
        "templates": len(catalog.templates),
        "source_aliases": alias_count,
        "by_disposition": [
            {"disposition": key, "count": dispositions[key]}
            for key in sorted(dispositions)
        ],
        "by_category": [
            {"category": key, "count": categories[key]}
            for key in sorted(categories)
        ],
        "by_isa_set": [
            {"isa_set": key, "count": isa_sets[key]}
            for key in sorted(isa_sets)
        ],
    }


def normalize_isa_catalog(*, catalog: Path, out: Path) -> dict[str, Any]:
    try:
        typed = parse_isa_catalog(_read_json(catalog, "ISA catalog"))
    except ISAConformanceError as exc:
        raise StageAInputError(f"invalid ISA catalog: {exc}") from exc
    if not isinstance(typed, XEDInstructionCatalog):
        raise StageAInputError(
            "catalog normalization currently requires pinned XED metadata"
        )
    payload = serialize_xed_instruction_catalog(typed)
    write_json(out, payload)
    return {
        "format": "stage-a-isa-catalog-normalization-result-v1",
        "status": "complete",
        "profile": typed.profile.id,
        "source_sha256": sha256_file(Path(catalog)),
        "out": str(out),
        "sha256": sha256_file(Path(out)),
        "counts": _catalog_summary(typed),
        "proof_authority": False,
        "closes_stage_a_proof": False,
    }


def write_isa_qualification_campaign(
    *,
    catalog: Path,
    out: Path,
    qualification: Path | None = None,
    selection: Path | None = None,
    crosswalk: Path | None = None,
) -> dict[str, Any]:
    try:
        typed_catalog = parse_isa_catalog(_read_json(catalog, "ISA catalog"))
        if not isinstance(typed_catalog, XEDInstructionCatalog):
            raise StageAInputError(
                "ISA qualification campaigns require the complete XED catalog"
            )
        typed_qualification = (
            None
            if qualification is None
            else parse_kernel_qualification(
                _read_json(qualification, "ISA kernel qualification")
            )
        )
        typed_selection = (
            None
            if selection is None
            else parse_kernel_selection(
                _read_json(selection, "ISA kernel selection")
            )
        )
        form_crosswalk: dict[str, str] = {}
        if crosswalk is not None:
            crosswalk_payload = _read_json(
                crosswalk, "ISA XED-to-Lean form crosswalk"
            )
            if crosswalk_payload.get("format") != ISA_LEAN_FORM_CROSSWALK_FORMAT:
                raise StageAInputError(
                    "unsupported ISA XED-to-Lean form crosswalk format"
                )
            rows = crosswalk_payload.get("cases")
            if not isinstance(rows, list) or any(
                not isinstance(row, Mapping) for row in rows
            ):
                raise StageAInputError(
                    "ISA XED-to-Lean form crosswalk cases must be objects"
                )
            for index, row in enumerate(rows):
                catalog_form_id = row.get("catalog_form_id")
                lean_form_id = row.get("form_id")
                if not isinstance(catalog_form_id, str) or not isinstance(
                    lean_form_id, str
                ):
                    raise StageAInputError(
                        f"ISA XED-to-Lean form crosswalk case {index} is incomplete"
                    )
                previous = form_crosswalk.setdefault(
                    catalog_form_id, lean_form_id
                )
                if previous != lean_form_id:
                    raise StageAInputError(
                        "one XED form maps to multiple Lean semantic forms"
                    )
        campaign = build_isa_qualification_campaign(
            catalog=typed_catalog,
            qualification=typed_qualification,
            selection=typed_selection,
            catalog_form_to_qualification_form=form_crosswalk,
        )
    except (ISAConformanceError, ISAKernelQualificationError) as exc:
        raise StageAInputError(
            f"cannot build ISA qualification campaign: {exc}"
        ) from exc
    write_json(out, serialize_isa_qualification_campaign(campaign))
    return {
        "format": "stage-a-isa-qualification-campaign-result-v1",
        "status": "complete",
        "out": str(out),
        "sha256": sha256_file(Path(out)),
        "counts": dict(campaign.counts),
        "proof_authority": False,
        "closes_stage_a_proof": False,
    }


def generate_isa_corpus(
    *, catalog: Path, seed: int, out: Path
) -> dict[str, Any]:
    exact_encoding_sources: dict[str, Mapping[str, Any]] = {}
    try:
        catalog_payload = _read_json(catalog, "ISA form catalog")
        if (
            catalog_payload.get("format")
            == SIDE_ISA_EXECUTABLE_CATALOG_PROPOSAL_FORMAT
        ):
            raise StageAInputError(
                "cannot generate ISA corpus from a side-ISA catalog proposal: "
                "effects, defined-output masks, and required features are not enriched"
            )
        if catalog_payload.get("format") == SIDE_ISA_CATALOG_ENRICHMENT_FORMAT:
            typed = resolved_isa_catalog(catalog_payload)
            qualified_encoding_ids = {
                entry.encoding_id for entry in typed.entries
            }
            exact_encoding_sources = {
                str(row["encoding_id"]): row
                for row in catalog_payload["encodings"]
                if row["encoding_id"] in qualified_encoding_ids
            }
        else:
            typed = parse_isa_catalog(catalog_payload)
        if not isinstance(typed, ISAFormCatalog):
            raise StageAInputError(
                "raw XED metadata must first be enriched with exact encodings "
                "and generic effect descriptors"
            )
        generated = generate_boundary_isa_corpus(typed, seed=seed)
        executor = generated_corpus_executor_input(generated)
    except (ISAConformanceError, ISAKernelQualificationError) as exc:
        raise StageAInputError(f"cannot generate ISA corpus: {exc}") from exc
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "generated-corpus.json", serialize_generated_isa_corpus(generated))
    write_json(
        out / "corpus.json",
        serialize_isa_conformance_corpus(executor.corpus),
    )
    manifest = {
        "format": ISA_GENERATED_CORPUS_MANIFEST_FORMAT,
        "profile": generated.profile,
        "catalog_sha256": generated.catalog_sha256,
        "generated_corpus": {
            "path": "generated-corpus.json",
            "sha256": sha256_file(out / "generated-corpus.json"),
        },
        "executor_corpus": {
            "path": "corpus.json",
            "sha256": sha256_file(out / "corpus.json"),
            "neutral_expectations": executor.neutral_expectations,
        },
        "cases": [
            {
                "case_id": case.id,
                "catalog_form_id": case.form_id,
                "coverage_cell": case.coverage_cell.id,
                **(
                    {
                        "source_encoding_id": case.form_id,
                        "source_form_id": exact_encoding_sources[case.form_id][
                            "form_id"
                        ],
                        "semantic_form": exact_encoding_sources[case.form_id][
                            "semantic_form"
                        ],
                    }
                    if case.form_id in exact_encoding_sources
                    else {}
                ),
            }
            for case in generated.cases
        ],
        "trust": {
            "role": "untrusted_isa_corpus_generation",
            "proof_authority": False,
            "closes_stage_a_proof": False,
        },
    }
    write_json(out / "manifest.json", manifest)
    return {
        "format": "stage-a-generated-isa-corpus-result-v1",
        "status": "generated",
        "out": str(out),
        "case_count": len(generated.cases),
        **(
            {
                "exact_decoded_encoding_count": catalog_payload["counts"][
                    "encodings"
                ],
                "resolved_encoding_count": catalog_payload["counts"]["resolved"],
                "unresolved_encoding_count": catalog_payload["counts"][
                    "unresolved"
                ],
                "qualified_form_count": catalog_payload["counts"][
                    "qualified_forms"
                ],
                "unresolved_form_count": catalog_payload["counts"][
                    "unresolved_forms"
                ],
            }
            if exact_encoding_sources
            else {}
        ),
        "manifest_sha256": sha256_file(out / "manifest.json"),
        "proof_authority": False,
        "closes_stage_a_proof": False,
    }


def _binary_requirements(
    payload: Mapping[str, Any],
    *,
    side: str,
    profile_id: str,
    semantic_kernel: SemanticKernelBinding,
) -> BinaryQualificationRequirements:
    inventory = ISARequirementInventory.parse(payload).to_payload()
    if side not in {"original", "candidate"}:
        raise StageAInputError("ISA qualification side must be original or candidate")
    binary_sha256 = inventory["inputs"][f"{side}_sha256"]
    if (
        not isinstance(binary_sha256, str)
        or len(binary_sha256) != 64
        or any(character not in "0123456789abcdef" for character in binary_sha256)
    ):
        raise StageAInputError(
            f"ISA requirements do not contain a valid {side} binary identity"
        )
    semantic_forms = {
        row["id"]: row["semantic_form"] for row in inventory["forms"]
    }
    by_form: dict[str, list[SourceLocation]] = {}
    for row in inventory["occurrences"]:
        if row["side"] != side:
            continue
        if row["form_id"] not in semantic_forms:
            raise StageAInputError(
                "ISA requirement occurrence references an unknown semantic form"
            )
        by_form.setdefault(row["form_id"], []).append(
            SourceLocation(
                image_id=side,
                image_sha256=binary_sha256,
                rva=int(row["rva"]),
                byte_length=int(row["size"]),
            )
        )
    forms = tuple(
        BinaryFormRequirement(
            form_id=form_id,
            semantic_form=semantic_forms[form_id],
            source_locations=tuple(
                sorted(
                    set(locations),
                    key=lambda row: (
                        row.image_id,
                        row.image_sha256,
                        row.rva,
                        row.byte_length,
                    ),
                )
            ),
        )
        for form_id, locations in sorted(by_form.items())
    )
    if not forms:
        raise StageAInputError(f"ISA requirements contain no {side} occurrences")
    return BinaryQualificationRequirements(
        binary_id=side,
        binary_sha256=binary_sha256,
        profile_id=profile_id,
        semantic_kernel_id=semantic_kernel.id,
        forms=forms,
    )


def select_isa_kernel_qualification(
    *,
    requirements: Path,
    qualification: Path,
    semantic_kernel: Path,
    side: str,
    out: Path,
) -> dict[str, Any]:
    try:
        typed_qualification = parse_kernel_qualification(
            _read_json(qualification, "ISA kernel qualification")
        )
        expected_kernel = load_isa_semantic_kernel_binding(semantic_kernel)
        selection = select_isa_kernel_qualification_for_inventory(
            requirements=_read_json(requirements, "ISA requirements"),
            qualification=typed_qualification,
            semantic_kernel=expected_kernel,
            side=side,
        )
    except ISAKernelQualificationError as exc:
        raise StageAInputError(f"cannot select ISA qualification: {exc}") from exc
    write_json(out, serialize_kernel_selection(selection))
    return {
        "format": "stage-a-isa-kernel-selection-result-v1",
        "status": selection.status.value,
        "side": side,
        "out": str(out),
        "sha256": sha256_file(Path(out)),
        "counts": dict(selection.counts),
        "proof_authority": False,
        "closes_stage_a_proof": False,
    }


def select_isa_kernel_qualification_for_inventory(
    *,
    requirements: Mapping[str, Any],
    qualification: ISAKernelQualification,
    semantic_kernel: SemanticKernelBinding,
    side: str,
) -> ISAKernelSelection:
    if qualification.semantic_kernel != semantic_kernel:
        raise StageAInputError(
            "ISA kernel qualification does not bind the expected semantic kernel"
        )
    typed_requirements = _binary_requirements(
        requirements,
        side=side,
        profile_id=qualification.profile.id,
        semantic_kernel=semantic_kernel,
    )
    return select_isa_kernel_qualification_from_requirements(
        requirements=typed_requirements,
        qualification=qualification,
    )


__all__ = [
    "build_isa_kernel_qualification",
    "generate_isa_corpus",
    "load_isa_semantic_kernel_binding",
    "normalize_isa_catalog",
    "select_isa_kernel_qualification",
    "select_isa_kernel_qualification_for_inventory",
    "write_isa_qualification_campaign",
]
