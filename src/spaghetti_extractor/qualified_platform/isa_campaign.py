"""Target-independent preparation for the shared IA-32 form campaign."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..artifacts.formats import ISA_ENCODING_PROPOSAL_FORMAT
from ..extraction.schema import STATIC_ANALYSIS_MODEL_ID
from ..isa.catalog import ISA_PROFILE_ID
from ..isa.catalog_enrichment import (
    _encoding_id,
    enrich_side_isa_catalog,
)
from ..isa.catalog_enrichment_lean import extract_lean_decoded_metadata
from ..isa.side_adapter import SIDE_ISA_EXECUTABLE_CATALOG_PROPOSAL_FORMAT
from ..util import sha256_file, write_json
from .isa_form_inventory import (
    load_qualified_platform_isa_form_inventory_v1,
)
from .isa_form_replay import (
    _load_kernel,
    reduce_qualified_platform_isa_form_replay_v1,
)


QUALIFIED_PLATFORM_ISA_CATALOG_ADAPTER_V1 = (
    "qualified-platform-isa-form-inventory-adapter-v1"
)


def build_qualified_platform_isa_catalog_proposal_v1(
    *, inventory_path: Path,
) -> dict[str, Any]:
    """Project the frozen intrinsic inventory into the existing enrichment IR."""

    inventory_path = Path(inventory_path)
    inventory = load_qualified_platform_isa_form_inventory_v1(inventory_path)
    forms: list[dict[str, Any]] = []
    encodings: list[dict[str, Any]] = []
    for row in inventory["forms"]:
        form_id = row["form_id"]
        encoded = row["representative_instruction_hex"]
        encoding_id = _encoding_id(form_id, encoded)
        forms.append({
            "form_id": form_id,
            "semantic_form": row["semantic_form"],
            "representative_encoding_id": encoding_id,
            "encoding_ids": [encoding_id],
        })
        encodings.append({
            "format": ISA_ENCODING_PROPOSAL_FORMAT,
            "encoding_id": encoding_id,
            "form_id": form_id,
            "semantic_form": row["semantic_form"],
            "instruction_bytes": list(bytes.fromhex(encoded)),
            "instruction_hex": encoded,
            "source_occurrence_ids": [
                "qualified-platform-isa-form:" + form_id
            ],
            "representative": True,
            "enrichment": {
                "status": "missing",
                "missing_fields": [
                    "defined_outputs",
                    "effects",
                    "required_features",
                ],
            },
        })
    payload = {
        "format": SIDE_ISA_EXECUTABLE_CATALOG_PROPOSAL_FORMAT,
        "status": "incomplete_missing_effect_enrichment",
        "profile": ISA_PROFILE_ID,
        "model": STATIC_ANALYSIS_MODEL_ID,
        "classifier_sha256": inventory["classifier_sha256"],
        "requirements_sha256": inventory["inventory_sha256"],
        "source": {
            "adapter": QUALIFIED_PLATFORM_ISA_CATALOG_ADAPTER_V1,
            "platform_inventory": {
                "sha256": inventory["inventory_sha256"],
                "content_sha256": sha256_file(inventory_path),
            },
        },
        "forms": forms,
        "encodings": encodings,
        "missing_enrichment": {
            "status": "required",
            "fields": ["defined_outputs", "effects", "required_features"],
            "encoding_count": len(encodings),
            "corpus_generation_allowed": False,
        },
        "counts": {
            "forms": len(forms),
            "encodings": len(encodings),
            "occurrences": len(encodings),
            "representatives": len(forms),
        },
        "trust": {
            "role": "untrusted_executable_catalog_enrichment_proposal",
            "proof_authority": False,
        },
    }
    # The digest is not a field in the legacy proposal schema, but calculating
    # it here catches non-JSON values before the expensive Lean pass.
    canonical_sha256_v3(payload)
    return payload


def prepare_qualified_platform_isa_campaign_v1(
    *, inventory_path: Path, semantic_kernel_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Run one Lean pass and emit proposal, enrichment, and replay members."""

    inventory_path = Path(inventory_path)
    proposal = build_qualified_platform_isa_catalog_proposal_v1(
        inventory_path=inventory_path
    )
    metadata, lean_binding = extract_lean_decoded_metadata(
        sorted(proposal["encodings"], key=lambda row: row["encoding_id"]),
        timeout_seconds=1800,
    )
    metadata_in_proposal_order = {
        row["encoding_id"]: metadata[row["encoding_id"]]
        for row in proposal["encodings"]
    }
    enrichment = enrich_side_isa_catalog(
        proposal,
        metadata_in_proposal_order,
        lean_binding=lean_binding,
    )
    inventory = load_qualified_platform_isa_form_inventory_v1(inventory_path)
    kernel, kernel_content_sha256 = _load_kernel(Path(semantic_kernel_path))
    metadata_by_form = {
        row["form_id"]: {
            **metadata_in_proposal_order[row["encoding_id"]],
            "encoding_id": row["form_id"],
        }
        for row in proposal["encodings"]
    }
    replay = reduce_qualified_platform_isa_form_replay_v1(
        inventory=inventory,
        inventory_content_sha256=sha256_file(inventory_path),
        semantic_kernel=kernel,
        semantic_kernel_content_sha256=kernel_content_sha256,
        decoded_metadata=metadata_by_form,
        lean_binding=lean_binding,
    )
    return proposal, enrichment, replay


def write_qualified_platform_isa_campaign_preparation_v1(
    *, inventory_path: Path, semantic_kernel_path: Path, out: Path,
) -> Mapping[str, Any]:
    proposal, enrichment, replay = prepare_qualified_platform_isa_campaign_v1(
        inventory_path=inventory_path,
        semantic_kernel_path=semantic_kernel_path,
    )
    output = Path(out)
    write_json(output.parent / "catalog-proposal.json", proposal)
    write_json(output, enrichment)
    write_json(output.parent / "isa-form-replay.json", replay)
    return enrichment


__all__ = [
    "QUALIFIED_PLATFORM_ISA_CATALOG_ADAPTER_V1",
    "build_qualified_platform_isa_catalog_proposal_v1",
    "prepare_qualified_platform_isa_campaign_v1",
    "write_qualified_platform_isa_campaign_preparation_v1",
]
