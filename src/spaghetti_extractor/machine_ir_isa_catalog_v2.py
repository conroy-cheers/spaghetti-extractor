"""Adapt exact machine-IR ISA requirements into oracle-campaign inputs."""

from __future__ import annotations

import copy
from collections import defaultdict
from collections.abc import Mapping
from typing import Any

from .analysis.schema import STATIC_ANALYSIS_MODEL_ID
from .artifact_identity_v2 import canonical_sha256
from .isa_catalog import ISA_PROFILE_ID
from .isa_semantic_forms import (
    lean_semantic_form_classifier_sha256,
    lean_semantic_form_id,
)
from .isa_side_adapter import SIDE_ISA_EXECUTABLE_CATALOG_PROPOSAL_FORMAT
from .machine_ir_isa_requirements_v2 import MACHINE_IR_ISA_REQUIREMENTS_V2_FORMAT
from .machine_ir_isa_requirements_v2 import (
    parse_machine_ir_isa_requirements_v2,
)


MACHINE_IR_ISA_CATALOG_ADAPTER_V2 = "machine-ir-isa-catalog-adapter-v2"
_ENCODING_FORMAT = "stage-a-side-isa-executable-encoding-proposal-v1"


class MachineIRISACatalogV2Error(ValueError):
    """Exact machine-IR requirements cannot form a qualification campaign."""


def build_machine_ir_isa_catalog_proposal_v2(
    requirements: Mapping[str, Any],
) -> dict[str, Any]:
    """Produce one exact-encoding proposal for each reachable semantic form."""

    try:
        typed = parse_machine_ir_isa_requirements_v2(requirements)
    except ValueError as exc:
        raise MachineIRISACatalogV2Error(
            f"invalid machine-IR ISA requirements: {exc}"
        ) from exc
    if typed.status != "complete":
        raise MachineIRISACatalogV2Error(
            "only complete exact ISA requirements may seed qualification"
        )
    requirements = typed.to_payload()
    binding = _mapping(requirements.get("binding"), "requirements binding")
    binary_sha256 = _digest(binding.get("binary_sha256"), "binary SHA-256")
    classifier_sha256 = _digest(
        binding.get("classifier_sha256"), "classifier SHA-256"
    )
    if classifier_sha256 != lean_semantic_form_classifier_sha256():
        raise MachineIRISACatalogV2Error("requirements use a stale classifier")
    requirements_sha256 = _digest(
        requirements.get("requirements_sha256"), "requirements SHA-256"
    )
    raw_forms = requirements.get("forms")
    raw_occurrences = requirements.get("occurrences")
    if not isinstance(raw_forms, list) or not raw_forms:
        raise MachineIRISACatalogV2Error("requirements contain no forms")
    if not isinstance(raw_occurrences, list) or not raw_occurrences:
        raise MachineIRISACatalogV2Error("requirements contain no occurrences")

    semantic_forms: dict[str, str] = {}
    for index, row in enumerate(raw_forms):
        item = _mapping(row, f"form {index}")
        form_id = _string(item.get("id"), f"form {index} ID")
        semantic_form = _string(
            item.get("semantic_form"), f"form {index} semantic form"
        )
        if form_id != lean_semantic_form_id(
            semantic_form,
            classifier_sha256=classifier_sha256,
        ):
            raise MachineIRISACatalogV2Error(
                f"form {index} has a noncanonical semantic identity"
            )
        if form_id in semantic_forms:
            raise MachineIRISACatalogV2Error("requirements repeat a form ID")
        semantic_forms[form_id] = semantic_form

    encodings: dict[tuple[str, str], dict[str, Any]] = {}
    occurrence_ids: set[str] = set()
    for index, row in enumerate(raw_occurrences):
        item = _mapping(row, f"occurrence {index}")
        form_id = _string(item.get("form_id"), f"occurrence {index} form ID")
        if form_id not in semantic_forms:
            raise MachineIRISACatalogV2Error(
                f"occurrence {index} names an unknown form"
            )
        encoded = _instruction_hex(item.get("bytes"), f"occurrence {index} bytes")
        byte_length = item.get("byte_length")
        if (
            not isinstance(byte_length, int)
            or isinstance(byte_length, bool)
            or byte_length != len(encoded) // 2
        ):
            raise MachineIRISACatalogV2Error(
                f"occurrence {index} byte length disagrees with its encoding"
            )
        occurrence_core = {
            "unit_id": _string(item.get("unit_id"), f"occurrence {index} unit"),
            "instruction_index": _uint(
                item.get("instruction_index"), f"occurrence {index} instruction index"
            ),
            "rva": _uint(item.get("rva"), f"occurrence {index} RVA"),
            "byte_length": byte_length,
            "bytes": encoded,
            "form_id": form_id,
        }
        occurrence_id = "machine-ir-isa-occurrence-v2:" + canonical_sha256(
            occurrence_core
        )
        if occurrence_id in occurrence_ids:
            raise MachineIRISACatalogV2Error("requirements repeat an occurrence")
        occurrence_ids.add(occurrence_id)
        key = (form_id, encoded)
        encoding = encodings.setdefault(
            key,
            {
                "format": _ENCODING_FORMAT,
                "encoding_id": _encoding_id(form_id, encoded),
                "form_id": form_id,
                "semantic_form": semantic_forms[form_id],
                "instruction_bytes": list(bytes.fromhex(encoded)),
                "instruction_hex": encoded,
                "source_occurrence_ids": [],
                "representative": False,
                "enrichment": {
                    "status": "missing",
                    "missing_fields": [
                        "defined_outputs",
                        "effects",
                        "required_features",
                    ],
                },
            },
        )
        encoding["source_occurrence_ids"].append(occurrence_id)

    for row in encodings.values():
        row["source_occurrence_ids"].sort()
    forms: list[dict[str, Any]] = []
    for form_id in sorted(semantic_forms):
        rows = sorted(
            (row for (candidate, _), row in encodings.items() if candidate == form_id),
            key=lambda row: (len(row["instruction_bytes"]), row["instruction_hex"]),
        )
        if not rows:
            raise MachineIRISACatalogV2Error(
                f"form {form_id} has no exact occurrence"
            )
        rows[0]["representative"] = True
        forms.append(
            {
                "form_id": form_id,
                "semantic_form": semantic_forms[form_id],
                "representative_encoding_id": rows[0]["encoding_id"],
                "encoding_ids": sorted(row["encoding_id"] for row in rows),
            }
        )

    encoding_rows = sorted(
        (copy.deepcopy(row) for row in encodings.values()),
        key=lambda row: (row["form_id"], row["instruction_hex"]),
    )
    proposal = {
        "format": SIDE_ISA_EXECUTABLE_CATALOG_PROPOSAL_FORMAT,
        "status": "incomplete_missing_effect_enrichment",
        "profile": ISA_PROFILE_ID,
        "model": STATIC_ANALYSIS_MODEL_ID,
        "classifier_sha256": classifier_sha256,
        "requirements_sha256": requirements_sha256,
        "source": {
            "adapter": MACHINE_IR_ISA_CATALOG_ADAPTER_V2,
            "side_isa_artifacts": [
                {
                    "side": "original",
                    "binary_sha256": binary_sha256,
                    "artifact_sha256": canonical_sha256(requirements),
                }
            ],
        },
        "forms": forms,
        "encodings": encoding_rows,
        "missing_enrichment": {
            "status": "required",
            "fields": ["defined_outputs", "effects", "required_features"],
            "encoding_count": len(encoding_rows),
            "corpus_generation_allowed": False,
        },
        "counts": {
            "forms": len(forms),
            "encodings": len(encoding_rows),
            "occurrences": len(occurrence_ids),
            "representatives": len(forms),
        },
        "trust": {
            "role": "untrusted_executable_catalog_enrichment_proposal",
            "proof_authority": False,
            "closes_stage_a_proof": False,
        },
    }
    return proposal


def _encoding_id(form_id: str, encoded: str) -> str:
    return "lean-x86-encoding-" + canonical_sha256(
        {"form_id": form_id, "bytes": encoded}
    )[:24]


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise MachineIRISACatalogV2Error(f"{context} must be an object")
    return value


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise MachineIRISACatalogV2Error(f"{context} must be a canonical string")
    return value


def _digest(value: Any, context: str) -> str:
    result = _string(value, context)
    if len(result) != 64 or any(character not in "0123456789abcdef" for character in result):
        raise MachineIRISACatalogV2Error(f"{context} is not a SHA-256 digest")
    return result


def _uint(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**32:
        raise MachineIRISACatalogV2Error(f"{context} is not an unsigned 32-bit integer")
    return value


def _instruction_hex(value: Any, context: str) -> str:
    encoded = _string(value, context)
    if (
        len(encoded) % 2
        or not 1 <= len(encoded) // 2 <= 15
        or any(character not in "0123456789abcdef" for character in encoded)
    ):
        raise MachineIRISACatalogV2Error(f"{context} is not an x86 instruction")
    return encoded


__all__ = [
    "MACHINE_IR_ISA_CATALOG_ADAPTER_V2",
    "MachineIRISACatalogV2Error",
    "build_machine_ir_isa_catalog_proposal_v2",
]
