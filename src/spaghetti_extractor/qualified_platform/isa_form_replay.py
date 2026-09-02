"""Lean decoder replay for the intrinsic qualified-platform form inventory."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..errors import ToolkitInputError
from ..util import sha256_bytes, sha256_file, write_json
from .formats import (
    ISA_SEMANTIC_KERNEL_BINDING_FORMAT,
    QUALIFIED_PLATFORM_ISA_FORM_REPLAY_FORMAT,
)
from .isa_form_inventory import (
    load_qualified_platform_isa_form_inventory_v1,
)


MAX_QUALIFIED_PLATFORM_ISA_FORM_REPLAY_BYTES = 8 * 1024 * 1024
_KERNEL_FORMAT = ISA_SEMANTIC_KERNEL_BINDING_FORMAT
_FIELDS = {
    "format",
    "status",
    "role",
    "authority",
    "inventory",
    "semantic_kernel",
    "lean_exporter",
    "forms",
    "issues",
    "counts",
    "trust",
    "replay_sha256",
}


class QualifiedPlatformISAFormReplayError(ToolkitInputError):
    """The platform form replay is malformed, stale, or contradictory."""


def _fail(message: str) -> None:
    raise QualifiedPlatformISAFormReplayError(message)


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{context} must be an object")
    return value


def _digest(value: object, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail(f"{context} must be lowercase SHA-256")
    return value


def _load_kernel(path: Path) -> tuple[dict[str, Any], str]:
    source = Path(path)
    try:
        data = source.read_bytes()
        payload = dict(_object(json.loads(data), "semantic kernel"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(f"cannot read semantic kernel: {exc}")
    if (
        set(payload)
        != {"format", "id", "decoder_sha256", "semantics_sha256", "lean_version"}
        or payload.get("format") != _KERNEL_FORMAT
        or not isinstance(payload.get("id"), str)
        or not payload["id"]
    ):
        _fail("semantic kernel binding is malformed")
    _digest(payload.get("decoder_sha256"), "kernel decoder SHA-256")
    _digest(payload.get("semantics_sha256"), "kernel semantics SHA-256")
    return payload, sha256_bytes(data)


def reduce_qualified_platform_isa_form_replay_v1(
    *,
    inventory: Mapping[str, Any],
    inventory_content_sha256: str,
    semantic_kernel: Mapping[str, Any],
    semantic_kernel_content_sha256: str,
    decoded_metadata: Mapping[str, Mapping[str, Any]],
    lean_binding: Mapping[str, str],
) -> dict[str, Any]:
    """Reduce exact Lean outputs without treating replay as qualification."""

    expected_ids = [str(row["form_id"]) for row in inventory["forms"]]
    if list(decoded_metadata) != expected_ids:
        _fail("Lean metadata does not cover the canonical form inventory")
    issues: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []
    for row in inventory["forms"]:
        form_id = str(row["form_id"])
        decoded = _object(decoded_metadata[form_id], f"Lean metadata {form_id}")
        expected_size = len(bytes.fromhex(row["representative_instruction_hex"]))
        reason = None
        if decoded.get("status") != "decoded":
            reason = "representative_decode_failed"
        elif decoded.get("semantic_form") != row["semantic_form"]:
            reason = "representative_semantic_form_mismatch"
        elif decoded.get("decoded_size") != expected_size:
            reason = "representative_size_mismatch"
        if reason is not None:
            issues.append({"kind": reason, "form_id": form_id})
        forms.append({
            "form_id": form_id,
            "representative_instruction_hex": row[
                "representative_instruction_hex"
            ],
            "status": "checked" if reason is None else "rejected",
            "decoded_metadata_sha256": canonical_sha256_v3(decoded),
        })
    binding = _object(lean_binding, "Lean exporter binding")
    if binding.get("classifier_sha256") != inventory["classifier_sha256"]:
        _fail("Lean exporter and inventory classifiers disagree")
    payload: dict[str, Any] = {
        "format": QUALIFIED_PLATFORM_ISA_FORM_REPLAY_FORMAT,
        "status": "complete" if not issues else "violated",
        "role": "lean_decoder_replay_not_qualification",
        "authority": False,
        "inventory": {
            "sha256": inventory["inventory_sha256"],
            "content_sha256": _digest(
                inventory_content_sha256, "inventory content SHA-256"
            ),
        },
        "semantic_kernel": {
            "id": semantic_kernel["id"],
            "decoder_sha256": semantic_kernel["decoder_sha256"],
            "semantics_sha256": semantic_kernel["semantics_sha256"],
            "content_sha256": _digest(
                semantic_kernel_content_sha256,
                "semantic kernel content SHA-256",
            ),
        },
        "lean_exporter": {
            "classifier_sha256": inventory["classifier_sha256"],
            "metadata_exporter_sha256": _digest(
                binding.get("metadata_exporter_sha256"),
                "Lean metadata exporter SHA-256",
            ),
            "lean_version": binding.get("lean_version"),
        },
        "forms": forms,
        "issues": issues,
        "counts": {
            "forms": len(forms),
            "checked": sum(row["status"] == "checked" for row in forms),
            "rejected": sum(row["status"] == "rejected" for row in forms),
        },
        "trust": {
            "qualifies_decoder": False,
            "qualifies_semantics": False,
            "qualifies_inventory_finiteness": False,
            "veto_only": True,
        },
    }
    if not isinstance(payload["lean_exporter"]["lean_version"], str) or not payload[
        "lean_exporter"
    ]["lean_version"]:
        _fail("Lean exporter version is malformed")
    payload["replay_sha256"] = canonical_sha256_v3(payload)
    return payload


def build_qualified_platform_isa_form_replay_v1(
    *, inventory_path: Path, semantic_kernel_path: Path,
) -> dict[str, Any]:
    # Imported lazily so the platform replay parser and release codec do not
    # load the Lean compilation implementation during ordinary inspection.
    from ..isa.catalog_enrichment_lean import extract_lean_decoded_metadata

    inventory_path = Path(inventory_path)
    inventory = load_qualified_platform_isa_form_inventory_v1(inventory_path)
    semantic_kernel, kernel_content_sha256 = _load_kernel(semantic_kernel_path)
    encodings = [
        {
            "encoding_id": row["form_id"],
            "instruction_bytes": list(
                bytes.fromhex(row["representative_instruction_hex"])
            ),
        }
        for row in inventory["forms"]
    ]
    decoded, binding = extract_lean_decoded_metadata(
        encodings,
        timeout_seconds=1800,
    )
    return reduce_qualified_platform_isa_form_replay_v1(
        inventory=inventory,
        inventory_content_sha256=sha256_file(inventory_path),
        semantic_kernel=semantic_kernel,
        semantic_kernel_content_sha256=kernel_content_sha256,
        decoded_metadata=decoded,
        lean_binding=binding,
    )


def parse_qualified_platform_isa_form_replay_v1(value: object) -> dict[str, Any]:
    payload = dict(_object(value, "qualified-platform ISA form replay"))
    if set(payload) != _FIELDS:
        _fail("qualified-platform ISA form replay fields are invalid")
    if payload.get("format") != QUALIFIED_PLATFORM_ISA_FORM_REPLAY_FORMAT:
        _fail("qualified-platform ISA form replay format is unsupported")
    declared = _digest(payload.get("replay_sha256"), "form replay SHA-256")
    core = {key: item for key, item in payload.items() if key != "replay_sha256"}
    if declared != canonical_sha256_v3(core):
        _fail("qualified-platform ISA form replay self hash is stale")
    if (
        payload.get("authority") is not False
        or payload.get("role") != "lean_decoder_replay_not_qualification"
        or payload.get("status") not in {"complete", "violated"}
    ):
        _fail("qualified-platform ISA form replay trust state is invalid")
    forms = payload.get("forms")
    issues = payload.get("issues")
    if not isinstance(forms, list) or not isinstance(issues, list):
        _fail("qualified-platform ISA form replay rows are malformed")
    form_ids = [str(_object(row, "form replay row").get("form_id")) for row in forms]
    if form_ids != sorted(set(form_ids)):
        _fail("qualified-platform ISA form replay form IDs are not canonical")
    counts = _object(payload.get("counts"), "form replay counts")
    checked = sum(row.get("status") == "checked" for row in forms)
    rejected = sum(row.get("status") == "rejected" for row in forms)
    if counts != {"forms": len(forms), "checked": checked, "rejected": rejected}:
        _fail("qualified-platform ISA form replay counts are stale")
    if (payload["status"] == "complete") != (not issues and rejected == 0):
        _fail("qualified-platform ISA form replay status is stale")
    return payload


def write_qualified_platform_isa_form_replay_v1(
    *, inventory_path: Path, semantic_kernel_path: Path, out: Path,
) -> dict[str, Any]:
    payload = build_qualified_platform_isa_form_replay_v1(
        inventory_path=inventory_path,
        semantic_kernel_path=semantic_kernel_path,
    )
    write_json(Path(out), payload)
    return payload


__all__ = [
    "QualifiedPlatformISAFormReplayError",
    "build_qualified_platform_isa_form_replay_v1",
    "parse_qualified_platform_isa_form_replay_v1",
    "reduce_qualified_platform_isa_form_replay_v1",
    "write_qualified_platform_isa_form_replay_v1",
]
