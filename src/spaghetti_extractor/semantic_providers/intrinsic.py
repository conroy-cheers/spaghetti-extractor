"""Qualify intrinsic semantic providers without materializing native code.

Selection is a semantic decision.  Runtime and ingress source generation,
compilation, and linking belong to native realization and are deliberately not
performed here.  This keeps one semantic-provider surface while allowing the
realizer to retain its complete working set in memory and compile in parallel.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..external.formats import RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT
from ..external.resolved import ResolvedExternalEnvironmentV1
from ..semantic_link.module_v2 import LinkedSemanticModuleV2
from ..util import sha256_file, write_json
from .qualification_v2 import write_semantic_provider_qualification_v2
from .slices_v2 import SemanticSliceV2, build_semantic_slice_v2


class IntrinsicProviderError(ValueError):
    """Intrinsic semantic-provider inputs are invalid or conflicting."""


def _load_object(path: Path, context: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntrinsicProviderError(f"cannot read {context}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise IntrinsicProviderError(f"{context} must be a JSON object")
    return dict(value)


def write_external_environment_provider_v2(
    *, linked_semantic_module: Path, provider_id: str, out: Path,
) -> dict[str, Any]:
    """Qualify active checked external definitions as one reusable V2 slice."""

    linked = LinkedSemanticModuleV2.load(
        Path(linked_semantic_module), require_complete=False,
    )
    semantic = linked.semantic_object
    if semantic is None:
        raise IntrinsicProviderError(
            "linked semantic module V2 has no semantic-object package"
        )
    environment_path = semantic.resolved_external_environment_path
    environment = _load_object(
        environment_path, "resolved external environment"
    )
    ResolvedExternalEnvironmentV1.parse(environment)
    if environment.get("format") != RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT:
        raise IntrinsicProviderError("external provider environment is unsupported")
    environment_sha256 = sha256_file(environment_path)
    required_definition_ids = {
        str(row["definition_id"])
        for row in linked.payload["definition_requirements"]
        if row.get("definition_id") is not None
        and "external_environment" in row["allowed_provider_kinds"]
    }
    definitions = [
        row for row in linked.payload["definitions"]
        if row["definition_kind"] == "checked_external_contract"
        and str(row["definition_id"]) in required_definition_ids
    ]
    if not definitions:
        raise IntrinsicProviderError(
            "linked semantic module has no active checked external definitions"
        )
    definition_ids = [str(row["definition_id"]) for row in definitions]
    semantic_slice = SemanticSliceV2.parse(build_semantic_slice_v2(
        linked_semantic_module=linked, definition_ids=definition_ids,
    ))
    materializations = [{
        "definition_id": str(row["definition_id"]),
        "native_symbol": (
            "spx_external_" + canonical_sha256_v3(str(row["symbol_id"]))[:24]
        ),
        "source_sha256s": [],
        "object_sha256s": [],
    } for row in definitions]
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    qualification_path = output / "semantic-provider-qualification.json"
    write_semantic_provider_qualification_v2(
        semantic_slice=semantic_slice,
        provider_id=provider_id,
        provider_kind="external_environment",
        provider_artifact_sha256=environment_sha256,
        facets=[{
            "name": "external_contract",
            "status": (
                "checked" if environment.get("status") == "complete"
                else "incomplete"
            ),
            "receipt_sha256": environment_sha256,
        }],
        definition_materializations=materializations,
        out=qualification_path,
    )
    write_json(output / "definition-choices.json", {
        definition_id: provider_id for definition_id in definition_ids
    })
    return _load_object(
        qualification_path, "external-environment V2 qualification"
    )


__all__ = [
    "IntrinsicProviderError",
    "write_external_environment_provider_v2",
]
