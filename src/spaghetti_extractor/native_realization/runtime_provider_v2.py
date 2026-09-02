"""Qualify the generated module runtime for V2 residual obligations.

The provider is deliberately module-scoped: admitted domains, ingress tables,
and the generated runtime sources all depend on the exact linked semantic
module.  It nevertheless uses the ordinary V2 semantic-slice admission and
provider-selection contracts, so the linker has one explicit provider for
every residual obligation and never treats runtime generation as an implicit
fallback.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..candidate.formats import (
    NATIVE_INGRESS_PLAN_FORMAT,
    SHARED_MODULE_RUNTIME_PACKAGE_FORMAT,
)
from ..semantic_link.module_v2 import LinkedSemanticModuleV2
from ..semantic_providers.qualification_v2 import (
    write_semantic_provider_qualification_v2,
)
from ..semantic_providers.slices_v2 import (
    SemanticSliceV2,
    build_semantic_slice_v2,
)
from ..util import sha256_file, write_json
from .materialize import (
    NativeMaterializationError,
    materialize_native_realization_support_v1,
)


class QualifiedRuntimeProviderV2Error(ValueError):
    """The checked module runtime could not qualify its selected contracts."""


def _object(path: Path, context: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise QualifiedRuntimeProviderV2Error(
            f"cannot read {context}: {exc}"
        ) from exc
    if not isinstance(value, Mapping):
        raise QualifiedRuntimeProviderV2Error(f"{context} must be an object")
    return dict(value)


def _runtime_materialization(
    *, root: Path, object_manifest: Mapping[str, Any],
) -> tuple[list[str], list[str], str]:
    rows = object_manifest.get("objects")
    compiler_sha256 = object_manifest.get("compiler_sha256")
    if (
        not isinstance(rows, list) or not rows
        or not isinstance(compiler_sha256, str)
    ):
        raise QualifiedRuntimeProviderV2Error(
            "runtime object manifest is incomplete"
        )
    source_sha256s: set[str] = set()
    object_sha256s: set[str] = set()
    for raw in rows:
        if not isinstance(raw, Mapping):
            raise QualifiedRuntimeProviderV2Error(
                "runtime object manifest row is malformed"
            )
        relative = raw.get("path")
        source_sha256 = raw.get("source_sha256")
        object_sha256 = raw.get("object_sha256")
        if not all(isinstance(value, str) and value for value in (
            relative, source_sha256, object_sha256,
        )):
            raise QualifiedRuntimeProviderV2Error(
                "runtime object row omits content provenance"
            )
        object_path = root / str(relative)
        if not object_path.is_file() or sha256_file(object_path) != object_sha256:
            raise QualifiedRuntimeProviderV2Error(
                "runtime object manifest has a stale object binding"
            )
        source_sha256s.add(str(source_sha256))
        object_sha256s.add(str(object_sha256))
    return sorted(source_sha256s), sorted(object_sha256s), compiler_sha256


def build_qualified_runtime_provider_v2(
    *, linked: LinkedSemanticModuleV2, provider_id: str,
    runtime_package_sha256: str, ingress_plan_sha256: str,
    object_manifest: Mapping[str, Any], object_root: Path,
) -> tuple[dict[str, Any], dict[str, dict[str, str]]]:
    """Build one total V2 qualification from exact generated runtime bytes."""

    definition_requirements = {
        str(row["definition_id"]): row
        for row in linked.payload["definition_requirements"]
        if row.get("definition_id") is not None
        and "qualified_runtime" in row["allowed_provider_kinds"]
    }
    obligations = {
        str(row["obligation_id"]): row
        for row in linked.payload["residual_obligations"]
        if "qualified_runtime" in row["allowed_provider_kinds"]
    }
    if not definition_requirements and not obligations:
        raise QualifiedRuntimeProviderV2Error(
            "linked module has no qualified-runtime contracts"
        )
    sources, objects, compiler_sha256 = _runtime_materialization(
        root=Path(object_root), object_manifest=object_manifest,
    )
    definition_ids = sorted(definition_requirements)
    obligation_ids = sorted(obligations)
    semantic_slice = SemanticSliceV2.parse(build_semantic_slice_v2(
        linked_semantic_module=linked,
        definition_ids=definition_ids,
        obligation_ids=obligation_ids,
    ))
    native_symbol = "spx_native_runtime_run_at_rva"
    definition_rows = [{
        "definition_id": definition_id,
        "native_symbol": native_symbol,
        "source_sha256s": sources,
        "object_sha256s": objects,
    } for definition_id in definition_ids]
    obligation_rows = [{
        "obligation_id": obligation_id,
        "native_symbol": native_symbol,
        "receipt_sha256": canonical_sha256_v3({
            "obligation": obligations[obligation_id],
            "runtime_package_sha256": runtime_package_sha256,
            "ingress_plan_sha256": ingress_plan_sha256,
            "object_sha256s": objects,
        }),
        "source_sha256s": sources,
        "object_sha256s": objects,
    } for obligation_id in obligation_ids]
    artifact_sha256 = canonical_sha256_v3({
        "runtime_package_sha256": runtime_package_sha256,
        "ingress_plan_sha256": ingress_plan_sha256,
        "object_manifest_receipt_sha256": object_manifest.get(
            "receipt_sha256"
        ),
        "object_sha256s": objects,
    })
    facet_receipt = canonical_sha256_v3({
        "provider_id": provider_id,
        "semantic_slice_sha256": semantic_slice.identity,
        "artifact_sha256": artifact_sha256,
    })
    from ..semantic_providers.qualification_v2 import (
        build_semantic_provider_qualification_v2,
    )
    qualification = build_semantic_provider_qualification_v2(
        semantic_slice=semantic_slice,
        provider_id=provider_id,
        provider_kind="qualified_runtime",
        provider_artifact_sha256=artifact_sha256,
        facets=[
            {
                "name": "reviewed_native_primitive",
                "status": "checked",
                "receipt_sha256": facet_receipt,
            },
            {
                "name": "runtime_qualification",
                "status": "checked",
                "receipt_sha256": runtime_package_sha256,
            },
        ],
        definition_materializations=definition_rows,
        obligation_implementations=obligation_rows,
        tool_sha256s=[compiler_sha256],
        dependencies=[
            f"linked-semantic-module-v2:{linked.identity}",
            f"native-ingress-plan-v1:{ingress_plan_sha256}",
        ],
    )
    choices = {
        "definitions": {
            definition_id: provider_id for definition_id in definition_ids
        },
        "obligations": {
            obligation_id: provider_id for obligation_id in obligation_ids
        },
    }
    return qualification, choices


def build_incomplete_qualified_runtime_provider_v2(
    *, linked: LinkedSemanticModuleV2, provider_id: str,
    compiler_sha256: str, blocker: Mapping[str, Any] | None = None,
    diagnostic_artifact_sha256s: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, dict[str, str]]]:
    """Describe an unavailable runtime without granting materialization.

    The qualification deliberately owns no definitions or obligations and
    publishes no choices.  It covers both a semantically incomplete module,
    which cannot be planned, and a semantically complete module whose checked
    native-ingress/runtime plan returned structured blockers.  Unexpected
    rendering, compilation, or artifact failures never enter this path.
    """

    definition_ids = sorted(
        str(row["definition_id"])
        for row in linked.payload["definition_requirements"]
        if row.get("definition_id") is not None
        and "qualified_runtime" in row["allowed_provider_kinds"]
    )
    obligation_ids = sorted(
        str(row["obligation_id"])
        for row in linked.payload["residual_obligations"]
        if "qualified_runtime" in row["allowed_provider_kinds"]
    )
    if not definition_ids and not obligation_ids:
        raise QualifiedRuntimeProviderV2Error(
            "linked module has no qualified-runtime contracts"
        )
    semantic_slice = SemanticSliceV2.parse(build_semantic_slice_v2(
        linked_semantic_module=linked,
        definition_ids=definition_ids,
        obligation_ids=obligation_ids,
    ))
    diagnostic_hashes = dict(diagnostic_artifact_sha256s or {})
    unavailable = dict(blocker) if blocker is not None else {
        "code": "linked_semantic_module_incomplete",
        "linked_semantic_module_sha256": linked.identity,
        "semantic_hole_ids": [
            row["hole_id"] for row in linked.payload["semantic_holes"]
        ],
    }
    artifact_sha256 = canonical_sha256_v3({
        "kind": "unmaterialized-qualified-runtime-v2",
        "semantic_slice_sha256": semantic_slice.identity,
        "compiler_sha256": compiler_sha256,
        "diagnostic_artifact_sha256s": diagnostic_hashes,
        "blocker": unavailable,
    })
    receipt_sha256 = canonical_sha256_v3({
        "linked_semantic_module_sha256": linked.identity,
        "diagnostic_artifact_sha256s": diagnostic_hashes,
        "blocker": unavailable,
    })
    from ..semantic_providers.qualification_v2 import (
        build_semantic_provider_qualification_v2,
    )
    qualification = build_semantic_provider_qualification_v2(
        semantic_slice=semantic_slice,
        provider_id=provider_id,
        provider_kind="qualified_runtime",
        provider_artifact_sha256=artifact_sha256,
        facets=[
            {
                "name": "reviewed_native_primitive",
                "status": "incomplete",
                "receipt_sha256": receipt_sha256,
            },
            {
                "name": "runtime_qualification",
                "status": "incomplete",
                "receipt_sha256": receipt_sha256,
            },
        ],
        tool_sha256s=[compiler_sha256],
        dependencies=[f"linked-semantic-module-v2:{linked.identity}"],
        blockers=[unavailable],
    )
    return qualification, {"definitions": {}, "obligations": {}}


def write_qualified_runtime_provider_v2(
    *, linked_semantic_module: Path, behavioral_c_package: Path,
    compiler: Path, nm: Path, provider_id: str, out: Path,
    pinned_layout_authorities: Sequence[Mapping[str, Any]] = (),
    recovered_executable_data: Path | None = None,
) -> dict[str, Any]:
    """Render, compile, and qualify the exact generated V2 module runtime."""

    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    linked = LinkedSemanticModuleV2.load(
        Path(linked_semantic_module), require_complete=False,
    )
    if linked.payload["status"] != "complete":
        qualification, choices = build_incomplete_qualified_runtime_provider_v2(
            linked=linked,
            provider_id=provider_id,
            compiler_sha256=sha256_file(Path(compiler)),
        )
        qualification_path = output / "semantic-provider-qualification.json"
        write_json(qualification_path, qualification)
        write_json(output / "implementation-choices.json", choices)
        return qualification
    try:
        materialized = materialize_native_realization_support_v1(
            linked_semantic_module=Path(linked_semantic_module),
            behavioral_c_package=Path(behavioral_c_package),
            compiler=Path(compiler),
            nm=Path(nm),
            out=output,
            pinned_layout_authorities=tuple(pinned_layout_authorities),
            recovered_executable_data=recovered_executable_data,
        )
    except NativeMaterializationError as exc:
        if exc.planning_blockers is None:
            raise
        runtime_path = output / "shared-module-runtime-package.json"
        ingress_path = output / "native-ingress-plan.json"
        runtime = _object(runtime_path, "incomplete shared runtime package")
        ingress = _object(ingress_path, "incomplete native ingress plan")
        if (
            runtime.get("format") != SHARED_MODULE_RUNTIME_PACKAGE_FORMAT
            or runtime.get("status") != "incomplete"
            or runtime.get("blockers") != list(exc.planning_blockers)
            or ingress.get("format") != NATIVE_INGRESS_PLAN_FORMAT
            or ingress.get("status") not in {"complete", "incomplete"}
            or (
                ingress.get("status") == "complete"
                and ingress.get("blockers") != []
            )
        ):
            raise QualifiedRuntimeProviderV2Error(
                "structured runtime-planning failure has stale diagnostics"
            ) from exc
        diagnostic_hashes = {
            "native_ingress_plan": sha256_file(ingress_path),
            "shared_module_runtime_package": sha256_file(runtime_path),
        }
        qualification, choices = build_incomplete_qualified_runtime_provider_v2(
            linked=linked,
            provider_id=provider_id,
            compiler_sha256=sha256_file(Path(compiler)),
            diagnostic_artifact_sha256s=diagnostic_hashes,
            blocker={
                "code": "runtime_materialization_incomplete",
                "linked_semantic_module_sha256": linked.identity,
                "diagnostic_artifact_sha256s": diagnostic_hashes,
                "runtime_blockers": list(exc.planning_blockers),
            },
        )
        write_json(output / "semantic-provider-qualification.json", qualification)
        write_json(output / "implementation-choices.json", choices)
        return qualification
    object_manifest = _object(
        materialized["object_manifest"], "runtime object manifest"
    )
    runtime_manifest_path = output / "shared-module-runtime-package.json"
    ingress_path = materialized["native_ingress_plan"]
    qualification, choices = build_qualified_runtime_provider_v2(
        linked=linked,
        provider_id=provider_id,
        runtime_package_sha256=sha256_file(runtime_manifest_path),
        ingress_plan_sha256=sha256_file(ingress_path),
        object_manifest=object_manifest,
        object_root=output,
    )
    qualification_path = output / "semantic-provider-qualification.json"
    write_semantic_provider_qualification_v2(
        semantic_slice=SemanticSliceV2.parse(qualification["semantic_slice"]),
        provider_id=provider_id,
        provider_kind="qualified_runtime",
        provider_artifact_sha256=qualification["bindings"][
            "provider_artifact_sha256"
        ],
        facets=qualification["facets"],
        definition_materializations=qualification[
            "definition_materializations"
        ],
        obligation_implementations=qualification[
            "obligation_implementations"
        ],
        tool_sha256s=qualification["tool_sha256s"],
        dependencies=qualification["dependencies"],
        out=qualification_path,
    )
    write_json(output / "implementation-choices.json", choices)
    return qualification


__all__ = [
    "QualifiedRuntimeProviderV2Error",
    "build_qualified_runtime_provider_v2",
    "build_incomplete_qualified_runtime_provider_v2",
    "write_qualified_runtime_provider_v2",
]
