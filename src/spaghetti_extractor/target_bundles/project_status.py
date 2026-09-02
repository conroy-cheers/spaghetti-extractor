"""Non-authorizing work views over materialized semantic-module products."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ..operator.work_status import write_operator_work_status_v1
from ..semantic_link.errors import LinkedSemanticModuleError
from ..semantic_link.formats import LINKED_SEMANTIC_MODULE_V2_FORMAT
from ..semantic_link.module_v2 import LinkedSemanticModuleV2
from ..semantic_providers.formats import IMPLEMENTATION_SELECTION_V2_FORMAT
from ..semantic_providers.selection_v2 import (
    ImplementationSelectionV2,
    ImplementationSelectionV2Error,
)
from ..util import sha256_file
from .status_common import StatusArtifactError


def _v2_next_action(blockers: list[dict[str, Any]]) -> str:
    if not blockers:
        return "qualify residual obligations and select definition providers"
    code = blockers[0].get("code")
    return (
        f"resolve semantic hole {code}"
        if isinstance(code, str) and code
        else "inspect the first semantic hole"
    )


def _selection_next_action(
    configuration_id: str,
    blockers: list[dict[str, Any]],
) -> str:
    if not blockers:
        return f"realize semantic module configuration {configuration_id}"
    code = blockers[0].get("code")
    return (
        f"resolve provider-selection blocker {code}"
        if isinstance(code, str) and code
        else "inspect the first provider-selection blocker"
    )


def build_project_status(
    *,
    target_id: str,
    linked_semantic_module: Path | str,
    implementation_selection: Path | str | None = None,
    configuration_id: str | None = None,
    out: Path | str,
) -> dict[str, object]:
    """Project checked module products without reconstructing authority.

    Project status supplies only ``linked_semantic_module``.  Candidate status
    supplies the exact implementation selection too and receives one compact
    configuration subject in the same domain-neutral view format.
    """

    if not target_id:
        raise StatusArtifactError("target ID must be nonempty")
    module_path = Path(linked_semantic_module)
    try:
        raw = json.loads(module_path.read_text(encoding="utf-8"))
        if not isinstance(raw, Mapping):
            raise LinkedSemanticModuleError("linked semantic module must be an object")
        module_format = raw.get("format")
        if module_format != LINKED_SEMANTIC_MODULE_V2_FORMAT:
            raise LinkedSemanticModuleError(
                "linked semantic module format is unsupported"
            )
        module = LinkedSemanticModuleV2.load(module_path)
    except (
        LinkedSemanticModuleError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
    ) as exc:
        raise StatusArtifactError(f"linked semantic module is invalid: {exc}") from exc
    payload = module.payload
    raw_blockers = payload["semantic_holes"]
    if not isinstance(raw_blockers, list) or any(
        not isinstance(row, Mapping) for row in raw_blockers
    ):
        # The strict module parser already checks this.  Keep the projection's
        # boundary explicit so a future parser relaxation cannot become a
        # misleading operator report.
        raise StatusArtifactError("linked semantic module blockers are malformed")
    blockers = [dict(row) for row in raw_blockers]
    bindings = payload["bindings"]
    if not isinstance(bindings, Mapping):
        raise StatusArtifactError("linked semantic module bindings are malformed")
    subjects = [{
        "subject": f"module:{target_id}",
        "state": payload["status"],
        "authority": False,
        "bindings": [{
            "artifact": "linked-semantic-module.json",
            "format": module_format,
            "identity": module.identity,
            "content_sha256": sha256_file(module_path),
            "semantic_complete": payload["status"] == "complete",
            "analysis_frontiers": len(payload["analysis_frontiers"]),
            "residual_obligations": len(payload["residual_obligations"]),
        }],
        "blockers": blockers,
        "dependencies": [
            {"role": str(role), "sha256": str(identity)}
            for role, identity in sorted(bindings.items())
        ],
        "ranked_next_action": _v2_next_action(blockers),
    }]
    if (implementation_selection is None) != (configuration_id is None):
        raise StatusArtifactError(
            "implementation selection and configuration ID must be supplied together"
        )
    if implementation_selection is not None:
        if not configuration_id:
            raise StatusArtifactError("configuration ID must be nonempty")
        selection_path = Path(implementation_selection)
        try:
            selection = ImplementationSelectionV2.load(selection_path)
        except (
            ImplementationSelectionV2Error,
            OSError,
            UnicodeError,
            json.JSONDecodeError,
        ) as exc:
            raise StatusArtifactError(
                f"implementation selection is invalid: {exc}"
            ) from exc
        selection_payload = selection.payload
        linked_identity = selection_payload["bindings"][
            "linked_semantic_module_sha256"
        ]
        if linked_identity != module.identity:
            raise StatusArtifactError(
                "implementation selection binds another linked semantic module"
            )
        selection_blockers = [
            dict(row) for row in selection_payload["blockers"]
        ]
        selected = [
            *selection_payload["definition_selections"],
            *selection_payload["obligation_selections"],
        ]
        provider_kinds = sorted({
            str(row["provider_kind"]) for row in selected
        })
        subjects.append({
            "subject": f"configuration:{target_id}:{configuration_id}",
            "state": selection_payload["status"],
            # A selection can be ready for realization but never grants
            # original semantic or release authority by itself.
            "authority": False,
            "bindings": [{
                "artifact": "implementation-selection.json",
                "format": IMPLEMENTATION_SELECTION_V2_FORMAT,
                "identity": selection.identity,
                "content_sha256": sha256_file(selection_path),
                "linked_semantic_module_sha256": module.identity,
                "mode": selection_payload["mode"],
                "ready_for_realization": selection_payload[
                    "ready_for_realization"
                ],
                "selected_symbols": len(selected),
                "selected_definitions": len(
                    selection_payload["definition_selections"]
                ),
                "selected_obligations": len(
                    selection_payload["obligation_selections"]
                ),
                "provider_kinds": provider_kinds,
            }],
            "blockers": selection_blockers,
            "dependencies": [
                {"role": "provider-qualification", "sha256": identity}
                for identity in selection_payload["qualification_sha256s"]
            ],
            "ranked_next_action": _selection_next_action(
                configuration_id, selection_blockers
            ),
        })
    return write_operator_work_status_v1(
        subjects=subjects,
        out=Path(out),
    )


__all__ = ["StatusArtifactError", "build_project_status"]
