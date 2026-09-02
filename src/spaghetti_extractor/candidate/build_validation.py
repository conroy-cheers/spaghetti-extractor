"""Linked semantic-module validation for native realization."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..util import sha256_file
from ..semantic_link.module_v2 import LinkedSemanticModuleV2
from ..semantic_providers.selection_v2 import ImplementationSelectionV2
from .build_model import CandidateNativeBuildError
from .build_values import _file
from ..transfer.plan import load_executable_transfer_plan


def _validate_linked_semantic_execution_v2(
    *,
    linked_semantic_module: Path | str,
    implementation_selection: Path | str,
    transfer_plan: Path | str,
) -> dict[str, Any]:
    """Derive native link scope from one complete V2 module and selection."""

    linked_path = _file(linked_semantic_module, "linked semantic module V2")
    linked = LinkedSemanticModuleV2.load(linked_path, require_complete=True)
    if linked.semantic_object is None:
        raise CandidateNativeBuildError(
            "native realization requires a packaged linked semantic module V2"
        )
    selection_path = _file(
        implementation_selection, "implementation selection V2"
    )
    selection = ImplementationSelectionV2.load(selection_path)
    if (
        selection.payload["status"] != "complete"
        or selection.payload["ready_for_realization"] is not True
        or selection.payload["bindings"].get(
            "linked_semantic_module_sha256"
        ) != linked.identity
    ):
        raise CandidateNativeBuildError(
            "implementation selection V2 is incomplete or binds another module"
        )
    plan_path = _file(transfer_plan, "executable transfer plan")
    transfer, _transfers = load_executable_transfer_plan(
        plan_path, require_complete=True
    )
    packaged_plan = linked.semantic_object.transfer_plan_path
    if (
        sha256_file(plan_path) != sha256_file(packaged_plan)
        or linked.payload["bindings"].get("executable_transfer_plan_sha256")
        != transfer["plan_sha256"]
    ):
        raise CandidateNativeBuildError(
            "linked semantic module V2 binds another executable transfer plan"
        )
    required_definition_ids = {
        str(row["definition_id"])
        for row in linked.payload["definition_requirements"]
        if row.get("definition_id") is not None
    }
    selected_definition_ids = {
        str(row["definition_id"])
        for row in selection.payload["definition_selections"]
    }
    required_obligation_ids = {
        str(row["obligation_id"])
        for row in linked.payload["residual_obligations"]
    }
    selected_obligation_ids = {
        str(row["obligation_id"])
        for row in selection.payload["obligation_selections"]
    }
    if (
        selected_definition_ids != required_definition_ids
        or selected_obligation_ids != required_obligation_ids
    ):
        raise CandidateNativeBuildError(
            "implementation selection V2 is not total over native link scope"
        )
    bindings = transfer["bindings"]
    return {
        "format": str(linked.payload["format"]),
        "artifact_sha256": sha256_file(linked_path),
        "receipt_sha256": linked.identity,
        "status": str(linked.payload["status"]),
        "executable": True,
        "release_accepted": False,
        "bindings": {
            "linked_semantic_module_sha256": linked.identity,
            "implementation_selection_sha256": selection.identity,
            "executable_transfer_plan_sha256": sha256_file(plan_path),
            "executable_transfer_semantics_sha256": transfer["plan_sha256"],
            "exact_universe_sha256": bindings["exact_universe_sha256"],
            "machine_ir_sha256": bindings["machine_ir_sha256"],
            "machine_ir_manifest_sha256": bindings[
                "machine_ir_manifest_sha256"
            ],
            "pe_sha256": bindings["pe_sha256"],
        },
        "selection_counts": {
            "definitions": len(selected_definition_ids),
            "obligations": len(selected_obligation_ids),
        },
    }


def _validate_linked_semantic_execution(
    *,
    linked_semantic_module: Path | str,
    implementation_selection: Path | str,
    transfer_plan: Path | str,
) -> dict[str, Any]:
    """Validate the sole active semantic-module generation."""

    return _validate_linked_semantic_execution_v2(
        linked_semantic_module=linked_semantic_module,
        implementation_selection=implementation_selection,
        transfer_plan=transfer_plan,
    )
