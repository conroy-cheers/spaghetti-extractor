"""Optional must-provenance analysis for semantic-link diagnostics.

This module is outside production module construction. It runs the historical
transfer fixed point for performance observations and future precision
proposals; its result is non-authorizing and is not part of module identity.
"""

from __future__ import annotations

import gc
from dataclasses import replace
from pathlib import Path
from ..semantic_objects.semantic_object import SemanticObjectV1
from ..transfer.closure import (
    derive_execution_closure_context_v1,
    write_bound_semantic_link_kernel_v1,
)
from .module import (
    _fail,
    _semantic_import_uses_v1,
    _semantic_link_kernel_input_v1,
    build_semantic_link_worklist_facts,
)


INCOMPLETE_PLAN_WORKLIST_STEPS = 32_768


def _effective_worklist_steps(
    transfer_payload: dict[str, object], requested: int,
) -> int:
    if requested <= 0:
        _fail("semantic-link worklist limit must be positive")
    # Preserve the migration behavior while the fixed point remains available
    # to the optional precision path: incomplete transfer plans are bounded so
    # their already-known semantic blockers cannot trigger an unbounded
    # diagnostic search.  Complete plans retain the explicitly requested
    # diagnostic budget.  Production V2 linkage does not call this path.
    if transfer_payload.get("status") == "incomplete":
        return min(requested, INCOMPLETE_PLAN_WORKLIST_STEPS)
    return requested


def compile_semantic_link_worklist_facts(
    *, semantic_object: Path, behavioral_roots: Path, original_pe: Path,
    out: Path, maximum_worklist_steps: int = 1_000_000,
    retain_transfer_plan: bool = False,
) -> tuple[SemanticObjectV1, dict[str, object]]:
    """Run the checked fixed point once and return diagnostic facts."""

    semantic = SemanticObjectV1.load_link_view(semantic_object)
    if semantic.package_root is None:
        _fail("semantic link requires a packaged semantic object")
    transfer_plan_path = semantic.transfer_plan_path
    module_interface_path = semantic.module_interface_path
    object_authority_path = semantic.machine_object_authority_path
    if semantic.resolved_external_environment is None:
        _fail("semantic link requires a resolved-environment semantic member")
    resolved_external_environment = semantic.resolved_external_environment_path
    transfer_payload = semantic.transfer_plan
    effective_worklist_steps = _effective_worklist_steps(
        transfer_payload, maximum_worklist_steps
    )
    context = derive_execution_closure_context_v1(
        transfer_payload=transfer_payload,
        behavioral_roots=behavioral_roots,
        original_pe=original_pe,
        module_interface=module_interface_path,
        object_authority=object_authority_path,
        resolved_external_environment=resolved_external_environment,
        checked_exception_transitions=semantic.checked_exception_transitions,
        maximum_worklist_steps=effective_worklist_steps,
    )
    runtime_provider_requirements = tuple(
        transfer_payload["runtime_provider_requirements"]
    )
    provisional_import_uses = _semantic_import_uses_v1(
        semantic=semantic,
        resolved_environment=semantic.resolved_external_environment.payload,
        roots_by_unit={
            str(row["identity"]): {"unbound:semantic-link-root"}
            for row in transfer_payload["transfers"]
        },
    )
    if not retain_transfer_plan:
        semantic = replace(semantic, transfer_plan={})
        del transfer_payload
        gc.collect()
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    closure, _edge_root_provenance, native_link_facts = (
        write_bound_semantic_link_kernel_v1(
            transfer_plan=transfer_plan_path,
            runtime_provider_requirements=runtime_provider_requirements,
            context=context,
            semantic_link_input=_semantic_link_kernel_input_v1(semantic),
            out=output,
        )
    )
    facts = build_semantic_link_worklist_facts(
        semantic=semantic,
        closure=closure,
        native_link_facts=native_link_facts,
        provisional_import_uses=provisional_import_uses,
    )
    # The fixed point is represented by V2 link facts and provenance.  Its
    # compatibility-shaped receipt is construction-local and never published.
    (output / "module-execution-closure.json").unlink()
    return semantic, facts


__all__ = ["compile_semantic_link_worklist_facts"]
