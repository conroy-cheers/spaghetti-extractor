"""Compatibility view over the unified operation-provenance analysis.

Register-held code and import targets are no longer analyzed by an independent
fixed point.  This facade preserves the v1 artifact consumed by older callers
while delegating to the register, stack, memory, and operation-table engine in
``interface_provenance``.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from .import_abi import SelectedImportABI
from .interface_provenance import recover_external_interface_targets
from .machine_import_profiles import MachineImportIdentity


VALUE_PROVENANCE_FORMAT = "stage-a-value-provenance-v1"


def recover_indirect_targets_from_value_provenance(
    *,
    units: Sequence[Mapping[str, Any]],
    roots: Iterable[str],
    direct_edges: Sequence[Mapping[str, Any]],
    internal_call_edges: Sequence[Mapping[str, Any]],
    recovered_indirect_edges: Sequence[Mapping[str, Any]] = (),
    indirect_exits: Sequence[Mapping[str, Any]],
    image_base: int,
    imports: Sequence[Mapping[str, Any]],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    internal_call_preserved_registers: Mapping[int, frozenset[str]] | None = None,
    finite_target_budget: int = 64,
) -> dict[str, Any]:
    """Return the legacy register-target artifact from one shared analysis."""

    result = recover_external_interface_targets(
        units=units,
        roots=roots,
        direct_edges=direct_edges,
        internal_call_edges=internal_call_edges,
        recovered_indirect_edges=recovered_indirect_edges,
        indirect_exits=indirect_exits,
        profiles=(),
        imports=imports,
        import_abis=import_abis,
        internal_call_preserved_registers=(
            internal_call_preserved_registers or {}
        ),
        image_base=image_base,
        finite_value_budget=finite_target_budget,
    )
    return legacy_value_provenance_view(
        result,
        finite_target_budget=finite_target_budget,
    )


def legacy_value_provenance_view(
    result: Mapping[str, Any],
    *,
    finite_target_budget: int,
) -> dict[str, Any]:
    """Project a shared operation analysis into the stable v1 schema."""

    resolutions = result["resolutions"]
    recovered = sum(row.get("status") == "recovered" for row in resolutions)
    issues = [
        {
            "code": "value_origin_unresolved",
            "indirect_exit_id": row.get("id"),
            "source_unit_id": row.get("source_unit_id"),
            "failure": row.get("failure"),
        }
        for row in resolutions
        if row.get("status") != "recovered"
    ]
    return {
        "format": VALUE_PROVENANCE_FORMAT,
        "status": "complete" if recovered == len(resolutions) else "incomplete",
        "proof_authority": False,
        "finite_target_budget": finite_target_budget,
        "resolutions": resolutions,
        "issues": issues,
        "counts": {
            "units": result["counts"]["units"],
            "reached_units": result["counts"]["reached_units"],
            "transfer_evaluations": result["counts"]["transfer_evaluations"],
            "indirect_exits": len(resolutions),
            "recovered_indirect_exits": recovered,
            "external_target_exits": sum(
                bool(row.get("external_targets")) for row in resolutions
            ),
            "internal_target_exits": sum(
                bool(row.get("target_unit_ids")) for row in resolutions
            ),
            "finite_budget_exceeded": result["counts"]["finite_budget_exceeded"],
        },
    }


__all__ = [
    "VALUE_PROVENANCE_FORMAT",
    "legacy_value_provenance_view",
    "recover_indirect_targets_from_value_provenance",
]
