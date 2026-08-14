"""Derive the authority-graph manifest from registered typed phases."""

from __future__ import annotations

from collections.abc import Iterable
import importlib
from typing import Any

from ..artifact_set_v3 import canonical_sha256_v3
from ..phase_framework_v3 import PhaseDefinitionV3
from ._schema import fail
from .registry import AUTHORITY_PHASE_REGISTRY_V3, AuthorityPhaseRegistryV3


def phase_reference_v3(phase: PhaseDefinitionV3) -> str:
    """Return the unique public module attribute exporting ``phase``."""

    module_name = phase.transform.__module__
    module = importlib.import_module(module_name)
    names = tuple(
        sorted(
            name
            for name, value in vars(module).items()
            if value is phase and name.endswith("_PHASE_V3")
        )
    )
    if len(names) != 1:
        fail(
            "ambiguous_phase_reference",
            f"phase {phase.name!r} has public exports {names!r}",
            "export every registered phase through exactly one *_PHASE_V3 constant in its defining module",
        )
    return f"{module_name}:{names[0]}"


def authority_graph_manifest_v3(
    *,
    graph_id: str,
    registry: AuthorityPhaseRegistryV3 = AUTHORITY_PHASE_REGISTRY_V3,
    outputs: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Create the canonical Nix DAG manifest from one immutable registry."""

    phases = tuple(registry)
    producers = {phase.output_artifact_kind: phase.name for phase in phases}
    if len(producers) != len(phases):
        fail(
            "duplicate_artifact_producer",
            "registered phases do not have unique output artifact kinds",
            "assign one producer to each v3 artifact kind",
        )
    rows: list[dict[str, Any]] = []
    external_kinds: dict[str, str] = {}
    for phase in phases:
        inputs: dict[str, dict[str, str]] = {}
        for input_name, artifact_kind in phase.input_artifact_kinds:
            producer = producers.get(artifact_kind)
            if producer is None:
                previous = external_kinds.setdefault(input_name, artifact_kind)
                if previous != artifact_kind:
                    fail(
                        "conflicting_external_input_kind",
                        f"external input {input_name!r} is expected as both {previous!r} and {artifact_kind!r}",
                        "give semantically distinct external artifacts distinct input names",
                    )
                inputs[input_name] = {"source": "external", "id": input_name}
            else:
                inputs[input_name] = {"source": "phase", "id": producer}
        resource_class = (
            "small"
            if phase.form == "map_units"
            else "medium"
            if phase.form == "map_sccs"
            else "large"
        )
        row = {
                "phase_id": phase.name,
                "phase_reference": phase_reference_v3(phase),
                "form": phase.form,
                "expected_kind": phase.output_artifact_kind,
                "inputs": inputs,
                "resource_class": resource_class,
                "schedule_record_inputs": list(phase.schedule_record_inputs),
                "unit_aligned_inputs": list(phase.unit_aligned_inputs),
                "scc_aligned_inputs": list(phase.scc_aligned_inputs),
                "status": "complete",
            }
        if phase.form == "map_units":
            row["source_input"] = phase.source_input
        rows.append(row)
    output_ids = tuple(outputs or (phase.name for phase in phases))
    unknown = sorted(set(output_ids) - {phase.name for phase in phases})
    if unknown:
        fail(
            "unknown_graph_output",
            f"authority graph outputs refer to unknown phases {unknown!r}",
            "select output IDs from the registered phase names",
        )
    # The graph identity describes topology and public phase interfaces only.
    # Each produced artifact independently binds its phase implementation via
    # PhaseDefinitionV3.definition_sha256.  Including implementation hashes
    # here would invalidate every unrelated phase whenever one checker changes.
    identity_payload = {
        "registered_phase_interfaces": [
            {
                "name": phase.name,
                "reference": phase_reference_v3(phase),
                "form": phase.form,
                "output_artifact_kind": phase.output_artifact_kind,
                "input_artifact_kinds": [list(row) for row in phase.input_artifact_kinds],
                "source_input": phase.source_input,
                "schedule_record_inputs": list(phase.schedule_record_inputs),
                "unit_aligned_inputs": list(phase.unit_aligned_inputs),
                "scc_aligned_inputs": list(phase.scc_aligned_inputs),
            }
            for phase in phases
        ],
        "outputs": list(output_ids),
    }
    return {
        "format": "spaghetti-extractor-authority-graph-v3",
        "graph_id": f"{graph_id}:{canonical_sha256_v3(identity_payload)[:24]}",
        "phases": rows,
        "outputs": list(output_ids),
        "external_artifact_kinds": dict(sorted(external_kinds.items())),
    }


__all__ = ["authority_graph_manifest_v3", "phase_reference_v3"]
