"""Linked-library replacements."""

from __future__ import annotations

import copy
import json
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from ..artifacts.formats import (
    COMPONENT_QUALIFICATION_FORMAT,
    LIBRARY_ARTIFACT_INDEX_FORMAT,
    LIBRARY_ARTIFACT_INDEX_V2_FORMAT,
    LIBRARY_ARTIFACT_INPUTS_FORMAT,
    LIBRARY_ARTIFACT_INPUTS_V2_FORMAT,
    LIBRARY_CATALOG_LOCK_FORMAT,
    LIBRARY_HYPOTHESIS_SET_FORMAT,
    LIBRARY_INTERFACE_CATALOG_FORMAT,
    LIBRARY_MATCH_EVIDENCE_FORMAT,
    LIBRARY_REPLACEMENT_PLAN_FORMAT,
    DYNAMIC_LIBRARY_REQUIREMENTS_FORMAT,
    LINKED_INTERFACE_ASSIGNMENTS_FORMAT,
    LINKED_INTERFACE_QUALIFICATION_FORMAT,
    LINKED_ISLAND_MANIFEST_FORMAT,
    LINKED_ISLAND_MANIFEST_V2_FORMAT,
    LINKED_ISLAND_REVIEW_FORMAT,
    MACHINE_IR_FORMAT,
)
from ..pe32.stage_binary import StageAInputError, _parse_stage_a_pe
from .contracts import (
    validate_linked_island_manifest as _validate_linked_island_contract,
)
from ..util import sha256_file, write_json


from .interfaces import (
    bind_interface_contract_catalog,
)
from .matching_support import (
    _canonical_sha256,
    _copy_object,
    _read_object,
    _validate_linked_island_manifest,
    _validate_self_hash,
)
from .model import (
    LinkedLibraryError,
)

def plan_library_replacements(
    *,
    linked_islands: Path | str,
    interface_qualification: Path | str,
    interface_catalog: Path | str | Mapping[str, Any],
    dynamic_requirements: Path | str | None = None,
    out: Path | str,
) -> dict[str, Any]:
    """Select qualified portable replacements and explicit machine-IR fallbacks."""

    manifest = _read_object(Path(linked_islands), "linked-island manifest")
    _validate_linked_island_manifest(manifest)
    qualification = _read_object(
        Path(interface_qualification), "linked interface qualification"
    )
    _validate_self_hash(
        qualification,
        LINKED_INTERFACE_QUALIFICATION_FORMAT,
        "qualification_sha256",
        "linked interface qualification",
    )
    if qualification["bindings"]["linked_island_manifest_sha256"] != manifest["manifest_sha256"]:
        raise LinkedLibraryError("interface qualification/linked islands are stale")
    catalog = (
        _copy_object(interface_catalog, "interface contract catalog")
        if isinstance(interface_catalog, Mapping)
        else _read_object(Path(interface_catalog), "interface contract catalog")
    )
    expected_catalog = catalog.get("catalog_sha256")
    if expected_catalog != bind_interface_contract_catalog(catalog)["catalog_sha256"]:
        raise LinkedLibraryError("interface contract catalog self-hash is stale")
    if qualification["bindings"]["interface_catalog_sha256"] != expected_catalog:
        raise LinkedLibraryError("interface qualification/catalog binding is stale")

    dynamic = None
    dynamic_by_unit: dict[str, Mapping[str, Any]] = {}
    dynamic_by_import: dict[tuple[str, str | None, int | None], Mapping[str, Any]] = {}
    if dynamic_requirements is not None:
        dynamic = _read_object(
            Path(dynamic_requirements), "dynamic library requirements"
        )
        _validate_self_hash(
            dynamic,
            DYNAMIC_LIBRARY_REQUIREMENTS_FORMAT,
            "requirements_sha256",
            "dynamic library requirements",
        )
        dynamic_by_unit = {
            str(item["unit_id"]): item for item in dynamic.get("callsites", [])
            if item.get("unit_id") is not None
        }
        dynamic_by_import = {
            (
                str(item.get("import", {}).get("dll", "")).lower(),
                item.get("import", {}).get("symbol"),
                item.get("import", {}).get("ordinal"),
            ): item
            for item in dynamic.get("imports", [])
        }

    qualified_by_island = {
        str(item["island_id"]): item
        for item in qualification.get("qualifications", [])
        if item.get("status") == "qualified"
    }
    replacements_by_contract: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for replacement in catalog.get("replacements", []):
        if replacement.get("qualification", {}).get("status") in {"qualified", "guarded"}:
            replacements_by_contract[str(replacement["contract_id"])].append(replacement)
    plan: list[dict[str, Any]] = []
    for island in manifest["islands"]:
        island_id = str(island["id"])
        qualified = qualified_by_island.get(island_id)
        selected: Mapping[str, Any] | None = None
        if qualified is not None:
            choices = replacements_by_contract.get(str(qualified["contract_id"]), [])
            qualified_implementation = qualified.get("evidence", {}).get(
                "implementation"
            )
            bound_choices = [
                choice
                for choice in choices
                if choice.get("implementation") == qualified_implementation
            ]
            portable = [
                choice
                for choice in bound_choices
                if bool(choice.get("portable", False))
            ]
            ordered = sorted(
                portable or bound_choices, key=lambda item: str(item["id"])
            )
            selected = ordered[0] if ordered else None
        external_calls = [
            dynamic_by_unit.get(str(unit_id)) for unit_id in island["unit_ids"]
        ]
        import_identity = island.get("match", {}).get("import", {})
        import_requirement = (
            dynamic_by_import.get(
                (
                    str(import_identity.get("dll", "")).lower(),
                    import_identity.get("symbol"),
                    import_identity.get("ordinal"),
                )
            )
            if island["kind"] == "import_thunk"
            else None
        )
        external_preserved = (
            island["kind"] == "import_thunk"
            and (
                (
                    import_requirement is not None
                    and import_requirement.get("status") == "qualified"
                )
                or (
                    bool(external_calls)
                    and all(
                        call is not None and call.get("status") == "qualified"
                        for call in external_calls
                    )
                )
            )
        )
        if selected is not None:
            disposition = str(selected["kind"])
            status = "ready"
            reason = "qualified_interface_and_replacement"
            replacement_id = selected["id"]
        elif external_preserved:
            disposition = "preserve_external_call"
            status = "ready"
            reason = "exact_import_identity_and_checked_machine_call_contract"
            replacement_id = None
        elif island["kind"] == "application":
            disposition = "lift_locally"
            status = "incomplete"
            reason = "application_island_requires_component_or_source_lift"
            replacement_id = None
        else:
            disposition = "portable_machine_ir_fallback"
            status = "fallback"
            reason = "no_qualified_portable_replacement"
            replacement_id = None
        plan.append(
            {
                "island_id": island_id,
                "kind": island["kind"],
                "unit_ids": copy.deepcopy(island["unit_ids"]),
                "status": status,
                "disposition": disposition,
                "reason": reason,
                "contract_id": qualified.get("contract_id") if qualified else None,
                "replacement_id": replacement_id,
                "external_call_contract_ids": sorted(
                    {
                        str(call.get("abi_contract", {}).get("contract_id"))
                        for call in external_calls
                        if isinstance(call, Mapping)
                        and isinstance(call.get("abi_contract"), Mapping)
                        and call.get("abi_contract", {}).get("contract_id") is not None
                    }
                ),
                "dynamic_import_requirement_id": (
                    import_requirement.get("id")
                    if import_requirement is not None
                    else None
                ),
            }
        )
    counts = Counter(row["status"] for row in plan)
    dynamic_callsites = (
        [
            {
                "id": item["id"],
                "status": (
                    "ready" if item.get("status") == "qualified" else "incomplete"
                ),
                "import": copy.deepcopy(item.get("import")),
                "source_unit_id": item.get("unit_id"),
                "instruction_rva": item.get(
                    "instruction_rva", item.get("rva_start")
                ),
                "contract_id": (
                    item.get("abi_contract", {}).get("contract_id")
                    if isinstance(item.get("abi_contract"), Mapping)
                    else None
                ),
            }
            for item in dynamic.get("callsites", [])
        ]
        if dynamic is not None
        else []
    )
    ready_dynamic_callsites = sum(
        item["status"] == "ready" for item in dynamic_callsites
    )
    incomplete_dynamic_callsites = len(dynamic_callsites) - ready_dynamic_callsites
    idiomatic_complete = (
        not counts["fallback"]
        and not counts["incomplete"]
        and not incomplete_dynamic_callsites
    )
    core = {
        "format": LIBRARY_REPLACEMENT_PLAN_FORMAT,
        "status": "complete" if idiomatic_complete else "incomplete",
        "executes_original_binary": False,
        "bindings": {
            "linked_island_manifest_sha256": manifest["manifest_sha256"],
            "interface_qualification_sha256": qualification["qualification_sha256"],
            "interface_catalog_sha256": expected_catalog,
            "dynamic_requirements_sha256": (
                dynamic.get("requirements_sha256") if dynamic is not None else None
            ),
        },
        "islands": plan,
        "dynamic_callsites": dynamic_callsites,
        "counts": {
            "islands": len(plan),
            "ready": counts["ready"],
            "fallback": counts["fallback"],
            "incomplete": counts["incomplete"],
            "preserved_external_calls": sum(
                row["disposition"] == "preserve_external_call" for row in plan
            ),
            "dynamic_callsites": (
                len(dynamic.get("callsites", [])) if dynamic is not None else 0
            ),
            "ready_dynamic_callsites": ready_dynamic_callsites,
            "incomplete_dynamic_callsites": incomplete_dynamic_callsites,
        },
        "completion": {
            "working_hybrid_executable": True,
            "idiomatic_source_complete": idiomatic_complete,
            "fallback_counts_as_lifting_progress": False,
        },
    }
    payload = {**core, "plan_sha256": _canonical_sha256(core)}
    write_json(Path(out), payload)
    return payload
