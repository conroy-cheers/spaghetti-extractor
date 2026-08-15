"""Linked-library refinement."""

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


from .matching import (
    bind_linked_island_review,
)
from .matching_support import (
    _array,
    _candidate_library_identity,
    _canonical_sha256,
    _claim_units,
    _copy_object,
    _import_thunk_event,
    _island_from_units,
    _issue,
    _issue_sort_key,
    _load_machine_package,
    _materialize_reviewed_complement,
    _nonempty,
    _object,
    _optional_reviewed_complement_policy,
    _read_object,
    _reviewed_island,
    _unknown_unit_components,
    _validate_self_hash,
)
from .model import (
    LinkedLibraryError,
    _MachinePackage,
    _Unit,
)

def derive_dynamic_library_requirements(
    *,
    machine_ir: Path | str,
    machine_import_report: Path | str | None = None,
    out: Path | str,
) -> dict[str, Any]:
    """Preserve exact dynamic import identities and checked ABI call boundaries."""

    machine = _load_machine_package(Path(machine_ir))
    if machine_import_report is not None:
        return _derive_dynamic_requirements_from_report(
            machine=machine,
            report_path=Path(machine_import_report),
            out=Path(out),
        )
    requirements: dict[str, dict[str, Any]] = {}
    callsites: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    for unit in machine.units:
        event = _import_thunk_event(unit.payload)
        if event is None:
            continue
        dll = _nonempty(event.get("dll"), "dynamic import DLL").lower()
        symbol = event.get("symbol")
        ordinal = event.get("ordinal")
        identity = str(symbol) if isinstance(symbol, str) and symbol else f"ordinal-{ordinal}"
        abi = event.get("abi_contract")
        qualified = isinstance(abi, Mapping) and all(
            key in abi
            for key in (
                "argument_words",
                "disposition",
                "memory_effect",
                "world_effect",
            )
        )
        if not qualified:
            issues.append(
                _issue(
                    "incomplete",
                    "dynamic_call_abi_incomplete",
                    "dynamic import has no complete checked machine-call contract",
                    unit_id=unit.identity,
                    dll=dll,
                    symbol=symbol,
                    ordinal=ordinal,
                    rva_start=unit.start,
                )
            )
        callsite = {
            "id": f"dynamic-call:{unit.start:08x}:{dll}:{identity}",
            "unit_id": unit.identity,
            "rva_start": unit.start,
            "rva_end": unit.end,
            "reachable": _unit_reachable(unit),
            "import": {"dll": dll, "symbol": symbol, "ordinal": ordinal},
            "status": "qualified" if qualified else "incomplete",
            "arguments": copy.deepcopy(event.get("arguments", [])),
            "stack_inputs": copy.deepcopy(event.get("stack_inputs", [])),
            "abi_contract": copy.deepcopy(abi),
        }
        callsites.append(callsite)
        requirement = requirements.setdefault(
            dll,
            {
                "dll": dll,
                "identity_status": "exact_import_identity",
                "symbols": set(),
                "ordinals": set(),
                "callsite_ids": [],
                "exact_runtime_version_known": False,
            },
        )
        if isinstance(symbol, str) and symbol:
            requirement["symbols"].add(symbol)
        elif isinstance(ordinal, int):
            requirement["ordinals"].add(ordinal)
        requirement["callsite_ids"].append(callsite["id"])

    libraries = []
    imports = []
    for dll, row in sorted(requirements.items()):
        libraries.append(
            {
                "id": f"dynamic-library:{dll}",
                "dll": dll,
                "identity_status": row["identity_status"],
                "symbols": sorted(row["symbols"]),
                "ordinals": sorted(row["ordinals"]),
                "callsite_ids": sorted(row["callsite_ids"]),
                "exact_runtime_version_known": False,
            }
        )
        for symbol in sorted(row["symbols"]):
            matching = [
                item
                for item in callsites
                if item["import"]["dll"] == dll
                and item["import"].get("symbol") == symbol
            ]
            imports.append(
                {
                    "id": f"dynamic-import:{dll}:{symbol}",
                    "import": {"dll": dll, "symbol": symbol, "ordinal": None},
                    "status": (
                        "qualified"
                        if matching and all(item["status"] == "qualified" for item in matching)
                        else "incomplete"
                    ),
                    "callsite_ids": sorted(item["id"] for item in matching),
                    "thunk_rvas": sorted({item["rva_start"] for item in matching}),
                }
            )
    reachable = [item for item in callsites if item["reachable"]]
    core = {
        "format": DYNAMIC_LIBRARY_REQUIREMENTS_FORMAT,
        "status": (
            "incomplete"
            if any(item["status"] != "qualified" for item in reachable)
            else "qualified"
        ),
        "executes_original_binary": False,
        "bindings": {
            "machine_ir_sha256": machine.ir_sha256,
            "machine_ir_manifest_sha256": machine.manifest_sha256,
        },
        "libraries": libraries,
        "imports": imports,
        "callsites": sorted(callsites, key=lambda item: (item["rva_start"], item["id"])),
        "issues": sorted(issues, key=_issue_sort_key),
        "counts": {
            "libraries": len(libraries),
            "import_identities": sum(
                len(item["symbols"]) + len(item["ordinals"]) for item in libraries
            ),
            "callsites": len(callsites),
            "reachable_callsites": len(reachable),
            "qualified_reachable_callsites": sum(
                item["status"] == "qualified" for item in reachable
            ),
        },
        "authority": {
            "same_abi_implies_same_behavior": False,
            "lockstep_external_identity_preserved": True,
            "can_authorize_static_library_replacement": False,
        },
    }
    payload = {**core, "requirements_sha256": _canonical_sha256(core)}
    write_json(Path(out), payload)
    return payload

def _derive_dynamic_requirements_from_report(
    *,
    machine: _MachinePackage,
    report_path: Path,
    out: Path,
) -> dict[str, Any]:
    report = _read_object(report_path, "static machine import contract report")
    if report.get("format") != "stage-a-static-machine-import-contracts-v1":
        raise LinkedLibraryError("unsupported static machine import report format")
    if report.get("status") != "ready":
        raise LinkedLibraryError("static machine import report is not ready")
    authority = _object(report.get("authority"), "machine import report authority")
    if (
        authority.get("lean_redecodes_boundary_routes") is not True
        or authority.get("lean_reparses_exact_pe_imports") is not True
        or authority.get("profile_status_fields_trusted") is not False
    ):
        raise LinkedLibraryError("static machine import report lacks checked authority")
    if report.get("exact_inventory_matches") is not True:
        raise LinkedLibraryError("static machine import report inventory is not exact")
    if _array(report.get("remaining_premises", []), "machine import premises"):
        raise LinkedLibraryError("static machine import report has remaining premises")
    if _array(report.get("blockers", []), "machine import blockers"):
        raise LinkedLibraryError("static machine import report has blockers")
    inputs = _object(report.get("inputs"), "machine import report inputs")
    machine_binary = _object(machine.manifest.get("binary"), "machine IR binary")
    if inputs.get("original_sha256") != machine_binary.get("sha256"):
        raise LinkedLibraryError("machine import report/original binary is stale")

    signature_rows = [
        _object(item, "machine import signature")
        for item in _array(report.get("signatures"), "machine import signatures")
    ]
    if any(not isinstance(item.get("id"), int) for item in signature_rows):
        raise LinkedLibraryError("machine import signature has no integer ID")
    signatures = {int(item["id"]): item for item in signature_rows}
    if len(signatures) != len(signature_rows):
        raise LinkedLibraryError("machine import report has duplicate signature IDs")
    units_by_start = {unit.start: unit for unit in machine.units}
    callsites: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    boundary_rows = [
        _object(item, "machine import boundary")
        for item in _array(report.get("boundaries"), "machine import boundaries")
    ]
    boundary_ids = [item.get("id") for item in boundary_rows]
    if any(not isinstance(value, int) for value in boundary_ids):
        raise LinkedLibraryError("machine import boundary has no integer ID")
    if len(set(boundary_ids)) != len(boundary_ids):
        raise LinkedLibraryError("machine import report has duplicate boundary IDs")
    for boundary in boundary_rows:
        imported = _object(boundary.get("import"), "machine import identity")
        dll = _nonempty(imported.get("dll"), "machine import DLL").lower()
        symbol = imported.get("symbol")
        ordinal = imported.get("ordinal")
        signature = signatures.get(boundary.get("signature_id"))
        argument_words = boundary.get("argument_words")
        qualified = (
            signature is not None
            and signature.get("bridgeable") is True
            and isinstance(argument_words, int)
            and argument_words >= 0
            and isinstance(boundary.get("argument_evidence"), str)
            and bool(boundary.get("argument_evidence"))
        )
        instruction_rva = int(boundary.get("instruction_rva", boundary.get("source_rva", 0)))
        containing = next(
            (
                unit
                for unit in machine.units
                if unit.start <= instruction_rva < unit.end
            ),
            None,
        )
        thunk_rva = boundary.get("thunk_rva")
        thunk_unit = units_by_start.get(thunk_rva) if isinstance(thunk_rva, int) else None
        identity = str(symbol) if isinstance(symbol, str) and symbol else f"ordinal-{ordinal}"
        if not qualified:
            issues.append(
                _issue(
                    "incomplete",
                    "checked_import_boundary_incomplete",
                    "checked import boundary lacks a bridgeable exact argument contract",
                    boundary_id=boundary.get("id"),
                    dll=dll,
                    symbol=symbol,
                    ordinal=ordinal,
                    rva_start=instruction_rva,
                )
            )
        callsites.append(
            {
                "id": f"dynamic-call:{instruction_rva:08x}:{dll}:{identity}:{boundary.get('id')}",
                "unit_id": containing.identity if containing is not None else None,
                "thunk_unit_id": thunk_unit.identity if thunk_unit is not None else None,
                "rva_start": int(boundary.get("source_rva", instruction_rva)),
                "rva_end": int(boundary.get("continuation_rva", instruction_rva + 1)),
                "instruction_rva": instruction_rva,
                "reachable": True,
                "import": {"dll": dll, "symbol": symbol, "ordinal": ordinal},
                "status": "qualified" if qualified else "incomplete",
                "route": boundary.get("route"),
                "thunk_rva": thunk_rva,
                "argument_evidence": boundary.get("argument_evidence"),
                "argument_words": argument_words,
                "abi_contract": (
                    {
                        "contract_id": (
                            f"{signature.get('profile_id')}:{signature.get('id')}"
                        ),
                        "calling_convention": signature.get("abi"),
                        "arity": copy.deepcopy(signature.get("arity")),
                        "argument_words": argument_words,
                        "disposition": signature.get("disposition"),
                        "memory_effect": signature.get("memory_effect"),
                        "memory_footprints": copy.deepcopy(
                            signature.get("memory_footprints", [])
                        ),
                        "world_effect": signature.get("world_effect"),
                        "callback_mode": signature.get("callback_mode"),
                    }
                    if signature is not None
                    else None
                ),
            }
        )

    grouped: dict[tuple[str, str | None, int | None], list[dict[str, Any]]] = defaultdict(list)
    for callsite in callsites:
        imported = callsite["import"]
        grouped[(imported["dll"], imported.get("symbol"), imported.get("ordinal"))].append(callsite)
    imports = []
    libraries_by_dll: dict[str, dict[str, Any]] = {}
    for (dll, symbol, ordinal), rows in sorted(
        grouped.items(), key=lambda item: (item[0][0], str(item[0][1]), int(item[0][2] or -1))
    ):
        identity = symbol or f"ordinal-{ordinal}"
        imports.append(
            {
                "id": f"dynamic-import:{dll}:{identity}",
                "import": {"dll": dll, "symbol": symbol, "ordinal": ordinal},
                "status": (
                    "qualified" if all(row["status"] == "qualified" for row in rows) else "incomplete"
                ),
                "callsite_ids": sorted(row["id"] for row in rows),
                "thunk_rvas": sorted(
                    {row["thunk_rva"] for row in rows if isinstance(row.get("thunk_rva"), int)}
                ),
            }
        )
        library = libraries_by_dll.setdefault(
            dll,
            {"symbols": set(), "ordinals": set(), "callsite_ids": []},
        )
        if symbol is not None:
            library["symbols"].add(symbol)
        elif ordinal is not None:
            library["ordinals"].add(ordinal)
        library["callsite_ids"].extend(row["id"] for row in rows)
    libraries = [
        {
            "id": f"dynamic-library:{dll}",
            "dll": dll,
            "identity_status": "exact_import_identity",
            "symbols": sorted(row["symbols"]),
            "ordinals": sorted(row["ordinals"]),
            "callsite_ids": sorted(row["callsite_ids"]),
            "exact_runtime_version_known": False,
        }
        for dll, row in sorted(libraries_by_dll.items())
    ]
    core = {
        "format": DYNAMIC_LIBRARY_REQUIREMENTS_FORMAT,
        "status": "incomplete" if issues else "qualified",
        "executes_original_binary": False,
        "bindings": {
            "machine_ir_sha256": machine.ir_sha256,
            "machine_ir_manifest_sha256": machine.manifest_sha256,
            "machine_import_report_sha256": sha256_file(report_path),
            "static_program_contract_sha256": inputs.get("static_program_contract_sha256"),
        },
        "libraries": libraries,
        "imports": imports,
        "callsites": sorted(callsites, key=lambda item: (item["instruction_rva"], item["id"])),
        "issues": sorted(issues, key=_issue_sort_key),
        "counts": {
            "libraries": len(libraries),
            "import_identities": len(imports),
            "callsites": len(callsites),
            "reachable_callsites": len(callsites),
            "qualified_reachable_callsites": sum(
                item["status"] == "qualified" for item in callsites
            ),
        },
        "authority": {
            "same_abi_implies_same_behavior": False,
            "lockstep_external_identity_preserved": True,
            "callsite_routes_lean_redecoded": True,
            "can_authorize_static_library_replacement": False,
        },
    }
    payload = {**core, "requirements_sha256": _canonical_sha256(core)}
    write_json(out, payload)
    return payload


def refine_linked_islands(
    *,
    original: Path | str,
    machine_ir: Path | str,
    match_evidence: Path | str,
    hypotheses: Path | str,
    review: Path | str | Mapping[str, Any] | None,
    out: Path | str,
) -> dict[str, Any]:
    """Materialize v2 ownership islands from checked constellation evidence."""

    original_path = Path(original)
    binary = _parse_stage_a_pe(original_path)
    machine = _load_machine_package(Path(machine_ir))
    machine_binary = _object(machine.manifest.get("binary"), "machine IR binary")
    if machine_binary.get("sha256") != binary.sha256:
        raise LinkedLibraryError("refined islands machine IR/original binary is stale")
    evidence = _read_object(Path(match_evidence), "library match evidence")
    _validate_self_hash(
        evidence,
        LIBRARY_MATCH_EVIDENCE_FORMAT,
        "evidence_sha256",
        "library match evidence",
    )
    hypothesis_set = _read_object(Path(hypotheses), "library hypothesis set")
    _validate_self_hash(
        hypothesis_set,
        LIBRARY_HYPOTHESIS_SET_FORMAT,
        "hypothesis_set_sha256",
        "library hypothesis set",
    )
    if hypothesis_set.get("bindings", {}).get("match_evidence_sha256") != evidence.get(
        "evidence_sha256"
    ):
        raise LinkedLibraryError("library hypotheses/match evidence are stale")
    if evidence.get("bindings", {}).get("original_binary_sha256") != binary.sha256:
        raise LinkedLibraryError("library evidence/original binary is stale")
    if evidence.get("bindings", {}).get("machine_ir_sha256") != machine.ir_sha256:
        raise LinkedLibraryError("library evidence/machine IR is stale")

    claimed: dict[str, str] = {}
    islands: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    review_sha256 = None
    complement_policy: Mapping[str, Any] | None = None
    if review is not None:
        reviewed = (
            _copy_object(review, "linked-island review")
            if isinstance(review, Mapping)
            else _read_object(Path(review), "linked-island review")
        )
        review_sha256 = reviewed.get("review_sha256")
        if bind_linked_island_review(reviewed).get("review_sha256") != review_sha256:
            raise LinkedLibraryError("linked-island review self-hash is stale")
        if reviewed.get("original_binary_sha256") != binary.sha256:
            raise LinkedLibraryError("linked-island review/original binary is stale")
        complement_policy = _optional_reviewed_complement_policy(reviewed)
        for raw in _array(reviewed.get("islands", []), "reviewed linked islands"):
            islands.append(_reviewed_island(raw, machine, claimed))

    thunk_groups: dict[tuple[str, str, int | None], list[_Unit]] = defaultdict(list)
    for unit in machine.units:
        if unit.identity in claimed:
            continue
        event = _import_thunk_event(unit.payload)
        if event is not None:
            key = (
                str(event.get("dll", "")).lower(),
                str(event.get("symbol") or ""),
                event.get("ordinal") if isinstance(event.get("ordinal"), int) else None,
            )
            thunk_groups[key].append(unit)
    for (dll, symbol, ordinal), units in sorted(thunk_groups.items()):
        suffix = symbol or f"ordinal-{ordinal}"
        row = _island_from_units(
            identity=f"import-thunk:{dll}:{suffix}",
            kind="import_thunk",
            units=units,
            match={
                "authority": "exact_artifact",
                "identity_status": "exact_import_identity",
                "import": {"dll": dll, "symbol": symbol or None, "ordinal": ordinal},
            },
        )
        _claim_units(row, claimed)
        islands.append(row)

    for placement in hypothesis_set.get("selected_placements", []):
        status = placement.get("identity_status")
        if status not in {"exact_artifact", "exact_release", "library_family_abi"}:
            continue
        target = _object(placement.get("target"), "selected target")
        unit_ids = [str(value) for value in target.get("unit_ids", [])]
        units = [machine.by_id[value] for value in unit_ids if value in machine.by_id]
        if len(units) != len(unit_ids) or any(unit.identity in claimed for unit in units):
            continue
        candidates = [
            _object(value, "selected target candidate")
            for value in placement.get("candidates", [])
        ]
        kinds = {str(candidate.get("island_kind")) for candidate in candidates}
        if len(kinds) != 1 or next(iter(kinds)) not in {
            "linked_dependency",
            "compiler_linker_support",
        }:
            issues.append(
                _issue(
                    "incomplete",
                    "constellation_kind_ambiguous",
                    "selected library candidates disagree about ownership kind",
                    target_id=placement.get("target_id"),
                    rva_start=target.get("rva_start"),
                )
            )
            continue
        kind = next(iter(kinds))
        identities = [_candidate_library_identity(candidate) for candidate in candidates]
        island_id = "constellation:" + _canonical_sha256(
            {
                "target_id": placement.get("target_id"),
                "status": status,
                "identities": identities,
            }
        )[:24]
        row = _island_from_units(
            identity=island_id,
            kind=kind,
            units=units,
            match={
                "authority": "exact_normalized_object",
                "identity_status": status,
                "library_identities": identities,
                "candidates": copy.deepcopy(candidates),
                "target_id": placement.get("target_id"),
            },
        )
        _claim_units(row, claimed)
        islands.append(row)

    reviewed_complement = None
    if complement_policy is not None:
        complement, reviewed_complement = _materialize_reviewed_complement(
            policy=complement_policy,
            machine=machine,
            claimed=claimed,
            original_binary_sha256=binary.sha256,
            review_sha256=str(review_sha256),
        )
        if complement is not None:
            islands.append(complement)

    remaining = [unit for unit in machine.units if unit.identity not in claimed]
    for position, units in enumerate(_unknown_unit_components(remaining)):
        row = _island_from_units(
            identity=f"unknown:cfg-component-{position:05d}",
            kind="unknown",
            units=units,
            match={"authority": "none", "identity_status": "unknown"},
        )
        _claim_units(row, claimed)
        islands.append(row)

    if set(claimed) != set(machine.by_id):
        raise LinkedLibraryError("refined linked islands omitted machine units")
    counts_by_kind = Counter(str(island["kind"]) for island in islands)
    units_by_kind = Counter()
    reachable_by_kind = Counter()
    potential_by_kind = Counter()
    for island in islands:
        kind = str(island["kind"])
        units_by_kind[kind] += int(island["unit_count"])
        reachable_by_kind[kind] += int(island["reachability"]["reachable_units"])
        potential_by_kind[kind] += int(island["reachability"]["potential_units"])
    islands.sort(key=lambda item: (item["rva_spans"][0]["rva_start"], item["id"]))
    if hypothesis_set.get("status") == "incomplete":
        issues.extend(copy.deepcopy(hypothesis_set.get("issues", [])))
    core = {
        "format": LINKED_ISLAND_MANIFEST_V2_FORMAT,
        "status": "incomplete" if units_by_kind["unknown"] or issues else "classified",
        "executes_original_binary": False,
        "bindings": {
            "original_binary_sha256": binary.sha256,
            "machine_ir_sha256": machine.ir_sha256,
            "machine_ir_manifest_sha256": machine.manifest_sha256,
            "review_sha256": review_sha256,
            "match_evidence_sha256": evidence["evidence_sha256"],
            "hypothesis_set_sha256": hypothesis_set["hypothesis_set_sha256"],
            "catalog_lock_sha256": evidence["bindings"].get("catalog_lock_sha256"),
        },
        "islands": islands,
        "coverage": {
            "machine_units": len(machine.units),
            "classified_units": len(claimed),
            "classified_exactly_once": len(claimed) == len(machine.units),
            "units_by_kind": dict(sorted(units_by_kind.items())),
            "reachable_units_by_kind": dict(sorted(reachable_by_kind.items())),
            "potential_units_by_kind": dict(sorted(potential_by_kind.items())),
            "unknown_units": units_by_kind["unknown"],
        },
        "counts": {
            "islands": len(islands),
            "islands_by_kind": dict(sorted(counts_by_kind.items())),
            "constellation_matches": sum(
                island["id"].startswith("constellation:") for island in islands
            ),
            "unknown_cfg_components": counts_by_kind["unknown"],
            "issues": len(issues),
        },
        "issues": sorted(issues, key=_issue_sort_key),
        "authority": {
            "artifact_recognition_authorizes_replacement": False,
            "reviewed_ranges_bind_ownership_only": True,
            "semantic_qualification_required": True,
            "abi_identity_implies_behavior": False,
        },
    }
    if reviewed_complement is not None:
        core["reviewed_unclaimed_exact_units"] = reviewed_complement
        core["authority"]["reviewed_complement_binds_ownership_only"] = True
    payload = {**core, "manifest_sha256": _canonical_sha256(core)}
    write_json(Path(out), payload)
    return payload
