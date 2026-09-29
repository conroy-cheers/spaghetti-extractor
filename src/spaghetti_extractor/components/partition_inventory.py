"""Audit a manually authored partition against the existing semantic universe.

This is planning input, not a new binding, interface, proof or selection format.
Ranges name original transfers only. Crossings come from the checked module,
never from operator-declared effects. No result of this audit authorizes a build.
"""
from __future__ import annotations

from bisect import bisect_right
import json
from pathlib import Path
from typing import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary._canonical import array, digest, exact, identifier, object_, uint
from ..semantic_link.module_v2 import LinkedSemanticModuleV2
from ..semantic_providers.qualification_v2 import SemanticProviderQualificationV2
from ..semantic_providers.slices_v2 import build_semantic_slice_v2
from .binding_intent import ComponentMachineBindingIntentV1
from .formats import COMPONENT_PARTITION_INTENT_V1_FORMAT
from .indexes_v5 import load_component_intent_index_v5
from .interface_package_v5 import ComponentInterfaceIntentV1


def parse_partition(value: object) -> dict:
    row = object_(value, "manual partition")
    exact(row, {"format", "target", "pe_sha256", "units"}, "manual partition")
    if row["format"] != COMPONENT_PARTITION_INTENT_V1_FORMAT:
        raise ValueError("unsupported manual partition format")
    identifier(row["target"], "partition target")
    digest(row["pe_sha256"], "partition original PE")
    ids: set[str] = set()
    intervals = []
    for raw in array(row["units"], "partition units"):
        unit = object_(raw, "partition unit")
        exact(unit, {"id", "description", "rva_ranges"}, "partition unit")
        name = identifier(unit["id"], "partition unit id")
        if name in ids:
            raise ValueError(f"duplicate partition unit: {name}")
        ids.add(name)
        if not isinstance(unit["description"], str) or not unit["description"].strip():
            raise ValueError(f"partition unit {name} needs a boundary description")
        spans = array(unit["rva_ranges"], "partition RVA ranges")
        if not spans:
            raise ValueError(f"partition unit {name} has no ranges")
        for span in spans:
            if not isinstance(span, list) or len(span) != 2:
                raise ValueError("partition ranges must be [start, end) pairs")
            start, end = (uint(item, "partition RVA") for item in span)
            if start >= end or end > 2**32:
                raise ValueError("partition range must be nonempty")
            intervals.append((start, end, name))
    intervals.sort()
    for left, right in zip(intervals, intervals[1:]):
        if left[1] > right[0]:
            raise ValueError(f"overlapping partition ranges: {left[2]}, {right[2]}")
    if not ids:
        raise ValueError("manual partition has no units")
    return dict(row)


def load_intents(index: Path | None, kind: str) -> dict:
    if index is None:
        return {}
    parsed = load_component_intent_index_v5(index, kind=kind)
    field, codec = (
        ("binding_intent", ComponentMachineBindingIntentV1)
        if kind == "machine_binding" else ("interface_intent", ComponentInterfaceIntentV1)
    )
    return {
        row["component_id"]: codec.parse(json.loads((index.parent / row[field]).read_text()))
        for row in parsed.components
    }


def inventory_partition(
    *, module: LinkedSemanticModuleV2, partition: object,
    bindings: Mapping | None = None, interfaces: Mapping | None = None,
    qualifications: tuple[SemanticProviderQualificationV2, ...] = (),
) -> dict:
    plan = parse_partition(partition)
    if module.semantic_object is None:
        raise ValueError("partition inventory requires the complete semantic-module package")
    transfer_plan = module.semantic_object.transfer_plan
    if plan["pe_sha256"] != transfer_plan["bindings"]["pe_sha256"]:
        raise ValueError("manual partition belongs to a different original PE")
    bindings, interfaces = bindings or {}, interfaces or {}
    intervals = sorted((a, b, unit["id"]) for unit in plan["units"] for a, b in unit["rva_ranges"])
    starts = [row[0] for row in intervals]
    units = {row["unit_id"]: row for row in transfer_plan["unit_inventory"]}
    ordered_units = sorted(units.values(), key=lambda row: row["rva_start"])
    unit_starts = [row["rva_start"] for row in ordered_units]
    for start, end, _ in intervals:
        for endpoint in (start, end):
            index = bisect_right(unit_starts, endpoint) - 1
            if index >= 0:
                unit = ordered_units[index]
                if unit["rva_start"] < endpoint < unit["rva_end"]:
                    raise ValueError(f"partition cuts through machine unit {unit['unit_id']}")
    owners, missing = {}, []
    assigned = {row["id"]: [] for row in plan["units"]}
    for uid, unit in units.items():
        index = bisect_right(starts, unit["rva_start"]) - 1
        if index < 0 or unit["rva_start"] >= intervals[index][1]:
            missing.append(uid)
            continue
        _, end, owner = intervals[index]
        if unit["rva_end"] > end:
            raise ValueError(f"partition cuts through machine unit {uid}")
        owners[uid] = owner
        assigned[owner].append(uid)
    empty = sorted(key for key, rows in assigned.items() if not rows)
    if empty:
        raise ValueError(f"partition units contain no machine transfers: {empty}")
    symbol_owner = {f"original:function:{uid}": owner for uid, owner in owners.items()}
    symbol_uid = {f"original:function:{uid}": uid for uid in units}
    reports = {row["id"]: {
        **row, "unit_ids": sorted(assigned[row["id"]]), "entries": set(), "exits": set(),
        "root_ids": [], "dependencies": {}, "incoming_owners": set(),
        "crossing_relocation_ids": set(), "binding_components": [],
        "admitted_domain_ids": set(), "qualification_ids": [],
        "observed_portable_definition_ids": set(),
        "residual_obligation_ids": [],
        "blockers": ["partition_is_not_a_checked_boundary_contract"],
    } for row in plan["units"]}
    for root in module.payload["roots"]:
        owner = symbol_owner.get(root["target_symbol"])
        if owner is not None:
            reports[owner]["root_ids"].append(root["root_id"])
            reports[owner]["entries"].add(symbol_uid[root["target_symbol"]])
    for symbol in module.payload["active_symbols"]:
        owner = symbol_owner.get(symbol["symbol_id"])
        if owner is not None:
            reports[owner]["admitted_domain_ids"].update(symbol["domain_ids"])
    # Keep unassigned/global obligations separately even when no local subject
    # can be recovered. Subject prefixes are existing transfer identities.
    for obligation in module.payload["residual_obligations"]:
        touched = set()
        for subject in obligation.get("subjects", []):
            candidate = subject
            while candidate:
                if candidate in owners:
                    touched.add(owners[candidate])
                    break
                candidate = candidate.rpartition(":")[0]
        for owner in sorted(touched):
            reports[owner]["residual_obligation_ids"].append(obligation["obligation_id"])
    def crossing(source, target, kind, evidence):
        left, right = symbol_owner.get(source), symbol_owner.get(target)
        if left == right and left is not None:
            return
        if left is not None:
            report = reports[left]
            report["exits"].add(symbol_uid[source])
            report["crossing_relocation_ids"].add(evidence)
            dependency = report["dependencies"].setdefault(right or target, set())
            dependency.add(kind)
        if right is not None:
            reports[right]["entries"].add(symbol_uid[target])
            reports[right]["incoming_owners"].add(left or source)
    # The linker owns reachability and checked-infeasible continuations. Raw
    # transfer-plan edges still include fallthrough after checked no-return calls.
    # Do not resurrect those targets or silently treat unresolved routes as edges.
    for relocation in module.payload["active_relocations"]:
        for target in relocation["target_symbols"]:
            crossing(relocation["source_symbol"], target, relocation["kind"], relocation["relocation_id"])
    terminals = {}
    for transfer in transfer_plan["transfers"]:
        uid = transfer["identity"]
        terminals[uid] = transfer["terminator"]["op"]
    binding_reports = []
    for name, binding in sorted(bindings.items()):
        owned = {uid for operation in binding.operations for uid in operation.semantics.unit_ids}
        context = {uid for operation in binding.operations for uid in operation.semantics.proof_context_transfer_ids} - owned
        unknown = sorted((owned | context) - units.keys())
        if unknown:
            raise ValueError(f"binding {name} names absent machine units: {unknown}")
        touched = sorted({owners[uid] for uid in owned if uid in owners})
        interface = interfaces.get(name)
        binding_reports.append({
            "component_id": name, "binding_sha256": binding.intent_sha256,
            "interface_sha256": interface.intent_sha256 if interface else None,
            "declared_interface": interface.to_payload() if interface else None,
            "binding_status": binding.status, "partition_units": touched,
            "owned_unit_ids": sorted(owned), "unowned_proof_context_unit_ids": sorted(context),
            "unowned_proof_context_owners": sorted({owners[uid] for uid in context if uid in owners}),
            "admission": "unverified", "activation_authorized": False,
        })
        for owner in touched:
            reports[owner]["binding_components"].append(name)
    qualification_reports = []
    for qualification in qualifications:
        selection = qualification.semantic_slice.payload
        current = build_semantic_slice_v2(linked_semantic_module=module,
            definition_ids=[row["definition_id"] for row in selection["definitions"]],
            obligation_ids=[row["obligation_id"] for row in selection["obligations"]])
        if current["semantic_slice_sha256"] != qualification.semantic_slice.identity:
            raise ValueError("qualification is stale for the current semantic module")
        context = qualification.payload.get("exact_context", {})
        if context:
            checked_context = build_semantic_slice_v2(linked_semantic_module=module,
                definition_ids=[row["definition_id"] for row in context["definitions"]])
            if checked_context["semantic_slice_sha256"] != context["semantic_slice_sha256"]:
                raise ValueError("qualification exact context is stale for the current semantic module")
        exact_symbols = [row["symbol_id"] for row in context.get("definitions", [])]
        qualification_reports.append({
            "qualification_sha256": qualification.identity,
            "provider_kind": qualification.payload["provider_kind"],
            "status": qualification.payload["status"],
            "definition_ids": [row["definition_id"] for row in selection["definitions"]],
            "exact_context_symbol_ids": exact_symbols,
            "exact_context_owners": sorted({symbol_owner[s] for s in exact_symbols if s in symbol_owner}),
        })
        for definition in selection["definitions"]:
            owner = symbol_owner.get(definition["symbol_id"])
            if owner is not None:
                reports[owner]["qualification_ids"].append(qualification.identity)
                if qualification.payload["status"] != "complete":
                    reports[owner]["blockers"].append("supplied_qualification_incomplete")
                elif qualification.payload["provider_kind"] == "qualified_portable_c":
                    reports[owner]["observed_portable_definition_ids"].add(definition["definition_id"])
                if exact_symbols:
                    reports[owner]["blockers"].append("qualification_requires_exact_machine_neighbors")
    for report in reports.values():
        report["terminal_kinds"] = sorted({terminals[uid] for uid in report["unit_ids"] if uid in terminals})
        report["dependencies"] = [{"subject": k, "kinds": sorted(v)} for k, v in sorted(report["dependencies"].items())]
        for key in ("entries", "exits", "incoming_owners", "crossing_relocation_ids", "admitted_domain_ids", "qualification_ids", "observed_portable_definition_ids", "blockers"):
            report[key] = sorted(set(report[key]))
        if not report["binding_components"]:
            report["blockers"].append("canonical_interface_and_binding_missing")
        if not report["qualification_ids"]:
            report["blockers"].append("qualification_not_supplied")
        if report["residual_obligation_ids"]:
            report["blockers"].append("runtime_obligations_require_provider_selection")
    original_symbols = set(symbol_uid)
    for definition in module.payload["definitions"]:
        owner = symbol_owner.get(definition["symbol_id"])
        if owner is not None:
            report = reports[owner]
            if definition["definition_id"] not in report["observed_portable_definition_ids"]:
                report.setdefault("machine_definition_ids_without_portable_qualification", []).append(definition["definition_id"])
    for report in reports.values():
        report.setdefault("machine_definition_ids_without_portable_qualification", [])
    non_code = [row for row in module.payload["definitions"] if row["symbol_id"] not in original_symbols]
    return {
        "target": plan["target"], "authority": False, "activation_authorized": False,
        "coverage_status": "complete" if not missing else "incomplete",
        "liftability_status": "unverified", "all_lifted_selection_status": "unverified",
        "semantic_module_status": module.payload["status"],
        "bindings": {"linked_semantic_module_sha256": module.identity,
                     "partition_sha256": canonical_sha256_v3(plan), "pe_sha256": plan["pe_sha256"]},
        "counts": {"partition_units": len(reports), "machine_units": len(units),
                   "assigned_machine_units": len(owners), "unassigned_machine_units": len(missing),
                   "non_code_definitions": len(non_code), "residual_obligations": len(module.payload["residual_obligations"])},
        "units": sorted(reports.values(), key=lambda row: row["id"]),
        "unassigned_unit_ids": sorted(missing), "component_bindings": binding_reports,
        "qualifications": qualification_reports, "non_code_definitions": non_code,
        "non_code_requirements": [row for row in module.payload["definition_requirements"]
                                  if row["symbol_id"] not in original_symbols],
        "residual_obligations": module.payload["residual_obligations"],
        "semantic_holes": module.payload["semantic_holes"],
        "analysis_frontiers": module.payload["analysis_frontiers"],
        "roots": module.payload["roots"],
        "relocations_without_targets": [row for row in module.payload["active_relocations"]
                                        if not row["target_symbols"]],
    }
