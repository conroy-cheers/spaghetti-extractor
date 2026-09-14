"""Checked callee stack premises at the actual original CALL boundary.

This is one composition premise, not a complete memory/lifetime contract and
not an independent activation receipt. It applies to checked memory suppliers
on replay as well as to prospective body-free calls.
"""

from collections.abc import Mapping
from pathlib import Path

from ..artifacts.artifact_set import canonical_sha256_v3
from .binding_intent import ComponentMachineBindingIntentV1
from .bisimulation_readable_entry import checked_memory_summary_facts, checked_mutable_entry_operations, readable_machine_state_guarantee
from .bisimulation_mutable_machine_frame import checked_mutable_machine_frame_operations, mutable_machine_state_guarantee
from .bisimulation_view_extent import stack_admission_expression
from .bisimulation_clobber_frame import call_assertions as clobber_assertions, result_registers
from . import bisimulation_private_frame as private_frame
from . import bisimulation_source_dependencies as source_dependencies
from .bisimulation_shared_model import SHARED_CONTRACT_POLICY

POLICY = "checked-readable-callee-stack-entry-v1"
MUTABLE_POLICY = "checked-mutable-callee-stack-entry-v1"
SOURCE_POLICIES = {**{p: POLICY for p in source_dependencies.READONLY_POLICIES},
                   **{p: MUTABLE_POLICY for p in source_dependencies.MUTABLE_POLICIES},
                   SHARED_CONTRACT_POLICY: MUTABLE_POLICY}


def _require(condition, detail):
    if not condition:
        raise ValueError("connected callee entry: " + detail)


def _derive_machine_entries(proof_system, binding_payload, *, mutable, runtime_assurance=None):
    from .contextual_bisimulation import validate_complete_local_refinement
    from .bisimulation_harness import _private_stack_high_offset

    _require(isinstance(proof_system, Mapping) and set(proof_system) == {"proof", "proof_plan", "exact_c_slice"},
             "supplier proof system is incomplete")
    proof = proof_system["proof"]
    source_dependencies.validate_qualified_dependency_tree(proof)
    validate_complete_local_refinement(proof_system, runtime_assurance=runtime_assurance)
    binding = ComponentMachineBindingIntentV1.parse(binding_payload)
    _require(binding.component_id == proof["component_id"] and binding.intent_sha256 ==
             proof["world"]["bindings"]["binding_intent_sha256"], "supplier binding intent differs")
    operations = {row["operation_id"]: row for row in proof["models"]["operation_models"]}
    _require(set(operations) == {row.semantics.operation_id for row in binding.operations}, "operation coverage differs")
    shards = {(row["operation_id"], row["obligation_id"]): row for row in proof["shards"]}
    entries = []
    for row in binding.operations:
        operation = row.semantics
        model = operations[operation.operation_id]
        if model.get("machine_clobbers"):
            _require(model.get("machine_result_registers") == list(result_registers(operation.machine_projection["operation"])),
                     "clobber frame result registers differ from the supplier binding")
        _require(bool(model["obligation_models"]), "supplier operation has no covered segments")
        wide = all(shards[(operation.operation_id, segment["obligation_id"])].get(
            "mutable_entry_contract" if mutable else "readable_entry_contract", {}).get("result", {}).get("status") == "satisfied"
            for segment in model["obligation_models"])
        entries.append({"operation_id": operation.operation_id, "entry_rvas": list(operation.entry_rvas),
            "domain": ("mutable-wide" if mutable else "readable-wide") if wide else "ordinary",
            "private_high_offset": _private_stack_high_offset(operation_projection=operation.machine_projection["operation"]),
            "machine_image": model["machine_image"]})
        if proof['models']['connected_components']:
            guarantee = mutable_machine_state_guarantee if mutable else readable_machine_state_guarantee
            _require(wide and guarantee(proof, model), "transitive supplier lacks its checked wider entry and machine frame")
    return proof, binding, entries


def _derive(proof_system, binding_payload, *, runtime_assurance=None):
    _require(isinstance(proof_system, Mapping) and set(proof_system) == {"proof", "proof_plan", "exact_c_slice"},
             "supplier proof system is incomplete")
    summary = proof_system.get("proof", {}).get("models", {}).get("source_summary_contracts")
    _require(isinstance(summary, Mapping) and summary["certificate"]["policy"] in SOURCE_POLICIES,
             "supplier lacks a checked memory source contract")
    proof, binding, entries = _derive_machine_entries(proof_system, binding_payload,
        mutable=SOURCE_POLICIES[summary["certificate"]["policy"]] == MUTABLE_POLICY, runtime_assurance=runtime_assurance)
    if summary['certificate']['policy'] == SHARED_CONTRACT_POLICY:
        from .bisimulation_shared_composition import shared_boundary_operations
        _require(shared_boundary_operations({'proof_system': proof_system, 'binding_intent': binding_payload,
            'operations': entries}, proof['models']) is not None,
            'shared supplier lacks checked alias, service, image-entry or frame premises')
    return proof, binding, entries


def checked_mutable_machine_call_entry_inputs(*, proof_system, binding_intent, artifacts, runtime_assurance=None):
    """Prepare the actual caller obligation independently of source summaries.

    This is internal renderer input, deliberately without a receipt digest.
    Existing provider entry-contract admission still requires its implemented
    source composition rule. Paired machine entry and frame evidence can be
    checked first at a real caller without inventing a source certificate.
    """
    proof, _, entries = _derive_machine_entries(proof_system, binding_intent, mutable=True, runtime_assurance=runtime_assurance)
    wide = checked_mutable_entry_operations(proof, artifacts=Path(artifacts), runtime_assurance=runtime_assurance)
    machine = checked_mutable_machine_frame_operations(proof, artifacts=Path(artifacts), runtime_assurance=runtime_assurance)
    operations = {entry["operation_id"] for entry in entries}
    _require(operations == set(wide) == set(machine)
             and all(entry["domain"] == "mutable-wide" for entry in entries),
             "machine-only caller premises lack complete wider entry and frame evidence")
    return {**({"assurance": runtime_assurance} if runtime_assurance is not None else {}),
            "policy": MUTABLE_POLICY, "authorizing": False, "proof_system": proof_system,
            "binding_intent": binding_intent, "operations": entries}


def validate_call_entry_contract(value, *, connected, runtime_assurance=None):
    fields = {"policy", "authorizing", "proof_system", "binding_intent", "operations", "receipt_sha256"}
    from .bisimulation_assurance import validate_runtime_assurance_binding
    validate_runtime_assurance_binding(value, runtime_assurance)
    if runtime_assurance is not None:
        fields.add("assurance")
    _require(isinstance(value, Mapping) and set(value) == fields, "contract fields differ")
    _require(value["policy"] in SOURCE_POLICIES.values() and value["authorizing"] is False, "unsupported contract policy")
    _require(value["receipt_sha256"] == canonical_sha256_v3({k: v for k, v in value.items() if k != "receipt_sha256"}),
             "contract digest is stale")
    proof, binding, entries = _derive(value["proof_system"], value["binding_intent"], runtime_assurance=runtime_assurance)
    _require(value["policy"] == SOURCE_POLICIES[proof["models"]["source_summary_contracts"]["certificate"]["policy"]],
             "entry policy differs from the supplier source contract")
    _require(value["operations"] == entries, "entry domains are not derived from the checked supplier")
    _require(proof["component_id"] == connected["component_id"]
             and proof["receipt_sha256"] == connected["proof_receipt_sha256"]
             and binding.intent_sha256 == connected["binding_intent_sha256"], "connected supplier identity differs")
    for key in ("implementation_sha256", "source_profile_sha256", "machine_overlay_sha256", "proof_overlay_sha256"):
        _require(proof["models"][key] == connected[key], "connected supplier " + key + " differs")


def checked_call_entry_contract(raw, *, connected, runtime_assurance=None):
    summary = raw.get("source_summary_contracts")
    if not isinstance(summary, Mapping) or summary.get("certificate", {}).get("policy") not in SOURCE_POLICIES:
        return None
    proof_system, binding = raw.get("proof_system"), raw.get("binding_intent")
    proof, _, entries = _derive(proof_system, binding, runtime_assurance=runtime_assurance)
    _require(summary == proof['models']['source_summary_contracts'],
             'current source summary differs from the paired supplier proof')
    _require(isinstance(raw.get("proof_artifacts"), (str, Path)), "supplier has no retained paired models")
    if SOURCE_POLICIES[summary["certificate"]["policy"]] == MUTABLE_POLICY:
        wide = checked_mutable_entry_operations(proof, artifacts=Path(raw["proof_artifacts"]), runtime_assurance=runtime_assurance)
        machine = checked_mutable_machine_frame_operations(proof, artifacts=Path(raw["proof_artifacts"]), runtime_assurance=runtime_assurance)
        from .bisimulation_image_frame import checked_operations as checked_image_frames
        checked_image_frames(proof, artifacts=Path(raw['proof_artifacts']), runtime_assurance=runtime_assurance)
        _require(set(machine) == {operation["operation_id"] for operation in proof["models"]["operation_models"]
                                 if mutable_machine_state_guarantee(proof, operation)}, "machine frames lack retained evidence")
    else:
        wide = checked_memory_summary_facts(proof, artifacts=Path(raw["proof_artifacts"]), runtime_assurance=runtime_assurance)["readable_entry_operations"]
    _require({row["operation_id"] for row in entries if row["domain"] != "ordinary"} == set(wide),
             "wider domains lack retained evidence")
    core = {**({"assurance": runtime_assurance} if runtime_assurance is not None else {}), "policy": SOURCE_POLICIES[summary["certificate"]["policy"]], "authorizing": False, "proof_system": proof_system,
            "binding_intent": binding, "operations": entries}
    result = {**core, "receipt_sha256": canonical_sha256_v3(core)}
    validate_call_entry_contract(result, connected=connected, runtime_assurance=runtime_assurance)
    return result


def call_entry_assertions(connected):
    contract = connected.get("entry_contract")
    return [] if contract is None else [
        f"spx-bisimulation-connected-callee-{kind}:{connected['component_id']}:{entry['operation_id']}"
        for entry in contract["operations"]
        for kind in (["stack-entry", "machine-state"] if connected.get("summary_strategy", "connected-replay-v1") == "connected-replay-v1"
                     else ["stack-entry"])] + clobber_assertions(connected) + private_frame.call_assertions(connected)


def call_entry_checks(row):
    contract = row.get("entry_contract")
    if contract is None:
        return []
    candidates = [entry for entry in contract["operations"] if entry["operation_id"] == row["operation_id"]]
    _require(len(candidates) == 1 and row["entry_rva"] in candidates[0]["entry_rvas"], "call entry is not covered")
    models = contract["proof_system"]["proof"]["models"]["operation_models"]
    covered = [model for model in models if model["operation_id"] == row["operation_id"]]
    _require(len(covered) == 1 and row["entry_rva"] == covered[0]["exact_entry_rva"]
             and row["symbol"] == covered[0]["overlay_symbol"], "dispatch differs from the checked supplier operation")
    entry = candidates[0]
    image = entry["machine_image"]
    predicate = stack_admission_expression(stack_pointer="call_state.esp",
        high_offset=f"UINT32_C({entry['private_high_offset']})", image_base=image["preferred_base"],
        image_size=image["image_size"], wide_domain=entry["domain"] in {"readable-wide", "mutable-wide"})
    condition = f"rt->image_base == UINT32_C({image['preferred_base']}) && {predicate}"
    ranges = private_frame.parse_stack_writes(covered[0].get("private_stack_writes", []))
    if ranges:
        condition += " && " + private_frame.admission(ranges, stack="call_state.esp", image_base=image["preferred_base"],
            image_size=image["image_size"], high=f"UINT32_C({entry['private_high_offset']})")
    lines = [f"      uint32_t entry_admitted = {condition};",
        f'      __CPROVER_assert(entry_admitted, "spx-bisimulation-connected-callee-stack-entry:{row["component_id"]}:{row["operation_id"]}");',
        "      __CPROVER_assume(entry_admitted);"]
    if row.get("summary_strategy", "connected-replay-v1") == "connected-replay-v1":
        proof = contract["proof_system"]["proof"]
        guarantee = mutable_machine_state_guarantee if contract["policy"] == MUTABLE_POLICY else readable_machine_state_guarantee
        available = "1U" if guarantee(proof, covered[0]) else "0U"
        lines += [f'      __CPROVER_assert({available}, "spx-bisimulation-connected-callee-machine-state:{row["component_id"]}:{row["operation_id"]}");',
                  f"      __CPROVER_assume({available});"]
    return lines
