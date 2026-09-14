"""Bounded operator explanations of a qualification's existing proof failures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..components.binding_intent import ComponentMachineBindingIntentV1

_MODEL_CAPACITY_ASSERTIONS = frozenset("spx-bisimulation-" + kind + "-capacity" for kind in (
    "public-write", "private-write", "atomic", "exact-call", "source-call", "typed-call", "typed-exact-call"))


def component_binding_details(*, value: Mapping, path: Path, component_id: str) -> list[str]:
    """Expose checked draft identity and declared blockers without granting authority."""
    binding = ComponentMachineBindingIntentV1.parse(value)
    if binding.component_id != component_id:
        raise ValueError("component binding intent names another component")
    lines = [f"Binding to review: {_text(path, 500)}"]
    for blocker in binding.blockers[:10]:
        code = _text(blocker.get("code", "binding_intent_incomplete"))
        detail = blocker.get("detail", blocker.get("message"))
        lines.append(f"  Declared blocker: {code}" + (f" — {_text(detail)}" if detail else ""))
    if len(binding.blockers) > 10:
        lines.append(f"  {len(binding.blockers) - 10} further declared blocker(s); inspect the binding.")
    if not binding.blockers:
        lines.append("The binding declares no blockers; inspect component status for missing proof inputs or unsupported admission.")
    return lines


def _rows(value: object) -> list[Mapping]:
    return [row for row in value if isinstance(row, Mapping)] if isinstance(value, list) else []


def _receipt(value: Mapping) -> str:
    return canonical_sha256_v3({
        "qualification_input_sha256": value["qualification_input_sha256"],
        "source_package_sha256": value["source_package_sha256"],
        "semantic_contract_sha256": value["proof_plan"]["bindings"]["semantic_contract_sha256"],
        "cbmc_sha256": value["proof"]["checker"]["cbmc_sha256"],
        "proof": value["proof"],
        "relation_evidence": value["relation_evidence"],
        "proof_plan_sha256": value["proof_plan"]["plan_sha256"],
        "exact_c_slice_sha256": value["exact_c_slice"]["slice_sha256"],
    })


def _text(value: object, limit: int = 300) -> str:
    text = " ".join("".join(character if ord(character) >= 32 and not 127 <= ord(character) <= 159 else " "
                            for character in str(value)).split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _hint(code: str, description: str) -> str:
    if description in _MODEL_CAPACITY_ASSERTIONS:
        return "The proof model exhausted its event history. Review the recorded bounds and source accesses before rechecking."
    if "timeout" in code:
        return "Inspect the region's query timings and refine its cuts or proved summaries."
    if description.startswith("spx-bisimulation-capture:"):
        return "Check this capture's source value and machine projection at the cut."
    if description.startswith(("spx-bisimulation-capture-memory:", "spx-bisimulation-capture-reference-memory:")):
        return "Compare this view's bytes on both sides; check preceding writes and aliases."
    if description.startswith("spx-bisimulation-capture-methods:"):
        return "Keep this borrowed view's access methods intact across the cut."
    if description.startswith("spx-bisimulation-capture-metadata:"):
        return "Check this view's reference identity, offset, permissions and element width at the cut."
    if description.startswith("spx-bisimulation-capture-context:"):
        return "Check the view's access context, address, extent, permissions and runtime dispatch at the cut."
    if description.startswith("spx-bisimulation-capture-extent:"):
        return "Check the view's visible and reference extents, aliases and terminating byte at the cut."
    if description.startswith(("spx-bisimulation-private-stack-scope:", "spx-bisimulation-private-stack-scope-input:")):
        return "Check the cut's invocation stack scope and predecessor register relation; changing ESP must not reclassify live memory."
    if description.startswith("spx-bisimulation-source-frame-preservation:"):
        return "A reconstructed frame changes borrowed memory; inspect the cut's storage mapping."
    if description.startswith("spx-bisimulation-resumed-view-admission:"):
        return "Review this view's extent and ownership at the cut."
    if description.startswith("spx-bisimulation-invariant:"):
        return "Check that the cut invariant holds on every incoming transition."
    if description.startswith("spx-bisimulation-derived:"):
        return "The predecessor does not establish this derived cut relation. Compare its outgoing registers or memory with the proposed relation before resuming the next region."
    if "connected-summary-input:" in description or "connected-summary-memory:" in description:
        return "Check the callee's arguments and readable memory on both sides of the call."
    if description.startswith("spx-bisimulation-connected-callee-machine-state:"):
        return "The callee lacks a checked machine-state guarantee for replay. Inspect its cut and exit frames before using its source adapter at this call."
    if description.startswith("spx-bisimulation-connected-callee-private-poststate:"):
        return "Transporting the callee's residual stack writes faults in this caller. Check its entry stack and the checked private footprint."
    if description.startswith("spx-bisimulation-private-write-frame:"):
        return "An original store escapes the writable views and declared private stack bytes. Inspect its address and footprint."
    if description.startswith("spx-bisimulation-private-cut-frame:"):
        return "The stack anchor changes across this cut. Preserve its relation or move the boundary before consuming this footprint."
    if "call-public-memory" in description:
        return "Public memory differs at this call; compare preceding writes and aliases. The current check observes all public bytes, so narrower read footprints may be needed."
    if description.startswith("spx-bisimulation-typed-service-reference:"):
        return "Check the service argument's issued origin, generation, permissions and visible extent at the call."
    if description.startswith("spx-bisimulation-typed-service-termination:"):
        return "The service requires a current readable terminator within this view: a checked registered prefix or the view's final byte. Inspect its extent, live origin and preceding writes through aliases."
    if "world-memory:" in description:
        return "Inspect writes and state representation for the differing memory."
    if "exit-continuation-state:" in description:
        return "The continuation receives different machine state; bind the missing output or prove a checked context relation for the difference."
    if "continuation-bound:" in description:
        return "The declared continuation did not reach a common boundary within its checked bound; review the context and required cut relations."
    if "continuation-memory:" in description:
        return "The continuation exposes a memory difference; inspect reads, writes and aliases before discarding machine state."
    if "continuation-implemented:" in description:
        return "A continuation unit did not execute; inspect exact slice coverage and required services."
    if "exit-observable:" in description or "exit-value:" in description:
        return "Compare the source result and live state with the original operation."
    if "unwind" in code or "unwind" in description:
        return "Check for an uncovered cycle or a region whose proved bound is insufficient."
    return "Inspect this obligation's counterexample and retained proof inputs."


def _source_location(shard: Mapping, artifact_root: Path) -> str | None:
    source = shard.get("source")
    trace = shard.get("counterexample")
    if isinstance(trace, list):
        # Prefer the latest source-program assignment over an assertion in the
        # generated harness. These are artifact snapshot locations, not claims
        # that an edited workspace file still has the same content.
        for step in reversed(trace):
            location = step.get("sourceLocation") if isinstance(step, Mapping) else None
            if isinstance(location, Mapping) and "/sources/" in str(location.get("file", "")):
                source = location
                break
    if not isinstance(source, Mapping) or not isinstance(source.get("file"), str):
        return None
    file = source["file"]
    parts = Path(file).parts
    for index, part in enumerate(parts):
        if part.startswith("operation-") and "-obligation-" in part:
            retained = artifact_root / "proof-diagnostics" / Path(*parts[index:])
            if (retained.resolve().is_relative_to((artifact_root / "proof-diagnostics").resolve())
                    and retained.is_file()):
                file = str(retained)
            break
    line = str(source.get("line", ""))
    return _text(file + (":" + line if line.isdigit() else ""), 500)


def _callee_machine_details(proof: Mapping, description: str, maximum: int) -> list[str]:
    """Navigate recorded supplier premises, without promoting them to authority."""
    models = proof.get("models")
    if not isinstance(models, Mapping):
        return []
    for connected in _rows(models.get("connected_components")):
        component = connected.get("component_id")
        entry = connected.get("entry_contract")
        if (not isinstance(component, str) or not isinstance(entry, Mapping)
                or entry.get("policy") != "checked-mutable-callee-stack-entry-v1"):
            continue
        operations = [row.get("operation_id") for row in _rows(entry.get("operations"))]
        operation = next((name for name in operations if isinstance(name, str) and description ==
            f"spx-bisimulation-connected-callee-machine-state:{component}:{name}"), None)
        system = entry.get("proof_system")
        supplier = system.get("proof") if isinstance(system, Mapping) else None
        if operation is None or not isinstance(supplier, Mapping) or supplier.get("component_id") != component:
            continue
        supplier_models = supplier.get("models")
        model = next((row for row in _rows(supplier_models.get("operation_models"))
                      if row.get("operation_id") == operation), {}) if isinstance(supplier_models, Mapping) else {}
        machine_kind = "clobber" if model.get("machine_clobbers") else "machine"
        fields = [("mutable_entry_contract", "wider entry"),
                  (f"exact_mutable_cut_{machine_kind}_frame", f"cut {machine_kind} frame"),
                  (f"exact_mutable_exit_{machine_kind}_frame", f"exit {machine_kind} frame")]
        if model.get("private_stack_writes"):
            fields += [("exact_private_write_frame", "private write frame"),
                       ("exact_private_cut_frame", "private stack anchor")]
        failures = []
        for shard in _rows(supplier.get("shards")):
            if shard.get("operation_id") != operation:
                continue
            for field, label in fields:
                fact = shard.get(field)
                result = fact.get("result") if isinstance(fact, Mapping) else None
                status = result.get("status") if isinstance(result, Mapping) else None
                if status == "satisfied":
                    continue
                status = status if status in {"violated", "incomplete"} else "not supplied"
                subject = _text(shard.get("obligation_id", shard.get("shard_id", "segment")))
                failures.append(f"  Supplier {_text(component)} / {_text(operation)} / {subject}: {label} {status}.")
        lines = failures[:maximum]
        if len(failures) > maximum:
            lines.append(f"  {len(failures) - maximum} further supplier premise(s); inspect the nested entry contract.")
        if lines:
            lines.append("  Recorded supplier proof: " + _text(supplier.get("receipt_sha256", "identity unavailable")))
            lines.append("  These are composition premises; their failure alone does not disprove the supplier's ordinary equivalence.")
        return lines
    return []


def component_failure_details(*, qualification: Mapping, qualification_path: Path,
                              component_id: str, maximum: int = 3) -> list[str]:
    """Explain existing failures without changing qualification or authority.

    The dependency identity binds the sidecar to the selected qualification.
    Missing, malformed or unrelated sidecars never replace its blockers or
    grant success. We deliberately do not treat a historical proof as current
    authorization, or execute tools while formatting its diagnostics.
    """
    path = qualification_path.parent / "contextual-refinement-result.json"
    if not isinstance(maximum, int) or isinstance(maximum, bool) or not 1 <= maximum <= 10:
        raise ValueError("proof diagnostic limit must be between one and ten")
    if not path.is_file():
        return []
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        proof = value["proof"]
        if not isinstance(proof, Mapping):
            raise ValueError("malformed proof")
        if (proof.get("component_id") != component_id
                or value.get("receipt_sha256") != _receipt(value)
                or "contextual-refinement:" + str(value.get("receipt_sha256", ""))
                not in qualification.get("dependencies", [])):
            return ["Proof diagnostics do not match this qualification; regenerate the component check."]
        shards = proof["shards"]
        if not isinstance(shards, list) or any(not isinstance(shard, Mapping) for shard in shards):
            raise ValueError("malformed shard list")
    except (OSError, UnicodeError, ValueError, KeyError, TypeError):
        return ["Proof diagnostics could not be read; inspect the qualification blockers and build log."]
    failures = [shard for shard in shards if shard.get("status") != "satisfied"]
    result = []
    if proof.get("status") == "satisfied" and proof.get("activation_authorized") is False:
        contexts = [operation for operation in _rows(value["proof_plan"].get("operations"))
                    if isinstance(operation.get("continuation"), Mapping)]
        for operation in contexts[:maximum]:
            identity = _text(operation.get("operation_id", "operation"))
            result.append(f"{identity}: continuation selection is required; local proof obligations pass.")
            result.append("  Dispatch/link proof must preserve the exact behavior of the declared continuation units before activation.")
    for shard in failures[:maximum]:
        code = _text(shard.get("code", "proof_incomplete"))
        description = _text(shard.get("detail", code))
        partitioned = shard.get("partitioned_evidence")
        if isinstance(partitioned, Mapping):
            assertions = {row.get("property_id"): row.get("description")
                          for row in _rows(partitioned.get("assertions"))
                          if isinstance(row.get("property_id"), str)}
            failed = next((query for query in _rows(partitioned.get("queries"))
                           if query.get("status") != "satisfied"), None)
            if (failed is not None and isinstance(failed.get("property_id"), str)
                    and failed["property_id"] in assertions):
                description = _text(assertions[failed["property_id"]])
        subject = _text(shard.get("shard_id", shard.get("operation_id", "operation")))
        if description in _MODEL_CAPACITY_ASSERTIONS:
            code = "proof_model_capacity_exhausted"
        elif description.startswith("spx-bisimulation-connected-callee-machine-state:"):
            code = "proof_callee_machine_state_unproved"
        result.append(f"{subject}: {code}: {description}")
        try:
            location = _source_location(shard, qualification_path.parent)
        except (OSError, ValueError):
            location = None
        if location is not None:
            result.append("  Artifact source/proof location: " + location)
        result.append("  " + _hint(code, description))
        if code == "proof_callee_machine_state_unproved":
            result.extend(_callee_machine_details(proof, description, maximum))
    if len(failures) > maximum:
        result.append(f"{len(failures) - maximum} further failed obligation(s) are in the proof artifact.")
    if result:
        result.append("Proof diagnostics: " + str(path))
    return result
