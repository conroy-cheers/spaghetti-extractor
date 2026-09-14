"""Checked image-backed readable composition in the existing summary engine.

The first admitted world has fixed image origins and no allocation history or
finite-control initial-byte overrides. Other worlds retain checked replay.
"""

import json
from collections.abc import Mapping

from .binding_intent import ComponentMachineBindingIntentV1
from .bisimulation_readable_entry import readable_machine_state_guarantee
from .bisimulation_mutable_machine_frame import mutable_machine_state_guarantee
from .bisimulation_projection import _projection_expression
from .bisimulation_readonly_model import fixed_readonly_summary_operations, fixed_mutable_summary_operations
from .machine_overlay_services_v5 import _c_identifier
from .interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from .bisimulation_source_dependencies import MUTABLE_POLICIES, READONLY_POLICIES

STRATEGY = "image-readable-body-free-v1"
MUTABLE_STRATEGY = "image-mutable-body-free-v1"


def image_readable_operations(entry, parent_models, *, mutable=False):
    """Derive admitted contracts, never accept caller-declared frame booleans.

    The caller validates the full nested supplier proof and retained bytes first.
    This function also serves the metadata reader after that validation.
    """
    if entry is None:
        return None
    proof = entry["proof_system"]["proof"]
    models = proof["models"]
    authority = models.get("reference_authority")
    if (not isinstance(authority, Mapping) or not authority.get("rules")
            or parent_models.get("reference_authority") != authority
            or authority.get("data_export_anchors")
            or any(rule.get("kind") != "image" or rule.get("lifetime") != "image"
                   or rule.get("locator", {}).get("kind") != "image_rva"
                   or rule.get("extent_mode", "fixed") != "fixed" for rule in authority["rules"])
            or any(owner.get(key) is not None for owner in (models, parent_models)
                   for key in ("reference_allocation_requirements", "reference_runtime_inventory"))):
        return None
    certificate = models.get("source_summary_contracts", {}).get("certificate", {})
    if certificate.get("policy") not in (MUTABLE_POLICIES if mutable else READONLY_POLICIES) or certificate.get("status") != "satisfied":
        return None
    bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(certificate["interface_intent"]))
    if (fixed_mutable_summary_operations if mutable else fixed_readonly_summary_operations)(bundle) is None:
        return None
    binding = ComponentMachineBindingIntentV1.parse(entry["binding_intent"])
    shards = {(s["operation_id"], s["obligation_id"]): s for s in proof["shards"]}
    operations = {o["operation_id"]: o for o in models["operation_models"]}
    domains = {o["operation_id"]: o for o in entry["operations"]}
    rules = {rule["id"]: rule for rule in authority["rules"]}
    result = []
    for bound in binding.operations:
        operation = bound.semantics
        model = operations[operation.operation_id]
        if (domains[operation.operation_id]["domain"] != ("mutable-wide" if mutable else "readable-wide")
                or not (mutable_machine_state_guarantee if mutable else readable_machine_state_guarantee)(proof, model)
                or any(parent["machine_image"] != model["machine_image"] for parent in parent_models["operation_models"])):
            return None
        for segment in model["obligation_models"]:
            shard = shards[(operation.operation_id, segment["obligation_id"])]
            theorem = shard.get("mutable_entry_contract" if mutable else "readable_entry_contract", {})
            if (segment.get("finite_control_route_inventory_sha256") is not None
                    or theorem.get("result", {}).get("status") != "satisfied"
):
                return None
        logical = next(o for o in bundle.interface.operations if o.identity == operation.operation_id)
        signature = bundle.intent.schema.signature_index[logical.signature_id]
        projection = operation.machine_projection["operation"]
        parameters = {p["id"]: p["projection"] for p in projection["parameters"]}
        selectors = {row["authority_id"]: row["rule_id"] for row in bound.authority["object_authority_selectors"]}
        views = []
        for value in signature.parameters:
            if value.interpretation != "view":
                continue
            parameter = parameters[value.identity]
            size = value.extent["bytes"]
            if not 0 < size <= 0xffffffff:
                return None
            if (parameter.get("kind") != "view" or any(
                    parameter.get(key, {}).get("kind") != "constant" or parameter[key].get("value") != size
                    for key in ("requested_extent", "extent"))):
                return None
            selector = selectors.get(parameter.get("authority", {}).get("id"))
            if selector is None and len(rules) == 1:
                selector = next(iter(rules))
            permissions = 3 if mutable and value.access == "read_write" else 1
            if selector not in rules or rules[selector]["permissions"] & permissions != permissions:
                return None
            address = _projection_expression(parameter["base"], state="call_state", read="spx_proof_exact_output_read")
            if address is None:
                return None
            views.append({"id": value.identity, "address": address, "bytes": size, "selector": selector,
                          **({"permissions": permissions} if mutable else {})})
        result.append({"operation_id": operation.operation_id, "views": views})
    return result


def image_readable_assertions(connected):
    if connected.get("summary_strategy") not in (STRATEGY, MUTABLE_STRATEGY):
        return []
    flavor = "mutable" if connected["summary_strategy"] == MUTABLE_STRATEGY else "readable"
    return [f"spx-bisimulation-connected-{flavor}-entry:{connected['component_id']}:{operation['operation_id']}"
            for operation in connected["entry_contract"]["operations"]]


def image_readable_entry_checks(row):
    if row.get("summary_strategy") not in (STRATEGY, MUTABLE_STRATEGY):
        return []
    mutable = row["summary_strategy"] == MUTABLE_STRATEGY
    entry = row["entry_contract"]
    child = entry["proof_system"]["proof"]["models"]
    operations = image_readable_operations(entry, child, mutable=mutable)
    if operations is None:
        raise ValueError("readable composition lacks checked supplier guarantees")
    operation = next(o for o in operations if o["operation_id"] == row["operation_id"])
    lines = ["      uint32_t readable_entry = rt->resolve_reference != 0 && spx_exact_world.allocation_count == 0U;"]
    for index, view in enumerate(operation["views"]):
        ref, address = f"readable_reference_{index}", f"readable_address_{index}"
        lines += [f"      uint32_t {address} = (uint32_t)({view['address']});",
            f"      spx_machine_reference_v1 {ref} = {{0}};",
            f"      readable_entry = readable_entry && rt->resolve_reference(rt->context, {address}, "
            f"UINT32_C({view['bytes']}), {view.get('permissions', 1)}U, {json.dumps(view['selector'])}, 0U, 0U, &{ref}) == SPX_BOUNDARY_OK;",
            f"      readable_entry = readable_entry && {ref}.offset <= {address} && {ref}.extent <= UINT32_MAX && "
            f"{ref}.offset <= {ref}.extent && UINT64_C({view['bytes']}) <= {ref}.extent - {ref}.offset && "
            f"(uint64_t){address} - {ref}.offset != 0U && "
            f"{ref}.extent <= UINT64_C(4294967296) - ((uint64_t){address} - {ref}.offset);"]
    flavor = "mutable" if mutable else "readable"
    return lines + [f'      __CPROVER_assert(readable_entry, "spx-bisimulation-connected-{flavor}-entry:{row["component_id"]}:{row["operation_id"]}");',
                    "      __CPROVER_assume(readable_entry);"]


def mutable_summary_bounds(connected_components):
    """Derive wrapper loop bounds and write budgets from checked fixed views.

    Callers validate suppliers first. The operation body has no role in either
    bound; overlapping writable views conservatively count each write again.
    """
    loops, writes = {}, 0
    for connected in connected_components:
        if connected.get("summary_strategy") != MUTABLE_STRATEGY:
            continue
        certificate = connected["entry_contract"]["proof_system"]["proof"]["models"]["source_summary_contracts"]["certificate"]
        bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(certificate["interface_intent"]))
        sizes = []
        for operation in bundle.interface.operations:
            values = bundle.intent.schema.signature_index[operation.signature_id].parameters
            extents = [v.extent["bytes"] for v in values if v.interpretation == "view" and v.access == "read_write"]
            symbol = _c_identifier(certificate["operation_symbols"][operation.identity])
            loops.update({f"{symbol}.{index}": size + 1 for index, size in enumerate(extents)})
            sizes.append(sum(extents))
        writes += max(sizes)
    return loops, writes


def mutable_summary_unwind_arguments(connected_components, authority_arguments):
    loops, _ = mutable_summary_bounds(connected_components)
    if not loops:
        return authority_arguments
    bounds = dict(item.rsplit(":", 1) for item in authority_arguments[1].split(",")) if authority_arguments else {}
    bounds.update(loops)
    return ["--unwindset", ",".join(f"{key}:{value}" for key, value in sorted(bounds.items()))]
