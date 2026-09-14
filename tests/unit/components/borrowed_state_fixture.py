"""Paired current-memory proof using the real helper's hand-defined boundary.

The transfer body copies one module byte into the buffer. It is a small test
operation, not a substitute for the real helper's unchecked LoadStringA call.
"""

import copy
from pathlib import Path

from spaghetti_extractor.components.binding_intent import ComponentMachineBindingIntentV1
from spaghetti_extractor.components.bisimulation import ComponentBisimulationIntentV1, build_component_proof_plan_v1
from spaghetti_extractor.components.bisimulation_refinement import check_bisimulation_refinement
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.component_exact_c_slice import write_component_exact_c_slice_v1
from spaghetti_extractor.components.contextual_bisimulation import (
    build_contextual_refinement_v2, operation_sources_from_package,
)
from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.machine_overlay_v5 import render_component_machine_overlay_v5
from spaghetti_extractor.components.normalized_component import NormalizedComponentContract, NormalizedMachineBinding
from spaghetti_extractor.components.refinement_v5 import _logical_projection
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.components.source_profile import check_component_source_profile
from spaghetti_extractor.semantic_objects.object_authority import MachineObjectAuthorityV2
from spaghetti_extractor.semantic_providers.portable_c_inputs import _component_proof_world_v1
from spaghetti_extractor.transfer.model import _Action, _Node, _Transfer
from .test_hand_defined_boundaries import shared_buffer_bundle
from .test_shared_state_views import projections
from .test_inductive_relation import _unit


def prepare_borrowed_state(*, foreign_read=False):
    original = shared_buffer_bundle().intent
    operations = copy.deepcopy(original.to_payload()["operations"])
    operations[0].update(effect_ids=[], allowed_service_ids=[])
    bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.create(
        component_id=original.component_id, schema=original.schema, state=original.state,
        operations=operations, effects=[], services=[], protocol_states=["ready"], initial_protocol_state="ready"))
    rows, result = projections()
    unit = "semantic-transfer:original-cutpoint-00001284-000012a7"
    operation = {"operation_id": "get", "entry_unit_ids": [unit], "exit_unit_ids": [unit],
        "parameters": [{"id": "id", "projection": {"kind": "stack", "width": 32, "offset": 4, "at": "entry"}}],
        "results": [{"id": "result", "projection": result}], "state": list(rows.values()),
        "effects": [], "preserved_state_ids": [], "callback_operation_ids": [], "continuation_unit_ids": []}
    binding = ComponentMachineBindingIntentV1.create(component_id="resource-text", blockers=[], operations=[{
        "id": "get", "kind": "operation", "unit_ids": [unit], "entry_rvas": [0x1284],
        "transfer_ids": [unit], "effect_ids": [], "service_ids": [], "callback_ids": [],
        "outcome_protocol_ids": [], "machine_projection": {"operation": operation, "service_bindings": []},
        "object_authority_selectors": [{"authority_id": name, "rule_id": name} for name in rows],
        "pointer_views": [], "relation_receipt_sha256s": [], "induction_evidence_sha256": None}])
    contract = NormalizedComponentContract.create(interface=bundle.interface,
        machine_semantics=[row.semantics for row in binding.operations])
    machine = NormalizedMachineBinding.create(bundle=bundle, contract=contract,
        artifacts={key: "a" * 64 for key in ("pe_sha256", "machine_ir_sha256", "machine_ir_manifest_sha256",
            "structural_units_sha256", "unit_inventory_sha256", "component_unit_inventory_sha256")},
        operation_authority={"get": {**dict(binding.operations[0].authority),
            "service_ids": [], "callback_ids": [], "outcome_protocol_ids": []}})
    nodes = (_Node("const", immediate=0x410150), _Node("load", (0,), aux=4),
             _Node("const", immediate=0x413d20), _Node("reg", aux=7), _Node("load", (3,), aux=4),
             _Node("const", immediate=4), _Node("add32", (3, 5)))
    if foreign_read:
        nodes += (_Node('const', immediate=0x600000), _Node('load', (7,), aux=4))
    transfer = _Transfer(unit, "a" * 64, "b" * 64, 0x1284, nodes, (),
        (*(_Action("eval_word", (i,)) for i in range(len(nodes))), _Action("memory_write", (2, 1), aux=1),
         _Action("set_reg", (2,), aux=0), _Action("set_reg", (6,), aux=7), _Action("outcome_return", (4,))), (), ())
    authority = MachineObjectAuthorityV2(machine_backend="x86-pe32", bindings={"original_pe_sha256": "a" * 64}, rules=[
        {"id": name, "kind": "image", "domain": 0x100000003, "object": 0x200000037 + i,
         "generation": 17, "extent": extent, "permissions": permissions, "lifetime": "image",
         "locator": {"kind": "image_rva", "image_id": "test", "rva": rva},
         "interior_pointers": True, "evidence_sha256": "a" * 64}
        for i, (name, rva, extent, permissions) in enumerate((
            ("module", 0x10150, 4, 1), ("buffer", 0x13d20, 500, 3)))])
    overlay = render_component_machine_overlay_v5(bundle=bundle, contract=contract,
        operation_symbols={"get": "borrowed_get"}, transfers=[transfer], machine_binding=machine,
        object_authority_rule_ids=["module", "buffer"])
    return bundle, binding, contract, operation, transfer, authority, overlay


def check_borrowed_state(root: Path, *, cbmc: Path, zero_contents=False, authority_missing=False, foreign_read=False, private_accesses=None, origin_capacity=None):
    bundle, binding, contract, projection, transfer, authority, overlay = prepare_borrowed_state(foreign_read=foreign_read)
    interface = ProofKernelComponentInterface.parse(_logical_projection(bundle, contract=contract))
    intent = ComponentBisimulationIntentV1.create(component_id="resource-text",
        operations=[{"operation_id": "get", "syncs": [],
            **({"private_stack_accesses": private_accesses} if private_accesses is not None else {}),
            **({"reference_origin_capacity": origin_capacity} if origin_capacity is not None else {})}])
    exact = write_component_exact_c_slice_v1(component_id="resource-text", transfers=[transfer],
        operations=[{"operation_id": "get", "unit_ids": [transfer.identity], "entry_rvas": [0x1284],
                     "context_unit_ids": [transfer.identity], "continuation_unit_ids": []}],
        intent=intent, executable_transfer_plan_sha256="a" * 64, out=root/"exact")
    source_path = root/"authored.c"
    source_path.write_text('''#include "portable-component-implementation.h"
spx_view_v5 borrowed_get(spx_resource_text_context_v5 *context, uint32_t id) {
  (void)id;
  SPX_PROOF_BEGIN(get);
  uint64_t current = 0;
  const spx_view_v5 *module = &context->state.module;
  if (module->read(module->access_context, module->base, 0, 4, &current)) return (spx_view_v5){0};
  if (spx_view_write_u8(&context->state.buffer, 0, CONTENTS)) return (spx_view_v5){0};
  return context->state.buffer;
}
'''.replace("CONTENTS", "0" if zero_contents else "(uint8_t)current"))
    symbols = {"get": "borrowed_get"}
    source = build_component_source_package(lift_unit_id="resource-text", files={"authored.c": source_path},
        shared_inputs={}, operation_symbols=symbols, out_dir=root/"source")
    unit = _unit(transfer.identity, 0x1284, [], [])
    unit["semantics"]["memory_events"] = [
        {"kind": "read", "width": 4, "address": {"op": "const", "width": 32, "value": 0x410150}},
        {"kind": "write", "width": 1, "address": {"op": "const", "width": 32, "value": 0x413d20},
         "value": {"op": "load", "width": 4, "address": {"op": "const", "width": 32, "value": 0x410150}}},
        {"kind": "read", "width": 4, "address": {"op": "reg", "width": 32, "name": "esp"}}]
    if foreign_read:
        unit['semantics']['memory_events'].append(
            {'kind': 'read', 'width': 4, 'address': {'op': 'const', 'width': 32, 'value': 0x600000}})
    semantic = {**projection, "machine_image": {"preferred_base": 0x400000, "image_size": 0x20000}, "units": [unit]}
    profile = check_component_source_profile(package=root/"source")
    proof_authority = authority.to_payload() if not authority_missing else MachineObjectAuthorityV2(
        machine_backend="x86-pe32", bindings={"original_pe_sha256": "a" * 64}, rules=[]).to_payload()
    result = check_bisimulation_refinement(semantic_contract={"component_id": "resource-text", "contract_sha256": "a" * 64,
        "operations": [semantic]}, interface=interface, source_package=root/"source", source_profile=profile, intent=intent,
        exact_c_root=root/"exact", exact_c_slice=exact, machine_overlay_source=overlay.source,
        machine_overlay_entries=overlay.entries, reference_authority=proof_authority,
        machine_projections={"get": {"operation": projection, "service_bindings": []}},
        cbmc=cbmc, c_headers=render_component_c_headers_v5(bundle, symbols), timeout_seconds=30,
        diagnostic_root=root/"diagnostics")
    plan = build_component_proof_plan_v1(component_id="resource-text", semantic_contract_sha256="a" * 64,
        interface=interface, operations=[semantic], operation_sources=operation_sources_from_package(
            source_root=root/"source", source=source, symbols=symbols),
        source_package_sha256=source["implementation_sha256"], intent=intent)
    proof = build_contextual_refinement_v2(proof_plan=plan, exact_c_slice=exact,
        implementation_sha256=source["implementation_sha256"], source_profile_sha256=profile["receipt_sha256"],
        checker=result["checker"], models=result["bindings"], shard_results=result["checks"], world=_component_proof_world_v1(
            bundle=bundle, binding_intent_sha256=binding.intent_sha256, machine_object_authority_sha256=authority.authority_sha256))
    return result, {"proof": proof, "proof_plan": plan, "exact_c_slice": exact}
