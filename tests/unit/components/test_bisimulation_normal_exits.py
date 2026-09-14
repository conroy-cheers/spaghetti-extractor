"""A normal region exit must preserve its declared logical register results."""
from __future__ import annotations

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.binding_intent import ComponentMachineBindingIntentV1
from spaghetti_extractor.components.bisimulation import ComponentBisimulationError, ComponentBisimulationIntentV1, build_component_proof_plan_v1
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_continuation import continuation_model
from spaghetti_extractor.components.bisimulation_refinement import check_bisimulation_refinement
from spaghetti_extractor.components.bisimulation_readonly_contracts import check_readonly_source_contracts, check_mutable_source_contracts
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.component_exact_c_slice import write_component_exact_c_slice_v1
from spaghetti_extractor.components.contextual_bisimulation import (
    build_contextual_refinement_v2, operation_sources_from_package, validate_contextual_refinement_v2,
)
from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.machine_overlay_v5 import render_component_machine_overlay_v5
from spaghetti_extractor.components.machine_overlay_logical_views_v5 import VIEW_CONTEXT_DECLARATION
from spaghetti_extractor.components.normalized_component import NormalizedComponentContract, NormalizedMachineBinding
from spaghetti_extractor.components.refinement_v5 import _logical_projection
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.components.source_profile import check_component_source_profile
from spaghetti_extractor.transfer.model import _Action, _Node, _Transfer
from spaghetti_extractor.semantic_objects.object_authority import MachineObjectAuthorityV2
from spaghetti_extractor.semantic_providers.portable_c_inputs import _component_proof_world_v1
from tests.unit.components.test_dynamic_state_storage import state_fixture
from tests.unit.components.test_inductive_relation import _unit
from tests.unit.components.readable_transfer_fixture import reader_transfers, DOMAIN_TRAP_ESP

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"), "resources": ("nix/jq/strong-contextual-proof.jq",)}


def check_normal_exit(root: Path, *, cbmc: Path, source_value: int = 7, exit_kind: str = "fallthrough",
                      extra_ecx_write: bool = False, common_context: bool = False,
                      context_observes_ecx: bool = False, context_loop: bool = False,
                      reference_authority: dict | None = None, reference_probe: bool = False,
                      reference_view: bool = False, reference_allocation_requirements=None,
                      entry_allocation_history=None,
                      read_buffer: bool = False, source_contracts: bool = False,
                      return_to_caller: bool = False, private_write: bool = False,
                      entry_domain_trap: bool = False, readable_clobber_ecx: bool = False, readable_clobber_before_cut: bool = False,
                      readable_body_growth: int = 0, write_buffer: bool = False,
                      restored_outside_write: bool = False, memory_cut_offset: int | None = None,
                      memory_cut_invariant_offset: int | None = None, timeout_seconds: int = 30,
                      machine_clobbers: tuple[str, ...] = (), private_stack_writes: tuple = (),
                      frame_base_offset: int | None = None, frame_relation_offset: int | None = None) -> dict:
    if read_buffer or source_contracts:
        assert reference_view
    if return_to_caller or private_write or entry_domain_trap or readable_clobber_ecx or readable_clobber_before_cut:
        assert reference_view and read_buffer and return_to_caller
    if write_buffer:
        assert reference_view and read_buffer and return_to_caller
    if memory_cut_offset is not None:
        assert write_buffer and not source_contracts and memory_cut_offset in (0, 4)
    if frame_base_offset is not None:
        assert private_write and return_to_caller and frame_base_offset >= 8
    if reference_authority is None:
        reference_authority = MachineObjectAuthorityV2(machine_backend="x86-pe32",
            bindings={"original_pe_sha256": "b" * 64}, rules=[]).to_payload()
    unit_id = "semantic-transfer:original-cutpoint-00001000-00001001"
    context_id = "semantic-transfer:original-cutpoint-00001001-00001002"
    context_ids = [context_id] if common_context else []
    old, _ = state_fixture(unit_id)
    raw = old.intent.to_payload()
    result = {**raw["state"][0]["value"], "id": "value"}
    types = copy.deepcopy(raw["schema"]["types"])
    next(row for row in types if row["kind"] == "function")["result_type_id"] = "u32"
    parameters = []
    if reference_view:
        assert not common_context
        types.extend([{"id": "u8", "kind": "integer", "signed": False, "width_bits": 8},
                      {"id": "span", "kind": "pointer", "pointee_type_id": "u8", "qualifiers": []}])
        next(row for row in types if row["kind"] == "function")["parameter_type_ids"] = ["span"]
        parameters = [{**result, "id": "buffer", "type_id": "span", "interpretation": "view", "access": "read_write" if write_buffer else "read",
                       "extent": {"kind": "fixed", "bytes": 4, "value_id": None}}]
        if memory_cut_offset is not None:
            parameters.append({**parameters[0], "id": "slot"})
            next(row for row in types if row["kind"] == "function")["parameter_type_ids"].append("span")
    schema = BoundarySchemaV1.create(schema_id="counter", types=types,
        signatures=[{"id": "run", "function_type_id": "run.fn", "parameters": parameters, "results": [result]}])
    operation = copy.deepcopy(raw["operations"][0])
    operation["source_values"] = [result]
    operation["projection_entries"] = [{"source_id": "value", "target": {
        "root": "result", "value_id": "value", "fields": []}}]
    if reference_view:
        operation["source_values"].extend(parameters)
        operation["projection_entries"].append({"source_id": "buffer", "target": {
            "root": "parameter", "value_id": "buffer", "fields": []}})
        operation["lifecycle_bindings"] = [{"id": "parameter.buffer", "path": {
            "root": "parameter", "value_id": "buffer", "fields": []}, "transition": "borrow_shared",
            "resource_kind": "memory-view", "provider_domain": "component-environment.counter",
            "service_id": None, "interaction_contract_id": None, "condition": None}]
        if memory_cut_offset is not None:
            operation["projection_entries"].append({"source_id": "slot", "target": {
                "root": "parameter", "value_id": "slot", "fields": []}})
            operation["lifecycle_bindings"].append({**operation["lifecycle_bindings"][0],
                "id": "parameter.slot", "path": {"root": "parameter", "value_id": "slot", "fields": []}})
    interface_intent = ComponentInterfaceIntentV1.create(component_id="counter", schema=schema,
        state=[], services=[], effects=[], protocol_states=["ready"], initial_protocol_state="ready",
        operations=[operation])
    bundle = compile_component_interface_v5(interface_intent)
    projection = {"operation_id": "run", "entry_unit_ids": [unit_id], "exit_unit_ids": [unit_id],
        "parameters": [], "results": [{"id": "value", "projection": {
            "kind": "register", "register": "eax", "width": 32, "at": "exit"}}],
        "state": [], "effects": [], "preserved_state_ids": [], "callback_operation_ids": [],
        "continuation_unit_ids": context_ids}
    body_ids = [unit_id, context_id] if reference_view else [unit_id]
    if reference_view:
        projection["exit_unit_ids"] = [context_id]
        projection["parameters"] = [{"id": "buffer", "projection": {
            "kind": "view", "at": "entry", "base": {"kind": "register", "register": "ebx", "width": 32, "at": "entry"},
            "requested_extent": {"kind": "constant", "width": 32, "value": 4},
            "extent": {"kind": "constant", "width": 32, "value": 4},
            "authority": {"kind": "external", "id": "buffer", "lifetime": "invocation"}}}]
        if memory_cut_offset is not None:
            projection["parameters"][0]["projection"]["base"] = {"kind": "static_slot", "width": 32, "rva": 4096, "at": "entry"}
            projection["parameters"].append({"id": "slot", "projection": {**projection["parameters"][0]["projection"],
                "base": {"kind": "constant", "width": 32, "value": 0x401000},
                "authority": {"kind": "external", "id": "slot", "lifetime": "invocation"}}})
    binding = ComponentMachineBindingIntentV1.create(component_id="counter", operations=[{
        "id": "run", "kind": "operation", "unit_ids": body_ids, "entry_rvas": [4096],
        "transfer_ids": [*body_ids, *context_ids], "effect_ids": [], "service_ids": [], "callback_ids": [],
        "outcome_protocol_ids": [], "machine_projection": {"operation": projection, "service_bindings": []},
        "object_authority_selectors": [], "pointer_views": [], "relation_receipt_sha256s": [],
        "induction_evidence_sha256": None}])
    contract = NormalizedComponentContract.create(interface=bundle.interface,
        machine_semantics=[row.semantics for row in binding.operations])
    interface = ProofKernelComponentInterface.parse(_logical_projection(bundle, contract=contract))
    transfer = _Transfer(unit_id, "a" * 64, "b" * 64, 4096, (_Node("const", immediate=7),), (),
        (_Action("set_reg", (0,), aux=0),
         *((_Action("set_reg", (0,), aux=2),) if extra_ecx_write else ()),
         _Action("outcome_" + exit_kind, (4097,))), (), ())
    context_target = 4097 if context_loop else 4098
    context_transfer = _Transfer(context_id, "a" * 64, "b" * 64, 4097,
        (_Node("const", immediate=0), _Node("const", immediate=0x408000), _Node("reg", aux=2)), (),
        (*((_Action("memory_write", (1, 2), aux=4),) if context_observes_ecx else ()),
         _Action("set_reg", (0,), aux=2), _Action("outcome_jump", (context_target,))), (), ())
    transfers = [transfer, *([context_transfer] if common_context else [])]
    if reference_view:
        transfers = [
            _Transfer(unit_id, "a" * 64, "b" * 64, 4096, (), (), (_Action("outcome_jump", (4097,)),), (), ()),
            _Transfer(context_id, "a" * 64, "b" * 64, 4097,
                      (_Node("reg", aux=1), _Node("load", (0,), aux=1)) if read_buffer else (_Node("const", immediate=7),), (),
                      (_Action("set_reg", (1 if read_buffer else 0,), aux=0), _Action("outcome_fallthrough", (4098,))), (), ())]
        if return_to_caller:
            transfers = reader_transfers(private_write=private_write, domain_trap=entry_domain_trap, clobber_ecx=readable_clobber_ecx, clobber_before_cut=readable_clobber_before_cut, write_buffer=write_buffer, restored_outside_write=restored_outside_write, frame_base_offset=frame_base_offset)
        if memory_cut_offset is not None:
            transfers = [
                _Transfer(unit_id, "a" * 64, "b" * 64, 4096,
                    (_Node("const", immediate=0x401000), _Node("const", immediate=0x401004)
                     if memory_cut_offset else _Node("load", (0,), aux=4)), (),
                    (_Action("eval_word", (0,)), _Action("eval_word", (1,)),
                     _Action("memory_write", (0, 1), aux=4), _Action("outcome_jump", (4097,))), (), ()),
                _Transfer(context_id, "a" * 64, "b" * 64, 4097,
                    (_Node("const", immediate=0x401000), _Node("load", (0,), aux=4), _Node("load", (1,), aux=1),
                     _Node("reg", aux=7), _Node("load", (3,), aux=4), _Node("const", immediate=4),
                     _Node("add32", (3, 5)), _Node("const", immediate=77)), (),
                    (*( _Action("eval_word", (i,)) for i in range(8)), _Action("memory_write", (1, 7), aux=1),
                     _Action("set_reg", (2,), aux=0), _Action("set_reg", (6,), aux=7), _Action("outcome_return", (4,))), (), ())]
    symbols = {"run": "authored_run"}
    normalized_binding = None
    if reference_view:
        normalized_binding = NormalizedMachineBinding.create(bundle=bundle, contract=contract,
            artifacts={key: "a" * 64 for key in ("pe_sha256", "machine_ir_sha256", "machine_ir_manifest_sha256",
                "structural_units_sha256", "unit_inventory_sha256", "component_unit_inventory_sha256")},
            operation_authority={"run": {**dict(binding.operations[0].authority),
                "object_authority_selectors": [{"authority_id": value["id"], "rule_id": "image-buffer"} for value in parameters],
                "service_ids": [], "callback_ids": [], "outcome_protocol_ids": []}})
    overlay = render_component_machine_overlay_v5(bundle=bundle, contract=contract,
        operation_symbols=symbols, transfers=transfers, machine_binding=normalized_binding,
        object_authority_rule_ids=[row["id"] for row in reference_authority["rules"]])
    if reference_view:
        assert overlay.entries[0]["object_authority_selectors"] == {value["id"]: "image-buffer" for value in parameters}
    overlay_source = overlay.source
    if reference_probe:
        signature = f"spx_step_result {overlay.entries[0]['symbol']}(spx_runtime *rt, spx_machine_state *state) {{"
        assert overlay_source.count(signature) == 1
        probe = """
  spx_machine_reference_v1 native_probe;
  if (rt->resolve_reference(rt->context, 4198404U, 4U, 1U, "image-buffer", 0U, 0U,
        &native_probe) != SPX_BOUNDARY_OK || native_probe.domain != UINT64_C(4294967299) ||
      native_probe.object != UINT64_C(8589934647) || native_probe.generation != 17U ||
      native_probe.offset != 4U || native_probe.extent != 16U || native_probe.permissions != 3U)
    return (spx_step_result){SPX_MEMORY_FAULT, 0U, 0U};
"""
        overlay_source = overlay_source.replace(signature, signature + probe)
    syncs = [] if not reference_view else [{"id": "cut", "exact_unit_id": context_id,
        "captures": [{"kind": "parameter", "id": "buffer", "mode": "machine_codec",
            "projection": projection["parameters"][0]["projection"],
            "encoding": {"op": "bytes_address", "name": "buffer"}, "decoding": None}],
        "derived": [], "invariant": {"op": "true"}}]
    if frame_relation_offset is not None:
        syncs[0]["derived"] = [{"id": "frame-base", "projection": {
            "kind": "register", "register": "ebp", "width": 32, "at": "entry"},
            "expression": {"op": "exact_stack_address", "offset": frame_relation_offset}}]
    if memory_cut_offset is not None:
        syncs[0]["captures"].append({"kind": "parameter", "id": "slot", "mode": "machine_codec",
            "projection": projection["parameters"][1]["projection"],
            "encoding": {"op": "bytes_address", "name": "slot"}, "decoding": None})
    if memory_cut_offset or memory_cut_invariant_offset is not None:
        syncs[0]["invariant"] = {"op": "eq", "args": [{"op": "bytes_address", "name": "buffer"},
            {"op": "const", "width": 32, "value": 0x401000 + (
                memory_cut_offset if memory_cut_invariant_offset is None else memory_cut_invariant_offset)}]}
    intent = ComponentBisimulationIntentV1.create(component_id="counter",
        operations=[{"operation_id": "run", "syncs": syncs,
                     **({"entry_allocation_history": entry_allocation_history} if entry_allocation_history is not None else {}),
                     **({"machine_clobbers": list(machine_clobbers)} if machine_clobbers else {}),
                     **({"private_stack_writes": list(private_stack_writes)} if private_stack_writes else {})}])
    exact = write_component_exact_c_slice_v1(component_id="counter", transfers=transfers,
        operations=[{"operation_id": "run", "unit_ids": body_ids, "entry_rvas": [4096],
                     "context_unit_ids": [*body_ids, *context_ids], "continuation_unit_ids": context_ids}],
        intent=intent, executable_transfer_plan_sha256="c" * 64, out=root / "exact")
    authored = root / "authored.c"
    authored.write_text('#include "portable-component-implementation.h"\n'
        'uint32_t authored_run(spx_counter_context_v5 *context'
        + (', const spx_view_v5 *buffer' if reference_view else '')
        + (', const spx_view_v5 *slot' if memory_cut_offset is not None else '') + ') {\n'
        + '  (void)context; SPX_PROOF_BEGIN(run); '
        + ('SPX_PROOF_SYNC(cut, 1, buffer' + (', slot' if memory_cut_offset is not None else '') + '); ' if reference_view else '')
        + ('uint8_t byte=0U; if(spx_view_read_u8(buffer,0U,&byte)!=0U) return 0U; '
           + ('if(spx_view_write_u8(buffer,0U,77U)!=0U) return 0U; ' if write_buffer else '') + 'return byte;\n}\n'
           if read_buffer else f'return {source_value}U;\n}}\n'))
    if readable_body_growth:
        assert read_buffer and 0 < readable_body_growth <= 64
        authored.write_text(authored.read_text().replace('return byte;',
            ('byte ^= 17U; byte ^= 17U;\n' * readable_body_growth) + 'return byte;'))
    if memory_cut_offset is not None:
        prefix = ""
        setup = ('uint64_t pointer = 0U; if (slot->read(slot->access_context, slot->base, 0U, 4U, &pointer) != 0U) return 0U; '
                 if not memory_cut_offset else 'uint64_t pointer = 4198404U; ')
        setup += 'slot->write(slot->access_context, slot->base, 0U, 4U, pointer); '
        if memory_cut_offset:
            (root / "fixture-view-context.h").write_text('#include "state-machine-runtime.h"\n' + VIEW_CONTEXT_DECLARATION)
            prefix = '#include "fixture-view-context.h"\n'
            # The native adapter's view object is mutable; keep its pointer
            # identity while updating its checked concrete transport metadata.
            setup += ('((spx_component_view_context *)buffer->context)->address = (uint32_t)pointer; '
                      '((spx_view_v5 *)buffer)->base.offset = pointer - 4198400U; ')
        authored.write_text(prefix + authored.read_text().replace('SPX_PROOF_SYNC(cut, 1, buffer, slot);',
            setup + 'SPX_PROOF_SYNC(cut, 1, buffer, slot);'))
    source = build_component_source_package(lift_unit_id="counter", files={"authored.c": authored},
        shared_inputs=({"fixture-view-context.h": root / "fixture-view-context.h"} if memory_cut_offset else {}),
        operation_symbols=symbols, out_dir=root / "source")
    semantic = {**projection, "machine_image": {"preferred_base": 0x400000, "image_size": 0x10000},
        "units": [_unit(unit_id, 4096, [(4097, {"op": "true"})], [
            {"register": "eax", "value": {"op": "const", "value": 7, "width": 32}},
            *([{"register": "ecx", "value": {"op": "const", "value": 7, "width": 32}}]
              if extra_ecx_write else [])])]}
    if reference_view:
        semantic["units"] = [_unit(unit_id, 4096, [(4097, {"op": "true"})], []),
            _unit(context_id, 4097, [] if return_to_caller else [(4098, {"op": "true"})], [
                {"register": "eax", "value": (
                    {"op": "load", "width": 1, "address": {"op": "reg", "name": "ebx", "width": 32}}
                    if read_buffer else {"op": "const", "value": 7, "width": 32})}])]
        if readable_clobber_before_cut:
            semantic["units"][0]["semantics"]["register_writes"].append({"register": "ecx", "value": {"op": "const", "value": 77, "width": 32}})
        if frame_base_offset is not None:
            semantic["units"][0]["semantics"]["register_writes"].append({"register": "ebp", "value": {
                "op": "add", "width": 32, "args": [{"op": "reg", "name": "esp", "width": 32},
                    {"op": "const", "value": frame_base_offset, "width": 32}]}})
        if return_to_caller:
            final = semantic["units"][1]["semantics"]
            stack = {"op": "reg", "name": "esp", "width": 32}
            if entry_domain_trap:
                value = final["register_writes"][0]["value"]
                final["register_writes"][0]["value"] = {"op": "ite", "width": 32, "args": [
                    {"op": "eq", "args": [stack, {"op": "const", "width": 32, "value": DOMAIN_TRAP_ESP}]},
                    {"op": "add", "width": 32, "args": [value, {"op": "const", "width": 32, "value": 1}]}, value]}
            final["register_writes"].append({"register": "esp", "value": {
                "op": "add", "width": 32, "args": [stack, {"op": "const", "value": 4, "width": 32}]}})
            if readable_clobber_ecx:
                final["register_writes"].append({"register": "ecx", "value": {"op": "const", "value": 77, "width": 32}})
            final["memory_events"] = [{"kind": "read", "width": 4, "address": stack}]
            if write_buffer:
                final["memory_events"].append({"kind": "write", "width": 1,
                    "address": {"op": "reg", "name": "ebx", "width": 32},
                    "value": {"op": "const", "value": 77, "width": 32}})
            if restored_outside_write:
                address = {"op": "add", "width": 32, "args": [{"op": "reg", "name": "ebx", "width": 32},
                           {"op": "const", "value": 4, "width": 32}]}
                final["memory_events"] += [{"kind": "write", "width": 1, "address": address, "value": value}
                    for value in ({"op": "const", "value": 77, "width": 32},
                                  {"op": "load", "width": 1, "address": address})]
            if private_write:
                final["memory_events"].append({"kind": "write", "width": 1, "address": {
                    "op": "sub", "width": 32, "args": [stack if frame_base_offset is None else
                        {"op": "reg", "name": "ebp", "width": 32}, {"op": "const", "value": 8, "width": 32}]},
                    "value": {"op": "const", "value": 77, "width": 32}})
    if memory_cut_offset is not None:
        address = {"op": "const", "width": 32, "value": 0x401000}
        pointer = {"op": "load", "width": 4, "address": address}
        semantic["units"][0]["semantics"]["memory_events"] = [{"kind": "write", "width": 4,
            "address": address, "value": {"op": "const", "width": 32, "value": 0x401004} if memory_cut_offset else pointer}]
        final = semantic["units"][1]["semantics"]
        final["register_writes"][0]["value"] = {"op": "load", "width": 1, "address": pointer}
        final["memory_events"][1]["address"] = pointer
        final["memory_events"].append({"kind": "read", "width": 4, "address": address})
    if common_context:
        context_unit = _unit(context_id, 4097, [(context_target, {"op": "true"})],
                            [{"register": "ecx", "value": {"op": "const", "value": 0, "width": 32}}])
        context_unit["status"] = "qualified"
        if context_observes_ecx:
            context_unit["semantics"]["memory_events"] = [{"kind": "write", "width": 4,
                "address": {"op": "const", "value": 0x408000, "width": 32},
                "value": {"op": "reg", "name": "ecx", "width": 32}}]
        semantic["continuation_units"] = [context_unit]
    profile = check_component_source_profile(package=root / "source")
    result = check_bisimulation_refinement(
        semantic_contract={"component_id": "counter", "contract_sha256": "a" * 64, "operations": [semantic]},
        interface=interface, source_package=root / "source",
        source_profile=profile, intent=intent,
        exact_c_root=root / "exact", exact_c_slice=exact, machine_overlay_source=overlay_source,
        reference_authority=reference_authority,
        reference_allocation_requirements=reference_allocation_requirements,
        machine_overlay_entries=overlay.entries, machine_projections={"run": {"operation": projection,
        "service_bindings": []}}, cbmc=cbmc, c_headers=render_component_c_headers_v5(bundle, symbols),
        timeout_seconds=timeout_seconds, diagnostic_root=root / "diagnostics")
    plan = build_component_proof_plan_v1(component_id="counter", semantic_contract_sha256="a" * 64,
        interface=interface, operations=[semantic], operation_sources=operation_sources_from_package(
            source_root=root / "source", source=source, symbols=symbols),
        source_package_sha256=source["implementation_sha256"], intent=intent)
    if source_contracts:
        checker = check_mutable_source_contracts if write_buffer else check_readonly_source_contracts
        certificate = checker(bundle=bundle, package=root / "source",
            output=root / "local-contract", goto_cc=cbmc.with_name("goto-cc"),
            goto_instrument=cbmc.with_name("goto-instrument"), cbmc=cbmc, timeout_seconds=30)
        assert certificate["status"] == "satisfied", certificate
        result["bindings"]["source_summary_contracts"] = {
            "implementation_sha256": source["implementation_sha256"],
            "source_profile_sha256": profile["receipt_sha256"],
            "proof_interface_sha256": result["bindings"]["interface_sha256"], "certificate": certificate}
    proof = build_contextual_refinement_v2(proof_plan=plan, exact_c_slice=exact,
        implementation_sha256=source["implementation_sha256"],
        source_profile_sha256=profile["receipt_sha256"], checker=result["checker"],
        models=result["bindings"], shard_results=result["checks"], world=_component_proof_world_v1(
            bundle=bundle, binding_intent_sha256=binding.intent_sha256,
            machine_object_authority_sha256=reference_authority["authority_sha256"]))
    validate_contextual_refinement_v2(proof, proof_plan=plan, exact_c_slice=exact)
    (root / "contextual-refinement-result.json").write_text(json.dumps({
        "proof": proof, "proof_plan": plan, "exact_c_slice": exact}, indent=2) + "\n")
    (root / "native-fixture-inputs.json").write_text(json.dumps({
        "overlays": overlay.entries, "units": [*semantic["units"], *semantic.get("continuation_units", [])],
    }, indent=2) + "\n")
    return result


class NormalExitResultTests(unittest.TestCase):
    def test_checked_exit_fact_cannot_hide_its_own_failure_before_context(self):
        cbmc, jq = shutil.which("cbmc"), shutil.which("jq")
        if cbmc is None or jq is None:
            self.skipTest("CBMC and independent receipt reader required")
        from spaghetti_extractor.components.bisimulation_harness import _render_harness

        def wrong_target(*args, **kwargs):
            source = _render_harness(*args, **kwargs)
            assertion = "  __CPROVER_assert(source_result.target_rva == spx_proof_exact_result.target_rva,"
            assumption = "  __CPROVER_assume(source_result.target_rva == spx_proof_exact_result.target_rva);"
            self.assertIn(assumption, source)
            self.assertLess(source.index(assertion), source.index(assumption))
            self.assertLess(source.index(assumption), source.index("const uint32_t continuation_active"))
            return source.replace(assertion, "  source_result.target_rva ^= UINT32_C(1);\n" + assertion)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch("spaghetti_extractor.components.bisimulation_refinement._render_harness", side_effect=wrong_target):
                result = check_normal_exit(root, cbmc=Path(cbmc), common_context=True)
            self.assertEqual(result["status"], "violated", result["issues"])
            self.assertIn("spx-bisimulation-exit-target:run:spx_bisimulation_check_0000",
                          [row.get("detail") for row in result["issues"]])
            packet = json.loads((root / "contextual-refinement-result.json").read_text())
            self.assertFalse(packet["proof"]["activation_authorized"])
            reader = (Path(__file__).resolve().parents[3] / TESTKIT["resources"][0]).read_text()
            for predicate, code in (("spx_contextual_proof_system", 0), ("spx_strong_contextual_proof", 1)):
                checked = subprocess.run([jq, "-e", reader + "\n" + predicate],
                    input=json.dumps(packet), capture_output=True, text=True)
                self.assertEqual(checked.returncode, code, checked.stderr)

    def test_context_requires_qualified_unowned_inventory_and_call_contracts(self) -> None:
        unit = _unit("context", 4097, [(4098, {"op": "true"})], [])
        unit["status"] = "qualified"
        operation = {"units": [{"id": "body"}], "continuation_unit_ids": ["context"], "continuation_units": [unit]}
        self.assertEqual(continuation_model(operation)["maximum_steps"], 1)
        for mutation in ("missing", "duplicate", "owned", "unqualified", "call"):
            raw = copy.deepcopy(operation)
            if mutation == "missing": raw["continuation_units"] = []
            elif mutation == "duplicate": raw["continuation_units"].append(copy.deepcopy(unit))
            elif mutation == "owned": raw["units"].append({"id": "context"})
            elif mutation == "unqualified": raw["continuation_units"][0]["status"] = "incomplete"
            else: raw["continuation_units"][0]["semantics"]["external_events"] = [{"kind": "external_call"}]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                continuation_model(raw)

    def test_common_context_proves_dead_state_but_keeps_observations_and_bounds(self) -> None:
        cbmc = shutil.which("cbmc")
        if cbmc is None:
            self.skipTest("CBMC unavailable")
        for observed, loop, expected in ((False, False, "satisfied"), (True, False, "memory"), (False, True, "bound")):
            with self.subTest(observed=observed, loop=loop), tempfile.TemporaryDirectory() as temporary:
                result = check_normal_exit(Path(temporary), cbmc=Path(cbmc), extra_ecx_write=True,
                    common_context=True, context_observes_ecx=observed, context_loop=loop)
                self.assertEqual(result["status"], "satisfied" if expected == "satisfied" else "violated", result["issues"])
                proof_result = json.loads((Path(temporary) / "contextual-refinement-result.json").read_text())
                self.assertEqual(proof_result["exact_c_slice"]["root_unit_ids"],
                                 ["semantic-transfer:original-cutpoint-00001000-00001001"])
                self.assertEqual(len(proof_result["exact_c_slice"]["root_context_unit_ids"]), 2)
                self.assertFalse(proof_result["proof"]["activation_authorized"])
                if expected == "satisfied":
                    proof_result["proof"]["activation_authorized"] = True
                    proof_result["proof"]["receipt_sha256"] = canonical_sha256_v3({
                        k: v for k, v in proof_result["proof"].items() if k != "receipt_sha256"})
                    with self.assertRaisesRegex(ComponentBisimulationError, "aggregate status"):
                        validate_contextual_refinement_v2(proof_result["proof"],
                            proof_plan=proof_result["proof_plan"], exact_c_slice=proof_result["exact_c_slice"])
                if expected != "satisfied":
                    self.assertIn(f"spx-bisimulation-continuation-{expected}:run:spx_bisimulation_check_0000",
                                  [row.get("detail") for row in result["issues"]])

    def test_unbound_register_difference_cannot_escape_into_continuation(self) -> None:
        cbmc = shutil.which("cbmc")
        if cbmc is None:
            self.skipTest("CBMC unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            result = check_normal_exit(Path(temporary), cbmc=Path(cbmc), extra_ecx_write=True)
            self.assertEqual(result["status"], "violated")
            self.assertIn("spx-bisimulation-exit-continuation-state:run:spx_bisimulation_check_0000",
                          [row.get("detail") for row in result["issues"]])

    def test_fallthrough_result_is_checked_by_full_contextual_engine(self) -> None:
        cbmc = shutil.which("cbmc")
        if cbmc is None:
            self.skipTest("CBMC unavailable")
        for exit_kind, value in (("fallthrough", 7), ("fallthrough", 8), ("jump", 7), ("jump", 8)):
            with self.subTest(exit_kind=exit_kind, value=value), tempfile.TemporaryDirectory() as temporary:
                result = check_normal_exit(Path(temporary), cbmc=Path(cbmc), source_value=value, exit_kind=exit_kind)
                issues = [(row.get("code"), row.get("detail")) for row in result["issues"]]
                self.assertEqual(result["status"], "satisfied" if value == 7 else "violated", issues)
                if value == 8:
                    self.assertIn(("cbmc_counterexample", "spx-bisimulation-exit-observable:run:result:value"), issues)
