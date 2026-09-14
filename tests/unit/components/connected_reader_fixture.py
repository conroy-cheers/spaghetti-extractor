"""A real internal-call fixture using a retained, separately checked reader.

This exercises the semantic engine's conditional supplier inputs. It does not
construct a provider qualification or a native activation receipt.
"""

import hashlib
import json
from pathlib import Path

from spaghetti_extractor.components.binding_intent import ComponentMachineBindingIntentV1
from spaghetti_extractor.components.bisimulation import ComponentBisimulationIntentV1, build_component_proof_plan_v1
from spaghetti_extractor.components.bisimulation_exact_frame import checked_empty_frame_operations
from spaghetti_extractor.components.bisimulation_refinement import check_bisimulation_refinement
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.component_exact_c_slice import write_component_exact_c_slice_v1
from spaghetti_extractor.components.contextual_bisimulation import (validate_contextual_refinement_v2,
    build_contextual_refinement_v2, operation_sources_from_package)
from spaghetti_extractor.semantic_providers.portable_c_inputs import _component_proof_world_v1
from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.machine_overlay_v5 import render_component_machine_overlay_v5
from spaghetti_extractor.components.normalized_component import NormalizedComponentContract, NormalizedMachineBinding
from spaghetti_extractor.components.refinement_v5 import _logical_projection
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.components.source_profile import check_component_source_profile
from spaghetti_extractor.transfer.model import _Action, _Call, _Node, _Transfer, _REGISTERS, _FLAGS
from tests.unit.components.test_inductive_relation import _unit
from tests.unit.components.readable_transfer_fixture import reader_transfers


def check_connected_reader(root: Path, *, leaf: Path, cbmc: Path, domain_trap=False, forged_reader=False,
                           invalid_callee_view=False, changed_byte=False, proof_workspace=None, previous_query_evidence=None, mutable=False, forged_writer=False, observe_callee_ecx=False,
                           omit_summary_contracts=False, private_write=False, observe_callee_private_byte=False,
                           caller_private_stack_writes=(), caller_machine_clobbers=(),
                           caller_id="caller", caller_rva=8192, child_spec=None,
                           extra_connected=(), capture_inputs=None, prepare_only=False, source_contracts=False,
                           timeout_seconds=30, runtime_assurance=None):
    assert not (observe_callee_ecx and observe_callee_private_byte)
    assert not observe_callee_private_byte or private_write
    root, leaf = root.resolve(), leaf.resolve()
    root.mkdir(parents=True, exist_ok=True)
    from spaghetti_extractor.components.bisimulation_assurance import admitted_supplier_assurance
    from spaghetti_extractor.components.contextual_bisimulation import validate_complete_local_refinement, build_conditional_contextual_refinement_v1
    conditional_path = leaf / "conditional-refinement-result.json"
    retained = json.loads((conditional_path if conditional_path.exists() else leaf / "contextual-refinement-result.json").read_text())
    proof = retained["proof"]
    supplier_assurance = admitted_supplier_assurance(proof, runtime_assurance)
    validate_complete_local_refinement(retained, runtime_assurance=supplier_assurance)
    assert proof["status"] == "satisfied"
    if not mutable:
        assert checked_empty_frame_operations(proof, artifacts=leaf / "diagnostics", runtime_assurance=supplier_assurance) == ("run",)
    certificate = proof["models"]["source_summary_contracts"]["certificate"]
    child = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(certificate["interface_intent"]))
    assert child_spec is not None or child.interface.identity == "counter"
    child_source = json.loads((leaf / "source/source-package.json").read_text())
    child_overlay = (leaf / "diagnostics/overlay-0000.c").read_text()
    assert hashlib.sha256(child_overlay.encode()).hexdigest() == proof["models"]["machine_overlay_sha256"]
    child_entries = (list(child_spec['overlays']) if child_spec is not None else
                     json.loads((leaf / "native-fixture-inputs.json").read_text())["overlays"])
    authority = proof["models"]["reference_authority"]

    # Same typed boundary; a distinct machine operation invokes the reader.
    caller = compile_component_interface_v5(ComponentInterfaceIntentV1.create(
        component_id=caller_id, schema=child.intent.schema, state=child.intent.state,
        operations=child.intent.operations, services=child.intent.services, effects=child.intent.effects,
        protocol_states=child.intent.protocol_states, initial_protocol_state=child.intent.initial_protocol_state))
    ids = [f"semantic-transfer:original-cutpoint-{rva:08x}-{rva+1:08x}" for rva in (caller_rva,caller_rva+1)]
    child_transfers = (child_spec['transfers'] if child_spec is not None else
        reader_transfers(domain_trap=domain_trap, write_buffer=mutable,
                         clobber_ecx=observe_callee_ecx, private_write=private_write))
    child_ids = [row.identity for row in child_transfers]
    projection = {"operation_id": "run", "entry_unit_ids": [ids[0]], "exit_unit_ids": [ids[1]],
        "parameters": [{"id": "buffer", "projection": {"kind": "view", "at": "entry",
            "base": {"kind": "register", "register": "ebx", "width": 32, "at": "entry"},
            "requested_extent": {"kind": "constant", "width": 32, "value": 4},
            "extent": {"kind": "constant", "width": 32, "value": 4},
            "authority": {"kind": "external", "id": "buffer", "lifetime": "invocation"}}}],
        "results": [{"id": "value", "projection": {"kind": "register", "register": "eax", "width": 32, "at": "exit"}}],
        "state": [], "effects": [], "preserved_state_ids": [], "callback_operation_ids": [], "continuation_unit_ids": []}
    child_binding = child_spec['binding'] if child_spec is not None else ComponentMachineBindingIntentV1.create(component_id="counter", operations=[{
        "id": "run", "kind": "operation", "unit_ids": child_ids, "entry_rvas": [4096],
        "transfer_ids": child_ids, "effect_ids": [], "service_ids": [], "callback_ids": [],
        "outcome_protocol_ids": [], "machine_projection": {"operation": {
            **projection, "entry_unit_ids": [child_ids[0]], "exit_unit_ids": [child_ids[1]]}, "service_bindings": []},
        "object_authority_selectors": [], "pointer_views": [], "relation_receipt_sha256s": [],
        "induction_evidence_sha256": None}])
    assert child_binding.intent_sha256 == proof["world"]["bindings"]["binding_intent_sha256"]
    child_rva = child_binding.operations[0].semantics.entry_rvas[0]
    binding = ComponentMachineBindingIntentV1.create(component_id=caller_id, operations=[{
        "id": "run", "kind": "operation", "unit_ids": ids, "entry_rvas": [caller_rva],
        "transfer_ids": ids + child_ids, "effect_ids": [], "service_ids": [], "callback_ids": [],
        "outcome_protocol_ids": [], "machine_projection": {"operation": projection, "service_bindings": []},
        "object_authority_selectors": [], "pointer_views": [], "relation_receipt_sha256s": [],
        "induction_evidence_sha256": None}])
    contract = NormalizedComponentContract.create(interface=caller.interface,
        machine_semantics=[row.semantics for row in binding.operations])
    normalized = NormalizedMachineBinding.create(bundle=caller, contract=contract,
        artifacts={key: "a" * 64 for key in ("pe_sha256", "machine_ir_sha256", "machine_ir_manifest_sha256",
            "structural_units_sha256", "unit_inventory_sha256", "component_unit_inventory_sha256")},
        operation_authority={"run": {**dict(binding.operations[0].authority),
            "object_authority_selectors": [{"authority_id": "buffer", "rule_id": "image-buffer"}],
            "service_ids": [], "callback_ids": [], "outcome_protocol_ids": []}})
    call_nodes = tuple(_Node("reg", aux=i) for i in range(len(_REGISTERS))) + tuple(
        _Node("flag", aux=i) for i in range(len(_FLAGS)))
    if observe_callee_ecx:
        call_nodes = (*call_nodes[:2], _Node("load", (1,), aux=1), *call_nodes[3:])
    if invalid_callee_view:
        call_nodes = (call_nodes[0], _Node("const", immediate=0), *call_nodes[2:])
    before_call = ()
    if observe_callee_private_byte:
        index = len(call_nodes)
        call_nodes += (_Node("const", immediate=12), _Node("sub32", (7, index)), _Node("const", immediate=0))
        before_call = (_Action("memory_write", (index + 1, index + 2), aux=1),)
    call = _Call("internal_call", caller_rva, 0, None, child_rva, caller_rva+1, None, None, None,
                 tuple(range(8)), tuple(range(8, 14)), (), ())
    return_nodes = (_Node("reg", aux=7), _Node("load", (0,), aux=4),
                    _Node("const", immediate=4), _Node("add32", (0, 2)))
    observed_result = None
    if observe_callee_ecx:
        return_nodes += (_Node("reg", aux=2),)
        observed_result = 4
    if observe_callee_private_byte:
        # CALL stores its return address at caller ESP-4; the supplier writes
        # eight bytes below that. Observe the residual byte after its return.
        return_nodes += (_Node("const", immediate=12), _Node("sub32", (0, 4)), _Node("load", (5,), aux=1))
        observed_result = 6
    transfers = [
        _Transfer(ids[0], "a" * 64, "b" * 64, caller_rva, call_nodes, (),
            (*( _Action("eval_word", (i,)) for i in range(len(call_nodes))),
             *before_call, _Action("call", (0,)), _Action("outcome_jump", (caller_rva+1,))), (call,), ()),
        _Transfer(ids[1], "a" * 64, "b" * 64, caller_rva+1,
            return_nodes, (),
            (*( _Action("eval_word", (i,)) for i in range(len(return_nodes))),
             *((_Action("set_reg", (observed_result,), aux=0),) if observed_result is not None else ()),
             _Action("set_reg", (3,), aux=7), _Action("outcome_return", (1,))), (), ()), *child_transfers]
    symbols = {"run": "authored_"+caller_id}
    overlay = render_component_machine_overlay_v5(bundle=caller, contract=contract,
        operation_symbols=symbols, transfers=transfers, machine_binding=normalized,
        object_authority_rule_ids=[row["id"] for row in authority["rules"]])
    intent = ComponentBisimulationIntentV1.create(component_id=caller_id, operations=[{"operation_id": "run", "syncs": [],
        **({"private_stack_writes":list(caller_private_stack_writes)} if caller_private_stack_writes else {}),
        **({"machine_clobbers":list(caller_machine_clobbers)} if caller_machine_clobbers else {})}])
    exact = write_component_exact_c_slice_v1(component_id=caller_id, transfers=transfers,
        operations=[{"operation_id": "run", "unit_ids": ids, "entry_rvas": [caller_rva], "context_unit_ids": ids + child_ids}],
        intent=intent, executable_transfer_plan_sha256="c" * 64, out=root / "exact",
        dependency_components=[{"component_id": child.interface.identity, "binding_intent_sha256": child_binding.intent_sha256,
            "operations": [{"unit_ids": list(child_binding.operations[0].semantics.unit_ids), "entry_rvas": [child_rva]}]},
            *[{'component_id':row['component_id'],'binding_intent_sha256':row['binding_intent_sha256'],
               'operations':[{'unit_ids':op['unit_ids'],'entry_rvas':op['entry_rvas']} for op in row['binding_intent']['operations']]}
              for row in extra_connected]])
    authored = root / "caller.c"
    authored.write_text('''#include "portable-component-implementation.h"
extern uint32_t spx_component_logical_counter_run(void *, const spx_view_v5 *);
uint32_t authored_caller(spx_caller_context_v5 *context, const spx_view_v5 *buffer) {
  SPX_PROOF_BEGIN(run);
  return spx_component_logical_counter_run(context->services->context, buffer);
}
''')
    if observe_callee_ecx:
        authored.write_text(authored.read_text().replace(
            '  return spx_component_logical_counter_run(context->services->context, buffer);',
            '''  uint8_t saved = 0U;
  if (spx_view_read_u8(buffer, 0U, &saved) != 0U) return 0U;
  (void)spx_component_logical_counter_run(context->services->context, buffer);
  return saved;'''))
    if observe_callee_private_byte:
        authored.write_text(authored.read_text().replace(
            '  return spx_component_logical_counter_run(context->services->context, buffer);',
            '  (void)spx_component_logical_counter_run(context->services->context, buffer);\n  return 0U;'))
    if forged_reader or changed_byte or forged_writer:
        code = authored.read_text().replace('#include "portable-component-implementation.h"',
            '#include "portable-component-implementation.h"\n#include "state-machine-runtime.h"')
        code = code.replace('uint32_t authored_caller(', '''typedef struct spx_component_service_context_v1 {
  spx_runtime *runtime; spx_machine_state *state;
  uint32_t *memory_fault; uint32_t *service_fault;
  struct { uint32_t physical_word; uint32_t target_rva; } callback_result;
} spx_component_service_context_v1;
static uint32_t forged_read(void *opaque, uint32_t address, uint32_t width, uint32_t *fault) {
  (void)opaque; (void)address; (void)width; *fault = 0U; return 99U;
}
uint32_t authored_caller(''')
        code = code.replace('  return spx_component_logical_counter_run(context->services->context, buffer);', '''
  spx_component_service_context_v1 service = *(spx_component_service_context_v1 *)context->services->context;
  spx_runtime runtime = *service.runtime;
  runtime.read = forged_read; service.runtime = &runtime;
  return spx_component_logical_counter_run(&service, buffer);''')
        if forged_writer:
            code = code.replace('static uint32_t forged_read(', 'static uint32_t unused_reader(')
            code = code.replace('uint32_t authored_caller(', """static void forged_write(void *opaque, uint32_t address, uint32_t width, uint32_t value, uint32_t *fault) {
  (void)opaque; (void)address; (void)width; (void)value; *fault = 0U;
}
uint32_t authored_caller(""")
            code = code.replace('runtime.read = forged_read;', 'runtime.write = forged_write;')
        if changed_byte:
            code = code.replace('  runtime.read = forged_read; service.runtime = &runtime;',
                '  uint32_t fault = 0U; runtime.write(runtime.context, service.state->ebx, 1U, 99U, &fault);\n'
                '  service.runtime = &runtime;')
        authored.write_text(code)
    authored.write_text(authored.read_text().replace('spx_caller_context_v5',f'spx_{caller_id}_context_v5')
        .replace('authored_caller',symbols['run'])
        .replace('spx_component_logical_counter_run',f'spx_component_logical_{child.interface.identity}_run'))
    source = build_component_source_package(lift_unit_id=caller_id, files={"caller.c": authored},
        shared_inputs={}, operation_symbols=symbols, out_dir=root / "source")
    units = [_unit(ids[0], caller_rva, [(caller_rva+1, {"op": "true"})], []), _unit(ids[1], caller_rva+1, [], [])]
    units[0]["semantics"]["external_events"] = [{"kind": "internal_call", "target_rva": child_rva, "return_rva": caller_rva+1}]
    if observe_callee_ecx:
        units[1]["semantics"]["register_writes"].append({"register": "eax", "value": {"op": "reg", "name": "ecx", "width": 32}})
    if observe_callee_private_byte:
        address = {"op": "sub", "width": 32, "args": [
            {"op": "reg", "name": "esp", "width": 32}, {"op": "const", "width": 32, "value": 12}]}
        units[1]["semantics"]["memory_events"].append({"kind": "read", "width": 1, "address": address})
        units[0]["semantics"]["memory_events"].append({"kind": "write", "width": 1, "address": address,
                                                     "value": {"op": "const", "width": 32, "value": 0}})
        units[1]["semantics"]["register_writes"].append({"register": "eax", "value": {
            "op": "load", "width": 1, "address": address}})
    semantic = {**projection, "machine_image": {"preferred_base": 0x400000, "image_size": 0x10000}, "units": units}
    connected = {"component_id": child.interface.identity, "source_package": leaf / "source", "source": child_source,
        "compiled_interface": child, "operation_symbols": certificate["operation_symbols"],
        "source_profile": certificate["source_profile"], "machine_overlay_source": child_overlay,
        "machine_overlay_entries": child_entries, "c_headers": render_component_c_headers_v5(child, certificate["operation_symbols"]),
        "binding_intent_sha256": child_binding.intent_sha256, "qualification_sha256": "b" * 64 if supplier_assurance is None else None,
        **({"assurance": supplier_assurance, "authorizing": False} if supplier_assurance is not None else {}),
        "contextual_refinement_sha256": proof["receipt_sha256"], "proof_receipt_sha256": proof["receipt_sha256"],
        "proof_system": {key: retained[key] for key in ("proof", "proof_plan", "exact_c_slice")},
        "binding_intent": child_binding.to_payload(), "proof_artifacts": leaf / "diagnostics",
        "source_summary_contracts": proof["models"]["source_summary_contracts"], "source_summary_artifacts": leaf / "local-contract"}
    if omit_summary_contracts:
        del connected["source_summary_contracts"]
        del connected["source_summary_artifacts"]
    interface = ProofKernelComponentInterface.parse(_logical_projection(caller, contract=contract))
    profile = check_component_source_profile(package=root / "source")
    if capture_inputs is not None:
        capture_inputs.update(transfers=transfers, binding=binding, overlays=overlay.entries,
                              connected=connected, bundle=caller)
    if prepare_only:
        return None
    result = check_bisimulation_refinement(
        runtime_assurance=runtime_assurance,        semantic_contract={"component_id": caller_id, "contract_sha256": "a" * 64, "operations": [semantic]},
        interface=interface,
        source_package=root / "source", source_profile=profile,
        intent=intent, exact_c_root=root / "exact", exact_c_slice=exact,
        machine_overlay_source=overlay.source, machine_overlay_entries=overlay.entries,
        machine_projections={"run": {"operation": projection, "service_bindings": []}},
        c_headers=render_component_c_headers_v5(caller, symbols),
        connected_components=sorted([connected,*extra_connected],key=lambda row:row['component_id']),
        reference_authority=authority, cbmc=cbmc, timeout_seconds=timeout_seconds, diagnostic_root=root / "diagnostics",
        proof_workspace=proof_workspace, previous_query_evidence=previous_query_evidence)
    plan = build_component_proof_plan_v1(component_id=caller_id, semantic_contract_sha256="a" * 64,
        interface=interface, operations=[semantic], operation_sources=operation_sources_from_package(
            source_root=root / "source", source=source, symbols=symbols),
        source_package_sha256=source["implementation_sha256"], intent=intent)
    if source_contracts:
        from spaghetti_extractor.components.bisimulation_readonly_contracts import check_optional_memory_source_contracts
        from spaghetti_extractor.components.bisimulation_source_dependencies import qualified_dependency_inputs
        certificate = check_optional_memory_source_contracts(bundle=caller, package=root/'source', output=root/'local-contract',
            cbmc=cbmc, timeout_seconds=30, summary_dependencies=qualified_dependency_inputs([connected,*extra_connected]))
        if certificate is None:
            raise AssertionError('composed source theorem is incomplete')
        result['bindings']['source_summary_contracts'] = {'implementation_sha256':source['implementation_sha256'],
            'source_profile_sha256':profile['receipt_sha256'],'proof_interface_sha256':result['bindings']['interface_sha256'],
            'certificate':certificate}
    build_proof = build_contextual_refinement_v2 if runtime_assurance is None else build_conditional_contextual_refinement_v1
    parent_proof = build_proof(**({"runtime_assurance": runtime_assurance} if runtime_assurance is not None else {}),
        proof_plan=plan, exact_c_slice=exact,
        implementation_sha256=source["implementation_sha256"], source_profile_sha256=profile["receipt_sha256"],
        checker=result["checker"], models=result["bindings"], shard_results=result["checks"],
        world=_component_proof_world_v1(bundle=caller, binding_intent_sha256=binding.intent_sha256,
            machine_object_authority_sha256=authority["authority_sha256"],
            checked_component_summaries_used=any(c["summary_strategy"] != "connected-replay-v1" for c in result["bindings"]["connected_components"])))
    if runtime_assurance is None:
        validate_contextual_refinement_v2(parent_proof, proof_plan=plan, exact_c_slice=exact)
    (root / ("contextual-refinement-result.json" if runtime_assurance is None else "conditional-refinement-result.json")).write_text(json.dumps({
        "proof": parent_proof, "proof_plan": plan, "exact_c_slice": exact}, indent=2) + "\n")
    (root / "conditional-caller-result.json").write_text(json.dumps({
        "authorizing": False, "scope": "conditional engine only; no supplier qualification or native receipt",
        "result": result}, indent=2) + "\n")
    return result
