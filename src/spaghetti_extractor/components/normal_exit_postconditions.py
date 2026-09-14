"""Checked consequences of the existing fixed-image state/result exit guards.

These facts are conditional on the bound local proof world and normal return.
They are not source-opacity certificates, heap/lifetime invariants, summaries or
provider qualification. Consumers must retain their enclosing proof bindings.
"""

from __future__ import annotations

import hashlib

from .contextual_bisimulation import validate_complete_local_refinement
from .binding_intent import ComponentMachineBindingIntentV1
from .interface_ir import ProofKernelComponentInterface
from .interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from .machine_overlay_state_views import checked_state_view_result
from .machine_overlay_v5 import render_component_machine_overlay_v5
from .normalized_component import NormalizedComponentContract
from .refinement_v5 import _logical_projection
from .relation_ir import BOOL_SORT, LogicalPathV1, RelationExpressionV1, RelationSortV1
from .relation_v5 import ComponentRelationIntentV1
from ..semantic_objects.object_authority import MachineObjectAuthorityV2


def _result_state_equality(expression, *, bundle, operation_id):
    predicate = RelationExpressionV1.parse(expression)
    if predicate.op != "eq" or predicate.sort != BOOL_SORT:
        raise ValueError("normal exit postcondition has no implemented derivation")
    terms = {}
    for term in predicate.arguments:
        if term.op != "logical" or term.sort.kind != "view":
            raise ValueError("normal exit postcondition requires logical view equality")
        path = LogicalPathV1.parse(term.attributes["path"])
        if path.root not in {"result", "state"} or path.fields or path.root in terms:
            raise ValueError("normal exit postcondition requires one result and one state view")
        terms[path.root] = (path.identity, term.sort)
    if set(terms) != {"result", "state"}:
        raise ValueError("normal exit postcondition requires one result and one state view")
    operation = next((op for op in bundle.interface.operations if op.identity == operation_id), None)
    if operation is None:
        raise ValueError("normal exit postcondition names an unknown operation")
    signature = bundle.intent.schema.signature_index[operation.signature_id]
    results = {value.identity: value for value in signature.results}
    states = {item.value.identity: item.value for item in bundle.interface.state}
    for root, values in (("result", results), ("state", states)):
        identity, sort = terms[root]
        value = values.get(identity)
        if value is None or value.interpretation != "view" or sort != RelationSortV1("view", type_id=value.type_id):
            raise ValueError("normal exit postcondition names a foreign or mistyped view")
    return results[terms["result"][0]], terms["state"][0]


def shared_result_postcondition(expression, *, bundle, operation_id):
    """Recognize an alias and an optional current-memory fact on that result.

    `view_has_zero` means a zero byte exists within the current readable view.
    It says nothing about the first zero, historical writes or other aliases'
    lifetimes. This recognizer supplies no evidence or composition rule.
    Descriptor guards cannot prove a memory predicate; the derivation below
    requires a separate, exactly bound source theorem for that conjunct.
    """
    predicate = RelationExpressionV1.parse(expression)
    has_zero = predicate.op == 'and'
    equality = predicate.arguments[0] if has_zero else predicate
    result, alias = _result_state_equality(equality.to_payload(), bundle=bundle, operation_id=operation_id)
    if has_zero:
        memory = predicate.arguments[1]
        returned = next(term for term in equality.arguments if term.attributes['path']['root'] == 'result')
        if memory.op != 'view_has_zero' or memory.arguments != (returned,):
            raise ValueError('shared postcondition requires current zero in the aliased result view')
    return result, alias, has_zero


def checked_normal_exit_view_postconditions(
    *, intent, bundle, binding, proof_system, transfers, machine_binding,
    operation_symbols, resolved_external_environment=None, relation_evidence=(), source_summary_artifacts=None,
    runtime_assurance=None,
):
    """Derive aliases from exact guards and memory facts from bound source proofs.

    Regenerate both overlays through the existing producers, then compare their
    bytes to the proof bindings. The result selector is shared with the actual
    guard emitter; matching types or equal physical pointer words cannot replace
    those guards. The operation's state-export guards preserve the same input
    descriptors, establishing equality to the state on normal return as well.
    """
    from .bisimulation_refinement import build_typed_proof_service_thunk_renderer

    intent = ComponentRelationIntentV1.parse(intent.to_payload())
    binding = ComponentMachineBindingIntentV1.parse(binding.to_payload())
    bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(bundle.intent.to_payload()))
    if intent.component_id != bundle.interface.identity or intent.status != "ready_for_check":
        raise ValueError("normal exit postcondition intent is not ready for this component")
    proof = proof_system["proof"]
    validate_complete_local_refinement(proof_system, runtime_assurance=runtime_assurance)
    world = proof["world"]["bindings"]
    if (binding.component_id != bundle.interface.identity or
            world["interface_sha256"] != bundle.interface.interface_sha256 or
            world["schema_sha256"] != bundle.interface.schema_sha256 or
            world["binding_intent_sha256"] != binding.intent_sha256):
        raise ValueError("normal exit postcondition interface or binding is stale")
    authority = MachineObjectAuthorityV2.parse(proof["models"]["reference_authority"])
    if authority.authority_sha256 != world["machine_object_authority_sha256"]:
        raise ValueError("normal exit postcondition object authority is stale")
    contract = NormalizedComponentContract.create(interface=bundle.interface,
        machine_semantics=[op.semantics for op in binding.operations])
    arguments = dict(bundle=bundle, contract=contract, operation_symbols=operation_symbols,
        transfers=transfers, machine_binding=machine_binding,
        object_authority_rule_ids=[rule.identity for rule in authority.rules],
        resolved_external_environment=resolved_external_environment)
    overlay = render_component_machine_overlay_v5(**arguments)
    expected = proof["models"]
    if hashlib.sha256(overlay.source.encode()).hexdigest() != expected["machine_overlay_sha256"]:
        raise ValueError("normal exit postcondition production overlay differs from the checked bytes")
    proof_overlay = overlay
    if expected["proof_overlay_sha256"] != expected["machine_overlay_sha256"]:
        interface = ProofKernelComponentInterface.parse(_logical_projection(bundle, contract=contract))
        services = [row for entry in overlay.entries for row in entry.get("service_bindings", [])]
        from .machine_overlay_v5 import render_bound_proof_overlay
        proof_overlay = render_bound_proof_overlay(**arguments,
            expected_sha256=expected["proof_overlay_sha256"],
            requires_local_view_codec=any("local_view_cut_policy" in op for op in expected["operation_models"]),
            external_service_thunk_renderer=build_typed_proof_service_thunk_renderer(
                interface=interface, service_bindings=services,
                relation_evidence=relation_evidence, reference_authority=authority.to_payload()))
    if (proof_overlay.entries != overlay.entries or
            hashlib.sha256(proof_overlay.source.encode()).hexdigest() != expected["proof_overlay_sha256"]):
        raise ValueError("normal exit postcondition proof overlay differs from the checked bytes")
    operations = {row.semantics.operation_id: row.semantics for row in binding.operations}
    proved_operations = {row["operation_id"] for row in expected["operation_models"]}
    facts = []
    for operation in intent.operations:
        operation_id = operation["operation_id"]
        if operation_id not in operations:
            raise ValueError("normal exit postcondition operation lacks a machine binding")
        if operation_id not in proved_operations:
            raise ValueError("normal exit postcondition operation lacks a checked local proof")
        projection = operations[operation_id].machine_projection["operation"]
        states = {row["id"]: row for row in projection["state"]}
        results = {row["id"]: row for row in projection["results"]}
        for requirement in operation["requirements"]:
            if requirement["relation"] != "normal_exit_postcondition":
                raise ValueError("normal exit postcondition checker cannot discharge another relation kind")
            result, state_id, has_zero = shared_result_postcondition(requirement["expression"], bundle=bundle, operation_id=operation_id)
            if result.identity not in results:
                raise ValueError("normal exit postcondition result lacks a machine binding")
            item, _, _ = checked_state_view_result(bundle=bundle, value=result,
                projection=results[result.identity]["projection"], state_projections=states)
            if item.value.identity != state_id:
                raise ValueError("normal exit postcondition does not follow from the checked view guards")
            memory_evidence = {}
            if has_zero:
                memory_evidence = _checked_current_memory_source(intent=intent, bundle=bundle, proof=proof,
                    operation_symbols=operation_symbols, overlay=overlay, artifacts=source_summary_artifacts)
            facts.append({"operation_id": operation_id, "id": requirement["id"],
                "expression": requirement["expression"], "normal_exit_only": True,
                "derivation": ("checked-shared-current-memory-exit-v1" if has_zero else "checked-fixed-image-view-exit-guards-v1"),
                **memory_evidence,
                **({"assurance": runtime_assurance, "authorizing": False} if runtime_assurance is not None else {}),
                "relation_intent_sha256": intent.intent_sha256,
                "proof_receipt_sha256": proof["receipt_sha256"],
                "binding_intent_sha256": binding.intent_sha256,
                "interface_sha256": bundle.interface.interface_sha256,
                "proof_overlay_sha256": expected["proof_overlay_sha256"]})
    return facts


def _checked_current_memory_source(*, intent, bundle, proof, operation_symbols, overlay, artifacts):
    """Transfer a checked source fact through the exact paired memory theorem.

    Descriptor guards only supply the alias. Current memory follows separately
    from this same implementation's local theorem under exactly the services
    selected by the paired proof. The certificate is inside that proof's model
    bindings, not an independently attachable consequence after qualification.
    """
    from pathlib import Path
    from .bisimulation_readonly_evidence import validate_shared_source_contracts
    from .bisimulation_shared_services import normalize_shared_service_bindings

    models = proof['models']
    certificate = models.get('source_summary_contracts', {}).get('certificate')
    if certificate is None or artifacts is None:
        raise ValueError('current-memory exit fact requires bound shared source evidence and retained artifacts')
    validate_shared_source_contracts(certificate, artifacts=Path(artifacts))
    selected = normalize_shared_service_bindings(bundle,
        [row for entry in overlay.entries for row in entry.get('service_bindings', [])])
    if (certificate['interface_intent'] != bundle.intent.to_payload()
            or certificate['source_package']['implementation_sha256'] != models['implementation_sha256']
            or certificate['source_profile']['receipt_sha256'] != models['source_profile_sha256']
            or certificate['operation_symbols'] != dict(operation_symbols)
            or certificate['shared_contract']['relation_intent'] != intent.to_payload()
            or certificate['shared_contract'].get('service_contracts') != selected):
        raise ValueError('current-memory exit fact source, relation or service premises differ from the paired proof')
    return {'source_contract_sha256': certificate['receipt_sha256']}
