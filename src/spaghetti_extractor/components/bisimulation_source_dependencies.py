"""Checked, body-free dependencies of local memory source theorems.

This rule composes source frame and input-dependence guarantees. It does not
establish original machine entry/frames, service effects or provider authority.
An uninterpreted function sees the complete scalar, view, alias and input-byte
tuple, never a digest of it. Related calls therefore get related arbitrary
results and post-bytes without executing a dependency implementation.
"""

import shutil
from pathlib import Path
from collections.abc import Mapping

from .component_c_v5 import _parameter_type, _result_type
from .interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from .machine_overlay_services_v5 import _c_identifier

READONLY_POLICY = "fixed-readable-source-contract-dependencies-v2"
MUTABLE_POLICY = "fixed-mutable-source-contract-dependencies-v2"
READONLY_MODEL = "fixed-readable-paired-functional-dependencies-v2"
MUTABLE_MODEL = "fixed-mutable-paired-functional-dependencies-v2"
READONLY_POLICIES = frozenset({READONLY_POLICY, "fixed-readable-source-contract-experiment-v1"})
MUTABLE_POLICIES = frozenset({MUTABLE_POLICY, "fixed-mutable-source-contract-experiment-v1"})
MEMORY_POLICIES = READONLY_POLICIES | MUTABLE_POLICIES


def validate_qualified_dependencies(certificate, *, connected, component_id):
    """Bind a composed source theorem to the same suppliers as its paired proof.

    Local certificates alone do not discharge these edges. The enclosing reader
    separately validates every entry contract and paired proof recursively.
    """
    if certificate.get("policy") not in {READONLY_POLICY, MUTABLE_POLICY}:
        return
    if not isinstance(connected, (list, tuple)):
        raise ValueError("composed source theorem lacks qualified dependencies")
    suppliers = {row['component_id']: row for row in connected}
    if len(suppliers) != len(connected) or component_id in suppliers:
        raise ValueError("qualified source dependency identities are duplicated or cyclic")
    for row in certificate['summary_dependencies']:
        identity = row['certificate']['interface_intent']['id']
        supplier = suppliers.get(identity)
        if supplier is None or supplier.get('summary_strategy') not in {
                'image-readable-body-free-v1', 'image-mutable-body-free-v1'}:
            raise ValueError("source dependency lacks a checked body-free machine supplier: " + identity)
        proof = supplier.get('entry_contract', {}).get('proof_system', {}).get('proof', {})
        bound = proof.get('models', {}).get('source_summary_contracts', {})
        if (bound.get('certificate') != row['certificate'] or proof.get('status') != 'satisfied'
                or proof.get('receipt_sha256') != supplier.get('proof_receipt_sha256')
                or row['operation_id'] not in row['certificate']['operation_symbols']):
            raise ValueError("source dependency differs from its current qualified supplier: " + identity)


def validate_qualified_dependency_tree(proof):
    """Reject cycles and inconsistent supplier versions before recursive readers."""
    seen = {}
    def visit(node, ancestors):
        identity = node['component_id']
        if identity in ancestors:
            raise ValueError("qualified memory dependency cycle: " + identity)
        receipt = node['receipt_sha256']
        if identity in seen:
            if seen[identity] != receipt:
                raise ValueError("qualified memory dependency versions disagree: " + identity)
            return
        children = node['models']['connected_components']
        if children:
            certificate = node['models'].get('source_summary_contracts', {}).get('certificate', {})
            if certificate.get('policy') not in {READONLY_POLICY, MUTABLE_POLICY}:
                raise ValueError("transitive entry needs a checked composed source theorem")
            validate_qualified_dependencies(certificate, connected=children, component_id=identity)
            for child in children:
                if child.get('summary_strategy') not in {'image-readable-body-free-v1', 'image-mutable-body-free-v1'}:
                    raise ValueError("transitive entry requires checked memory frames for every dependency")
                nested = child.get('entry_contract', {}).get('proof_system', {}).get('proof')
                if not isinstance(nested, Mapping) or nested.get('component_id') != child['component_id']:
                    raise ValueError("transitive memory supplier proof is absent")
                visit(nested, (*ancestors, identity))
        seen[identity] = receipt
    visit(proof, ())


def qualified_dependency_inputs(connected):
    """Use already-validated provider inputs in the auxiliary source checker."""
    rows = []
    for supplier in connected:
        bound = supplier.get('source_summary_contracts')
        if not isinstance(bound, Mapping) or bound.get('certificate', {}).get('policy') not in MEMORY_POLICIES:
            # Keep the auxiliary checker fail-closed on unsupported callees.
            return ()
        certificate = bound['certificate']
        for operation in sorted(certificate['operation_symbols']):
            rows.append({'symbol':f"spx_component_logical_{_c_identifier(supplier['component_id'])}_{_c_identifier(operation)}",
                'operation_id':operation, 'certificate':certificate, 'artifacts':supplier['source_summary_artifacts']})
    return sorted(rows, key=lambda row:row['symbol'])


def validate_current_qualified_closure(rows):
    """Require current retained provider inputs for every transitive proof edge."""
    current = {row['component_id']: row for row in rows}
    for row in rows:
        proof = row.get('proof_system', {}).get('proof', {})
        if proof.get('models', {}).get('source_summary_contracts', {}).get('certificate', {}).get('policy') not in {READONLY_POLICY, MUTABLE_POLICY}:
            continue
        validate_qualified_dependency_tree(proof)
        for dependency in proof['models']['connected_components']:
            other = current.get(dependency['component_id'])
            if other is None or any(dependency[key] != other.get(key) for key in (
                    'proof_receipt_sha256', 'binding_intent_sha256', 'qualification_sha256', 'contextual_refinement_sha256')):
                raise ValueError("transitive supplier lacks matching current retained input: " + dependency['component_id'])


def dependency_bundle(row):
    return compile_component_interface_v5(ComponentInterfaceIntentV1.parse(row["certificate"]["interface_intent"]))


def validate_dependencies(rows, *, component_id, artifacts=None, ancestors=()):
    from .bisimulation_readonly_evidence import _validate_memory_source_contracts
    from .bisimulation_readonly_model import MUTABLE_CONTRACT_POLICY, READONLY_CONTRACT_POLICY

    if not isinstance(rows, (list, tuple)) or not rows or component_id in ancestors:
        raise ValueError("source summary dependencies are empty, malformed or cyclic")
    names = []
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping) or set(row) != {"symbol", "operation_id", "certificate"}:
            raise ValueError("source summary dependency fields differ")
        bundle = dependency_bundle(row)
        name = f"spx_component_logical_{_c_identifier(bundle.interface.identity)}_{_c_identifier(row['operation_id'])}"
        if row["symbol"] != name or name in names or bundle.interface.identity in (*ancestors, component_id):
            raise ValueError("source summary dependency identity is duplicated, cyclic or noncanonical")
        names.append(name)
        certificate = row["certificate"]
        policy = certificate.get("policy")
        if policy not in {MUTABLE_POLICY, READONLY_POLICY, MUTABLE_CONTRACT_POLICY, READONLY_CONTRACT_POLICY}:
            raise ValueError("source summary dependency policy is unsupported")
        _validate_memory_source_contracts(certificate,
            artifacts=None if artifacts is None else Path(artifacts)/f"dependency-{index:04d}",
            mutable=policy in {MUTABLE_POLICY, MUTABLE_CONTRACT_POLICY}, ancestors=(*ancestors, component_id))
        if row["operation_id"] not in certificate["operation_symbols"]:
            raise ValueError("source summary dependency operation is absent")
    if names != sorted(names):
        raise ValueError("source summary dependencies must have canonical symbol order")


def prepare_dependencies(inputs, *, component_id, output):
    """Require retained evidence before a producer uses any dependency rule."""
    rows = []
    for index, raw in enumerate(inputs):
        if not isinstance(raw, Mapping) or set(raw) != {"symbol", "operation_id", "certificate", "artifacts"}:
            raise ValueError("source summary dependency needs its exact retained certificate")
        row = {k: raw[k] for k in ("symbol", "operation_id", "certificate")}
        # Validate in a temporary logical root only after copying the actual
        # artifacts. No path supplied by a certificate chooses a new input.
        destination = output/f"dependency-{index:04d}"
        shutil.copytree(Path(raw["artifacts"]), destination)
        rows.append(row)
    validate_dependencies(rows, component_id=component_id, artifacts=output)
    return rows


def _signature(row):
    bundle = dependency_bundle(row)
    operation = next(op for op in bundle.interface.operations if op.identity == row["operation_id"])
    signature = bundle.intent.schema.signature_index[operation.signature_id]
    types = bundle.intent.schema.type_index
    parameters = ["void *opaque"] + [f"{_parameter_type(types, value)} p{i}" for i,value in enumerate(signature.parameters)]
    return signature, types, f"{_result_type(types, signature)} {row['symbol']}({', '.join(parameters)})"


def dependency_headers(headers, rows):
    if not rows:
        return headers
    result = dict(headers)
    result["portable-component-implementation.h"] += "\n" + "\n".join(_signature(row)[2]+";" for row in rows) + "\n"
    return result


def context_setup(component_id, side):
    prefix = _c_identifier(component_id)
    return [f"  uint8_t spx_dependency_token_{side};",
        f"  spx_{prefix}_services_v5 spx_dependency_services_{side};",
        f"  spx_dependency_services_{side}.context = &spx_dependency_token_{side};",
        f"  spx_context_{side}->services = &spx_dependency_services_{side};"]


def render_dependencies(rows, *, mutable):
    """Apply conservative functional summaries to the existing canonical world.

    Every key byte is captured before any write. Overlapping writable views
    receive the same post-byte at a physical address. Read-only aliases observe
    those writes through the existing alias-preserving storage implementation.
    No private context address participates in the functional key.
    """
    if not rows:
        return []
    lines = ["static void *spx_dependency_expected_context;"]
    for row in rows:
        signature, types, declaration = _signature(row)
        stem = "__CPROVER_uninterpreted_"+row["symbol"]
        body = [declaration+" {", '  __CPROVER_assert(opaque == spx_dependency_expected_context, "spx-summary-dependency-context");']
        keys = []
        def key(typ, expression):
            name = f"key{len(keys)}"
            keys.append((typ,name))
            body.append(f"  {typ} {name} = {expression};")
        views = []
        for i,value in enumerate(signature.parameters):
            if value.interpretation != "view":
                key(_parameter_type(types,value),f"p{i}")
                continue
            extent = value.extent["bytes"]
            body += [f'  __CPROVER_assert(p{i} != 0 && p{i}->extent == UINT64_C({extent}) && p{i}->element_width == 1U, "spx-summary-dependency-view");',
                f'  __CPROVER_assert(p{i}->context == p{i}->access_context && p{i}->read_u8 == spx_component_view_read && p{i}->read == spx_component_view_read_span, "spx-summary-dependency-read-transport");',
                f"  spx_component_view_context *v{i} = (spx_component_view_context *)p{i}->context;",
                f'  __CPROVER_assert(v{i}->extent == UINT64_C({extent}) && v{i}->permissions == {3 if value.access == "read_write" else 1}U, "spx-summary-dependency-backing-view");',
                f'  __CPROVER_assert((uint64_t)v{i}->address + UINT64_C({extent}) <= UINT64_C(4294967296), "spx-summary-dependency-address-range");',
                f'  __CPROVER_assert(v{i}->runtime->read == spx_{"mutable" if mutable else "readonly"}_read, "spx-summary-dependency-readable-world");',
                f"  uint32_t fault{i} = 0U;"]
            for field in ("domain","object","generation","offset","extent","permissions"):
                key("uint64_t" if field != "permissions" else "uint32_t",f"p{i}->base.{field}")
            key("uint32_t",f"v{i}->address")
            for prior in views:
                key("uint32_t",f"p{i} == p{prior}")
            for offset in range(extent):
                key("uint8_t",f"(uint8_t)v{i}->runtime->read(v{i}->runtime->context, v{i}->address+{offset}U, 1U, &fault{i})")
            body.append(f'  __CPROVER_assert(fault{i} == 0U, "spx-summary-dependency-input-memory");')
            views.append(i)
        parameters = ", ".join(f"{typ} {name}" for typ,name in keys)
        arguments = ", ".join(name for _,name in keys)
        result_type = _result_type(types,signature)
        if result_type != "void":
            lines.append(f"{result_type} {stem}_result({parameters});")
            body.append(f"  {result_type} result = {stem}_result({arguments});")
        writers = [i for i in views if signature.parameters[i].access == "read_write"]
        if writers:
            if not mutable:
                raise ValueError("read-only source cannot consume a mutable dependency model")
            lines.append(f"uint8_t {stem}_byte({parameters}, uint32_t address);")
            for i in writers:
                extent = signature.parameters[i].extent["bytes"]
                body += [f'  __CPROVER_assert(p{i}->write_u8 == spx_component_view_write && p{i}->write == spx_component_view_write_span && v{i}->runtime->write == spx_mutable_write, "spx-summary-dependency-write-transport");',
                    f"  for (uint32_t i=0U; i<{extent}U; ++i) {{",
                    f"    uint8_t byte = {stem}_byte({arguments}, v{i}->address+i);",
                    f"    v{i}->runtime->write(v{i}->runtime->context, v{i}->address+i, 1U, byte, &fault{i});",
                    f'    __CPROVER_assert(fault{i} == 0U, "spx-summary-dependency-post-memory");', "  }"]
        if result_type != "void":
            body.append("  return result;")
        lines.extend([*body,"}"])
    return lines
