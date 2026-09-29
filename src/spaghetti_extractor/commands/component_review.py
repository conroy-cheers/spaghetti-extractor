"""Normalize edited component inputs without conferring proof authority."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Mapping

from ..boundary import BoundarySchemaV1
from ..components.binding_intent import ComponentMachineBindingIntentV1
from ..components.bisimulation import ComponentBisimulationIntentV1
from ..components.formats import COMPONENT_PROPOSAL_INSPECTION_V1_FORMAT
from ..components.indexes_v5 import ComponentIntentIndexV5
from ..components.interface_package_v5 import ComponentInterfaceIntentV1
from ..components.lifting_intent import ComponentLiftingIntentV1
from ..components.machine_binding import OperationMachineBindingV1
from ..components.relation_v5 import ComponentRelationIntentV1
from ..components.work_package_editing import validate_editing_relation
from .component_start import safe_package_file


def _read(root: Path, name: str) -> dict:
    value = json.loads(safe_package_file(root, name, "component review").read_text())
    if not isinstance(value, dict):
        raise ValueError(f"component review {name} must be an object")
    return value


def reviewed_seed_identity(root: Path) -> str:
    inspection = _read(root, "component-proposal-inspection.json")
    if (inspection.get("format") != COMPONENT_PROPOSAL_INSPECTION_V1_FORMAT
            or inspection.get("authority") is not False):
        raise ValueError("component review must contain a non-authorizing seed inspection")
    proposal = inspection.get("proposal")
    identity = proposal.get("id") if isinstance(proposal, dict) else None
    if not isinstance(identity, str):
        raise ValueError("component review has no proposal identity")
    return identity


def _interface(value: dict) -> ComponentInterfaceIntentV1:
    # Only derived self-digests may be absent/stale in editable canonical inputs.
    # Reparse the complete result to reject extra fields and unsupported formats.
    schema = dict(value["schema"])
    rebuilt = BoundarySchemaV1.create(schema_id=schema["schema_id"],
                                     types=schema["types"], signatures=schema["signatures"])
    schema["schema_sha256"] = rebuilt.schema_sha256
    value = {**value, "schema": BoundarySchemaV1.parse(schema).to_payload()}
    protocol = value["protocol"]
    intent = ComponentInterfaceIntentV1.create(
        component_id=value["id"], schema=rebuilt, state=value["state"],
        operations=value["operations"], effects=value["effects"], services=value["services"],
        protocol_states=protocol["states"], initial_protocol_state=protocol["initial_state"],
    )
    return ComponentInterfaceIntentV1.parse({**value, "intent_sha256": intent.intent_sha256})


def _binding(raw: dict) -> ComponentMachineBindingIntentV1:
    for operation in raw['operations']:
        projection = operation['machine_projection'].get('operation', {})
        # Map ordering is derived; signature and codec operand order is not.
        for field in ('parameters', 'results', 'state'):
            rows = projection.get(field)
            if isinstance(rows, list) and all(isinstance(row, dict) and isinstance(row.get('id'), str) for row in rows):
                projection[field] = sorted(rows, key=lambda row: row['id'])
    binding = ComponentMachineBindingIntentV1.create(
        component_id=raw['component_id'], operations=raw['operations'], blockers=raw['blockers'])
    return ComponentMachineBindingIntentV1.parse(
        {**raw, 'intent_sha256': binding.intent_sha256, 'status': binding.status})


def _bisimulation(raw: dict) -> ComponentBisimulationIntentV1:
    try:
        rebuilt = ComponentBisimulationIntentV1.create(
            component_id=raw['component_id'], operations=raw['operations'])
    except (KeyError, TypeError) as exc:
        raise ValueError(f'component review has incomplete bisimulation input: {exc}') from exc
    return ComponentBisimulationIntentV1.parse({**raw, 'intent_sha256': rebuilt.intent_sha256})


def _reviewed_relation(draft, binding, *, required=False):
    path = draft / 'relation.json'
    if not required and not path.exists() and not path.is_symlink():
        return None
    raw = _read(draft, 'relation.json')
    try:
        rebuilt = ComponentRelationIntentV1.create(component_id=raw['component_id'],
            operations=raw['operations'], blockers=raw['blockers'])
    except (KeyError, TypeError) as exc:
        raise ValueError(f'component review has incomplete relation input: {exc}') from exc
    return validate_editing_relation({**raw, 'intent_sha256': rebuilt.intent_sha256,
                                     'status': rebuilt.status}, binding)


def _reviewed_bisimulation(
    draft: Path, *, component_id: str, operation_id: str, unit_ids: set[str],
) -> ComponentBisimulationIntentV1 | None:
    path = draft / "bisimulation.json"
    if not path.exists() and not path.is_symlink():
        return None
    intent = _bisimulation(_read(draft, 'bisimulation.json'))
    if intent.component_id != component_id:
        raise ValueError("reviewed bisimulation names a different component")
    if [row.operation_id for row in intent.operations] != [operation_id]:
        raise ValueError("reviewed bisimulation names different operations")
    if any(sync.exact_unit_id not in unit_ids for row in intent.operations for sync in row.syncs):
        raise ValueError("reviewed bisimulation cut is outside the selected boundary")
    return intent


def reviewed_component_inputs(*, draft: Path, proposal: Mapping, program_id: str) -> dict[str, dict]:
    inspection = _read(draft, "component-proposal-inspection.json")
    reviewed_seed_identity(draft)
    if inspection.get("proposal") != proposal:
        raise ValueError("component review proposal is stale or differs from the selected boundary")
    try:
        interface = _interface(_read(draft, "interface.json"))
        binding = _binding(_read(draft, 'binding.json'))
    except (KeyError, TypeError) as exc:
        raise ValueError(f"component review has incomplete canonical input: {exc}") from exc
    if interface.component_id != binding.component_id:
        raise ValueError("reviewed interface and binding name different components")
    if len(binding.operations) != 1 or len(interface.operations) != 1:
        raise ValueError("seed review requires one operation over the selected boundary")
    operation = binding.operations[0].semantics
    if operation.operation_id != interface.operations[0]["id"]:
        raise ValueError("reviewed interface and binding name different operations")
    projection = OperationMachineBindingV1.parse(
        operation.machine_projection.get("operation"), "reviewed operation projection")
    continuation_ids = set(projection.continuation_unit_ids)
    if (set(operation.unit_ids) != set(proposal["membership"]["unit_ids"])
            or continuation_ids & set(operation.unit_ids)
            or set(operation.transfer_ids) != set(operation.unit_ids) | continuation_ids
            or set(operation.entry_rvas) != {row["rva"] for row in proposal["boundary"]["entries"]}):
        raise ValueError("reviewed binding changes the selected boundary")
    if (projection.operation_id != operation.operation_id
            or set(projection.entry_unit_ids) != {row["unit_id"] for row in proposal["boundary"]["entries"]}
            or set(projection.exit_unit_ids) != {row["source_unit_id"] for row in proposal["boundary"]["exits"]}):
        raise ValueError("reviewed projection changes the selected boundary entries or exits")
    _check_projection_values(interface, interface.operations[0], projection)
    bisimulation = _reviewed_bisimulation(
        draft, component_id=interface.component_id, operation_id=operation.operation_id,
        unit_ids=set(operation.unit_ids))
    return _draft_inputs(interface, binding, bisimulation, program_id, _reviewed_relation(draft, binding))


def _check_projection_values(interface, operation, projection):
    signature = interface.schema.signature_index[operation['signature_id']]
    for label, expected, actual in (
        ("parameters", {row.identity for row in signature.parameters},
         {row.identity for row in projection.parameters}),
        ("results", {row.identity for row in signature.results},
         {row.identity for row in projection.results}),
        ("state", {row["value"]["id"] for row in interface.state},
         {row.identity for row in projection.state}),
    ):
        if expected != actual:
            raise ValueError(f"reviewed {label} do not match the interface")


def _draft_inputs(interface, binding, bisimulation, program_id, relation=None):
    identity = interface.component_id
    component = {"id": identity, "label": identity}
    if bisimulation is not None:
        component["bisimulation_intent"] = f"bisimulation/{identity}.json"
    if relation is not None:
        component['relation_intent'] = f'relations/{identity}.json'
    # These are the existing canonical inputs. No new executable/provider format
    # and no candidate selection are produced by reviewing an interface.
    lifting = ComponentLiftingIntentV1.create(
        program_id=program_id, components=[component], groups=[],
        configurations=[{"id": "draft", "label": "Reviewed component draft", "selections": [
            {"id": identity, "kind": "component", "activation": "draft"}]}])
    result = {"components.json": lifting.to_payload()}
    if bisimulation is not None:
        result[str(component["bisimulation_intent"])] = bisimulation.to_payload()
    if relation is not None:
        result[str(component['relation_intent'])] = relation.to_payload()
    for kind, directory, field, intent in (
        ("interface", "interfaces-v5", "interface_intent", interface),
        ("machine_binding", "bindings-v5", "binding_intent", binding),
    ):
        blockers = [] if kind == "interface" else [
            {"component_id": identity, "code": code}
            for code in sorted({row["code"] for row in binding.blockers})]
        index = ComponentIntentIndexV5.create(kind=kind, components=[{
            "component_id": identity, field: identity + ".json",
            "intent_sha256": intent.intent_sha256}], blockers=blockers)
        result[f"{directory}/{identity}.json"] = intent.to_payload()
        result[f"{directory}/index.json"] = index.to_payload()
    return result


def reviewed_configured_component_inputs(*, draft: Path, package: Mapping, program_id: str) -> dict[str, dict]:
    """Refine a configured interface and internal cuts against its current scope.

    Changing ownership needs a separately checked partition proposal. Editing
    declarations here grants neither contract compatibility nor transport proof.
    """
    from ..components.work_package_v6 import ComponentWorkPackageV6
    from ..components.work_package_editing import editing_input_texts, validate_editing_bisimulation

    current = ComponentWorkPackageV6.parse(package)
    baseline = ComponentWorkPackageV6.parse(_read(draft, 'component-work-package-v6.json'))
    if baseline.identity != current.identity:
        raise ValueError('component editing baseline is stale; propose a current work package before adopting')
    if not editing_input_texts(current.payload):
        raise ValueError('component work package has no canonical editing inputs; regenerate its work package')
    try:
        interface = _interface(_read(draft, 'interface.json'))
        binding = _binding(_read(draft, 'binding.json'))
    except (KeyError, TypeError) as exc:
        raise ValueError(f'component review has incomplete canonical input: {exc}') from exc
    if interface.component_id != current.payload['component_id'] or binding.component_id != interface.component_id:
        raise ValueError('reviewed inputs change the configured component identity')
    originals = ComponentMachineBindingIntentV1.parse(current.payload['requirements']['editing_inputs']['binding'])
    old = {op.semantics.operation_id: op.semantics for op in originals.operations}
    signatures = {op['id']: op for op in interface.operations}
    if set(old) != {op.semantics.operation_id for op in binding.operations} or set(old) != set(signatures):
        raise ValueError('reviewed inputs change the configured operation inventory')
    for op in binding.operations:
        semantics = op.semantics
        original = old[semantics.operation_id]
        projection = OperationMachineBindingV1.parse(semantics.machine_projection.get('operation'), 'reviewed projection')
        original_projection = OperationMachineBindingV1.parse(original.machine_projection.get('operation'), 'baseline projection')
        if (projection.operation_id != semantics.operation_id
                or any(getattr(semantics, key) != getattr(original, key) for key in ('unit_ids', 'transfer_ids', 'entry_rvas'))
                or any(getattr(projection, key) != getattr(original_projection, key) for key in
                       ('entry_unit_ids', 'exit_unit_ids', 'continuation_unit_ids'))):
            raise ValueError('reviewed binding changes configured ownership, entries, exits or continuation context')
        _check_projection_values(interface, signatures[semantics.operation_id], projection)
    bisimulation = None
    path = draft / 'bisimulation.json'
    if path.exists() or path.is_symlink() or 'bisimulation' in current.payload['requirements']['editing_inputs']:
        bisimulation = _bisimulation(_read(draft, 'bisimulation.json'))
        validate_editing_bisimulation(bisimulation.to_payload(), binding)
    relation = _reviewed_relation(draft, binding,
        required='relation' in current.payload['requirements']['editing_inputs'])
    return _draft_inputs(interface, binding, bisimulation, program_id, relation)


def write_reviewed_configured_component_inputs(*, draft: Path, package: Mapping, program_id: str, output: Path) -> None:
    _write_inputs(reviewed_configured_component_inputs(draft=draft, package=package, program_id=program_id), output)


def write_reviewed_component_inputs(*, draft: Path, proposal: Mapping,
                                   program_id: str, output: Path,
                                   expected_component_id: str | None = None) -> None:
    payloads = reviewed_component_inputs(draft=draft, proposal=proposal, program_id=program_id)
    if (expected_component_id is not None
            and payloads["components.json"]["components"][0]["id"] != expected_component_id):
        raise ValueError("reviewed component identity differs from the configured seed")
    _write_inputs(payloads, output)


def _write_inputs(payloads, output):
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("component review output must be a new or empty directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".component-review-", dir=output.parent) as temporary:
        staging = Path(temporary) / "inputs"
        staging.mkdir()
        for relative, payload in payloads.items():
            path = staging / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        os.replace(staging, output)
