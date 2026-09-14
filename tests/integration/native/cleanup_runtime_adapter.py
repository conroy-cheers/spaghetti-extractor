"""Render the current complete cleanup adapter from retained real transfer inputs."""
import json
from pathlib import Path

from spaghetti_extractor.components.capabilities import spx_portable_reference_runtime_v5_source
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, write_component_interface_package_v5
from spaghetti_extractor.components.machine_overlay_v5 import render_component_machine_overlay_v5
from spaghetti_extractor.semantic_providers.portable_c_inputs import _direct_component_view
from spaghetti_extractor.transfer.plan import _transfer_from_payload
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.candidate.test_runtime_allocation_lifetime import allocation_fixture_source

FIXTURE = Path(__file__).parents[2]/'fixtures/metapad-cleanup-runtime'
SOURCE = Path(__file__).parents[2]/'fixtures/metapad-authored-call'


def prepare(root):
    inputs = json.loads((FIXTURE/'inputs.json').read_text())
    intent = ComponentInterfaceIntentV1.parse(json.loads((SOURCE/'component-interface-intent-v1.json').read_text()))
    bundle = write_component_interface_package_v5(root/'interface', intent)
    (root/'binding.json').write_text(json.dumps(inputs['binding'])+'\n')
    bundle, contract, machine, _ = _direct_component_view(binding_intent=root/'binding.json',
        interface_package=root/'interface', transfer_payload={'bindings': inputs['bindings']},
        semantic_slice_sha256=inputs['semantic_slice_sha256'])
    overlay = render_component_machine_overlay_v5(bundle=bundle, contract=contract,
        machine_binding=machine, operation_symbols={'cleanup': 'cleanup'},
        transfers=[_transfer_from_payload(row) for row in inputs['transfers']],
        object_authority_rule_ids=[row['id'] for row in inputs['object_authority']['rules']],
        resolved_external_environment=inputs['external_environment'])
    (root/'overlay.c').write_text(overlay.source)
    for name, text in render_component_c_headers_v5(bundle, {'cleanup': 'cleanup'}).items():
        (root/name).write_text(text)
    (root/'state-machine-runtime.h').write_text(exact_runtime_header())
    (root/'portable-reference-runtime.c').write_text(spx_portable_reference_runtime_v5_source())
    (root/'cleanup.c').write_bytes((SOURCE/'cleanup.c').read_bytes())
    allocator = allocation_fixture_source('', domain=3, object_id=1, extent_mode=1,
        identity='cleanup.scratch', minimum_extent=1)
    (root/'runtime-test.c').write_text((FIXTURE/'runtime.c.in').read_text().replace('@NATIVE_ALLOCATOR@', allocator))
    return inputs
