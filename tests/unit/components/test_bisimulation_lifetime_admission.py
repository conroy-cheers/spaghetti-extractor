"""Normal typed lowering and receipts consume checked local allocation premises."""

import copy
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from functools import partial

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.binding_intent import ComponentMachineBindingIntentV1
from spaghetti_extractor.components.bisimulation import ComponentBisimulationIntentV1, build_component_proof_plan_v1
from spaghetti_extractor.components.bisimulation_refinement import check_bisimulation_refinement
from spaghetti_extractor.components.bisimulation_typed_services import build_typed_proof_service_thunk_renderer, _trusted_adapter_lowering_receipt
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.component_exact_c_slice import write_component_exact_c_slice_v1
from spaghetti_extractor.components.contextual_bisimulation import (
    build_contextual_refinement_v2, operation_sources_from_package, validate_contextual_refinement_v2,
    _trusted_adapter_lowering_used,
)
from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.machine_overlay_v5 import render_component_machine_overlay_v5, render_bound_proof_overlay
from spaghetti_extractor.components.normalized_component import NormalizedComponentContract, NormalizedMachineBinding
from spaghetti_extractor.components.refinement_v5 import _logical_projection
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.components.source_profile import check_component_source_profile
from spaghetti_extractor.semantic_providers.portable_c_inputs import _component_proof_world_v1
from spaghetti_extractor.transfer.model import _Action, _Call, _Node, _Transfer
from .test_bisimulation_allocation_namespace import inputs
from .test_bisimulation_allocation_calls import selected_row
from .test_inductive_relation import _unit
from .test_machine_overlay_v5 import _resolved_environment
from .test_bisimulation_service_effects import rehash_model

TESTKIT = {'fixtures': ('cbmc', 'compiler', 'jq'), 'resources': ('profiles/pe32-kernel32-runtime-v1.json',
    'nix/jq/strong-contextual-proof.jq')}


def interface_fixture(*, buffer_view=False):
    def value(identity, reference=False):
        return {'id': identity, 'type_id': 'buffer' if reference else 'u32',
                'interpretation': 'reference' if reference else 'value',
                'access': 'read_write' if reference else 'none', 'nullable': reference,
                'provider_domain': None, 'resource_kind': None,
                'extent': {'kind': 'none', 'bytes': None, 'value_id': None}}
    signatures = [('run', [], [value('value')]),
                  ('allocate', [value('flags'), value('size')], [value('result', True)]),
                  ('release', [value('buffer', True)], [value('result')])]
    if buffer_view:
        signatures[1][2][0].update(interpretation='view',
            extent={'kind': 'value', 'bytes': None, 'value_id': 'size'})
    schema = BoundarySchemaV1.create(schema_id='owned', types=[
        {'id': 'u32', 'kind': 'integer', 'signed': False, 'width_bits': 32},
        {'id': 'u8', 'kind': 'integer', 'signed': False, 'width_bits': 8},
        {'id': 'buffer', 'kind': 'pointer', 'pointee_type_id': 'u8', 'qualifiers': []},
        *({'id': name + '.fn', 'kind': 'function', 'calling_convention': 'cdecl',
           'parameter_type_ids': [row['type_id'] for row in args], 'result_type_id': results[0]['type_id'],
           'variadic': False} for name, args, results in signatures)],
        signatures=[{'id': name, 'function_type_id': name + '.fn', 'parameters': args, 'results': results}
                    for name, args, results in signatures])
    intent = ComponentInterfaceIntentV1.create(component_id='owned', schema=schema, state=[], effects=[],
        services=[{'id': name, 'signature_id': name, 'effect_ids': [],
                   'interaction_contract_id': 'component-service.owned.' + name} for name in ('allocate', 'release')],
        protocol_states=['ready'], initial_protocol_state='ready', operations=[{
            'id': 'run', 'signature_id': 'run', 'source_values': [value('value')],
            'projection_entries': [{'source_id': 'value', 'target': {'root': 'result', 'value_id': 'value', 'fields': []}}],
            'lifecycle_bindings': [], 'lifecycle_additional_roots': {'state': []},
            'checked_interaction_contract_ids': [], 'effect_ids': [], 'allowed_service_ids': ['allocate', 'release'],
            'pre_states': ['ready'], 'post_states': ['ready']}])
    return compile_component_interface_v5(intent)


def checked_fixture(root, *, cbmc=None, wrong_extent=False, wrong_generation=False,
                    preparation_only=False, fallthrough=False, buffer_view=False, wrong_byte=False,
                    timeout_seconds=30, proof_overlay_renderer=render_component_machine_overlay_v5):
    authority, requirements = inputs()
    bundle = interface_fixture(buffer_view=buffer_view)
    ids = ['semantic-transfer:original-cutpoint-00001000-00001010',
           'semantic-transfer:original-cutpoint-00001010-00001020']
    if buffer_view:
        ids[1] = 'semantic-transfer:original-cutpoint-00001030-00001040'
    projection = {'operation_id': 'run', 'entry_unit_ids': ids[:1], 'exit_unit_ids': ids[1:],
        'parameters': [], 'results': [{'id': 'value', 'projection': {
            'kind': 'register', 'register': 'eax', 'width': 32, 'at': 'exit'}}],
        'state': [], 'effects': [], 'preserved_state_ids': [], 'callback_operation_ids': [], 'continuation_unit_ids': []}
    services, transfers, units = [], [], []
    for index, (service, symbol) in enumerate((('allocate', 'GlobalAlloc'), ('release', 'GlobalFree'))):
        rva = 4096 + (48 if buffer_view else 16) * index
        provider = {'kind': 'external_call', 'identity': {'dll': 'kernel32.dll', 'symbol': symbol, 'ordinal': None},
                    'events': [{'unit_id': ids[index], 'event_index': 0}]}
        if not index:
            provider['result_projection'] = {'kind': 'reference', 'at': 'call',
                'source': {'kind': 'register', 'register': 'eax', 'width': 32, 'at': 'call'},
                'requested_extent': {'kind': 'constant', 'value': 1, 'width': 32},
                'authority': {'id': 'allocated', 'kind': 'external', 'lifetime': 'allocation'}}
            if buffer_view:
                result = provider['result_projection']
                result.update(kind='view', base=result.pop('source'), extent={'kind': 'origin_remainder'})
        services.append({'service_id': service, 'mediation': 'direct', 'provider': provider})
        nodes = tuple(_Node('reg', aux=i) for i in range(8)) + tuple(_Node('flag', aux=i) for i in range(6))
        if not index:
            nodes += (_Node('const', immediate=64), _Node('const', immediate=16))
        arguments = (14, 15) if not index else (0,)
        # Model the caller's argument reservation as well as stdcall cleanup.
        # Captured argument values alone do not preserve the enclosing ESP.
        reservation = len(nodes)
        nodes += (_Node('const', immediate=4 * len(arguments)), _Node('sub32', (7, reservation)))
        call_esp = reservation + 1
        call = _Call('external_call', rva + 4, 0, None, 0, rva + 9, 'kernel32.dll', symbol, None,
            (*range(7), call_esp), tuple(range(8, 14)), arguments,
            tuple((4 * i, 4, arg) for i, arg in enumerate(arguments)))
        actions = (_Action('set_reg', (call_esp,), aux=7), _Action('call', (0,)))
        if index and not fallthrough:
            epilogue = len(nodes)
            nodes += (_Node('load', (7,), aux=4), _Node('const', immediate=4), _Node('add32', (7, epilogue + 1)))
            actions += (_Action('set_reg', (epilogue + 2,), aux=7), _Action('outcome_return', (epilogue,)))
        else:
            actions += (_Action('outcome_fallthrough', (rva + 16,)),)
        transfers.append(_Transfer(ids[index], 'a' * 64, 'b' * 64, rva, nodes, (),
            actions, (call,), ()))
        unit = _unit(ids[index], rva, [] if index and not fallthrough else [(rva + 16, {'op': 'true'})], [])
        if index and not fallthrough:
            unit['semantics']['memory_events'] = [{'kind': 'read', 'width': 4,
                'address': {'op': 'reg', 'name': 'esp', 'width': 32}}]
        unit['semantics']['external_events'] = [{'kind': 'external_call'}]
        units.append(unit)
    if buffer_view:
        middle = ['semantic-transfer:original-cutpoint-00001010-00001020',
                  'semantic-transfer:original-cutpoint-00001020-00001030']
        null = {'op': 'eq', 'args': [{'op': 'reg', 'name': 'eax', 'width': 32},
                                   {'op': 'const', 'value': 0, 'width': 32}], 'width': 1}
        branch = _unit(middle[0], 0x1010, [(0x1030, null), (0x1020, {'op': 'not', 'args': [null], 'width': 1})], [])
        write = _unit(middle[1], 0x1020, [(0x1030, {'op': 'true'})], [])
        write['semantics']['memory_events'] = [{'kind': 'write', 'width': 1,
            'address': {'op': 'reg', 'name': 'eax', 'width': 32}, 'value': {'op': 'const', 'value': 7, 'width': 8}}]
        added = [
            _Transfer(middle[0], 'a' * 64, 'b' * 64, 0x1010,
                (_Node('reg', aux=0), _Node('const'), _Node('eq', (0, 1))), (),
                (_Action('outcome_branch', (2, 0x1030, 0x1020)),), (), ()),
            _Transfer(middle[1], 'a' * 64, 'b' * 64, 0x1020,
                (_Node('reg', aux=0), _Node('const', immediate=7)), (),
                (_Action('memory_write', (0, 1), aux=1), _Action('outcome_fallthrough', (0x1030,))), (), ()),
        ]
        ids[1:1], transfers[1:1], units[1:1] = middle, added, [branch, write]
    binding = ComponentMachineBindingIntentV1.create(component_id='owned', operations=[{
        'id': 'run', 'kind': 'operation', 'unit_ids': ids, 'entry_rvas': [4096], 'transfer_ids': ids,
        'effect_ids': [], 'service_ids': ['allocate', 'release'], 'callback_ids': [], 'outcome_protocol_ids': [],
        'machine_projection': {'operation': projection, 'service_bindings': services},
        'object_authority_selectors': [{'authority_id': 'allocated', 'rule_id': 'text'}],
        'pointer_views': [], 'relation_receipt_sha256s': [], 'induction_evidence_sha256': None}])
    contract = NormalizedComponentContract.create(interface=bundle.interface,
        machine_semantics=[row.semantics for row in binding.operations])
    machine = NormalizedMachineBinding.create(bundle=bundle, contract=contract,
        artifacts={key: 'a' * 64 for key in ('pe_sha256', 'machine_ir_sha256', 'machine_ir_manifest_sha256',
            'structural_units_sha256', 'unit_inventory_sha256', 'component_unit_inventory_sha256')},
        operation_authority={'run': {**dict(binding.operations[0].authority),
            'service_ids': ['allocate', 'release'], 'callback_ids': [], 'outcome_protocol_ids': []}})
    interface = ProofKernelComponentInterface.parse(_logical_projection(bundle, contract=contract))
    symbols = {'run': 'authored_run'}
    overlay_options = dict(bundle=bundle, contract=contract, operation_symbols=symbols, transfers=transfers,
        machine_binding=machine, object_authority_rule_ids=['text'],
        resolved_external_environment=_resolved_environment(selected_row('GlobalAlloc'), selected_row('GlobalFree')))
    overlay = render_component_machine_overlay_v5(**overlay_options)
    service_bindings = overlay.entries[0]['service_bindings']
    renderer = build_typed_proof_service_thunk_renderer(interface=interface, service_bindings=service_bindings,
        reference_authority=authority.to_payload(), allocation_requirements=requirements)
    proof_overlay = proof_overlay_renderer(**overlay_options, external_service_thunk_renderer=renderer)
    assert proof_overlay.entries == overlay.entries
    if preparation_only:
        return dict(interface=interface, service_bindings=service_bindings,
            production_overlay_source=overlay.source, proof_overlay_source=proof_overlay.source,
            reference_authority=authority.to_payload(), allocation_requirements=requirements)
    intent = ComponentBisimulationIntentV1.create(component_id='owned', operations=[{'operation_id': 'run', 'syncs': []}])
    exact = write_component_exact_c_slice_v1(component_id='owned', transfers=transfers,
        operations=[{'operation_id': 'run', 'unit_ids': ids, 'entry_rvas': [4096],
                     'context_unit_ids': ids, 'continuation_unit_ids': []}],
        intent=intent, executable_transfer_plan_sha256='a' * 64, out=root / 'exact')
    authored = root / 'authored.c'
    source_text = '''#include "portable-component-implementation.h"
uint32_t authored_run(spx_owned_context_v5 *context) {
  SPX_PROOF_BEGIN(run);
  spx_ref_v5 buffer = context->services->allocate(context->services->context, 64U, 16U);
  if (buffer.object != 0U && buffer.extent != EXPECTED) return UINT32_MAX;
  MUTATION
  return context->services->release(context->services->context, buffer);
}
'''.replace('EXPECTED', '17U' if wrong_extent else '16U').replace('MUTATION',
    'if (buffer.object != 0U) buffer.generation++;' if wrong_generation else '')
    if buffer_view:
        source_text = source_text.replace('spx_ref_v5 buffer', 'spx_view_v5 buffer')
        source_text = source_text.replace('buffer.object', 'buffer.base.object').replace('buffer.generation', 'buffer.base.generation')
        source_text = source_text.replace('  return context->services->release(context->services->context, buffer);', '''
  if (buffer.base.object != 0U) {
    uint8_t observed = 0U;
    if (spx_view_write_u8(&buffer, 0U, BYTE) != SPX_REF_OK ||
        spx_view_read_u8(&buffer, 0U, &observed) != SPX_REF_OK || observed != BYTE)
      return UINT32_MAX;
  }
  return context->services->release(context->services->context, buffer.base);
'''.replace('BYTE', '8U' if wrong_byte else '7U'))
    authored.write_text(source_text)
    source = build_component_source_package(lift_unit_id='owned', files={'authored.c': authored}, shared_inputs={},
        operation_symbols=symbols, out_dir=root / 'source')
    semantic = {**projection, 'machine_image': {'preferred_base': 0x400000, 'image_size': 0x20000}, 'units': units}
    profile = check_component_source_profile(package=root / 'source')
    result = check_bisimulation_refinement(semantic_contract={'component_id': 'owned', 'contract_sha256': 'a' * 64,
        'operations': [semantic]}, interface=interface, source_package=root / 'source', source_profile=profile, intent=intent,
        exact_c_root=root / 'exact', exact_c_slice=exact, machine_overlay_source=overlay.source,
        trusted_proof_overlay_source=proof_overlay.source, machine_overlay_entries=overlay.entries,
        reference_authority=authority.to_payload(), reference_allocation_requirements=requirements,
        machine_projections={'run': {'operation': projection, 'service_bindings': services}},
        cbmc=cbmc, c_headers=render_component_c_headers_v5(bundle, symbols), timeout_seconds=timeout_seconds,
        diagnostic_root=root / 'diagnostics')
    plan = build_component_proof_plan_v1(component_id='owned', semantic_contract_sha256='a' * 64, interface=interface,
        operations=[semantic], operation_sources=operation_sources_from_package(source_root=root / 'source', source=source,
        symbols=symbols), source_package_sha256=source['implementation_sha256'], intent=intent)
    proof = build_contextual_refinement_v2(proof_plan=plan, exact_c_slice=exact,
        implementation_sha256=source['implementation_sha256'], source_profile_sha256=profile['receipt_sha256'],
        checker=result['checker'], models=result['bindings'], shard_results=result['checks'], world=_component_proof_world_v1(
            bundle=bundle, binding_intent_sha256=binding.intent_sha256,
            machine_object_authority_sha256=authority.authority_sha256))
    artifact = {'proof': proof, 'proof_plan': plan, 'exact_c_slice': exact}
    (root / 'contextual-refinement-result.json').write_text(json.dumps(artifact, indent=2) + '\n')
    return result, artifact


class LifetimeAdmissionTests(unittest.TestCase):
    def test_retained_overlay_import_requires_exact_bytes_and_required_cut_codec(self):
        def prepare(renderer):
            return checked_fixture(None, preparation_only=True, buffer_view=True,
                                   proof_overlay_renderer=renderer)

        variants = {}
        for enabled in (False, True):
            variants[enabled] = prepare(partial(render_component_machine_overlay_v5,
                emit_proof_local_view_codec=enabled))
        symbol = '__CPROVER_spx_owned_local_view_codec'
        self.assertNotIn(symbol, variants[False]['proof_overlay_source'])
        self.assertIn(symbol, variants[True]['proof_overlay_source'])
        self.assertEqual(variants[False]['production_overlay_source'],
                         variants[True]['production_overlay_source'])
        for enabled, retained in variants.items():
            digest = hashlib.sha256(retained['proof_overlay_source'].encode()).hexdigest()
            for required in (False, True):
                renderer = partial(render_bound_proof_overlay, expected_sha256=digest,
                                   requires_local_view_codec=required)
                with self.subTest(enabled=enabled, required=required):
                    if required and not enabled:
                        with self.assertRaisesRegex(ValueError, 'checked bytes'):
                            prepare(renderer)
                    else:
                        self.assertEqual(prepare(renderer), retained)
            with self.assertRaisesRegex(ValueError, 'checked bytes'):
                prepare(partial(render_bound_proof_overlay,
                    expected_sha256=hashlib.sha256((retained['proof_overlay_source'] + '\n').encode()).hexdigest(),
                    requires_local_view_codec=False))

    def model(self, *, buffer_view=False):
        prepared = checked_fixture(None, preparation_only=True, buffer_view=buffer_view)
        receipt = _trusted_adapter_lowering_receipt(**prepared)
        return {'interface_sha256': prepared['interface'].sha256,
            'machine_overlay_sha256': receipt['production_overlay_sha256'],
            'proof_overlay_sha256': receipt['proof_overlay_sha256'], 'trusted_adapter_lowering': receipt,
            'reference_authority': prepared['reference_authority'],
            'reference_allocation_requirements': prepared['allocation_requirements'],
            'reference_allocation_requirements_sha256': canonical_sha256_v3(prepared['allocation_requirements']),
            'connected_components': [], 'operation_models': []}

    def jq_accepts(self, model):
        jq = shutil.which('jq')
        self.assertIsNotNone(jq, 'the declared jq fixture must be available')
        program = (Path(__file__).resolve().parents[3] / 'nix/jq/strong-contextual-proof.jq').read_text()
        program += '''\n. as $models | ({models: .} | spx_allocation_class_inputs) and
          (.trusted_adapter_lowering | spx_typed_adapter_renderer_inventory and
           all(.adapter_plan[]; spx_declared_external_range_effects($models)))'''
        result = subprocess.run([jq, '-e', program], input=json.dumps(model), text=True, capture_output=True)
        self.assertNotIn('compile error', result.stderr, result.stderr)
        return result.returncode == 0

    def test_both_adapter_readers_require_checked_local_premises(self):
        model = self.model()
        self.assertTrue(_trusted_adapter_lowering_used(model))
        self.assertTrue(self.jq_accepts(model))
        for mutation in ('classes', 'class-effect', 'site', 'frame', 'outcome', 'renderer', 'connected', 'unproved-framed'):
            changed = copy.deepcopy(model)
            adapter = changed['trusted_adapter_lowering']['adapter_plan'][0]
            if mutation == 'classes': del changed['reference_allocation_requirements']
            if mutation == 'class-effect':
                row = changed['reference_allocation_requirements'][0]
                row['effect']['nullable'] = False
                row['class_sha256'] = canonical_sha256_v3({k: v for k, v in row.items() if k != 'class_sha256'})
                changed['reference_allocation_requirements_sha256'] = canonical_sha256_v3(changed['reference_allocation_requirements'])
            if mutation == 'site': del adapter['proof_call_specs'][0]['checked_external_contract']
            if mutation == 'frame': adapter['proof_call_specs'][0]['offsets'] = [4, 8]
            if mutation == 'outcome':
                adapter['proof_call_specs'][0]['checked_external_contract']['profile_disposition'] = 'terminates'
                adapter['checked_binding']['events'][0]['checked_external_contract']['profile_disposition'] = 'terminates'
            if mutation == 'renderer':
                renderer = changed['trusted_adapter_lowering']['renderer']
                renderer['implementation_files'] = [row for row in renderer['implementation_files']
                    if row['path'] != 'bisimulation_allocation_lifetime.py']
                renderer['implementation_closure_sha256'] = canonical_sha256_v3(renderer['implementation_files'])
            if mutation == 'connected': changed['connected_components'] = [{'summary_strategy': 'connected-replay-v1'}]
            if mutation == 'unproved-framed':
                changed['connected_components'] = [{'summary_strategy': 'image-shared-framed-body-free-v1'}]
            rehash_model(changed)
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError): _trusted_adapter_lowering_used(changed)
                self.assertFalse(self.jq_accepts(changed))

    def test_normal_checker_accepts_local_lifetime_calls(self):
        cbmc = shutil.which('cbmc')
        if cbmc is None: self.skipTest('CBMC unavailable')
        with tempfile.TemporaryDirectory() as temporary:
            result, artifact = checked_fixture(Path(temporary), cbmc=Path(cbmc))
            self.assertEqual(result['status'], 'satisfied', result.get('issues'))
            validate_contextual_refinement_v2(artifact['proof'], proof_plan=artifact['proof_plan'], exact_c_slice=artifact['exact_c_slice'])
            jq = shutil.which('jq')
            self.assertIsNotNone(jq, 'the declared jq fixture must be available')
            program = (Path(__file__).resolve().parents[3] / 'nix/jq/strong-contextual-proof.jq').read_text()
            checked = subprocess.run([jq, '-e', program + '\nspx_strong_contextual_proof'],
                input=json.dumps(artifact), text=True, capture_output=True)
            self.assertEqual(checked.returncode, 0, checked.stderr or checked.stdout)

    def test_normal_checker_rejects_wrong_extent_forged_generation_and_unqualified_continuation(self):
        cbmc = shutil.which('cbmc')
        if cbmc is None: self.skipTest('CBMC unavailable')
        for mutation in ('wrong_extent', 'wrong_generation', 'fallthrough'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                result, _ = checked_fixture(Path(temporary), cbmc=Path(cbmc), **{mutation: True})
                self.assertEqual(result['status'], 'violated', [(row.get('code'), row.get('detail'))
                    for row in result.get('issues', [])])
                if mutation == 'fallthrough':
                    self.assertTrue(any('exit-continuation-state' in row.get('detail', '') for row in result['issues']))

    def test_renderer_still_requires_explicit_checked_lifetime_inputs(self):
        prepared = checked_fixture(None, preparation_only=True)
        for missing in ('allocation_requirements', 'reference_authority'):
            options = {key: value for key, value in prepared.items()
                       if key not in {'production_overlay_source', 'proof_overlay_source', missing}}
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                build_typed_proof_service_thunk_renderer(**options)
