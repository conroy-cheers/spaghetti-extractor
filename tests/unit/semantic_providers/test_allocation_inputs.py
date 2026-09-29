"""Local producer preparation shares native frames without inventing ownership."""

import copy
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.candidate.runtime_canonical_common import _checked_contract
from spaghetti_extractor.external.contracts import CheckedExternalSiteContractError
from spaghetti_extractor.external.import_sites import bind_import_site
from spaghetti_extractor.external.resolved import ExternalEnvironmentError
from spaghetti_extractor.external.resolved_contract import resolved_import_contract_behavior
from spaghetti_extractor.semantic_objects.object_authority import MachineObjectAuthorityV2
from spaghetti_extractor.semantic_providers.allocation_inputs import allocation_producer_inputs
from spaghetti_extractor.semantic_providers import portable_c_work_package as provider
from spaghetti_extractor.transfer.model import _Action, _Call, _Transfer, TransferPlanError
from tests.unit.candidate.test_runtime_contract_identity import selected_row
from tests.unit.components.machine_overlay_fixture import _resolved_environment

TESTKIT = {"fixtures": (), "resources": ("profiles/pe32-kernel32-runtime-v1.json",)}


def rehash(environment):
    environment.pop('resolved_environment_sha256', None)
    environment['resolved_environment_sha256'] = canonical_sha256_v3(environment)
    return environment


def authority(allocation_id=None, *, pe_sha256='2' * 64, extra=()):
    allocation_id = allocation_id or selected_row()['contract']['payload']['id']
    rule = {'id': 'text', 'kind': 'external', 'domain': 3, 'object': 55,
            'generation': 1, 'extent': 1, 'extent_mode': 'instance_remainder',
            'permissions': 3, 'lifetime': 'allocation', 'interior_pointers': True,
            'locator': {'kind': 'external_allocation', 'allocation_id': allocation_id, 'offset': 0},
            'evidence_sha256': 'b' * 64}
    return MachineObjectAuthorityV2(machine_backend='x86-pe32',
        bindings={'original_pe_sha256': pe_sha256}, rules=[rule, *extra])


def transfer(rva=0x5838, *, tail=False, kind='external_call', nodes=()):
    call = _Call(kind=kind, instruction_rva=rva, call_index=0, target_node=None,
        target_rva=0xe000, return_rva=rva + 6, dll='KERNEL32.dll', symbol='GlobalAlloc',
        ordinal=None, register_nodes=(), flag_nodes=(), argument_nodes=nodes, stack_inputs=())
    return _Transfer(identity=f'transfer:{rva:x}', contract_sha256='c' * 64,
        instruction_bytes_sha256='d' * 64, rva_start=rva, nodes=(), x87_nodes=(),
        actions=(_Action('outcome_external' if tail else 'outcome_jump'),),
        calls=(call,), x87_operations=())


def inputs(**overrides):
    return {'authority': authority(), 'transfers': (transfer(),),
        'resolved_environment': _resolved_environment(selected_row()),
        'transfer_plan': {'plan_sha256': 'e' * 64, 'status': 'complete',
                          'bindings': {'pe_sha256': '2' * 64}},
        'module_interface': {'interface_sha256': '1' * 64, 'identity': {'pe_sha256': '2' * 64}},
        **overrides}


class AllocationProducerInputTests(unittest.TestCase):
    def test_repeated_direct_calls_and_tail_share_native_contract_and_exact_frames(self):
        transfers = (transfer(), transfer(0x55d1, nodes=(7,)), transfer(0x59aa, tail=True))
        report = allocation_producer_inputs(**inputs(transfers=transfers))
        self.assertEqual(report['blockers'], [])
        self.assertEqual(len(report['classes']), 1)
        sites = {site['instruction_rva']: site for site in report['classes'][0]['direct_sites']}
        self.assertEqual(len(sites), 3)
        for exact in transfers:
            site = sites[exact.rva_start]
            expected = _checked_contract(row=selected_row(), call=exact.calls[0], escape_index={},
                                         tail_jump=exact.rva_start == 0x59aa).payload()
            self.assertEqual(site['checked_external_contract'], expected)
            self.assertEqual(site['checked_external_contract_sha256'], canonical_sha256_v3(expected))
            self.assertEqual(site['transfer_sha256'], exact.contract_sha256)
            self.assertEqual(site['instruction_bytes_sha256'], exact.instruction_bytes_sha256)
        self.assertEqual(sites[0x5838]['checked_external_contract']['argument_base_offset'], 0)
        self.assertEqual(sites[0x59aa]['checked_external_contract']['argument_base_offset'], 4)
        self.assertTrue(report['direct_site_scan_complete'])
        for field in ('authority', 'producer_set_complete', 'native_runtime_inventory', 'caller_ownership_proved'):
            self.assertIs(report[field], False)
        self.assertEqual(report['producer_inputs_sha256'], canonical_sha256_v3({
            k: v for k, v in report.items() if k != 'producer_inputs_sha256'}))
        self.assertEqual(report, allocation_producer_inputs(**inputs(transfers=reversed(transfers))))

    def test_unrelated_environment_blockers_and_indirect_routes_remain_visible(self):
        environment = _resolved_environment(selected_row())
        environment.update(status='incomplete', authority='none',
                           blockers=[{'code': 'unresolved_import', 'symbol': 'UnrelatedService'}])
        indirect_jump = replace(transfer(0x6000), calls=(), actions=(_Action('outcome_indirect'),))
        report = allocation_producer_inputs(**inputs(resolved_environment=rehash(environment),
            transfers=(transfer(), transfer(0x7000, kind='indirect_call'), indirect_jump)))
        self.assertEqual(report['resolved_environment_status'], 'incomplete')
        self.assertEqual(report['blockers'], [])
        self.assertEqual(len(report['classes'][0]['direct_sites']), 1)
        self.assertEqual({r['kind'] for r in report['unresolved_indirect_sites']},
                         {'indirect_call', 'indirect_jump'})
        self.assertFalse(report['producer_set_complete'])

    def test_missing_ambiguous_or_nonallocator_contract_cannot_supply_a_producer(self):
        row = selected_row()
        for rows, selected_authority, code in (
            ((), authority(), 'allocation_producer_contract_missing'),
            ((row, copy.deepcopy(row)), authority(), 'allocation_producer_contract_ambiguous'),
            ((selected_row('GlobalFree'),), authority(selected_row('GlobalFree')['contract']['payload']['id']),
             'allocation_producer_contract_unsupported'),
        ):
            with self.subTest(code=code):
                report = allocation_producer_inputs(**inputs(authority=selected_authority,
                    resolved_environment=_resolved_environment(*rows)))
                self.assertEqual(report['classes'], [])
                self.assertEqual(report['blockers'][0]['code'], code)
        report = allocation_producer_inputs(**inputs(transfers=()))
        self.assertEqual(report['blockers'][0]['code'], 'allocation_producer_direct_site_absent')

    def test_profile_and_exact_transfer_changes_invalidate_preparation(self):
        original = allocation_producer_inputs(**inputs())
        row = selected_row()
        row['contract']['profile_sha256'] = 'f' * 64
        changed = allocation_producer_inputs(**inputs(resolved_environment=_resolved_environment(row)))
        self.assertNotEqual(original['producer_inputs_sha256'], changed['producer_inputs_sha256'])
        self.assertNotEqual(original['classes'][0]['contract_identity_sha256'],
                            changed['classes'][0]['contract_identity_sha256'])
        self.assertNotEqual(original['classes'][0]['direct_sites'][0]['checked_external_contract_sha256'],
                            changed['classes'][0]['direct_sites'][0]['checked_external_contract_sha256'])
        changed = allocation_producer_inputs(**inputs(transfers=(replace(transfer(), contract_sha256='f' * 64),)))
        self.assertNotEqual(original['producer_inputs_sha256'], changed['producer_inputs_sha256'])

    def test_mismatched_modules_and_stale_environment_are_rejected(self):
        for change in ({'authority': authority(pe_sha256='a' * 64)},
                       {'transfer_plan': {**inputs()['transfer_plan'], 'bindings': {'pe_sha256': 'a' * 64}}}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'different original modules'):
                allocation_producer_inputs(**inputs(**change))
        environment = inputs()['resolved_environment']
        environment['bindings']['module_interface_sha256'] = 'a' * 64
        with self.assertRaises(ExternalEnvironmentError):
            allocation_producer_inputs(**inputs(resolved_environment=environment))
        with self.assertRaises(ExternalEnvironmentError):
            allocation_producer_inputs(**inputs(resolved_environment=rehash(environment)))

    def test_duplicate_transfers_and_ambiguous_external_tails_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'repeats a transfer'):
            allocation_producer_inputs(**inputs(transfers=(transfer(), transfer())))
        tail = transfer(tail=True)
        with self.assertRaises(TransferPlanError):
            allocation_producer_inputs(**inputs(transfers=(replace(tail, calls=tail.calls * 2),)))

    def test_callback_frame_cannot_be_invented_from_behavior_declaration(self):
        behavior = replace(resolved_import_contract_behavior(selected_row()), callback_effect='explicit')
        with self.assertRaisesRegex(CheckedExternalSiteContractError, 'callback provenance'):
            bind_import_site(behavior, argument_nodes=())

    def test_provider_prepares_before_local_binding_work_without_linked_module(self):
        data = inputs()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module_path = root / 'module-interface.json'
            module_path.write_text(json.dumps(data['module_interface']))
            authority_payload = data['authority'].to_payload()
            authority_model = MachineObjectAuthorityV2(machine_backend='x86-pe32',
                bindings={**authority_payload['bindings'], 'module_interface_sha256': provider.sha256_file(module_path)},
                rules=authority_payload['rules'])
            for name, value in (('authority', authority_model.to_payload()),
                                ('environment', data['resolved_environment']), ('slice', {})):
                (root / name).write_text(json.dumps(value))
            module = {**data['module_interface'], 'loader': {'image_size': 0x20000, 'preferred_base': 0x400000}}
            with patch.object(provider.SemanticSliceV2, 'parse', return_value=SimpleNamespace(identity='f' * 64)), \
                 patch.object(provider, 'load_executable_transfer_plan', return_value=(data['transfer_plan'], data['transfers'])), \
                 patch.object(provider.Pe32ModuleInterfaceV2, 'load', return_value=SimpleNamespace(payload=module)), \
                 patch.object(provider, '_direct_component_view', side_effect=RuntimeError('stop before binding proof')):
                with self.assertRaisesRegex(RuntimeError, 'stop before binding proof'):
                    provider.write_portable_c_work_package_provider_v2(
                        semantic_slice=root / 'slice', machine_object_authority=root / 'authority',
                        resolved_external_environment=root / 'environment', transfer_plan=root / 'transfer',
                        binding_intent=root / 'binding', interface_package=root / 'interface', source_package=root / 'source',
                        host_compiler=root / 'cc', pe32_compiler=root / 'pecc', nm=root / 'nm', cbmc=root / 'cbmc',
                        provider_id='fixture', proof_classification='machine_overlay', out=root / 'out')
            report = json.loads((root / 'out/allocation-producer-inputs.json').read_text())
            self.assertEqual(len(report['classes'][0]['direct_sites']), 1)
            self.assertFalse(report['authority'])
            self.assertFalse((root / 'out/qualification.json').exists())
