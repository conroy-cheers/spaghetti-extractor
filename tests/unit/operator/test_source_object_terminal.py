"""Public terminal evidence checks prefixes and retains its conditional outcomes."""
import copy
from dataclasses import replace
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.binding_intent import ComponentMachineBindingIntentV1
from spaghetti_extractor.components.bisimulation_object_call import checked_object_call_supplier, checked_object_supplier_facts
from spaghetti_extractor.components.bisimulation_shared_original_check import checked_object_original_transition
from spaghetti_extractor.components.component_exact_c_slice import write_component_exact_c_slice_v1
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.operator.source_check import write_component_source_check
from spaghetti_extractor.transfer.model import _Action, _Call, _Node, _Transfer
from tests.unit.components.test_object_initialization import initializer_transfer
from tests.unit.components.test_object_terminal import fixture

TESTKIT = {'fixtures': ('cbmc', 'compiler')}


def check(root, *, corrupt_context=False, smt_solver=None, written_value='value', edited=False,
          initialized_extent=8):
    bundle, original_binding, domain, services, events = fixture()
    domain['initializes'][0]['extent'] = initialized_extent
    (root/'interface').mkdir(parents=True)
    (root/'interface/component-interface-intent-v1.json').write_text(json.dumps(bundle.intent.to_payload()))
    ids = [f'semantic-transfer:original-cutpoint-{r:08x}-{r+1:08x}' for r in (4096, 4097, 4098)]
    raw = original_binding.operations[0].to_payload()
    raw.update(unit_ids=ids, transfer_ids=ids, service_ids=['stop'], outcome_protocol_ids=['normal', 'terminates'])
    raw['machine_projection']['operation'].update(entry_unit_ids=[ids[0]], exit_unit_ids=ids[1:])
    binding = ComponentMachineBindingIntentV1.create(component_id='initializer', operations=[raw])
    nodes = tuple(_Node('reg', aux=i) for i in range(8)) + tuple(_Node('flag', aux=i) for i in range(6))
    call = _Call('external_call', 4098, 0, None, 0, 4099, 'runtime.dll', 'stop', None,
                 tuple(range(8)), tuple(range(8, 14)), (), ())
    transfers = [
        _Transfer(ids[0], 'a'*64, 'b'*64, 4096,
            (_Node('reg', aux=3), _Node('const', immediate=10), _Node('eq', (0, 1))), (),
            (_Action('outcome_branch', (2, 4098, 4097)),), (), ()),
        replace(initializer_transfer(), identity=ids[1], rva_start=4097),
        _Transfer(ids[2], 'a'*64, 'b'*64, 4098, nodes, (),
            (*(_Action('eval_word', (i,)) for i in range(14)), _Action('call', (0,)),
             _Action('outcome_fallthrough', (4099,))), (call,), ())]
    events[0]['event'].update(source_rva=4098, instruction_rva=4098, return_rva=4099)
    write_component_exact_c_slice_v1(component_id='initializer', transfers=transfers,
        operations=[{'operation_id': 'initialize', 'unit_ids': ids, 'entry_rvas': [4096]}],
        intent=None, executable_transfer_plan_sha256='c'*64, out=root/'exact')
    source = root/'initialize.c'
    source.write_text('''#include "portable-component-implementation.h"
void authored_initialize(spx_initializer_context_v5 *context,const spx_view_v5 *output,uint32_t value){
 if(value==10U){
  CORRUPTION
  context->services->stop(context->services->context);
 }
 for(uint32_t i=0;i<2U;i++)output->write(output->access_context,output->base,4U*i,4U,value);
}
'''.replace('CORRUPTION', 'context->protocol_state=99;' if corrupt_context else '')
   .replace('for(uint32_t i=0;i<2U;i++)output->write(output->access_context,output->base,4U*i,4U,value);',
       'output->write(output->access_context,output->base,0U,4U,value);\n'
       'output->write(output->access_context,output->base,4U,4U,value);' if edited else
       'for(uint32_t i=0;i<2U;i++)output->write(output->access_context,output->base,4U*i,4U,value);')
   .replace('4U,value);', '4U,'+written_value+');'))
    build_component_source_package(lift_unit_id='initializer', files={'initialize.c': source}, shared_inputs={},
        operation_symbols={'initialize': 'authored_initialize'}, out_dir=root/'source')
    return write_component_source_check(target_id='fixture', component_id='initializer',
        interface_package=root/'interface', source_package=root/'source', out=root/'feedback',
        host_compiler=Path(shutil.which('cc')), pe32_compiler=Path(shutil.which('cc')), cbmc=Path(shutil.which('cbmc')),
        contract_workspace=root/'work', contract_timeout_seconds=60, terminal_services=services, smt_solver=smt_solver,
        original_comparison={'exact_c_slice': root/'exact', 'binding_intent': binding.to_payload(),
                             'machine_domain': domain, 'service_bindings': events})


class SourceObjectTerminalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.status = check(cls.root/'baseline')
        if cls.status['status'] != 'complete':
            raise AssertionError((cls.root/'baseline/feedback/source-check-details.json').read_text())

    def test_complete_conditional_terminal_evidence_replays_without_tools(self):
        with patch('subprocess.run', side_effect=AssertionError('evidence reader must not execute tools')):
            checked = checked_object_call_supplier(self.root/'baseline/feedback')
        self.assertFalse(checked['activation_authorized'])
        self.assertEqual(checked['contract']['terminal_services'], fixture()[3])
        self.assertEqual(checked['contract']['initializes'], fixture()[2]['initializes'])
        facts, dependency = checked_object_supplier_facts(self.root/'baseline/feedback', ['eax'])
        self.assertEqual(facts['terminal_services'], checked['contract']['terminal_services'])
        self.assertEqual(dependency['consumer_requirements']['status'], 'compatible')

    def test_an_earlier_context_write_is_not_hidden_by_termination(self):
        status = check(self.root/'bad-frame', corrupt_context=True)
        self.assertEqual(status['status'], 'incomplete')
        certificate = json.loads((self.root/'bad-frame/feedback/local-contract.json').read_text())
        opacity = next(c for c in certificate['checks'] if c['kind'] == 'source_opacity')
        self.assertEqual(opacity['status'], 'incomplete')
        self.assertIn('shared_source_transport_not_opaque', [row['code'] for row in opacity['issues']])

    def test_event_changes_and_missing_terminal_premises_reject(self):
        feedback = self.root/'baseline/feedback'
        result = json.loads((feedback/'original-comparison/result.json').read_text())
        certificate = json.loads((feedback/'local-contract.json').read_text())
        changed = copy.deepcopy(result)
        changed['bindings']['service_bindings'][0]['event']['instruction_rva'] += 1
        changed['receipt_sha256'] = canonical_sha256_v3({k: v for k, v in changed.items() if k != 'receipt_sha256'})
        with self.assertRaisesRegex(ValueError, 'model meaning differs'):
            checked_object_original_transition(changed, artifacts=feedback/'original-comparison',
                certificate=certificate, source_artifacts=feedback/'local-contract-models')
        changed = copy.deepcopy(certificate)
        del changed['terminal_services']
        changed['receipt_sha256'] = canonical_sha256_v3({k: v for k, v in changed.items() if k != 'receipt_sha256'})
        with self.assertRaises(ValueError):
            checked_object_original_transition(result, artifacts=feedback/'original-comparison',
                certificate=changed, source_artifacts=feedback/'local-contract-models')
