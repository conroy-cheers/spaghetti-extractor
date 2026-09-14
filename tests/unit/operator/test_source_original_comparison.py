"""Public original/source feedback consumes exact source and original evidence."""

import contextlib
import copy
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.cli import main
from spaghetti_extractor.components.bisimulation_shared_original_check import check_shared_original_comparison, checked_shared_original_transition
from spaghetti_extractor.components.bisimulation_shared_services import normalize_shared_service_bindings
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.operator.source_check import write_component_source_check
from spaghetti_extractor.transfer.behavioral_c_render import behavioral_c_support_source
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.components.test_shared_original_comparison import inputs, ORIGINAL
from tests.unit.components.test_shared_service_premises import binding as service_binding

TESTKIT = {'fixtures':('cbmc','compiler','z3'), 'commands':('component check',), 'resources':(
    'tests/fixtures/hand-defined-boundaries/resource-text','profiles/pe32-user32-resource-text-runtime-v1.json')}


def ordinary_inputs():
    args = inputs()
    selected = service_binding()
    args['service_bindings'][0].update({k:selected[k] for k in ('external_effect_contract','external_contract_identity_sha256')})
    args['shared_contract']['service_contracts'] = normalize_shared_service_bindings(args['bundle'],args['service_bindings'])
    relation = args['shared_contract']['relation_intent']
    requirement = relation['operations'][0]['requirements'][0]
    requirement['expression'] = requirement['expression']['args'][0]
    relation['intent_sha256'] = canonical_sha256_v3({k:v for k,v in relation.items() if k != 'intent_sha256'})
    return args


def materialize(root, source):
    args = ordinary_inputs()
    interface = root/'interface'
    interface.mkdir(parents=True)
    (interface/'component-interface-intent-v1.json').write_text(json.dumps(args['bundle'].intent.to_payload()))
    (root/'author.c').write_text(source)
    build_component_source_package(lift_unit_id='resource-text',files={'resource-text.c':root/'author.c'},
        shared_inputs={},operation_symbols={'get':'resource_text'},out_dir=root/'source')
    exact = root/'exact'
    exact.mkdir()
    boundary = json.loads((ORIGINAL/'boundary.json').read_text())
    (exact/'component-exact-c-slice-v1.json').write_text(json.dumps(boundary['provenance']['exact_slice']))
    for name in ('behavioral-c.h','behavioral-fn-00001284.c','behavioral-dispatch.c'):
        shutil.copyfile(ORIGINAL/name,exact/name)
    (exact/'state-machine-runtime.h').write_text(exact_runtime_header())
    (exact/'behavioral-support.c').write_text(behavioral_c_support_source())
    return args


def check(root, source):
    args = materialize(root,source)
    timings = []
    status = write_component_source_check(target_id='metapad',component_id='resource-text',
        interface_package=root/'interface',source_package=root/'source',out=root/'feedback',
        host_compiler=Path(shutil.which('cc')),pe32_compiler=Path(shutil.which('cc')),
        cbmc=Path(shutil.which('cbmc')),smt_solver=Path(shutil.which('z3')),
        contract_workspace=root/'contracts',contract_timeout_seconds=60,
        shared_contract=args['shared_contract'],shared_service_bindings=args['service_bindings'],
        original_comparison={'exact_c_slice':root/'exact','binding_intent':args['binding_intent'],
            'machine_domain':args['machine_domain']},timings=timings)
    return status,timings,args


class SourceOriginalComparisonTests(unittest.TestCase):
    def test_public_functional_check_rejects_behavior_that_passes_source_contract(self):
        domains=[]
        original = (ORIGINAL/'resource-text.c').read_text()
        start,end = original.index('  uint64_t module;'),original.index('  spx_view_v5 buffer =')
        loop = original[:start]+'''  uint32_t module = 0U;
  for (uint32_t i=0; i<4U; ++i) {
    uint64_t byte;
    const spx_view_v5 *view = &context->state.module;
    if (view->read(view->access_context,view->base,i,1U,&byte)) return (spx_view_v5){0};
    module |= (uint32_t)byte << (8U*i);
  }
'''+original[end:]
        for source,expected in ((original,'complete'),(loop,'complete'),
                                (loop.replace('(uint32_t)module, id,','(uint32_t)module, id+1U,'),'violated')):
            with self.subTest(expected=expected),tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                status,timings,_ = check(root,source)
                self.assertEqual(status['status'],expected,(root/'feedback/source-check-details.json').read_text())
                certificate = json.loads((root/'feedback/local-contract.json').read_text())
                self.assertEqual(certificate['status'],'satisfied')
                result = json.loads((root/'feedback/original-comparison/result.json').read_text())
                self.assertFalse(result['authorizing'])
                self.assertEqual(result['bindings']['authored_goto_sha256'],certificate['authored_goto_sha256'])
                self.assertEqual(result['runtime_compatibility'],'unverified')
                self.assertIn('authored.goto',result['models']['compiled_files'])
                self.assertNotIn('resource-text.c',result['models']['compiled_files'])
                self.assertTrue({'symbolic-execution','solver-conversion','solver-backend'} <= {r['phase'] for r in timings})
                output = io.StringIO()
                with patch('spaghetti_extractor.commands.workflows._operator_index',return_value={
                    'components':{'units':{'resource-text':{'products':['sourceContractCheck']}}}}), patch(
                    'spaghetti_extractor.commands.workflows._realize_artifact',return_value=(root/'feedback/source-check.json',status)),contextlib.redirect_stdout(output):
                    code = main(['component','check','metapad','resource-text','--source','--local-contracts','--json'])
                self.assertEqual(code,0 if expected=='complete' else 2)
                public = json.loads(output.getvalue())
                self.assertFalse(public['local_contract']['original_comparison']['authorizing'])
                self.assertEqual(public['status']['counts']['authority_held'],0)
                if expected=='complete':
                    with patch('subprocess.run',side_effect=AssertionError('transition import must not compile or solve')):
                        transition=checked_shared_original_transition(result,
                            artifacts=root/'feedback/original-comparison',certificate=certificate,
                            source_artifacts=root/'feedback/local-contract-models')
                    domains.append(transition['domain_sha256'])
                    self.assertEqual(public['local_contract']['original_comparison']['transition_domain_sha256'],domains[-1])
                    for field in ('authorizing','runtime_contract_sha256','checks'):
                        changed=copy.deepcopy(result)
                        if field=='authorizing':changed[field]=True
                        elif field=='checks':changed[field][0]['property_ids']=[]
                        else:changed[field]='f'*64
                        changed['receipt_sha256']=canonical_sha256_v3({k:v for k,v in changed.items() if k!='receipt_sha256'})
                        with self.assertRaises(ValueError):
                            checked_shared_original_transition(changed,artifacts=root/'feedback/original-comparison',
                                certificate=certificate,source_artifacts=root/'feedback/local-contract-models')
                if expected=='violated':
                    self.assertIn('service-arguments',result['checks'][0]['detail'])
                    self.assertIsNone(public['local_contract']['original_comparison']['transition_domain_sha256'])
        self.assertEqual(len(domains),2)
        self.assertEqual(domains[0],domains[1])

    def test_stale_source_object_or_original_bytes_never_reach_solver(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            status,_,args = check(root,(ORIGINAL/'resource-text.c').read_text())
            self.assertEqual(status['status'],'complete')
            certificate = json.loads((root/'feedback/local-contract.json').read_text())
            for changed in ('authored.goto','original'):
                if changed=='authored.goto':
                    path = root/'feedback/local-contract-models/authored.goto'
                else:
                    path = root/'exact/behavioral-fn-00001284.c'
                before = path.read_bytes()
                path.write_bytes(before+b'changed')
                with patch('spaghetti_extractor.components.bisimulation_shared_original_check.run_cbmc_properties',
                           side_effect=AssertionError('stale input must not reach solver')):
                    result = check_shared_original_comparison(certificate=copy.deepcopy(certificate),
                        source_artifacts=root/'feedback/local-contract-models',exact_c_slice=root/'exact',
                        binding_intent=args['binding_intent'],machine_domain=args['machine_domain'],service_bindings=args['service_bindings'],
                        output=root/('rejected-'+changed),goto_cc=Path(shutil.which('goto-cc')),
                        cbmc=Path(shutil.which('cbmc')),smt_solver=Path(shutil.which('z3')))
                self.assertEqual(result['status'],'incomplete')
                self.assertFalse(result['authorizing'])
                self.assertEqual(result['models'],{})
                path.write_bytes(before)
            comparison=json.loads((root/'feedback/original-comparison/result.json').read_text())
            artifacts=root/'feedback/original-comparison'
            for name in ('model.goto','authored.goto','behavioral-fn-00001284.c'):
                file=artifacts/name; before=file.read_bytes();file.write_bytes(before+b'changed')
                with self.subTest(transition_artifact=name),self.assertRaises(ValueError),patch(
                        'subprocess.run',side_effect=AssertionError('stale transition must not execute tools')):
                    checked_shared_original_transition(comparison,artifacts=artifacts,
                        certificate=certificate,source_artifacts=root/'feedback/local-contract-models')
                file.write_bytes(before)
