"""Real comparison selections bind shared representation inputs before compilation."""
import json
from pathlib import Path
import unittest

from spaghetti_extractor.components.comparison_package import load_comparison_package
from spaghetti_extractor.components.comparison_representation import validate_representation_selection,representation_binding
from tests.unit.components import test_comparison_dependencies as base
from tests.unit.candidate import test_experimental as experimental

TESTKIT = {'fixtures': ('compiler',), 'commands': ('component start','component check','candidate build'),
           'resources': ('tests/fixtures/jq-array-concat','tests/fixtures/jq-array-append')}


class RepresentationSelectionTests(unittest.TestCase):
    setUp=base.ComparisonDependencyTests.setUp
    command=base.ComparisonDependencyTests.command
    check=base.ComparisonDependencyTests.check
    supplier=base.ComparisonDependencyTests.supplier
    select=base.ComparisonDependencyTests.select
    candidate=experimental.ExperimentalCandidateTests.candidate
    policy=experimental.ExperimentalCandidateTests.policy

    def representation(self,package,revision='raw',members=None):
        path=package/'comparison-plan.json';plan=json.loads(path.read_text())
        plan['representation']={'group':{'id':'values','label':'Private values',
            'members':members or ['array-concat','array-append']},'revision':revision,
            'inputs':{'layout':'source/layout.h'}}
        (package/'source/layout.h').write_text('/* '+revision+' ownership and layout */\n')
        path.write_text(json.dumps(plan))
        return plan

    def test_same_signature_requires_group_revision_and_shared_bytes(self):
        supplier=self.supplier();self.representation(supplier);self.representation(self.package);self.select(supplier)
        code,text,baseline=self.check(self.package,'raw');self.assertEqual(code,0,text)
        (supplier/'source/layout.h').write_text('/* altered layout with unchanged revision */\n')
        code,text,out=self.check(self.package,'mixed-bytes','--dependency-package','array-append='+str(supplier))
        self.assertEqual(code,2,text);self.assertIn('incompatible representation selection',text)
        self.assertFalse(list(out.rglob('*.o')))
        self.representation(supplier,'handles')
        code,text,out=self.check(self.package,'mixed-revision','--dependency-package','array-append='+str(supplier))
        self.assertEqual(code,2,text);self.assertIn('dependency contract changed',text)
        plan=self.representation(self.package,'handles')
        plan['dependencies'][0]['representation']['revision']='handles'
        (self.package/'comparison-plan.json').write_text(json.dumps(plan))
        code,text,out=self.check(self.package,'coherent','--dependency-package','array-append='+str(supplier),
            '--reuse-comparison',str(baseline))
        self.assertEqual(code,0,text);self.assertIn('complete selected group',text)
        self.assertIn('invalidated',text)

    def test_missing_declaration_and_conflicting_membership_reject(self):
        supplier=self.supplier();self.representation(self.package);self.select(supplier)
        code,text,_=self.check(self.package,'undeclared');self.assertEqual(code,2,text)
        self.assertIn('incompatible representation selection',text)
        self.representation(supplier,members=['array-append'])
        self.select(supplier)
        code,text,_=self.check(self.package,'membership');self.assertEqual(code,2,text)
        self.assertIn('incompatible representation selection',text)

    def test_partial_local_group_cannot_run_experiment(self):
        self.representation(self.package)
        code,text,local=self.check(self.package,'partial');self.assertEqual(code,0,text)
        self.assertIn('local check missing array-append',text)
        plan,_=load_comparison_package(local/'inputs')
        with self.assertRaisesRegex(ValueError,'incomplete representation replacement group'):
            validate_representation_selection(local/'inputs',plan,complete=True)
        policy=self.policy();value=json.loads(policy.read_text())
        value['accepted_representations']={'array-concat':{k:plan['representation'][k] for k in ('group','revision')}}
        policy.write_text(json.dumps(value))
        code,text=self.candidate('build','fixture','--experimental-comparison',str(local),
            '--experimental-policy',str(policy),'--output',str(self.root/'experiment'))
        self.assertEqual(code,2,text);self.assertIn('incomplete representation replacement group',text)

    def test_experimental_policy_requires_representation_acceptance(self):
        self.representation(self.package,members=['array-concat'])
        code,text,local=self.check(self.package,'complete');self.assertEqual(code,0,text)
        policy=self.policy()
        code,text=self.candidate('build','fixture','--experimental-comparison',str(local),
            '--experimental-policy',str(policy),'--output',str(self.root/'unaccepted'))
        self.assertEqual(code,2,text);self.assertIn('representation has not been accepted',text)
        plan,_=load_comparison_package(local/'inputs');value=json.loads(policy.read_text())
        value['accepted_representations']={'array-concat':{k:plan['representation'][k] for k in ('group','revision')}}
        policy.write_text(json.dumps(value))
        code,text=self.candidate('build','fixture','--experimental-comparison',str(local),
            '--experimental-policy',str(policy),'--output',str(self.root/'accepted'))
        self.assertEqual(code,0,text)

    def test_representation_inputs_cannot_escape_owned_headers(self):
        plan=self.representation(self.package)
        plan['representation']['inputs']['layout']='adapters/driver.c'
        with self.assertRaisesRegex(ValueError,'outside component include'):
            representation_binding(self.package,plan)
        plan['representation']['inputs']['layout']='../outside'
        with self.assertRaises(ValueError):
            representation_binding(self.package,plan)
