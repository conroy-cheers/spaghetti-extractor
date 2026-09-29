"""Complete local/original partitions use bound tools and reject missing proof."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_object_call import checked_object_call_supplier
from spaghetti_extractor.components.bisimulation_readonly_evidence import validate_object_source_contracts
from tests.unit.operator.test_source_object_terminal import check

TESTKIT = {'capabilities': ('cbmc',), 'fixtures': ('cbmc', 'compiler', 'z3')}


class SourceObjectPartitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(); cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.solver = Path(shutil.which('z3'))
        status = check(cls.root/'baseline', smt_solver=cls.solver)
        if status['status'] != 'complete':
            raise AssertionError((cls.root/'baseline/feedback/source-check-details.json').read_text())
        cls.feedback = cls.root/'baseline/feedback'
        cls.certificate = json.loads((cls.feedback/'local-contract.json').read_text())

    def test_local_and_original_partitions_replay_all_evidence_without_tools(self):
        self.assertTrue(self.certificate['checks'][-1]['partitioned_evidence']['loops'])
        with patch('subprocess.run', side_effect=AssertionError('reader executed a tool')):
            checked = checked_object_call_supplier(self.feedback)
        self.assertFalse(checked['activation_authorized'])
        self.assertEqual(checked['runtime_compatibility'], 'unverified')

    def test_weakened_policy_or_missing_query_cannot_authorize_a_supplier(self):
        changed = deepcopy(self.certificate)
        changed['property_checker_command']['assertion_arguments'].append('--no-pointer-check')
        changed['receipt_sha256'] = canonical_sha256_v3({k: v for k, v in changed.items() if k != 'receipt_sha256'})
        with self.assertRaisesRegex(ValueError, 'policy is weakened'):
            validate_object_source_contracts(changed)
        for name in ['local-contract-models/query-evidence/initialize-input_dependence',
                     'original-comparison/query-evidence']:
            with self.subTest(queries=name):
                root = self.root/('missing-'+name.split('/')[0]); shutil.copytree(self.feedback, root)
                missing = next(p for p in (root/name).glob('*/query.json')
                    if '--show-properties' in json.loads(p.read_text())['binding']['arguments'])
                shutil.rmtree(missing.parent)
                with patch('subprocess.run', side_effect=AssertionError('missing proof executed a tool')):
                    with self.assertRaises(ValueError):
                        checked_object_call_supplier(root)

    def test_a_wrong_normal_write_is_rejected_with_both_outcomes_admitted(self):
        status = check(self.root/'wrong', smt_solver=self.solver, written_value='value^1U')
        self.assertNotEqual(status['status'], 'complete')
        result = json.loads((self.root/'wrong/feedback/original-comparison/result.json').read_text())
        self.assertEqual(result['status'], 'violated')
