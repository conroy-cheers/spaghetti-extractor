"""Account narrowly for DFCC's comparison warning without hiding public writes."""

import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tests.unit.components.dfcc_array_equal_frame import check_array_equal_frame

TESTKIT = {'fixtures': ('cbmc', 'compiler')}


class DfccArrayEqualFrameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(shutil.which(t) for t in ('goto-cc', 'goto-instrument')):
            raise unittest.SkipTest('compiler fixtures unavailable')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'model.c').write_text('''unsigned int left[2], right[2];
_Bool public_result;
void compare(void) __CPROVER_requires(1) __CPROVER_ensures(1) __CPROVER_assigns();
void compare(void) { __CPROVER_assert(__CPROVER_array_equal(left, right), "equal"); }
void main(void) { compare(); }
''')
            commands = [['goto-cc', '--i386-win32', str(root/'model.c'), '-o', str(root/'raw.goto')],
                        ['goto-instrument', '--dfcc', 'main', '--enforce-contract', 'compare',
                         str(root/'raw.goto'), str(root/'checked.goto')]]
            for command in commands:
                result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                if result.returncode:
                    raise AssertionError(result.stderr)
            cls.inputs = {'warnings': result.stderr.splitlines()}
            for side, model in [('original', 'raw.goto'), ('instrumented', 'checked.goto')]:
                for key, field, flag in [('functions', 'functions', '--show-goto-functions'),
                                         ('symbols', 'symbolTable', '--show-symbol-table')]:
                    result = subprocess.run(['goto-instrument', flag, '--json-ui', str(root/model)],
                                            capture_output=True, text=True, timeout=30)
                    if result.returncode:
                        raise AssertionError(result.stderr)
                    rows = next(v[field] for v in json.loads(result.stdout) if field in v)
                    cls.inputs[side+'_'+key] = {v['name']: v for v in rows} if key == 'functions' else rows

    def setUp(self):
        self.data = copy.deepcopy(self.inputs)

    def operation(self, side='original'):
        for body in self.data[side+'_functions'].values():
            for row in body.get('instructions', []):
                if row.get('code', {}).get('namedSub', {}).get('statement', {}).get('id') == 'array_equal':
                    return body, row
        self.fail('missing comparison')

    def test_actual_compiler_temporary_accounts_only_for_the_frame(self):
        result = check_array_equal_frame(**self.data)
        self.assertEqual(len(result['retained_operations']), 1)
        self.assertFalse(result['memory_read_safety_checked'])
        self.assertFalse(result['comparison_truth_checked'])
        self.assertFalse(result['callee_contract_checked'])
        self.assertFalse(result['authorizing'])

    def test_global_result_is_a_public_write(self):
        _, row = self.operation()
        row['code']['sub'][2]['namedSub']['identifier']['id'] = 'public_result'
        with self.assertRaisesRegex(ValueError, 'private compiler Boolean'):
            check_array_equal_frame(**self.data)

    def test_missing_declaration_cannot_claim_fresh_storage(self):
        body, row = self.operation()
        identity = row['code']['sub'][2]['namedSub']['identifier']['id']
        body['instructions'] = [r for r in body['instructions'] if not (
            r['instructionId'] == 'DECL' and identity in str(r.get('code')))]
        with self.assertRaisesRegex(ValueError, 'fresh result declaration'):
            check_array_equal_frame(**self.data)

    def test_branch_cannot_bypass_the_fresh_declaration(self):
        body, row = self.operation()
        body['instructions'][0]['targets'] = [row['locationNumber']]
        with self.assertRaisesRegex(ValueError, 'bypasses result declaration'):
            check_array_equal_frame(**self.data)

    def test_effectful_input_is_not_a_readonly_comparison(self):
        _, row = self.operation()
        row['code']['sub'][0]['id'] = 'side_effect'
        with self.assertRaisesRegex(ValueError, 'input expression has an effect'):
            check_array_equal_frame(**self.data)

    def test_instrumented_operands_must_match_the_original(self):
        _, row = self.operation('instrumented')
        row['code']['sub'][0] = copy.deepcopy(row['code']['sub'][1])
        with self.assertRaisesRegex(ValueError, 'changed an intrinsic'):
            check_array_equal_frame(**self.data)

    def test_another_warning_cannot_be_silenced(self):
        self.data['warnings'].append('file fixture: unsupported array_copy')
        with self.assertRaisesRegex(ValueError, 'unrecognized instrumentation diagnostic'):
            check_array_equal_frame(**self.data)

    def test_every_warning_needs_a_checked_operation(self):
        self.data['warnings'] *= 2
        with self.assertRaisesRegex(ValueError, 'diagnostic coverage differs'):
            check_array_equal_frame(**self.data)

    def test_missing_operation_in_a_surviving_body_is_rejected(self):
        body, row = self.operation('instrumented')
        body['instructions'].remove(row)
        with self.assertRaisesRegex(ValueError, 'lost from a surviving body'):
            check_array_equal_frame(**self.data)

    def test_unrelated_diagnostic_location_is_rejected(self):
        self.data['warnings'] = [v.replace('function compare:', 'function foreign:')
                                 for v in self.data['warnings']]
        with self.assertRaisesRegex(ValueError, 'diagnostic coverage differs'):
            check_array_equal_frame(**self.data)
