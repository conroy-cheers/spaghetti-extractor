"""Typed caller predicates preserve arithmetic and demand memory only when used."""

from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.components.bisimulation_call_relations import (
    ScalarBinding, ViewBinding, constant, expression, lower_call_relation, parameter,
)
from spaghetti_extractor.components.bisimulation_cleanup_entry_relations import (
    MEMORY, PARAMETERS, U32, cleanup_entry_predicates, normalized_cleanup_entry_relations,
)
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.relation_ir import BOOL_SORT, RelationSortV1


FIXTURE = Path(__file__).parents[2] / 'fixtures/metapad-cleanup-save/summary-input.json'
TESTKIT = {'fixtures': ('compiler', 'cbmc'), 'resources': ('tests/fixtures/metapad-cleanup-save',)}


class CallRelationTests(unittest.TestCase):
    def check_c(self, text):
        """Actual compiler/checker semantics, with no Python expression evaluator."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_cbmc_stdint(root / 'stdint.h')
            (root / 'pair.c').write_text('#include "stdint.h"\n' + text)
            compiler = shutil.which('goto-cc')
            cbmc = shutil.which('cbmc')
            self.assertIsNotNone(compiler, 'test requires the declared compiler fixture')
            self.assertIsNotNone(cbmc, 'test requires the declared CBMC fixture')
            compiled = subprocess.run([compiler, '--i386-win32', '-nostdinc', '-I', '.',
                'pair.c', '--function', 'check', '-o', 'model.goto'], cwd=root,
                capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            query = subprocess.run([cbmc, 'model.goto', '--function', 'check', '--json-ui',
                '--unwind', '2', '--unwinding-assertions', '--bounds-check', '--pointer-check',
                '--signed-overflow-check', '--undefined-shift-check'], cwd=root,
                capture_output=True, text=True, timeout=60)
            self.assertEqual(query.returncode, 0, query.stdout + query.stderr)
            rows = [row for block in json.loads(query.stdout) for row in block.get('result', [])]
            self.assertTrue(rows)
            self.assertEqual({row['status'] for row in rows}, {'SUCCESS'})

    def test_cleanup_normalization_matches_legacy_predicates_for_all_inputs(self):
        c = json.loads(FIXTURE.read_text())['contract']
        typed = cleanup_entry_predicates(c)
        legacy = [v for _, v in sorted(c['input_relation']['caller_requirements'].items())]
        legacy += c['input_relation']['entry_admission']
        self.assertEqual(len(legacy), len(typed))
        source = 'uint8_t __CPROVER_uninterpreted_readonly_byte(uint32_t);\nvoid check(void) {\n'
        source += 'uint32_t ' + ','.join(PARAMETERS) + ';\n'
        for i, (old, new) in enumerate(zip(legacy, typed, strict=True)):
            source += f'__CPROVER_assert(!!({old}) == !!({new}), "entry-relation-{i}");\n'
        self.check_c(source + '}\n')

    def test_inactive_or_ite_branch_does_not_demand_pointer_validity(self):
        active = parameter('active', BOOL_SORT)
        read = expression('byte_read', RelationSortV1('bitvector', width=8),
                          parameter('buffer', MEMORY), constant(1, 64))
        zero = expression('eq', BOOL_SORT, read, constant(0, 8))
        yes = expression('true', BOOL_SORT)
        predicates = [expression('or', BOOL_SORT, expression('not', BOOL_SORT, active), zero),
                      expression('ite', BOOL_SORT, active, zero, yes),
                      expression('and', BOOL_SORT, active, zero)]
        bindings = {'active': ScalarBinding(BOOL_SORT, 'active'),
                    'buffer': ViewBinding(MEMORY, 'UINT32_MAX', '2U', 'read_byte')}
        source = ('uint8_t read_byte(uint32_t address) {\n'
                  '__CPROVER_assert(0, "invalid-branch-must-not-read"); return 0U; }\n'
                  'void check(void) { _Bool active;\n')
        for i, node in enumerate(predicates):
            result = lower_call_relation(node, parameters=bindings)
            expected = '!active' if i < 2 else '0U'
            source += f'__CPROVER_assert(!!({result.predicate()}) == !!({expected}), "short-circuit-{i}");\n'
        self.check_c(source + '}\n')

    def test_unsigned_widths_wrap_without_signed_overflow(self):
        source = 'void check(void) {\n'
        for width in (8, 16, 32, 64):
            sort = RelationSortV1('bitvector', width=width)
            one, zero, maximum = constant(1, width), constant(0, width), constant(2**width-1, width)
            for name, node, expected in (
                ('add', expression('add', sort, maximum, one), zero),
                ('sub', expression('sub', sort, zero, one), maximum),
                ('not', expression('bit_not', sort, zero), maximum),
            ):
                eq = expression('eq', BOOL_SORT, node, expected)
                result = lower_call_relation(eq, parameters={})
                source += f'__CPROVER_assert({result.predicate()}, "unsigned-{width}-{name}");\n'
        self.check_c(source + '}\n')

    def test_extent_narrowing_and_wide_offsets_are_checked(self):
        buffer = parameter('buffer', MEMORY)
        extent = expression('view_extent', U32, buffer)
        eq = expression('eq', BOOL_SORT, extent, constant(0))
        bindings = {'buffer': ViewBinding(MEMORY, '0U', 'UINT64_C(4294967296)', 'read_byte')}
        result = lower_call_relation(eq, parameters=bindings)
        wide = expression('byte_read', RelationSortV1('bitvector', width=8), buffer,
                          constant(2**64-1, 64))
        read = lower_call_relation(expression('eq', BOOL_SORT, wide, constant(0, 8)), parameters=bindings)
        self.check_c('uint8_t read_byte(uint32_t p) { __CPROVER_assert(0, "invalid-read"); return 0U; }\n'
            'void check(void) {\n'
            f'__CPROVER_assert(!({result.predicate()}), "extent-does-not-truncate");\n'
            f'__CPROVER_assert(!({read.predicate()}), "offset-does-not-wrap");\n' + '}\n')

    def test_unreviewed_legacy_predicates_are_rejected(self):
        c = json.loads(FIXTURE.read_text())['contract']
        self.assertEqual(len(normalized_cleanup_entry_relations(c)), 15)
        for predicate in ('1U', 'length_target!=1U', '0U); __CPROVER_assume(0U); (1U',
                          '__CPROVER_uninterpreted_readonly_byte(text_address+length+1U)==0U'):
            changed = deepcopy(c)
            changed['input_relation']['entry_admission'][0] = predicate
            with self.subTest(predicate=predicate), self.assertRaisesRegex(ValueError, 'checked typed rule'):
                normalized_cleanup_entry_relations(changed)

    def test_wrong_binding_sort_and_unimplemented_operations_reject(self):
        node = parameter('value', U32)
        with self.assertRaisesRegex(ValueError, 'binding or sort'):
            lower_call_relation(node, parameters={'value': ScalarBinding(BOOL_SORT, 'value')})
        with self.assertRaisesRegex(ValueError, 'binding or sort'):
            lower_call_relation(node, parameters={})
        signed = expression('sign_extend', RelationSortV1('bitvector', width=64), node)
        with self.assertRaisesRegex(ValueError, 'unsupported operation sign_extend'):
            lower_call_relation(signed, parameters={'value': ScalarBinding(U32, 'value')})

    def test_concat_preserves_byte_order_and_full_unsigned_width(self):
        u8=RelationSortV1('bitvector',width=8)
        bytes_=[parameter('b'+str(i),u8) for i in range(4)]
        joined=expression('concat',U32,*reversed(bytes_))
        bindings={'b'+str(i):ScalarBinding(u8,'b'+str(i)) for i in range(4)}
        lowered=lower_call_relation(joined,parameters=bindings)
        full=lower_call_relation(expression('concat',RelationSortV1('bitvector',width=64),
            constant(2**32-1),constant(2**32-1)),parameters={})
        self.check_c('void check(void){uint8_t b0,b1,b2,b3;\n'
            f'__CPROVER_assert({lowered.defined} && {lowered.value}=='
            '((uint32_t)b0|((uint32_t)b1<<8U)|((uint32_t)b2<<16U)|((uint32_t)b3<<24U)),"little-endian-word");\n'
            f'__CPROVER_assert({full.defined} && {full.value}==UINT64_MAX,"full-concat-width");\n'+'}\n')


if __name__ == '__main__':
    unittest.main()
