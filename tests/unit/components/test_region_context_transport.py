"""The real-region context rule preserves caller code without accepting region behavior."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.components.bisimulation_cut_state import _symbol, _walk
from tests.unit.components.region_context_transport import (
    check_inert_region_markers, check_region_context_transport, check_marked_region_observer_transport,
    _normalized,
)
from tests.unit.components import test_source_region_transport as body_fixture
from tests.unit.components.test_source_region_observers import OBSERVED


TESTKIT = {'fixtures': ('cbmc', 'compiler')}
MARKERS = ['region_entry', 'region_lookahead', 'region_tail']
SOURCE = '''unsigned int input_word;
unsigned int read_byte(unsigned char *out) { *out = input_word; return 0; }
unsigned int cleanup(void) {
  unsigned char a;
  unsigned int output = 7;
  region_entry();
  if (read_byte(&a)) return 99;
  if (!a) goto tail;
  region_lookahead();
  if (a == 1) goto tail;
  return output + a;
tail:;
  region_tail();
  return output;
}
'''


class RegionContextTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler, instrument = shutil.which('goto-cc'), shutil.which('goto-instrument')
        if not compiler or not instrument:
            raise unittest.SkipTest('GOTO compiler is unavailable')
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.models = {}
        for name in ['ordinary', 'baseline', 'edited']:
            root = Path(cls.directory.name) / name
            root.mkdir()
            source = SOURCE
            if name == 'ordinary':
                for marker in MARKERS:
                    source = source.replace('  ' + marker + '();\n', '')
            else:
                source = ''.join('void ' + marker + '(void) {}\n' for marker in MARKERS) + source
            if name == 'edited':
                source = source.replace('if (!a) goto tail;', 'int has_byte = a != 0;\n  if (!has_byte) goto tail;')
            (root / 'source.c').write_text(source)
            r = subprocess.run([compiler, '--i386-win32', 'source.c', '-o', 'model.goto'], cwd=root, capture_output=True, text=True)
            if r.returncode:
                raise AssertionError(r.stderr)
            model = {}
            for key, field, flag in [('functions', 'functions', '--show-goto-functions'), ('symbols', 'symbolTable', '--show-symbol-table')]:
                r = subprocess.run([instrument, flag, '--json-ui', str(root / 'model.goto')], capture_output=True, text=True)
                if r.returncode:
                    raise AssertionError(r.stderr)
                rows = next(v[field] for v in json.loads(r.stdout) if field in v)
                model[key] = {v['name']: v for v in rows} if key == 'functions' else rows
            cls.models[name] = model

    def relation(self, edited=None):
        a, b = self.models['baseline'], self.models['edited'] if edited is None else edited
        return check_region_context_transport(original_functions=a['functions'], original_symbols=a['symbols'],
            edited_functions=b['functions'], edited_symbols=b['symbols'], function='cleanup', entry='region_entry',
            exits={'lookahead': 'region_lookahead', 'tail': 'region_tail'})

    def inert(self, marked=None):
        a, b = self.models['ordinary'], self.models['baseline'] if marked is None else marked
        return check_inert_region_markers(original_functions=a['functions'], original_symbols=a['symbols'],
            marked_functions=b['functions'], marked_symbols=b['symbols'], function='cleanup', markers=MARKERS)

    def test_actual_compiler_markers_erase_without_changing_context(self):
        result = self.inert()
        self.assertEqual(result['status'], 'matched-inert-region-markers')
        self.assertFalse(result['authorizing'])

    def test_private_local_edit_preserves_context_with_separate_proof_obligations(self):
        result = self.relation()
        self.assertEqual(result['status'], 'matched-compiled-region-context')
        self.assertEqual(result['ports'], ['@return', 'lookahead', 'tail'])
        self.assertTrue(result['new_private_scalars'][0].endswith('::has_byte'))
        self.assertTrue(result['erased_private_lifetime_ends'])
        for key in ['authorizing', 'local_behavior_checked', 'frame_checked', 'incoming_domain_checked', 'local_theorem_import_authorized']:
            self.assertFalse(result[key], key)

    def test_changed_region_branch_is_left_to_local_proof(self):
        edited = deepcopy(self.models['edited'])
        rows = edited['functions']['cleanup']['instructions']
        branch = next(r for r in rows if r['instructionId'] == 'GOTO' and 'has_byte' in str(r.get('guard')))
        branch['guard'] = {'id': 'not', 'namedSub': {'type': {'id': 'bool'}}, 'sub': [branch['guard']]}
        self.assertFalse(self.relation(edited)['local_behavior_checked'])

    def test_marker_effect_is_rejected(self):
        marked = deepcopy(self.models['baseline'])
        row = next(r for r in marked['functions']['cleanup']['instructions'] if r['instructionId'] == 'ASSIGN')
        marked['functions']['region_entry']['instructions'].insert(0, deepcopy(row))
        with self.assertRaisesRegex(ValueError, 'marker has behavior'):
            self.inert(marked)

    def test_marker_arguments_are_rejected(self):
        marked = deepcopy(self.models['baseline'])
        row = next(r for r in marked['functions']['cleanup']['instructions'] if r['instructionId'] == 'FUNCTION_CALL'
                   and _symbol(r['code']['sub'][1]) == 'region_entry')
        row['code']['sub'][2]['sub'] = [deepcopy(row['code']['sub'][1])]
        with self.assertRaisesRegex(ValueError, 'argument-free'):
            self.inert(marked)

    def test_changed_global_initialization_is_rejected(self):
        edited = deepcopy(self.models['edited'])
        edited['symbols']['input_word']['value'] = {'id': 'constant', 'namedSub': {'value': {'id': '1'}}}
        with self.assertRaisesRegex(ValueError, 'context storage changed'):
            self.relation(edited)

    def test_changed_helper_is_rejected(self):
        edited = deepcopy(self.models['edited'])
        row = next(r for r in edited['functions']['read_byte']['instructions'] if r['instructionId'] == 'SET_RETURN_VALUE')
        value = next(v for v in _walk(row['code']) if v.get('id') == 'constant')
        value['namedSub']['value']['id'] = '1'
        with self.assertRaisesRegex(ValueError, 'context helper changed'):
            self.relation(edited)

    def test_changed_outgoing_context_is_rejected(self):
        edited = deepcopy(self.models['edited'])
        value = next(v for r in edited['functions']['cleanup']['instructions'] if r['instructionId'] == 'SET_RETURN_VALUE'
                     for v in _walk(r['code']) if v.get('id') in {'plus', '+'})
        value['id'] = '-' if value['id'] == '+' else 'minus'
        with self.assertRaisesRegex(ValueError, 'compiled context outside region differs'):
            self.relation(edited)

    def test_new_local_address_escape_is_rejected(self):
        edited = deepcopy(self.models['edited'])
        rows = edited['functions']['cleanup']['instructions']
        row = next(r for r in rows if r['instructionId'] == 'ASSIGN' and 'has_byte' in str(r['code']))
        row['code']['sub'][1] = {'id': 'address_of', 'sub': [deepcopy(row['code']['sub'][0])]}
        with self.assertRaisesRegex(ValueError, 'exposes its address'):
            self.relation(edited)

    def test_new_static_storage_is_rejected(self):
        edited = deepcopy(self.models['edited'])
        symbol = next(v for k, v in edited['symbols'].items() if k.endswith('::has_byte'))
        symbol['isStaticLifetime'] = True
        with self.assertRaisesRegex(ValueError, 'automatic scalar'):
            self.relation(edited)

    def test_new_volatile_storage_is_rejected(self):
        edited = deepcopy(self.models['edited'])
        symbol = next(v for k, v in edited['symbols'].items() if k.endswith('::has_byte'))
        symbol['type']['namedSub']['#volatile'] = {'id': '1'}
        with self.assertRaisesRegex(ValueError, 'new private storage is volatile'):
            self.relation(edited)

    def test_edge_bypassing_entry_is_rejected(self):
        edited = deepcopy(self.models['edited'])
        rows = edited['functions']['cleanup']['instructions']
        entry = next(i for i, r in enumerate(rows) if r['instructionId'] == 'FUNCTION_CALL'
                     and _symbol(r['code']['sub'][1]) == 'region_entry')
        branch = deepcopy(next(r for r in rows if r['instructionId'] == 'GOTO'))
        branch['locationNumber'] = max(r['locationNumber'] for r in rows) + 1
        branch['targets'] = [rows[entry + 1]['locationNumber']]
        rows.insert(0, branch)
        with self.assertRaisesRegex(ValueError, 'bypasses region entry'):
            self.relation(edited)

    def test_internal_cycle_requires_a_progress_rule(self):
        edited = deepcopy(self.models['edited'])
        row = next(r for r in edited['functions']['cleanup']['instructions'] if r['instructionId'] == 'GOTO'
                   and 'has_byte' in str(r.get('guard')))
        row['targets'] = [row['locationNumber']]
        with self.assertRaisesRegex(ValueError, 'internal cycle requires a progress rule'):
            self.relation(edited)


class MarkedRegionBodyTests(unittest.TestCase):
    inventories = body_fixture.SourceRegionTransportTests.inventories

    def check(self, *, wrong_actual_branch=False, wrong_parameter=False):
        marked = ('#undef CUT\n#define CUT(id) region_##id()\n'
                  'void region_entry(void) {}\nvoid region_next(void) {}\nvoid region_tail(void) {}\n')
        body = body_fixture.BODY
        if wrong_actual_branch:
            body = body.replace('if (!a) break;', 'if (a) break;')
        local = OBSERVED.replace('const uint8_t *a)', 'const uint8_t *a, int value)').replace(
            'observe(3U,input,&a)', 'observe(3U,input,&a,' + ('value+1' if wrong_parameter else 'value') + ')').replace(
            'observe(6U,input,&a)', 'observe(6U,input,&a,value)')
        data = self.inventories(original_body=marked + body, local=local)
        return check_marked_region_observer_transport(marked_functions=data['original_functions'], marked_symbols=data['original_symbols'],
            local_functions=data['local_functions'], local_symbols=data['local_symbols'], function='run', entry_sync='entry',
            markers={'entry': 'region_entry', 'next': 'region_next', 'tail': 'region_tail'},
            restored_locals={'run::1::input': 'input', 'run::1::a': 'a'}, cut_results={'next': 3, 'tail': 6},
            observer='observe', observer_arguments=[('run::1::input', False), ('run::1::a', True), ('run::value', False)],
            parameter_arguments=['run::value'])

    def test_actual_marked_body_and_parameter_values_match_local_observer(self):
        result = self.check()
        self.assertTrue(result['local_cut_observer_arguments_checked'])
        self.assertEqual(result['parameter_capture_arguments'], ['run::value'])
        self.assertFalse(result['inventory_tokens_executed'])
        self.assertFalse(result['input_harness_domain_checked'])

    def test_actual_changed_branch_does_not_match_old_local_body(self):
        with self.assertRaisesRegex(ValueError, 'body instruction differs'):
            self.check(wrong_actual_branch=True)

    def test_local_observer_cannot_substitute_a_parameter_expression(self):
        with self.assertRaisesRegex(ValueError, 'different local'):
            self.check(wrong_parameter=True)


class CompilerBranchFormTests(unittest.TestCase):
    def bodies(self):
        guard = {'id': 'symbol', 'namedSub': {'identifier': {'id': 'g'}, 'type': {'id': 'bool'}}}
        true = {'id': 'constant', 'namedSub': {'type': {'id': 'bool'}, 'value': {'id': 'true'}}}
        tail = [{'instructionId': 'ASSIGN', 'locationNumber': 11, 'code': {'observable': 'same assignment'}},
                {'instructionId': 'END_FUNCTION', 'locationNumber': 20}]
        ordinary = {'instructions': [{'instructionId': 'GOTO', 'locationNumber': 0,
            'guard': {'id': 'not', 'namedSub': {'type': {'id': 'bool'}}, 'sub': [guard]}, 'targets': [20]}, *tail]}
        lowered = {'instructions': [{'instructionId': 'GOTO', 'locationNumber': 0, 'guard': guard, 'targets': [11]},
            {'instructionId': 'GOTO', 'locationNumber': 1, 'guard': true, 'targets': [20]}, *tail]}
        return ordinary, lowered

    def test_finite_inverted_branch_after_private_lifetime_erasure_matches(self):
        ordinary, lowered = self.bodies()
        self.assertEqual(_normalized(ordinary), _normalized(lowered))

    def test_jump_with_another_incoming_edge_is_not_erased(self):
        ordinary, lowered = self.bodies()
        other = deepcopy(lowered['instructions'][1])
        other.update(locationNumber=21, targets=[1])
        lowered['instructions'].append(other)
        self.assertEqual(len(_normalized(lowered)['instructions']), 5)
        self.assertNotEqual(_normalized(ordinary), _normalized(lowered))

    def test_intermediate_jump_semantics_are_not_dropped(self):
        ordinary, lowered = self.bodies()
        lowered['instructions'][1]['sourceLocation'] = {'comment': 'preserve this property meaning'}
        self.assertEqual(len(_normalized(lowered)['instructions']), 4)
        self.assertNotEqual(_normalized(ordinary), _normalized(lowered))
