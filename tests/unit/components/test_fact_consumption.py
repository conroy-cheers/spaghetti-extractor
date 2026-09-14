"""Same-program fact consumption changes only explicitly selected assumptions."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
from tests.unit.components.entry_fact_transport import (
    check_compiled_fact_consumption, check_compiled_fact_substitution,
)

TESTKIT = {'fixtures': ('cbmc', 'compiler')}

HEADER = 'struct item { unsigned value; }; struct item state, before;\n'
FACTS = '''void facts(void) {
  unsigned same = __CPROVER_array_equal(&state, &before);
  unsigned valid = state.value == before.value;
  __CPROVER_assert(same, "frame");
  __CPROVER_assert(valid, "contents");
}
'''
CALLER = '''void run(unsigned branch) {
  __CPROVER_assume(1);
  before=state;
  if (branch) facts(); else facts();
}
'''


def consume(source):
    for value, description in [('same', 'frame'), ('valid', 'contents')]:
        anchor = f'__CPROVER_assert({value}, "{description}");'
        source = source.replace(anchor, anchor+f' __CPROVER_assume({value});')
    return source


class FactConsumptionTests(unittest.TestCase):
    def models(self, *, original=FACTS, consumer=None, caller=CALLER):
        if not all(shutil.which(t) for t in ('goto-cc', 'goto-instrument')):
            self.skipTest('compiler fixtures unavailable')
        if consumer is None:
            consumer = consume(original)
        inputs = {}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for side, source in [('original', HEADER+original+CALLER), ('consumer', HEADER+consumer+caller)]:
                file, model = root/(side+'.c'), root/(side+'.goto')
                file.write_text(source)
                result = subprocess.run([shutil.which('goto-cc'), '--i386-win32', str(file), '-o', str(model)],
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                for key, flag, field in [('functions', '--show-goto-functions', 'functions'),
                                         ('symbols', '--show-symbol-table', 'symbolTable')]:
                    result = subprocess.run([shutil.which('goto-instrument'), flag, '--json-ui', str(model)],
                                            capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    values = [v[field] for v in json.loads(result.stdout) if field in v]
                    self.assertEqual(len(values), 1)
                    inputs[side+'_'+key] = {v['name']: v for v in values[0]} if key == 'functions' else values[0]
        return inputs

    def check(self, inputs):
        return check_compiled_fact_consumption(**inputs, facts={'facts': ['frame', 'contents']})

    def test_scalar_snapshots_support_both_caller_contexts(self):
        result = self.check(self.models())
        self.assertEqual(result['status'], 'matched-same-program-fact-consumption')
        self.assertEqual(len(result['facts']), 2)
        self.assertFalse(result['authorizing'])
        self.assertFalse(result['fact_truth_checked'])
        self.assertFalse(result['body_independent'])

    def test_missing_assumption_is_rejected(self):
        with self.assertRaisesRegex(BisimulationRefinementError, 'immediately preceding assertion'):
            self.check(self.models(consumer=consume(FACTS).replace('__CPROVER_assume(valid);', '')))

    def test_changed_guard_is_rejected(self):
        with self.assertRaisesRegex(BisimulationRefinementError, 'immediately preceding assertion'):
            self.check(self.models(consumer=consume(FACTS).replace('__CPROVER_assume(same);', '__CPROVER_assume(valid);')))

    def test_extra_assumption_is_not_part_of_qualification(self):
        with self.assertRaisesRegex(BisimulationRefinementError, 'more than the checked assumptions'):
            self.check(self.models(consumer=consume(FACTS).replace('\n}', '\n__CPROVER_assume(state.value < 5);\n}')))

    def test_changed_caller_requires_new_whole_program_qualification(self):
        with self.assertRaisesRegex(BisimulationRefinementError, 'more than the checked assumptions'):
            self.check(self.models(caller=CALLER.replace('before=state;', 'before=state; state.value++;')))

    def test_bypass_of_assertion_cannot_inherit_qualification(self):
        source = consume(FACTS).replace('__CPROVER_assert(same, "frame");',
            'if (same) goto skipped; __CPROVER_assert(same, "frame");').replace(
            '__CPROVER_assume(same);', 'skipped: __CPROVER_assume(same);')
        with self.assertRaises(BisimulationRefinementError):
            self.check(self.models(consumer=source))

    def test_volatile_guard_is_not_a_stable_snapshot(self):
        with self.assertRaisesRegex(BisimulationRefinementError, 'stable scalar expression'):
            self.check(self.models(original=FACTS.replace('unsigned same', 'volatile unsigned same')))


SUBSTITUTION = '''unsigned saved;
void facts(void) {
  unsigned local = state.value;
  __CPROVER_assert(local == saved, "value");
  state.value = local;
}
'''


class FactSubstitutionTests(unittest.TestCase):
    models = FactConsumptionTests.models

    def check(self, *, original=SUBSTITUTION, consumer=None, caller=CALLER):
        if consumer is None:
            consumer = original.replace('"value");', '"value"); local = saved;')
        return check_compiled_fact_substitution(
            **self.models(original=original, consumer=consumer, caller=caller), function='facts', description='value')

    def test_equal_scalar_can_replace_the_computed_value(self):
        result = self.check()
        self.assertEqual(result['status'], 'matched-same-program-scalar-substitution')
        self.assertFalse(result['fact_truth_checked'])
        self.assertFalse(result['query_domain_checked'])
        self.assertFalse(result['authorizing'])
        self.assertFalse(result['body_independent'])

    def test_wrong_value_is_rejected(self):
        with self.assertRaisesRegex(BisimulationRefinementError, 'adjacent equality-preserving assignment'):
            self.check(consumer=SUBSTITUTION.replace('"value");', '"value"); local = 0;'))

    def test_intervening_state_change_is_rejected(self):
        with self.assertRaisesRegex(BisimulationRefinementError, 'adjacent equality-preserving assignment'):
            self.check(consumer=SUBSTITUTION.replace('"value");', '"value"); saved++; local = saved;'))

    def test_changed_caller_cannot_reuse_whole_program_fact(self):
        with self.assertRaisesRegex(BisimulationRefinementError, 'additional semantics'):
            self.check(caller=CALLER.replace('before=state;', 'before=state; state.value++;'))

    def test_volatile_read_is_rejected(self):
        with self.assertRaisesRegex(BisimulationRefinementError, 'stable scalar equality'):
            self.check(original=SUBSTITUTION.replace('unsigned saved;', 'volatile unsigned saved;'))

    def test_bypassed_equality_is_rejected(self):
        consumer = SUBSTITUTION.replace('__CPROVER_assert(local == saved, "value");',
            'if (saved) goto skip; __CPROVER_assert(local == saved, "value"); skip: local = saved;')
        with self.assertRaises(BisimulationRefinementError):
            self.check(consumer=consumer)

    def test_global_assignment_is_outside_the_supported_rule(self):
        with self.assertRaisesRegex(BisimulationRefinementError, 'automatic local'):
            self.check(original=SUBSTITUTION.replace('unsigned local = state.value;', 'saved = state.value;')
                       .replace('local == saved', 'saved == saved').replace('state.value = local;', 'state.value = saved;'),
                       consumer=SUBSTITUTION.replace('unsigned local = state.value;', 'saved = state.value;')
                       .replace('local == saved', 'saved == saved').replace('state.value = local;', 'state.value = saved;')
                       .replace('"value");', '"value"); saved = saved;'))
