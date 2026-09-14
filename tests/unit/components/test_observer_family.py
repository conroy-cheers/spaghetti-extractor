"""Compiler-backed dependency and effect controls for observation boundaries."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tests.unit.components.observer_family import check_observer_family

TESTKIT = {'fixtures': ('cbmc', 'compiler')}

SOURCE = '''struct world { unsigned byte; } world;
unsigned fill, exposure, observed, hidden;
unsigned __CPROVER_uninterpreted_byte(unsigned);
static unsigned leaf(const struct world *w, unsigned address) {
  observed = 1u;
  if (w != 0 && exposure) return w->byte;
  return fill ^ __CPROVER_uninterpreted_byte(address);
}
unsigned root(unsigned address) { return leaf(&world, address); }
'''


class ObserverFamilyTests(unittest.TestCase):
    def check(self, source=SOURCE, readable=('world', 'fill', 'exposure')):
        if not all(shutil.which(t) for t in ('goto-cc', 'goto-instrument')):
            self.skipTest('compiler fixtures unavailable')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            file, model = path/'model.c', path/'model.goto'
            file.write_text(source)
            r = subprocess.run([shutil.which('goto-cc'), '--i386-win32', str(file), '-o', str(model)],
                               capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, r.stderr)
            inputs = {}
            for name, flag, field in [('functions', '--show-goto-functions', 'functions'),
                                      ('symbols', '--show-symbol-table', 'symbolTable')]:
                r = subprocess.run([shutil.which('goto-instrument'), flag, '--json-ui', str(model)],
                                   capture_output=True, text=True, timeout=30)
                self.assertEqual(r.returncode, 0, r.stderr)
                rows = [b[field] for b in json.loads(r.stdout) if field in b]
                self.assertEqual(len(rows), 1)
                inputs[name] = {row['name']: row for row in rows[0]} if name == 'functions' else rows[0]
        return check_observer_family(**inputs, root='root', readable_globals=readable, observation_bit='observed')

    def test_pointer_reads_are_rooted_in_declared_storage(self):
        result = self.check()
        self.assertEqual(result['status'], 'checked-closed-observer-family')
        self.assertEqual(result['observed_global_reads'], ['exposure', 'fill', 'world'])
        self.assertEqual(result['mathematical_oracles'], ['__CPROVER_uninterpreted_byte'])
        self.assertEqual(set(result['bodies_sha256']), {'root', 'leaf'})
        self.assertFalse(result['authorizing'])
        self.assertFalse(result['safety_checked'])
        self.assertFalse(result['summary_consumption_checked'])

    def test_omitted_exposure_dependency_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'undeclared readable global: exposure'):
            self.check(readable=('world', 'fill'))

    def test_new_hidden_global_requires_a_contract_change(self):
        with self.assertRaisesRegex(ValueError, 'undeclared readable global: hidden'):
            self.check(SOURCE.replace('return fill ^', 'return hidden ^ fill ^'))

    def test_effect_cannot_become_an_undeclared_input(self):
        with self.assertRaisesRegex(ValueError, 'undeclared readable global: observed'):
            self.check(SOURCE.replace('observed = 1u;', 'if (observed) return 9u; observed = 1u;'))

    def test_mutating_readable_memory_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'write escapes automatic storage'):
            self.check(SOURCE.replace('observed = 1u;', 'world.byte++; observed = 1u;'))

    def test_effect_must_be_set_to_one(self):
        with self.assertRaisesRegex(ValueError, 'effect must set the bit to one'):
            self.check(SOURCE.replace('observed = 1u;', 'observed = 0u;'))

    def test_reconstructed_address_is_not_heap_correspondence(self):
        with self.assertRaisesRegex(ValueError, 'provenance|pointer reconstruction'):
            self.check(SOURCE.replace('return w->byte;', 'return ((const struct world *)address)->byte;'))

    def test_pointer_identity_cannot_hide_in_the_value(self):
        with self.assertRaisesRegex(ValueError, 'pointer identity'):
            self.check(SOURCE.replace('return w->byte;', 'return (unsigned)w;'))

    def test_unknown_callback_requires_a_separate_boundary(self):
        with self.assertRaisesRegex(ValueError, 'indirect or external call'):
            self.check(SOURCE.replace('unsigned root(unsigned address)', 'unsigned (*callback)(unsigned);\nunsigned root(unsigned address)')
                       .replace('return leaf(&world, address);', 'return callback(address);'))

    def test_loop_requires_a_progress_rule(self):
        with self.assertRaisesRegex(ValueError, 'backward control'):
            self.check(SOURCE.replace('observed = 1u;', 'while (address) address--; observed = 1u;'))

    def test_volatile_input_is_not_stable(self):
        with self.assertRaisesRegex(ValueError, 'nonvolatile|stable global'):
            self.check(SOURCE.replace('} world;', '}; volatile struct world world;'))

    def test_embedded_heap_pointer_is_not_a_copied_memory_value(self):
        with self.assertRaisesRegex(ValueError, 'pointer-free'):
            self.check(SOURCE.replace('unsigned byte;', 'unsigned byte; unsigned *heap;'))
