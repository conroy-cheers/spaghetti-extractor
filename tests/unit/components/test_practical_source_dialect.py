"""Compiled storage admits immutable tables without weakening formal eligibility."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.components.source_profile import check_component_source_profile
from spaghetti_extractor.components.source_dialect import inspect_object_storage, practical_source_profile

TESTKIT = {'fixtures': ('compiler',)}


class PracticalDialectTests(unittest.TestCase):
    def profile(self, text):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root/'table.c'; source.write_text(text)
            build_component_source_package(lift_unit_id='table', files={'table.c':source}, shared_inputs={},
                                           operation_symbols={'run':'run'}, out_dir=root/'source')
            proof = check_component_source_profile(package=root/'source')
            compiler = Path(shutil.which('cc'))
            subprocess.run([str(compiler), '-std=c11', '-c', str(source), '-o', str(root/'table.o')], check=True, capture_output=True)
            storage = inspect_object_storage(compiler, root/'table.o')
            return proof, practical_source_profile(proof, [dict(storage, source='table.c')])

    def test_static_descriptors_and_function_local_const_keep_lifetime(self):
        proof, practical = self.profile('''
typedef struct { const char *name; int size; } Description;
static const Description descriptions[] = {{"first", 1}, {"second", 2}};
const Description *run(unsigned index) {
    static const Description invalid = {"invalid", -1};
    return index < 2 ? &descriptions[index] : &invalid;
}
''')
        self.assertEqual(proof['status'], 'incomplete')
        self.assertEqual(practical['status'], 'satisfied', practical)
        self.assertEqual(practical['proof_profile'], proof)

    def test_const_pointee_does_not_make_pointer_storage_immutable(self):
        proof, practical = self.profile('const char *name = "first"; const char *run(void) { return name; }')
        self.assertEqual(practical['status'], 'incomplete', practical)
        _, fixed = self.profile('const char *const name = "first"; const char *run(void) { return name; }')
        self.assertEqual(fixed['status'], 'satisfied', fixed)

    def test_inactive_code_and_macros_do_not_impose_formal_syntax(self):
        proof, practical = self.profile('''
#define VALUE(x) ((x) + 1)
#if 0
void *malloc(unsigned long);
#endif
int run(int x) { return VALUE(x); }
''')
        self.assertEqual(proof['status'], 'incomplete')
        self.assertEqual(practical['status'], 'satisfied')
        self.assertEqual(practical_source_profile(proof)['status'], 'pending-storage')
        self.assertEqual(practical_source_profile(proof, [])['status'], 'incomplete')

    def test_compiled_macro_storage_is_always_inspected(self):
        _, practical = self.profile('''
#define DECLARE_COUNTER(name) static int name;
DECLARE_COUNTER(counter)
int run(void) { return ++counter; }
''')
        self.assertEqual(practical['status'], 'incomplete')
        self.assertIn('counter', practical['issues'][0]['diagnostic'])
