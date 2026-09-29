"""Conventional guards do not exempt authored header bodies from profile checks."""
from pathlib import Path
import tempfile
import unittest

from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.components.source_profile import check_component_source_profile

TESTKIT={'fixtures':()}


class HeaderProfileTests(unittest.TestCase):
    def check(self,header):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'body.c').write_text('#include "helper.h"\nint body(void) { return helper(); }\n')
            (root/'helper.h').write_text(header)
            build_component_source_package(lift_unit_id='header',files={name:root/name for name in ('body.c','helper.h')},
                shared_inputs={},operation_symbols={'run':'body'},out_dir=root/'source')
            return check_component_source_profile(package=root/'source')

    def test_guarded_inline_helper_is_accepted_with_comments(self):
        result=self.check('/* outer\ncomment */\n#ifndef HELPER_H /* guard */\n#define HELPER_H\n'
            'static inline int helper(void) { return 1; }\n#endif /* HELPER_H */\n')
        self.assertEqual(result['status'],'satisfied',result)

    def test_guard_does_not_hide_inner_conditionals_intrinsics_or_macros(self):
        cases=[('#if 1\n#endif\n','restricted_c_conditional_compilation'),
               ('#define DO(x) (x)\n','restricted_c_macro_definition'),
               ('static inline void bad(void) { __CPROVER_assume(0); }\n','restricted_c_cbmc_intrinsic')]
        for body,code in cases:
            with self.subTest(code=code):
                result=self.check('#ifndef H\n#define H\n'+body+'#endif\n')
                self.assertIn(code,[row['code'] for row in result['issues']])

    def test_nonmatching_and_partial_guards_remain_conditional_compilation(self):
        for text in ['#ifndef H\n#define OTHER\n#endif\n',
                     '#ifndef H\n#define H\n#endif\nint outside;\n',
                     '#ifndef H\n#define H 1\n#endif\n',
                     '#ifndef H\n#define H\n']:
            with self.subTest(text=text):
                self.assertIn('restricted_c_conditional_compilation',[row['code'] for row in self.check(text)['issues']])

    def test_compiler_and_proof_configuration_macros_are_not_header_guards(self):
        for name in ['__CPROVER__','__GNUC__','_WIN32','WIN32','linux','_STDINT_H']:
            with self.subTest(name=name):
                result=self.check(f'#ifndef {name}\n#define {name}\n'
                    '#undef UINT32_MAX\n#define UINT32_MAX 0\n#endif\n')
                self.assertEqual(result['status'],'incomplete')
                self.assertIn('restricted_c_conditional_compilation',[r['code'] for r in result['issues']])

    def test_record_declarations_are_allowed_but_header_storage_is_not(self):
        declarations='struct object;\nstruct record { struct object *pointer; unsigned int count; };\n'
        self.assertEqual(self.check(declarations)['status'],'satisfied')
        for storage,code in [('static unsigned int hidden;','restricted_c_hidden_storage'),
                             ('struct object *hidden;','restricted_c_hidden_storage'),
                             ('static inline int helper(void) { static int counter; return ++counter; }',
                              'restricted_c_hidden_static_storage')]:
            with self.subTest(storage=storage):
                self.assertIn(code,[r['code'] for r in self.check(declarations+storage)['issues']])
