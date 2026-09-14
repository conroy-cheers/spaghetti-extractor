"""Cut observers must receive the actual live locals without changing the body."""

import unittest

from tests.unit.components.source_region_transport import check_source_region_observer_transport
from tests.unit.components import test_source_region_transport as transport_fixture

TESTKIT = {'fixtures': ('cbmc', 'compiler')}

OBSERVER = '''static void observe(uint32_t cut, uint32_t input, const uint8_t *a) {
  __CPROVER_assert(cut == 3U || cut == 6U, "known-cut");
  __CPROVER_assert(input == spx_cut.input && a != 0, "live-arguments");
}
'''
OBSERVED = transport_fixture.LOCAL.replace('#define BEGIN', OBSERVER+'#define BEGIN').replace(
    '"source-cut-invariant:next");', '"source-cut-invariant:next"); observe(3U,input,&a);').replace(
    '"source-cut-invariant:tail");', '"source-cut-invariant:tail"); observe(6U,input,&a);')


class SourceRegionObserverTests(unittest.TestCase):
    inventories = transport_fixture.SourceRegionTransportTests.inventories

    def check(self, local=OBSERVED):
        return check_source_region_observer_transport(**self.inventories(local=local), function='run',
            entry_sync='entry', restored_locals={'run::1::input': 'input', 'run::1::a': 'a'},
            cut_results={'next': 3, 'tail': 6}, observer='observe',
            observer_arguments=[('run::1::input', False), ('run::1::a', True)])

    def test_live_arguments_and_original_body_are_checked(self):
        result = self.check()
        self.assertTrue(result['local_cut_observer_arguments_checked'])
        self.assertEqual({r['cut'] for r in result['observer_calls']}, {'next', 'tail'})
        self.assertFalse(result['observer_predicates_checked'])
        self.assertFalse(result['input_harness_domain_checked'])
        self.assertFalse(result['paired_cut_observer_transport_checked'])
        self.assertFalse(result['authorizing'])

    def test_wrong_cut_argument_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'ordinal or arity'):
            self.check(OBSERVED.replace('observe(3U,input,&a)', 'observe(6U,input,&a)'))

    def test_changed_scalar_is_not_the_live_local(self):
        with self.assertRaisesRegex(ValueError, 'different local'):
            self.check(OBSERVED.replace('observe(3U,input,&a)', 'observe(3U,input+1U,&a)'))

    def test_pointer_reconstruction_is_not_the_local_address(self):
        with self.assertRaisesRegex(ValueError, 'live automatic address'):
            self.check(OBSERVED.replace('observe(3U,input,&a)', 'observe(3U,input,&a+1)'))

    def test_observer_cannot_assume_away_a_failed_comparison(self):
        with self.assertRaisesRegex(ValueError, 'only assertions'):
            self.check(OBSERVED.replace('  __CPROVER_assert(cut', '  __CPROVER_assume(0);\n  __CPROVER_assert(cut'))

    def test_observer_cannot_change_state(self):
        with self.assertRaisesRegex(ValueError, 'only assertions'):
            self.check(OBSERVED.replace('  __CPROVER_assert(cut', '  spx_cut.input++;\n  __CPROVER_assert(cut'))

    def test_each_successor_requires_its_own_observer(self):
        with self.assertRaisesRegex(ValueError, 'missing cut observer'):
            self.check(OBSERVED.replace(' observe(6U,input,&a);', ''))

    def parameter_check(self, *, changed=False, admitted=('run::value',)):
        observed = OBSERVED.replace('const uint8_t *a)', 'const uint8_t *a, int value)').replace(
            'observe(3U,input,&a)', 'observe(3U,input,&a,' + ('value+1' if changed else 'value') + ')').replace(
            'observe(6U,input,&a)', 'observe(6U,input,&a,value)')
        return check_source_region_observer_transport(**self.inventories(local=observed), function='run',
            entry_sync='entry', restored_locals={'run::1::input': 'input', 'run::1::a': 'a'},
            cut_results={'next': 3, 'tail': 6}, observer='observe',
            observer_arguments=[('run::1::input', False), ('run::1::a', True), ('run::value', False)],
            parameter_arguments=admitted)

    def test_parameter_value_is_explicitly_transported(self):
        result = self.parameter_check()
        self.assertEqual(result['parameter_capture_arguments'], ['run::value'])
        self.assertFalse(result['observer_predicates_checked'])

    def test_parameter_expression_cannot_replace_its_live_value(self):
        with self.assertRaisesRegex(ValueError, 'different local'):
            self.parameter_check(changed=True)

    def test_undeclared_parameter_capture_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'not a selected automatic'):
            self.parameter_check(admitted=())

    def test_unknown_parameter_capture_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'unknown or duplicate parameter capture'):
            self.parameter_check(admitted=('run::missing',))

    def test_declared_parameter_without_an_observer_argument_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'parameter capture inventory differs'):
            check_source_region_observer_transport(**self.inventories(local=OBSERVED), function='run',
                entry_sync='entry', restored_locals={'run::1::input': 'input', 'run::1::a': 'a'},
                cut_results={'next': 3, 'tail': 6}, observer='observe',
                observer_arguments=[('run::1::input', False), ('run::1::a', True)], parameter_arguments=['run::value'])

    def scalar_check(self, source, local_source=None):
        return transport_fixture.SourceRegionTransportTests.check(self,
            self.inventories(original_body=source, body=local_source or source))

    def test_private_local_scope_renaming_preserves_the_refactor(self):
        source = transport_fixture.BODY.replace('if (!a) break;',
            'int has_byte = a != 0U; if (!has_byte) break;')
        relation = self.scalar_check(source)
        self.assertEqual(len(relation['private_scalar_renaming']), 1)

    def test_renamed_local_type_change_is_rejected(self):
        source = transport_fixture.BODY.replace('if (!a) break;',
            'int has_byte = a != 0U; if (!has_byte) break;')
        with self.assertRaisesRegex(ValueError, 'renamed local storage differs'):
            self.scalar_check(source, source.replace('int has_byte', 'unsigned int has_byte'))

    def test_renamed_local_changed_value_is_rejected(self):
        source = transport_fixture.BODY.replace('if (!a) break;',
            'int has_byte = a != 0U; if (!has_byte) break;')
        with self.assertRaisesRegex(ValueError, 'body instruction differs'):
            self.scalar_check(source, source.replace('a != 0U', 'a == 0U'))

    def test_renamed_local_address_requires_a_storage_relation(self):
        source = transport_fixture.BODY.replace('if (!a) break;',
            'int has_byte = a != 0U; int *pointer = &has_byte; if (!*pointer) break;')
        with self.assertRaisesRegex(ValueError, 'exposes its address'):
            self.scalar_check(source)

    def test_renamed_local_static_storage_is_rejected(self):
        source = transport_fixture.BODY.replace('if (!a) break;',
            'static int has_byte; has_byte = a != 0U; if (!has_byte) break;')
        with self.assertRaisesRegex(ValueError, 'body instruction differs'):
            self.scalar_check(source)
