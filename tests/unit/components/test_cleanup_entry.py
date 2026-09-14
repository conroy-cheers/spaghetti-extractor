"""Actual entry admission, allocation/copy errors and complete outgoing state."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from .cleanup_entry import SOURCE, prepare_entry, compile_entry, checked_entry_transport, check_entry_properties

TESTKIT = {'capabilities': ('cbmc',), 'fixtures': ('cbmc', 'compiler', 'z3'),
           'resources': ('tests/fixtures/metapad-cleanup-entry', 'tests/fixtures/metapad-authored-call')}


class CleanupEntryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.source = (SOURCE/'cleanup.c').read_text()

    def prove(self, name, source):
        root = self.root/name
        data = prepare_entry(root, body=source)
        local, _ = compile_entry(root)
        with patch('subprocess.run', side_effect=AssertionError('transport import must not execute tools')):
            transport = checked_entry_transport(data, local)
        self.assertEqual(transport['status'], 'matched-source-region-transport')
        self.assertFalse(transport['runtime_contracts_checked'])
        self.assertTrue(transport['local_cut_observer_arguments_checked'])
        return data, check_entry_properties(root)

    def test_actual_entry_reaches_the_loop_domain_with_complete_properties(self):
        data, result = self.prove('baseline', self.source)
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))
        self.assertGreater(result['properties'], 3400)
        self.assertEqual([r['dependency'] for r in data['footprint']['calls']],
                         ['length', 'allocate', 'length', 'spx_view_read_u8', 'spx_view_write_u8'])
        self.assertFalse(data['footprint']['service_contracts_checked'])

    def test_wrong_allocation_flags_reach_and_fail_the_invocation_proof(self):
        source = self.source.replace('context, 64U, length + 1U)', 'context, 0U, length + 1U)')
        self.assertNotEqual(source, self.source)
        _, result = self.prove('wrong-allocation', source)
        self.assertEqual(result['status'], 'violated', result.get('detail'))
        self.assertIn('entry-allocation-call', result['detail'])

    def test_wrong_short_input_copy_reaches_and_fails_the_memory_proof(self):
        old = 'spx_view_write_u8(&scratch, output, a)'
        source = self.source.replace(old, 'spx_view_write_u8(&scratch, output, a+1U)', 1)
        _, result = self.prove('wrong-copy', source)
        self.assertEqual(result['status'], 'violated', result.get('detail'))
        self.assertIn('entry-whole-post-memory', result['detail'])

    def test_equal_cursors_do_not_hide_a_changed_outgoing_view(self):
        source = self.source.replace('  uint8_t a, b, c;\n', '  uint8_t a, b, c;\n  scratch.element_width = 2U;\n')
        _, result = self.prove('wrong-view', source)
        self.assertEqual(result['status'], 'violated', result.get('detail'))
        self.assertIn('entry-full-view-element_width', result['detail'])

    def test_unmodeled_inputs_effects_and_predecessors_are_rejected_before_comparison(self):
        anchor = '  uint8_t a, b, c;\n'
        edits = {
            'context-read': '  output = context->state.reserved;\n',
            'context-write': '  context->state.reserved = 1U;\n',
            'other-parameter': '  output = suppress_notice->extent;\n',
            'other-service': '  context->services->focus(context->services->context, 0U);\n',
            'pointer-alias': '  const spx_view_v5 *other = text;\n  output = other->extent;\n',
        }
        for name, extra in edits.items():
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'fresh buffer entry frame:'):
                prepare_entry(self.root/name, body=self.source.replace(anchor, anchor+extra))
        first = '  uint32_t length = context->services->length(context->services->context, text);\n'
        with self.assertRaisesRegex(ValueError, 'unproved predecessor'):
            prepare_entry(self.root/'predecessor', body=self.source.replace(first, '  context->state.reserved = 1U;\n'+first))

    def test_unsigned_high_length_and_short_input_branches_remain_real_source_logic(self):
        # The signed original comparison also covers lengths above INT32_MAX;
        # nullable allocation keeps that real case in the admitted PE32 domain.
        changed = self.source.replace('length < 3U || length >= 2147483648U', 'length < 3U')
        data, result = self.prove('changed-branch', changed)
        self.assertEqual(data['footprint']['status'], 'checked-fresh-buffer-entry-footprint')
        self.assertEqual(result['status'], 'violated', result.get('detail'))
        self.assertIn('entry-fault-correspondence', result['detail'])
