"""Tail edits must expose all public inputs and effects to the paired proof."""
from pathlib import Path
import tempfile
import unittest

from spaghetti_extractor.components.bisimulation_compaction_inputs import read_inventory
from spaghetti_extractor.components.bisimulation_source_call_check import checked_source_region_graphs
from .cleanup_tail_frame import BOUNDARY
from spaghetti_extractor.components.bisimulation_cleanup_frame import check_cleanup_tail_frame
from ..operator.test_source_call_regions import check as prepare, FIXTURE

TESTKIT = {'fixtures': ('compiler', 'cbmc'), 'resources': ('tests/fixtures/metapad-authored-call', 'tests/fixtures/metapad-cleanup-tail')}


def prepare_tail_frame(root, source):
    root = Path(root); root.mkdir()
    status, feedback, _ = prepare(root, source, boundary=BOUNDARY, graph=True)
    if status['status'] != 'complete':
        raise ValueError('tail preparation incomplete: ' + str(feedback))
    prepared = feedback['source_region_graphs']
    graph, = checked_source_region_graphs(prepared, artifacts=root/'feedback/source-region-graph-models')
    inventory = read_inventory(root/'feedback/source-region-graph-models/0000-marked')
    symbols = inventory['symbols']; function = graph['function']
    parameters = {symbols[name]['baseName']: name for name in inventory['functions'][function]['parameterIdentifiers']}
    scratch, = [name for name, row in symbols.items() if row.get('baseName') == 'scratch'
                and row.get('location', {}).get('function') == function and not row.get('isAuxiliary')]
    selected = {i for region in graph['regions'] for i in region['instruction_indices']}
    frame = check_cleanup_tail_frame(**inventory, function=function, instruction_indices=selected,
                                     parameters=parameters, scratch_local=scratch)
    return frame


class CleanupTailFrameTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(); self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name); self.source = (FIXTURE/'cleanup.c').read_text()
        self.anchor = '  if (removed) context->services->copy(context->services->context, text, &scratch);\n'
        self.assertEqual(self.source.count(self.anchor), 1)

    def check(self, name, source):
        return prepare_tail_frame(self.root/name, source)

    def test_actual_tail_has_only_declared_reads_and_five_services(self):
        frame = self.check('baseline', self.source)
        self.assertEqual([r['dependency'] for r in frame['calls']], [
            'spx_view_read_u8', 'spx_view_write_u8', 'copy', 'release', 'read:suppress_notice',
            'resource_text', 'read:main_window', 'message', 'read:edit_window', 'focus'])
        self.assertFalse(frame['coverage_checked'])
        self.assertFalse(frame['service_contracts_checked'])

    def test_unmodeled_public_fields_aliases_and_additional_services_reject(self):
        edits = {
            'context-input': '  removed += context->state.reserved;\n',
            'protocol-input': '  removed += context->protocol_state;\n',
            'context-write': '  context->state.reserved = 1U;\n',
            'view-metadata': '  removed += main_window->extent;\n',
            'pointer-alias': '  const spx_view_v5 *alias = text;\n  removed += alias->extent;\n',
            'extra-service': '  removed += context->services->length(context->services->context, text);\n',
        }
        for name, extra in edits.items():
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'cleanup tail frame:'):
                self.check(name, self.source.replace(self.anchor, extra+self.anchor))

    def test_mismatched_read_receiver_and_context_reject(self):
        changed = self.source.replace('suppress_notice->read(suppress_notice->access_context,',
                                      'suppress_notice->read(main_window->access_context,')
        with self.assertRaisesRegex(ValueError, 'read context or reference differs'):
            self.check('wrong-context', changed)

    def test_functional_reference_and_lifetime_errors_reach_the_paired_checker(self):
        release = '  context->services->release(context->services->context, scratch.base);\n'
        changes = {
            'wrong-resource': self.source.replace('context, 31U);', 'context, 32U);'),
            'wrong-reference': self.source.replace(release, '  scratch.base.generation += 1U;\n'+release),
            'after-release': self.source.replace(release, release+'  if (removed) spx_view_write_u8(&scratch, 0U, 0U);\n'),
            'result-sensitive': self.source.replace(release, '  removed += context->services->release(context->services->context, scratch.base);\n'),
        }
        for name, source in changes.items():
            with self.subTest(name=name):
                frame = self.check(name, source)
                self.assertEqual(frame['status'], 'checked-cleanup-tail-footprint')
                self.assertFalse(frame['runtime_compatibility_checked'])
