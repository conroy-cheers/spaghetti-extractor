"""Hand-defined real cleanup regions stay distinct from correctness and activation."""
import contextlib
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.cli import main
from spaghetti_extractor.components.bisimulation_source_call_check import (
    checked_source_call_regions, checked_source_region_graphs,
)
from .test_source_call_regions import check, FIXTURE

TESTKIT = {'fixtures': ('compiler', 'cbmc'), 'commands': ('component check',),
           'resources': ('tests/fixtures/metapad-authored-call',)}
BOUNDARY = {'operation_id': 'cleanup', 'source': 'cleanup.c',
    'entry': {'position': 'after', 'text': '  for (;;) {\n'},
    'exits': {
        'copy': {'position': 'after', 'text': '    else {\n'},
        'advance': {'position': 'before', 'text': '    ++input;\n  }\n'},
        'tail': {'position': 'before', 'text': '  for (uint32_t k = 0; k < 2U; ++k) {\n    if (spx_view_read_u8(text, input, &a)) return UINT32_MAX;\n'},
    }, 'regions': ['entry', 'copy', 'advance']}


class SourceRegionGraphTests(unittest.TestCase):
    def test_shared_operation_graph_exposes_reachable_coverage_holes(self):
        boundary=json.loads((FIXTURE/'cleanup-regions.json').read_text())
        for omit_tail in [False,True]:
            with self.subTest(omit_tail=omit_tail),tempfile.TemporaryDirectory() as directory:
                selected=deepcopy(boundary)
                if omit_tail:
                    selected['regions'].remove('tail_iteration')
                status,feedback,_=check(Path(directory),boundary=selected,graph=True)
                self.assertEqual(status['status'],'complete',feedback)
                graph=feedback['source_region_graphs']['regions'][0]['projection']
                self.assertGreater(graph['reachable_instruction_count'],0)
                self.assertGreater(graph['uncovered_instruction_count'],0)
                self.assertEqual(graph['uncovered_reachable_instruction_count']>0,omit_tail)
                self.assertFalse(graph['functional_correctness_checked'])
                self.assertFalse(graph['whole_component_complete'])

    def test_marker_names_do_not_depend_on_json_object_key_order(self):
        from spaghetti_extractor.components.bisimulation_source_edit_check import _marked_source
        source=(FIXTURE/'cleanup.c').read_text()
        reordered={**BOUNDARY,'exits':dict(reversed(list(BOUNDARY['exits'].items())))}
        self.assertEqual(_marked_source(source,BOUNDARY),_marked_source(source,reordered))

    def test_actual_loop_graph_is_public_but_not_a_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            status, feedback, _ = check(root, boundary=BOUNDARY, graph=True)
            self.assertEqual(status['status'], 'complete', feedback)
            result = feedback['source_region_graphs']
            with patch('subprocess.run', side_effect=AssertionError('import cannot execute tools')):
                graph, = checked_source_region_graphs(result, artifacts=root/'regions')
            self.assertEqual({(e['source'], e['target']) for e in graph['edges']}, {
                ('entry', 'copy'), ('entry', 'advance'), ('entry', 'tail'),
                ('copy', 'advance'), ('advance', 'entry')})
            self.assertEqual(graph['unselected_cut_regions'], ['tail'])
            self.assertTrue(all(not r['external_interior_entries'] for r in graph['regions']))
            self.assertFalse(graph['whole_component_complete'])
            self.assertFalse(graph['state_transport_checked'])
            self.assertFalse(graph['progress_checked'])
            self.assertTrue(any(r['calls'] for r in graph['regions']))
            self.assertTrue(all(not c['contract_checked'] for r in graph['regions'] for c in r['calls']))
            output = io.StringIO()
            with patch('spaghetti_extractor.commands.workflows._operator_index', return_value={
                'components': {'units': {'text-cleanup': {'products': ['sourceCheck']}}}}), patch(
                'spaghetti_extractor.commands.workflows._realize_artifact', return_value=(root/'feedback/source-check.json', status)), contextlib.redirect_stdout(output):
                code = main(['component', 'check', 'metapad', 'text-cleanup', '--source', '--json'])
            self.assertEqual(code, 0)
            self.assertIn('source_region_graphs', json.loads(output.getvalue()))
            changed = deepcopy(result)
            changed['regions'][0]['projection']['edges'] = []
            changed['receipt_sha256'] = canonical_sha256_v3({k: v for k, v in changed.items() if k != 'receipt_sha256'})
            with self.assertRaisesRegex(ValueError, 'compiled projection differs'):
                checked_source_region_graphs(changed, artifacts=root/'regions')
            with self.assertRaisesRegex(ValueError, 'incomplete, stale or authorizing'):
                checked_source_call_regions(result, artifacts=root/'regions')

    def test_local_body_edit_preserves_neighbor_region_semantic_bindings(self):
        source = (FIXTURE/'cleanup.c').read_text()
        old = '      if (spx_view_write_u8(&scratch, output, a)) return UINT32_MAX;\n      ++output;'
        self.assertEqual(source.count(old), 1)
        signatures = []
        for text in [source, source.replace(old, old.replace('output, a)', 'output, a+1U)'))]:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                status, feedback, _ = check(root, text, boundary=BOUNDARY, graph=True)
                self.assertEqual(status['status'], 'complete', feedback)
                graph, = checked_source_region_graphs(feedback['source_region_graphs'], artifacts=root/'regions')
                signatures.append({r['entry']: r['semantic_sha256'] for r in graph['regions']})
        self.assertNotEqual(signatures[0]['copy'], signatures[1]['copy'])
        self.assertEqual(signatures[0]['entry'], signatures[1]['entry'])
        self.assertEqual(signatures[0]['advance'], signatures[1]['advance'])

    def test_uncut_cycle_fails_with_a_boundary_diagnostic(self):
        boundary = deepcopy(BOUNDARY)
        boundary['entry']['position'] = 'before'
        boundary['exits'] = {'tail': boundary['exits']['tail']}
        boundary['regions'] = ['entry']
        with tempfile.TemporaryDirectory() as directory:
            status, feedback, _ = check(Path(directory), boundary=boundary, graph=True)
            self.assertEqual(status['status'], 'incomplete')
            row, = feedback['source_region_graphs']['checks']
            self.assertEqual(row['code'], 'source_region_graph_unsupported')
            self.assertIn('internal cycle requires another manual cut', row['detail'])

    def test_indirect_service_invocation_remains_an_unqualified_dependency(self):
        boundary = json.loads((FIXTURE/'boundary.json').read_text())
        boundary['regions'] = ['entry']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            status, feedback, _ = check(root, boundary=boundary, graph=True)
            self.assertEqual(status['status'], 'complete', feedback)
            graph, = checked_source_region_graphs(feedback['source_region_graphs'], artifacts=root/'regions')
            call, = graph['regions'][0]['calls']
            self.assertIsNone(call['direct_callee'])
            self.assertFalse(call['contract_checked'])
