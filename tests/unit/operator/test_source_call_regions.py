"""Real authored call boundaries through source feedback and compiled projection."""

import contextlib
import copy
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.cli import main
from spaghetti_extractor.components.bisimulation_source_call_check import checked_source_call_regions
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.operator.source_check import write_component_source_check

FIXTURE = Path(__file__).parents[2] / 'fixtures/metapad-authored-call'
TESTKIT = {'fixtures': ('compiler', 'cbmc'), 'commands': ('component check',),
           'resources': ('tests/fixtures/metapad-authored-call',)}


def check(root, text=None, *, boundary=None, graph=False):
    text = (FIXTURE/'cleanup.c').read_text() if text is None else text
    boundary = json.loads((FIXTURE/'boundary.json').read_text()) if boundary is None else boundary
    (root/'author.c').write_text(text)
    build_component_source_package(lift_unit_id='text-cleanup', files={'cleanup.c': root/'author.c'},
        shared_inputs={}, operation_symbols={'cleanup': 'cleanup'}, out_dir=root/'source')
    (root/'interface').mkdir()
    shutil.copyfile(FIXTURE/'component-interface-intent-v1.json', root/'interface/component-interface-intent-v1.json')
    timings = []
    status = write_component_source_check(target_id='metapad', component_id='text-cleanup',
        interface_package=root/'interface', source_package=root/'source', out=root/'feedback',
        host_compiler=Path(shutil.which('cc')), pe32_compiler=Path(shutil.which('cc')),
        region_goto_cc=Path(shutil.which('goto-cc')), timings=timings,
        **({'source_region_graphs': [boundary], 'graph_workspace': root/'regions'} if graph else
           {'source_call_regions': [boundary], 'region_workspace': root/'regions'}))
    return status, json.loads((root/'feedback/compiler-checks.json').read_text()), timings


class SourceCallRegionTests(unittest.TestCase):
    def test_actual_caller_binding_is_public_and_has_no_proof_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            status, feedback, timings = check(root)
            self.assertEqual(status['status'], 'complete', feedback)
            result = feedback['source_call_regions']
            with patch('subprocess.run', side_effect=AssertionError('binding import must not compile or solve')):
                projection, = checked_source_call_regions(result, artifacts=root/'feedback/source-call-region-models')
            self.assertEqual(projection['arguments'], [31])
            self.assertEqual(projection['service_id'], 'resource_text')
            self.assertEqual(projection['context_type'], 'spx_text_cleanup_context_v5')
            self.assertTrue(projection['result_local'].endswith('::message'))
            self.assertFalse(projection['functional_correctness_checked'])
            self.assertEqual(len(projection['instruction_indices']), 5)
            self.assertTrue({'compiler', 'model'} <= {row['phase'] for row in timings})
            output = io.StringIO()
            with patch('spaghetti_extractor.commands.workflows._operator_index', return_value={
                'components': {'units': {'text-cleanup': {'products': ['sourceCheck']}}}}), patch(
                'spaghetti_extractor.commands.workflows._realize_artifact', return_value=(root/'feedback/source-check.json', status)), contextlib.redirect_stdout(output):
                code = main(['component', 'check', 'metapad', 'text-cleanup', '--source', '--json'])
            self.assertEqual(code, 0)
            public = json.loads(output.getvalue())
            self.assertFalse(public['source_call_regions']['activation_authorized'])
            self.assertEqual(public['status']['counts']['authority_held'], 0)
            changed = copy.deepcopy(result)
            changed['regions'][0]['projection']['arguments'] = [32]
            changed['receipt_sha256'] = canonical_sha256_v3({k: v for k, v in changed.items() if k != 'receipt_sha256'})
            with self.assertRaisesRegex(ValueError, 'compiled projection differs'):
                checked_source_call_regions(changed, artifacts=root/'feedback/source-call-region-models')
            model = root/'feedback/source-call-region-models/0000-ordinary/model.goto'
            model.write_bytes(model.read_bytes()+b'stale')
            with self.assertRaisesRegex(ValueError, 'stale'):
                checked_source_call_regions(result, artifacts=root/'feedback/source-call-region-models')

    def test_changed_authored_argument_is_visible_but_needs_a_functional_proof(self):
        text = (FIXTURE/'cleanup.c').read_text().replace('context, 31U);', 'context, 30U);')
        boundary = json.loads((FIXTURE/'boundary.json').read_text())
        for anchor in [boundary['entry'], *boundary['exits'].values()]:
            anchor['text'] = anchor['text'].replace('31U', '30U')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            status, feedback, _ = check(root, text, boundary=boundary)
            self.assertEqual(status['status'], 'complete')
            projection, = checked_source_call_regions(feedback['source_call_regions'], artifacts=root/'regions')
            self.assertEqual(projection['arguments'], [30])
            self.assertFalse(projection['functional_correctness_checked'])

    def test_effects_and_branches_inside_the_boundary_cannot_disappear(self):
        baseline = (FIXTURE/'cleanup.c').read_text()
        boundary = json.loads((FIXTURE/'boundary.json').read_text())
        line = boundary['entry']['text']
        for extra in ('      ++removed;\n',
                      '      context->services->focus(context->services->context, 0U);\n',
                      '      if (removed) return removed;\n'):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as directory:
                changed = copy.deepcopy(boundary)
                # Keep the entry before the new effect and the exit after the call.
                changed['entry']['text'] = extra + line
                status, feedback, _ = check(Path(directory), baseline.replace(line, extra+line), boundary=changed)
                self.assertEqual(status['status'], 'incomplete', feedback)
                self.assertEqual(feedback['source_call_regions']['checks'][0]['code'], 'source_call_region_unsupported')
