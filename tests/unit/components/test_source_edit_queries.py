"""Bounded query transport must retain exact scope and published process bytes."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.components.bisimulation_query_evidence import CbmcQueryEvidence
from spaghetti_extractor.components.bisimulation_source_edit_queries import (
    checked_bounded_query_scope, retained_bounded_queries,
)
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties

TESTKIT = {'fixtures': ('cbmc', 'compiler')}
ARGS = ['$GOTO_MODEL', '--function', 'check', '--json-ui', '--unwind', '3', '--no-unwinding-assertions',
        '--no-self-loops-to-assumptions', '--property', 'check.assertion.1']


class SourceEditQueryScopeTests(unittest.TestCase):
    def test_bounded_result_does_not_acquire_termination(self):
        scope = checked_bounded_query_scope(ARGS)
        self.assertEqual(scope['kind'], 'bounded-property-checks')
        self.assertEqual(scope['unwind'], 3)
        self.assertFalse(scope['termination_proved'])
        self.assertFalse(scope['unwinding_assertions'])

    def test_instruction_depth_and_partial_loop_shortcuts_are_rejected(self):
        for options in (['--depth', '100'], ['--partial-loops'], ['--no-assumptions'], ['--unwinding-assertions']):
            with self.subTest(options=options), self.assertRaisesRegex(ValueError, 'unsupported query option'):
                checked_bounded_query_scope([*ARGS, *options])

    def test_duplicate_and_thread_scoped_limits_are_rejected(self):
        for options in (['--unwind', '5'], ['--unwindset', '0:check.0:4'], ['--unwindset', 'check.0:4,check.0:5']):
            with self.subTest(options=options), self.assertRaises(ValueError):
                checked_bounded_query_scope([*ARGS, *options])


class RetainedSourceEditQueryTests(unittest.TestCase):
    def setUp(self):
        self.compiler, self.cbmc = [shutil.which(v) for v in ('goto-cc', 'cbmc')]
        if not all((self.compiler, self.cbmc)):
            self.skipTest('compiler/CBMC fixtures unavailable')
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.model = self.root / 'model.goto'
        source = self.root / 'source.c'
        source.write_text('void check(unsigned char a) { __CPROVER_assert(a < 256, "byte"); }\n')
        subprocess.run([self.compiler, '--i386-win32', str(source), '-o', str(self.model)], check=True, capture_output=True)
        cache = CbmcQueryEvidence(model=self.model, checker=self.cbmc, compiler=self.compiler,
            output=self.root / 'previous')
        result = run_cbmc_properties(command=[self.cbmc, str(self.model), *ARGS[1:]], timeout_seconds=10, query_evidence=cache)
        self.assertEqual(result['status'], 'satisfied')
        self.previous = {'directory': self.root / 'previous', 'outputs': {result['output_sha256']},
            'goto_model_sha256': hashlib.sha256(self.model.read_bytes()).hexdigest(),
            'checker': {'cbmc_sha256': cache.tools['checker_sha256'], 'goto_cc_sha256': cache.tools['compiler_sha256']},
            'assurance': None, 'proof_receipt_sha256': 'a' * 64}
        # The real integration uses checked_conditional_packet. Here the packet
        # validator is isolated so these controls exercise the process boundary.
        path = next((self.root / 'previous').glob('*/query.json'))
        record = json.loads(path.read_text())
        record['binding']['assurance'] = None
        from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
        path.write_text(json.dumps(record))
        path.parent.rename(path.parent.with_name(canonical_sha256_v3(record['binding'])))

    def read(self, previous=None, model=None):
        with patch('spaghetti_extractor.components.bisimulation_source_edit_queries.previous_proof_queries',
                   return_value={('operation', 'cut'): self.previous if previous is None else previous}):
            return retained_bounded_queries(evidence=self.root, operation_id='operation', obligation_id='cut',
                assurance=None, model=self.model if model is None else model, cbmc=self.cbmc, goto_cc=self.compiler,
                out=self.root / 'copied')

    def test_completed_process_is_reparsed_without_a_solver_run(self):
        with patch('spaghetti_extractor.components.bisimulation_query_evidence.run_cbmc_process',
                   side_effect=AssertionError('fresh solver forbidden')):
            rows = self.read()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['result']['status'], 'satisfied')
        self.assertEqual(rows[0]['scope']['kind'], 'bounded-property-checks')

    def test_unpublished_output_cannot_supply_evidence(self):
        previous = deepcopy(self.previous)
        previous['outputs'] = set()
        with self.assertRaisesRegex(ValueError, 'not bound by the previous'):
            self.read(previous)

    def test_corrupt_output_is_rejected(self):
        path = next((self.root / 'previous').glob('*/stdout'))
        path.write_text(path.read_text() + '\nchanged')
        with self.assertRaisesRegex(ValueError, 'retained bytes differ'):
            self.read()

    def test_rewriting_the_target_model_cannot_create_an_exact_cache_hit(self):
        edited = self.root / 'different.goto'
        edited.write_bytes(self.model.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'original query model'):
            self.read(model=edited)
