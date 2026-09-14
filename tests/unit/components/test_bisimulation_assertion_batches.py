"""Bounded assertion groups preserve complete coverage and exact input worlds."""

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.components.bisimulation_diagnostics import ProofQueryTimings
from spaghetti_extractor.components.bisimulation_execution import (
    _assertion_query_batches, _run_assertion_query, _run_partitioned_properties,
    property_checker_command,
)
from spaghetti_extractor.components.bisimulation_support import (
    ASSERTION_BATCH_STRATEGY, ASSERTION_SINGLE_STRATEGY, PACKED_SAFETY_STRATEGY, APPLICATION_FIRST_STRATEGY, assertion_policy_option,
    CUT_CONTROL_FIRST_STRATEGY, authored_query_ids, property_query_order,
)
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.bisimulation_refinement import check_bisimulation_refinement
from spaghetti_extractor.components.contextual_bisimulation import (
    build_contextual_refinement_v2, validate_contextual_refinement_v2,
)
from tests.unit.components import test_bisimulation_normal_exits as fixture

TESTKIT = {'fixtures': ('cbmc', 'compiler', 'jq'),
           'resources': ('nix/jq/strong-contextual-proof.jq',)}


class AssertionBatchTests(unittest.TestCase):
    def reader(self, evidence, expression='spx_selected_authored_queries'):
        module = Path(__file__).resolve().parents[3] / TESTKIT['resources'][0]
        result = subprocess.run([shutil.which('jq'), '-e', module.read_text() + '\n' + expression],
            input=json.dumps(evidence), text=True, capture_output=True, timeout=10)
        self.assertIn(result.returncode, (0, 1), result.stderr)
        return result.returncode == 0

    def test_groups_preserve_order_owner_entry_and_instrumentation(self):
        assertions, queries = [], []
        for i in range(12):
            identity = f'body.assertion.{i}'
            entry = 'entry' if i < 8 else 'focused'
            owner = 'body' if i < 7 else 'helper'
            command = ['cbmc', 'model.goto', '--function', entry, '--property', identity,
                       '--unwinding-assertions' if i < 10 else '--no-unwinding-assertions']
            assertions.append({'property_id': identity, 'source_function': owner})
            queries.append(('authored_assertion', identity, entry, command))
        groups = _assertion_query_batches(queries, assertions, enabled=True)
        self.assertEqual([len(row[1]) for row in groups], [1, 4, 2, 1, 2, 2])
        self.assertEqual([identity for row in groups for identity in row[1]],
                         [row[1] for row in queries])
        for _, identities, entry, command in groups:
            self.assertEqual(command[command.index('--function') + 1], entry)
            self.assertEqual([command[i+1] for i, arg in enumerate(command) if arg == '--property'], identities)
        legacy = _assertion_query_batches(queries, assertions, enabled=False)
        self.assertTrue(all(len(row[1]) == 1 for row in legacy))
        self.assertEqual([row[3] for row in legacy], [row[3] for row in queries])

    def test_application_first_order_is_versioned_and_keeps_all_state_checks(self):
        pairs = [
            ('cleanup.assertion.1', 'capture-metadata:loop:caption'),
            ('cleanup.assertion.2', 'capture-reference-memory:loop:scratch'),
            ('proof.assertion.1', 'exit-control:run:proof'),
            ('proof.assertion.2', 'exit-value:run:proof'),
            ('proof.assertion.3', 'exit-world-memory:run:proof'),
            ('proof.assertion.4', 'exit-world-calls:run:proof'),
            ('proof.assertion.5', 'unrelated-frame:run:proof'),
        ]
        assertions = [{'property_id': identity, 'description': 'spx-bisimulation-' + description,
                       'source_function': identity.split('.')[0], 'entry_function': 'proof'}
                      for identity, description in pairs]
        for strategy in (ASSERTION_SINGLE_STRATEGY, ASSERTION_BATCH_STRATEGY,
                         PACKED_SAFETY_STRATEGY, APPLICATION_FIRST_STRATEGY):
            ordered = sorted(assertions, key=lambda row: property_query_order(row, strategy=strategy))
            first = 'proof.assertion.1' if strategy == APPLICATION_FIRST_STRATEGY else 'cleanup.assertion.1'
            self.assertEqual(ordered[0]['property_id'], first)
            queries = []
            for row in ordered:
                query = {'kind': 'authored_assertion', 'entry_function': 'proof', 'status': 'satisfied',
                         'code': 'cbmc_properties_satisfied', 'properties': 1, 'output_sha256': 'a' * 64}
                query.update({'property_id': row['property_id']} if strategy == ASSERTION_SINGLE_STRATEGY
                             else {'property_ids': [row['property_id']]})
                queries.append(query)
            evidence = {'strategy': strategy, 'assertions': assertions, 'queries': queries}
            self.assertTrue(self.reader(evidence))
            if strategy == APPLICATION_FIRST_STRATEGY:
                self.assertEqual([row['property_id'] for row in ordered],
                    ['proof.assertion.1', 'proof.assertion.2', 'proof.assertion.3', 'proof.assertion.4',
                     'cleanup.assertion.2', 'cleanup.assertion.1', 'proof.assertion.5'])
                for mutation in ('drop_memory', 'drop_metadata', 'old_order'):
                    changed = copy.deepcopy(evidence)
                    if mutation == 'old_order':
                        changed['queries'][0], changed['queries'][5] = changed['queries'][5], changed['queries'][0]
                    else:
                        changed['queries'].pop(4 if mutation == 'drop_memory' else 5)
                    self.assertFalse(self.reader(changed), mutation)
        ordinary = property_checker_command([])
        preferred = property_checker_command([], application_first=True)
        self.assertEqual(preferred, {**ordinary, 'strategy': CUT_CONTROL_FIRST_STRATEGY})

    def test_cut_failure_precedes_exit_timeout_without_changing_legacy_order(self):
        for strategy in (APPLICATION_FIRST_STRATEGY, CUT_CONTROL_FIRST_STRATEGY):
            for wrong in (False, True):
                with self.subTest(strategy=strategy, wrong=wrong), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    source, model = root / 'source.c', root / 'model.goto'
                    source.write_text('void proof(void) { unsigned x; __CPROVER_havoc_object(&x); '
                        '__CPROVER_assume(x<10); unsigned values[10]={0}; values[x]=x; '
                        '__CPROVER_assert(' + ('x<9' if wrong else 'x<10') +
                        ',"spx-bisimulation-sync-alignment:next"); '
                        '__CPROVER_assert(x<10,"spx-bisimulation-exit-control:run:proof"); }')
                    subprocess.run([shutil.which('goto-cc'), str(source), '-o', str(model)],
                        check=True, capture_output=True, text=True, timeout=30)
                    exit_queries = []
                    def execute(**kwargs):
                        command = kwargs['command']
                        if '--no-assertions' not in command and 'proof.assertion.2' in command:
                            exit_queries.append(command)
                            return {'status': 'incomplete', 'code': 'cbmc_timeout',
                                    'detail': 'controlled exit timeout', 'output_sha256': 'b' * 64}
                        return run_cbmc_properties(**kwargs)
                    with patch('spaghetti_extractor.components.bisimulation_execution.run_cbmc_properties', execute):
                        result = _run_partitioned_properties(cbmc=Path(shutil.which('cbmc')), goto_model=model,
                            command={**property_checker_command([], application_first=True), 'strategy': strategy},
                            proof_function='proof',
                            required_assertion_descriptions=['spx-bisimulation-sync-alignment:next'],
                            timeout_seconds=30)
                    detected = wrong and strategy == CUT_CONTROL_FIRST_STRATEGY
                    self.assertEqual(result['status'], 'violated' if detected else 'incomplete')
                    self.assertEqual(len(exit_queries), 0 if detected else 1)
                    if detected:
                        self.assertIn('sync-alignment:next', result['detail'])
                    evidence = result['partitioned_evidence']
                    self.assertTrue(self.reader(evidence))
                    mismatched = copy.deepcopy(evidence)
                    mismatched['strategy'] = (APPLICATION_FIRST_STRATEGY
                        if strategy == CUT_CONTROL_FIRST_STRATEGY else CUT_CONTROL_FIRST_STRATEGY)
                    self.assertFalse(self.reader(mismatched))
                    if not wrong and strategy == CUT_CONTROL_FIRST_STRATEGY:
                        omitted = copy.deepcopy(evidence)
                        omitted['queries'] = [q for q in omitted['queries']
                            if q['kind'] != 'authored_assertion' or 'proof.assertion.1' not in q['property_ids']]
                        self.assertFalse(self.reader(omitted))

    def test_exhausted_groups_split_with_every_attempt_retained(self):
        identities = [f'body.assertion.{i}' for i in range(4)]
        for failure in ({'status': 'incomplete', 'code': 'cbmc_timeout'},
                        {'status': 'incomplete', 'code': 'cbmc_failed', 'detail': 'std::bad_alloc'}):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                model = Path(temporary) / 'model.goto'
                model.write_bytes(b'exact compiled input')
                base = ['cbmc', str(model), '--function', 'paired', '--no-standard-checks']
                command = base + [arg for identity in identities for arg in ('--property', identity)]
                def execute(*, command, timeout_seconds):
                    self.assertEqual(command[:len(base)], base)
                    self.assertEqual(timeout_seconds, 20)
                    selected = command[len(base)+1::2]
                    return failure if len(selected) > 1 else {
                        'status': 'satisfied', 'property_ids': selected, 'output_sha256': 'a' * 64}
                timings = ProofQueryTimings(model, {'operation_id': 'run'})
                with patch('spaghetti_extractor.components.bisimulation_execution.run_cbmc_properties', execute):
                    completed = _run_assertion_query(('authored_assertion', identities, 'paired', command),
                        timings=timings, timeout_seconds=20)
                self.assertEqual([identity for query, _ in completed for identity in query[1]], identities)
                attempts = [json.loads(line) for line in timings.path.read_text().splitlines()]
                self.assertEqual(len(attempts), 7)
                self.assertEqual(sum(row['status'] == 'incomplete' for row in attempts), 3)
                self.assertEqual(len({row['goto_model_sha256'] for row in attempts}), 1)
                self.assertEqual(len({tuple(row['command']) for row in attempts}), 7)
        for failure in ({'status': 'violated', 'code': 'cbmc_property_failed'},
                        {'status': 'incomplete', 'code': 'cbmc_parse_failed'}):
            with patch('spaghetti_extractor.components.bisimulation_execution.run_cbmc_properties',
                       return_value=failure) as execute:
                completed = _run_assertion_query(('authored_assertion', identities, 'paired', command),
                    timings=None, timeout_seconds=20)
            self.assertEqual(execute.call_count, 1)
            self.assertEqual(completed[0][1], failure)

    def test_receipts_reject_missing_duplicate_foreign_or_cross_world_properties(self):
        assertions = [{'property_id': f'body.assertion.{i}', 'description': f'goal {i}',
            'source_function': 'body', 'entry_function': 'paired'} for i in range(6)]
        def receipt(ids):
            return {'kind': 'authored_assertion', 'property_ids': ids, 'entry_function': 'paired',
                    'status': 'satisfied', 'code': 'cbmc_properties_satisfied',
                    'properties': len(ids), 'output_sha256': 'a' * 64}
        ids = [row['property_id'] for row in assertions]
        evidence = {'strategy': ASSERTION_BATCH_STRATEGY, 'assertions': assertions,
                    'queries': [receipt(ids[:1]), receipt(ids[1:5]), receipt(ids[5:])]}
        for mutation in (None, 'missing', 'duplicate', 'foreign', 'order', 'owner', 'entry',
                         'oversize', 'empty', 'wrong_count', 'mixed_fields', 'strategy'):
            changed = copy.deepcopy(evidence)
            queries = changed['queries']
            if mutation == 'missing': queries.pop()
            elif mutation == 'duplicate': queries.append(copy.deepcopy(queries[-1]))
            elif mutation == 'foreign': queries[1]['property_ids'][0] = 'foreign.assertion.1'
            elif mutation == 'order': queries.reverse()
            elif mutation == 'owner': changed['assertions'][2]['source_function'] = 'other'
            elif mutation == 'entry': changed['assertions'][2]['entry_function'] = 'other'
            elif mutation == 'oversize': changed['queries'] = [receipt(ids)]
            elif mutation == 'empty': queries[1] = receipt([])
            elif mutation == 'wrong_count': queries[1]['properties'] = 1
            elif mutation == 'mixed_fields': queries[1]['property_id'] = ids[1]
            elif mutation == 'strategy': changed['strategy'] = ASSERTION_SINGLE_STRATEGY
            with self.subTest(mutation=mutation):
                index = {row['property_id']: row for row in changed['assertions']}
                selected = [authored_query_ids(row, changed['strategy'], index) for row in changed['queries']]
                accepted = (all(row is not None for row in selected) and
                    [identity for row in selected for identity in row] ==
                    [row['property_id'] for row in sorted(changed['assertions'], key=property_query_order)])
                self.assertEqual(accepted, mutation is None)
                self.assertEqual(self.reader(changed), mutation is None)
        legacy = {**evidence, 'strategy': ASSERTION_SINGLE_STRATEGY, 'queries': []}
        for identity in ids:
            row = receipt([identity])
            row['property_id'] = row.pop('property_ids')[0]
            legacy['queries'].append(row)
        self.assertTrue(self.reader(legacy))
        self.assertTrue(all(authored_query_ids(row, ASSERTION_SINGLE_STRATEGY,
            {a['property_id']: a for a in assertions}) for row in legacy['queries']))

    def test_policy_is_uniform_and_keeps_legacy_receipts_valid(self):
        for strategies in ([ASSERTION_SINGLE_STRATEGY], [ASSERTION_BATCH_STRATEGY], [PACKED_SAFETY_STRATEGY], [APPLICATION_FIRST_STRATEGY], [CUT_CONTROL_FIRST_STRATEGY],
                           [ASSERTION_BATCH_STRATEGY, PACKED_SAFETY_STRATEGY],
                           [ASSERTION_SINGLE_STRATEGY, ASSERTION_BATCH_STRATEGY], ['unknown'], []):
            models = {'operation_models': [{'obligation_models': [
                {'property_checker_command': {'strategy': strategy}} for strategy in strategies]}]}
            option = assertion_policy_option(models)
            self.assertEqual(option is not None, len(strategies) == 1 and strategies[0] != 'unknown')
            self.assertTrue(self.reader({'models': models, 'expected': option},
                                       'spx_assertion_option == .expected'))

    def test_real_grouped_checker_covers_all_goals_and_rejects_wrong_source(self):
        for case in ('valid', 'wrong_source', 'omitted_result'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, model = root / 'source.c', root / 'model.goto'
                source.write_text('void proof(void) {\n'
                    'unsigned x; __CPROVER_havoc_object(&x); __CPROVER_assume(x<10);\n'
                    'unsigned values[10]={0}; values[x]=x; x=values[x];\n'
                    '__CPROVER_assert(x<10,"spx-bisimulation-exit-control:run:proof");\n' +
                    ''.join(f'__CPROVER_assert(x+{i}U<{10+i}U,"goal {i}");\n' for i in range(1, 5)) +
                    '__CPROVER_assert(' + ('x==0' if case == 'wrong_source' else 'x<=9') + ',"last goal");\n}\n')
                subprocess.run([shutil.which('goto-cc'), str(source), '-o', str(model)],
                    check=True, capture_output=True, text=True, timeout=30)
                def execute(**kwargs):
                    result = run_cbmc_properties(**kwargs)
                    command = kwargs['command']
                    if case == 'omitted_result' and command.count('--property') > 1 and '--no-assertions' not in command:
                        self.assertEqual(result['status'], 'satisfied')
                        result['property_ids'].pop()
                    return result
                with patch('spaghetti_extractor.components.bisimulation_execution.run_cbmc_properties', execute):
                    result = _run_partitioned_properties(cbmc=Path(shutil.which('cbmc')), goto_model=model,
                        command=property_checker_command([]), proof_function='proof',
                        required_assertion_descriptions=['last goal'], timeout_seconds=30)
                self.assertEqual(result['status'], {'valid': 'satisfied', 'wrong_source': 'violated',
                    'omitted_result': 'incomplete'}[case], result.get('detail'))
                evidence = result['partitioned_evidence']
                self.assertTrue(self.reader(evidence))
                groups = [row for row in evidence['queries'] if row['kind'] == 'authored_assertion']
                self.assertEqual([len(row['property_ids']) for row in groups], [1, 4, 1])
                if case == 'omitted_result':
                    self.assertEqual(result['code'], 'cbmc_selected_assertion_not_checked')
                if case == 'valid':
                    self.assertEqual(result['properties'], 6)
                    self.assertEqual(len(set(result['property_ids'])), 6)

    def test_application_failure_precedes_metadata_timeout_but_success_keeps_it(self):
        for wrong in (False, True):
            with self.subTest(wrong=wrong), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, model = root / 'source.c', root / 'model.goto'
                source.write_text('void proof(void) { unsigned x; __CPROVER_havoc_object(&x); '
                    '__CPROVER_assume(x<10); unsigned values[10]={0}; values[x]=x; '
                    '__CPROVER_assert(x<10,"spx-bisimulation-capture-context:loop:caption"); '
                    '__CPROVER_assert(' + ('x==0' if wrong else 'x<10') +
                    ',"spx-bisimulation-exit-world-memory:run:proof"); }')
                subprocess.run([shutil.which('goto-cc'), str(source), '-o', str(model)],
                    check=True, capture_output=True, text=True, timeout=30)
                metadata_queries = []
                def execute(**kwargs):
                    command = kwargs['command']
                    if '--no-assertions' not in command and 'proof.assertion.1' in command:
                        metadata_queries.append(command)
                        return {'status': 'incomplete', 'code': 'cbmc_timeout',
                                'detail': 'controlled metadata timeout', 'output_sha256': 'b' * 64}
                    return run_cbmc_properties(**kwargs)
                with patch('spaghetti_extractor.components.bisimulation_execution.run_cbmc_properties', execute):
                    result = _run_partitioned_properties(cbmc=Path(shutil.which('cbmc')), goto_model=model,
                        command=property_checker_command([], application_first=True), proof_function='proof',
                        required_assertion_descriptions=['spx-bisimulation-exit-world-memory:run:proof'],
                        timeout_seconds=30)
                self.assertEqual(result['status'], 'violated' if wrong else 'incomplete')
                self.assertEqual(len(metadata_queries), 0 if wrong else 1)
                if wrong:
                    self.assertIn('exit-world-memory', result['detail'])
                self.assertTrue(self.reader(result['partitioned_evidence']))

    def test_full_v11_to_application_first_recheck_reuses_only_identical_queries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            captured = {}
            def check(**kwargs):
                captured.update(kwargs, proof_workspace=root / 'staging')
                return check_bisimulation_refinement(**captured)
            def legacy_policy(*args, **kwargs):
                return {**property_checker_command(*args, **kwargs), 'strategy': ASSERTION_SINGLE_STRATEGY}
            with patch.object(fixture, 'check_bisimulation_refinement', check), patch(
                    'spaghetti_extractor.components.bisimulation_refinement.make_property_checker_command', legacy_policy):
                original = fixture.check_normal_exit(root, cbmc=Path(shutil.which('cbmc')))
            self.assertEqual(original['status'], 'satisfied', original['issues'])
            previous = json.loads((root / 'contextual-refinement-result.json').read_text())
            self.assertTrue(self.reader(previous, 'spx_contextual_proof_system'))
            old_queries = {tuple(json.loads(path.read_text())['binding']['arguments'][1:])
                for path in (root / 'diagnostics').rglob('query.json')}
            process_run = subprocess.run
            fresh = []
            def execute(command, **kwargs):
                if Path(command[0]).name == 'cbmc' and '--version' not in command:
                    self.assertNotIn(tuple(command[2:]), old_queries)
                    fresh.append(command)
                return process_run(command, **kwargs)
            def preferred_policy(*args, **kwargs):
                return property_checker_command(*args, **{**kwargs, 'application_first': True})
            with patch('spaghetti_extractor.components.bisimulation_query_evidence.subprocess.run', execute), patch(
                    'spaghetti_extractor.components.bisimulation_refinement.make_property_checker_command', preferred_policy):
                current = check_bisimulation_refinement(**{**captured,
                    'diagnostic_root': root / 'batched', 'previous_query_evidence': root})
            self.assertEqual(current['status'], 'satisfied', current['issues'])
            self.assertEqual(current['bindings']['operation_models'][0]['obligation_models'][0]
                             ['property_checker_command']['strategy'], CUT_CONTROL_FIRST_STRATEGY)
            old = previous['proof']
            proof = build_contextual_refinement_v2(proof_plan=previous['proof_plan'],
                exact_c_slice=previous['exact_c_slice'], implementation_sha256=old['bindings']['implementation_sha256'],
                source_profile_sha256=old['bindings']['source_profile_sha256'], checker=current['checker'],
                models=current['bindings'], shard_results=current['checks'], world=old['world'])
            validate_contextual_refinement_v2(proof, proof_plan=previous['proof_plan'],
                                             exact_c_slice=previous['exact_c_slice'])
            self.assertTrue(self.reader({**previous, 'proof': proof}, 'spx_contextual_proof_system'))
            for status in ('incomplete', 'violated', 'unknown'):
                changed = copy.deepcopy(proof)
                query = next(row for row in changed['shards'][0]['partitioned_evidence']['queries']
                             if row['kind'] == 'authored_assertion')
                query['status'] = status
                with self.subTest(status=status):
                    self.assertFalse(self.reader({**previous, 'proof': changed}, 'spx_contextual_proof_system'))
            self.assertEqual(proof['shards'][0]['goto_model_sha256'], old['shards'][0]['goto_model_sha256'])
            # Existing authored singletons form complete binary subdivisions.
            # V13's new safety groups still execute when legacy owner groups
            # cannot provide an exact binary subdivision of their selection.
            self.assertTrue(fresh)
            self.assertTrue(all('--no-assertions' in command for command in fresh))
            reuse = json.loads(next((root / 'batched').rglob('reuse.json')).read_text())
            self.assertGreater(reuse['reused_queries'], 0)
            self.assertEqual(reuse['executed_queries'], len(fresh))
