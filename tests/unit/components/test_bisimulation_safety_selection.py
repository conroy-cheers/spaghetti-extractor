"""Real indirect calls keep all safety checks when cutpoint slicing renumbers IDs."""
from __future__ import annotations

import shutil
import copy
import json
from .jq_reader import run as run_jq_reader
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from spaghetti_extractor.components.bisimulation_execution import _run_partitioned_properties, _run_safety_query
from spaghetti_extractor.components.bisimulation_support import (
    safety_group_refinement, safety_property_groups, ASSERTION_BATCH_STRATEGY, PACKED_SAFETY_STRATEGY, PACKED_SINGLE_STRATEGY,
)
from tests.unit.components.test_bisimulation_refinement_execution import _task

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"),
           "resources": ("nix/jq/strong-contextual-proof.jq",)}


class SafetySelectionTests(unittest.TestCase):
    def test_bounded_safety_groups_preserve_ids_and_legacy_policy_in_both_readers(self):
        module = Path(__file__).resolve().parents[3] / TESTKIT['resources'][0]
        inventory = [{'property_id': f'{owner}.pointer.{index:04}', 'source_function': owner,
                      'class': 'pointer dereference', 'description': 'pointer is readable'}
                     for owner in ('first', 'second', 'third') for index in range(700)]
        ids = [row['property_id'] for row in inventory]
        for strategy, sizes in ((ASSERTION_BATCH_STRATEGY, [700, 700, 700]),
                                (PACKED_SAFETY_STRATEGY, [1024, 1024, 52]),
                                (PACKED_SINGLE_STRATEGY, [1024, 1024, 52])):
            groups = safety_property_groups('pointer', ids, inventory, strategy=strategy)
            self.assertEqual(list(map(len, groups)), sizes)
            self.assertEqual([identity for group in groups for identity in group], ids)
            self.assertEqual(safety_property_groups('unwinding', ids, inventory, strategy=strategy), [ids])
            evidence = {'strategy': strategy, 'language_safety_inventory': inventory, 'loops': []}
            run = run_jq_reader([shutil.which('jq'), '-c', module.read_text() +
                '\nspx_safety_query_groups'], input=json.dumps(evidence), capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout), [
                {'safety_partition': 'pointer', 'expected_property_ids': group} for group in groups])
        with self.assertRaisesRegex(ValueError, 'unknown safety'):
            safety_property_groups('pointer', ids, inventory, strategy='unknown')

    def test_terminal_safety_timeout_retains_an_honest_partial_inventory(self):
        selected = ['a.bounds.1', 'a.bounds.2', 'a.bounds.3', 'a.bounds.4']
        base = ['cbmc', 'model.goto', '--function', 'paired', '--no-assertions']
        seen = []

        def execute(*, command, timeout_seconds):
            ids = command[len(base) + 1::2]
            seen.append(ids)
            return {'status': 'incomplete', 'code': 'cbmc_timeout'}

        with mock.patch('spaghetti_extractor.components.bisimulation_execution.run_cbmc_properties', execute):
            checked = _run_safety_query(('bounds', selected,
                base + [v for p in selected for v in ('--property', p)]), timings=None, timeout_seconds=20)
        self.assertEqual(seen, [selected, selected[:2], selected[:1]])
        self.assertEqual(len(checked), 1)
        self.assertEqual(checked[0][1]['status'], 'incomplete')
        expected = [('bounds', selected), ('pointer', ['p.1', 'p.2'])]
        # The pointer group may already have run in the same bounded window.
        actual = [('bounds', selected[:1]), ('pointer', ['p.1', 'p.2'])]
        module = Path(__file__).resolve().parents[3] / TESTKIT['resources'][0]
        for mutation in (None, 'missing_first', 'duplicate', 'out_of_order', 'middle_gap'):
            changed = copy.deepcopy(actual)
            if mutation == 'missing_first': changed.pop(0)
            elif mutation == 'duplicate': changed.insert(0, changed[0])
            elif mutation == 'out_of_order': changed.reverse()
            elif mutation == 'middle_gap': changed.insert(1, ('bounds', selected[2:]))
            for complete in (False, True):
                accepted = mutation is None and not complete
                self.assertEqual(safety_group_refinement(changed, expected, complete=complete), accepted)
                value = {'actual': [{'safety_partition': p, 'expected_property_ids': ids} for p, ids in changed],
                         'expected': [{'safety_partition': p, 'expected_property_ids': ids} for p, ids in expected]}
                run = run_jq_reader([shutil.which('jq'), '-e', module.read_text() +
                    '\n.expected as $expected | .actual | spx_safety_group_refinement($expected; ' +
                    str(complete).lower() + ')'], input=json.dumps(value), capture_output=True, text=True)
                self.assertEqual(run.returncode, int(not accepted), run.stderr)

    def test_exhausted_safety_groups_keep_all_properties_and_the_same_entry(self):
        selected = ['read.array_bounds.1', 'read.array_bounds.2',
                    'write.array_bounds.1', 'write.array_bounds.2']
        base = ['cbmc', 'model.goto', '--function', 'paired_entry', '--no-assertions']
        command = base + [v for p in selected for v in ('--property', p)]
        seen = []

        def execute(*, command, timeout_seconds):
            self.assertEqual(command[:len(base)], base)
            self.assertEqual(timeout_seconds, 20)
            ids = command[len(base) + 1::2]
            seen.append(ids)
            return ({'status':'incomplete', 'code':'cbmc_timeout'} if len(ids) > 1 else
                    {'status':'satisfied', 'property_ids':ids})

        with mock.patch('spaghetti_extractor.components.bisimulation_execution.run_cbmc_properties', execute):
            checked = _run_safety_query(('bounds', selected, command),
                                        timings=None, timeout_seconds=20)
        self.assertEqual(len(seen), 7)
        actual = [(query[0], query[1]) for query, _result in checked]
        expected = [('bounds', selected)]
        self.assertTrue(safety_group_refinement(actual, expected))
        for changed in (actual[:-1], actual + actual[:1], list(reversed(actual)),
                        [('bounds', [])] + actual):
            self.assertFalse(safety_group_refinement(changed, expected))
        self.assertFalse(safety_group_refinement(
            [('unwinding', selected[:2]), ('unwinding', selected[2:])], [('unwinding', selected)]))
        for partition, result in [('bounds', {'status':'violated', 'code':'cbmc_counterexample'}),
                                  ('unwinding', {'status':'incomplete', 'code':'cbmc_timeout'})]:
            with mock.patch('spaghetti_extractor.components.bisimulation_execution.run_cbmc_properties',
                            return_value=result) as run:
                checked = _run_safety_query((partition, selected, command),
                                            timings=None, timeout_seconds=20)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(checked[0][1], result)

    def test_real_checks_and_independent_reader_cover_refined_bounds_queries(self):
        from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
        module = Path(__file__).resolve().parents[3] / TESTKIT['resources'][0]
        for invalid in (False, True):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, model = root/'array.c', root/'model.goto'
                source.write_text('unsigned arbitrary(void) { unsigned value; __CPROVER_havoc_object(&value); return value; }\nvoid proof(void) {\n'
                    'unsigned a[2]={3,4}, b[2]={5,6}, i=arbitrary(); __CPROVER_assume(i<2);\n'
                    'unsigned x=a[i], y=b[' + ('2' if invalid else 'i') + '];\n'
                    '__CPROVER_assert(x+y>=8,"semantic goal");\n}\n')
                subprocess.run([shutil.which('goto-cc'), '--i386-win32', str(source), '-o', str(model)],
                               capture_output=True, check=True)
                exhausted = []

                def execute(*, command, timeout_seconds):
                    ids = [command[i+1] for i, item in enumerate(command[:-1]) if item == '--property']
                    if len(ids) > 1 and all('.array_bounds.' in p for p in ids):
                        exhausted.append(ids)
                        return {'status':'incomplete', 'code':'cbmc_no_properties_checked',
                                'detail':'Solver ran out of memory during propositional reduction.'}
                    return run_cbmc_properties(command=command, timeout_seconds=timeout_seconds)

                with mock.patch('spaghetti_extractor.components.bisimulation_execution.run_cbmc_properties', execute):
                    result = _run_partitioned_properties(cbmc=Path(shutil.which('cbmc')), goto_model=model,
                        command=_task(root)['property_checker_command'], proof_function='proof',
                        required_assertion_descriptions=['semantic goal'], timeout_seconds=20)
                self.assertTrue(exhausted)
                self.assertEqual(result['status'], 'violated' if invalid else 'satisfied', result.get('detail'))
                evidence = result['partitioned_evidence']
                for missing in (False, True):
                    changed = copy.deepcopy(evidence)
                    if missing:
                        position = next(i for i, q in enumerate(changed['queries'])
                                        if q.get('safety_partition') == 'bounds')
                        del changed['queries'][position]
                    checked = run_jq_reader([shutil.which('jq'), '-e', module.read_text() +
                        '\nspx_selected_safety_queries'], input=json.dumps(changed), text=True,
                        capture_output=True, timeout=10)
                    self.assertEqual(checked.returncode, int(missing), checked.stderr)

    def test_large_pointer_inventory_checks_every_function_and_rejects_late_failure(self):
        module = Path(__file__).resolve().parents[3] / TESTKIT["resources"][0]
        reads = "\n".join(f"  result += p[{i}];" for i in range(200))
        for strategy, invalid in [(s, invalid) for s in (ASSERTION_BATCH_STRATEGY, PACKED_SAFETY_STRATEGY)
                                  for invalid in (False, True)]:
            with self.subTest(strategy=strategy, invalid=invalid), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "large.c"
                source.write_text("\n".join(
                    f"unsigned {name}(const unsigned *p) {{ unsigned result=0;\n{reads}\nreturn result; }}"
                    for name in ("first", "second")) +
                    "\nvoid proof(void) { unsigned a[200]={0};\n" +
                    f"unsigned result=first(a)+second({'0' if invalid else 'a'});\n" +
                    '__CPROVER_assert(result==0,"semantic goal");\n}\n')
                model = root / "model.goto"
                subprocess.run([shutil.which("goto-cc"), "--i386-win32", str(source), "-o", str(model)],
                    capture_output=True, check=True)
                result = _run_partitioned_properties(cbmc=Path(shutil.which("cbmc")), goto_model=model,
                    command={**_task(root)["property_checker_command"], 'strategy': strategy}, proof_function="proof",
                    required_assertion_descriptions=["semantic goal"], timeout_seconds=20)
                self.assertEqual(result["status"], "violated" if invalid else "satisfied", result.get("detail"))
                evidence = result["partitioned_evidence"]
                queries = [q for q in evidence["queries"] if q.get("safety_partition") == "pointer"]
                self.assertGreater(len(queries), 1)
                selected = [p for q in queries for p in q["expected_property_ids"]]
                self.assertEqual(len(selected), len(set(selected)))
                inventory = {r["property_id"]: r["source_function"] for r in evidence["language_safety_inventory"]}
                for query in queries:
                    if strategy == ASSERTION_BATCH_STRATEGY:
                        self.assertEqual(len({inventory[p] for p in query["expected_property_ids"]}), 1)
                    else:
                        self.assertLessEqual(len(query['expected_property_ids']), 1024)
                if invalid:
                    self.assertTrue(any(q["status"] == "violated" and
                        any(inventory[p] == 'second' for p in q['expected_property_ids']) for q in queries))
                    self.assertFalse(any(q["kind"] == "authored_assertion" for q in evidence["queries"]))
                    continue
                for mutation in (None, "missing", "duplicate", "overlap", "foreign", "order", "unknown_class", "strategy"):
                    changed = copy.deepcopy(evidence)
                    rows = changed["queries"]
                    positions = [i for i,q in enumerate(rows) if q.get("safety_partition") == "pointer"]
                    a,b = positions[:2]
                    if mutation == "missing": del rows[a]
                    elif mutation == "duplicate": rows.insert(a, copy.deepcopy(rows[a]))
                    elif mutation == "overlap": rows[b]["expected_property_ids"].append(rows[a]["expected_property_ids"][0])
                    elif mutation == "foreign": rows[a]["property_ids"].append("foreign.pointer.1")
                    elif mutation == "order": rows[a],rows[b] = rows[b],rows[a]
                    elif mutation == 'strategy':
                        changed['strategy'] = (PACKED_SAFETY_STRATEGY if strategy == ASSERTION_BATCH_STRATEGY
                                               else ASSERTION_BATCH_STRATEGY)
                    elif mutation == "unknown_class":
                        dropped = rows[a]["expected_property_ids"].pop()
                        rows[a]["property_ids"].remove(dropped)
                        rows[a]["properties"] -= 1
                        next(r for r in changed["language_safety_inventory"] if r["property_id"] == dropped)["class"] = "unknown"
                    checked = run_jq_reader([shutil.which("jq"), "-e", module.read_text() +
                        "\nspx_selected_safety_queries"], input=json.dumps(changed), text=True,
                        capture_output=True, timeout=10)
                    self.assertEqual(checked.returncode, int(mutation is not None), (mutation, checked.stderr))

    def test_callback_cut_checks_pointer_bounds_and_unwinding(self) -> None:
        cbmc = shutil.which("cbmc")
        goto_cc = shutil.which("goto-cc")
        self.assertIsNotNone(cbmc)
        self.assertIsNotNone(goto_cc)
        # There are two identical callback sites. Entering at the cut removes
        # the first, and standard instrumentation renumbers the second. The
        # unsliced no-standard-checks unwind baseline keeps both old IDs.
        for failure in (None, "pointer", "bounds", "unwinding"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "test.c"
                source.write_text('''
unsigned callback(unsigned x) { return x + 1; }
void proof(void) {
    unsigned (*f)(unsigned) = callback;
    unsigned a[2] = {1, 2};
    unsigned i = 0;
    goto cut;
    i = f(i);
cut:
    ''' + ('f = 0;\n' if failure == "pointer" else '') + '''
    i = f(i);
    unsigned result = a[''' + ('2' if failure == "bounds" else '0') + '''];
    for (unsigned j = 0; j < ''' + ('4' if failure == "unwinding" else '1') + '''; ++j)
        result += j;
    __CPROVER_assert(i == 1 && result >= 1, "semantic goal");
}
''')
                model = root / "model.goto"
                subprocess.run([goto_cc, "--i386-win32", str(source), "-o", str(model)],
                               check=True, capture_output=True)
                result = _run_partitioned_properties(cbmc=Path(cbmc), goto_model=model,
                    command=_task(root)["property_checker_command"], proof_function="proof",
                    required_assertion_descriptions=["semantic goal"], timeout_seconds=10)
                self.assertEqual(result["status"], "satisfied" if failure is None else "violated", result)
                evidence = result["partitioned_evidence"]
                if failure is None:
                    pointer = next(q for q in evidence["queries"] if q.get("safety_partition") == "pointer")
                    baseline_ids = {r["property_id"] for r in evidence["language_safety_baseline_inventory"]}
                    self.assertNotEqual(set(pointer["expected_property_ids"]), baseline_ids)
                    self.assertEqual(pointer["property_ids"], pointer["expected_property_ids"])
                    inventory = evidence["language_safety_inventory"]
                    self.assertTrue(any("dereferenced function pointer" in r["description"] for r in inventory))
                else:
                    self.assertTrue(any(q.get("safety_partition") == failure and q["status"] == "violated"
                                        for q in evidence["queries"]), result)


if __name__ == "__main__":
    unittest.main()
