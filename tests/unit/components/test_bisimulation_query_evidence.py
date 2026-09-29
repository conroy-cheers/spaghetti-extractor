"""Reuse binds compiled bytes and actual outputs, and reparses every hit."""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.components.bisimulation_query_evidence import CbmcQueryEvidence, proof_workspace
from spaghetti_extractor.components.bisimulation_assurance import checked_runtime_assurance
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties, _output_sha256
from spaghetti_extractor.components.bisimulation_diagnostics import ProofQueryTimings
from spaghetti_extractor.components.bisimulation_execution import (
    _cached_query_partition, _run_assertion_query, _run_safety_query,
)

TESTKIT = {"fixtures": ("cbmc", "compiler")}


class QueryEvidenceTests(unittest.TestCase):
    def test_runtime_contract_identity_separates_reuse_from_ordinary_proofs(self):
        import copy

        assurance = {"kind": "conditional-runtime-contracts", "contracts": [
            {"id": "allocator.reference-frame", "revision": 2, "contract_sha256": "a" * 64},
        ]}
        def evidence(name, selected, previous):
            return CbmcQueryEvidence(model=self.model, checker=self.cbmc, compiler=self.compiler,
                                     output=self.root / name, previous=previous, assurance=selected)

        first = evidence("conditional", assurance, self.previous)
        self.assertFalse(first.can_reuse(self.command))
        result = run_cbmc_properties(command=self.command, timeout_seconds=10, query_evidence=first)
        self.assertEqual((first.executed, first.reused), (1, 0))
        previous = {**self.previous, "directory": first.output,
                    "outputs": {result["output_sha256"]}, "assurance": copy.deepcopy(assurance)}
        same = evidence("same-contract", assurance, previous)
        with patch("spaghetti_extractor.components.cbmc_backend.subprocess.run",
                   side_effect=AssertionError("unchanged contract must reuse")):
            self.assertEqual(run_cbmc_properties(command=self.command, timeout_seconds=10,
                                                query_evidence=same)["status"], "satisfied")
        self.assertEqual((same.executed, same.reused), (0, 1))

        revised = copy.deepcopy(assurance)
        revised["contracts"][0]["revision"] += 1
        changed_semantics = copy.deepcopy(assurance)
        changed_semantics["contracts"][0]["contract_sha256"] = "b" * 64
        # Identical GOTO bytes and signatures do not establish compatibility.
        for name, selected in (("revised", revised), ("changed-semantics", changed_semantics), ("ordinary", None)):
            with self.subTest(name=name):
                current = evidence(name, selected, previous)
                self.assertFalse(current.can_reuse(self.command))
                self.assertEqual(run_cbmc_properties(command=self.command, timeout_seconds=10,
                                                    query_evidence=current)["status"], "satisfied")
                self.assertEqual((current.executed, current.reused), (1, 0))

        # Selection input is copied, not a mutable alias into cache identity.
        assurance["contracts"][0]["contract_sha256"] = "c" * 64
        self.assertEqual(first.assurance, previous["assurance"])
        record = json.loads(next(first.output.glob("*/query.json")).read_text())
        self.assertFalse(record["binding"]["authorizing"])
        self.assertEqual(record["binding"]["assurance"], previous["assurance"])

    def test_runtime_assurance_rejects_ambiguous_or_authorizing_selections(self):
        row = {"id": "runtime.frame", "revision": 1, "contract_sha256": "a" * 64}
        for value in (
            {}, {"kind": "strong", "contracts": [row]},
            {"kind": "conditional-runtime-contracts", "contracts": []},
            {"kind": "conditional-runtime-contracts", "contracts": [row, row]},
            {"kind": "conditional-runtime-contracts", "contracts": [dict(row, revision=True)]},
            {"kind": "conditional-runtime-contracts", "contracts": [dict(row, contract_sha256="signature")]},
            {"kind": "conditional-runtime-contracts", "contracts": [dict(row, checked=True)]},
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                checked_runtime_assurance(value)

    def test_cached_subdivisions_reparse_every_property_and_counterexample(self):
        for negative in (False, True):
            source = self.root / 'partition.c'
            source.write_text('void check(void) { unsigned x;\n' + '\n'.join(
                f'__CPROVER_assert({"x == 0" if negative and i == 2 else "x == x"}, "goal {i}");'
                for i in range(4)) + '\n}')
            subprocess.run([str(self.compiler), '--i386-win32', str(source), '-o', str(self.model)],
                           capture_output=True, text=True, check=True)
            identities = [f'check.assertion.{i}' for i in range(1, 5)]
            command = lambda ids: self.command + [arg for identity in ids for arg in ('--property', identity)]
            seed = self.evidence(f'partition-seed-{negative}')
            # Uneven depth exercises recursive recovery, not only two siblings.
            groups = [identities[:1], identities[1:2], identities[2:]]
            results = [run_cbmc_properties(command=command(ids), timeout_seconds=10, query_evidence=seed)
                       for ids in groups]
            previous = {**self.previous, 'directory': seed.output,
                'goto_model_sha256': hashlib.sha256(self.model.read_bytes()).hexdigest(),
                'outputs': {result['output_sha256'] for result in results}}
            for safety in (False, True):
                with self.subTest(negative=negative, safety=safety):
                    evidence = self.evidence(f'partition-replay-{negative}-{safety}', previous)
                    timings = ProofQueryTimings(self.model, {}, query_evidence=evidence)
                    with patch('spaghetti_extractor.components.bisimulation_query_evidence.run_cbmc_process',
                               side_effect=AssertionError('completed descendants must avoid fresh queries')):
                        if safety:
                            completed = _run_safety_query(('pointer', identities, command(identities)),
                                timings=timings, timeout_seconds=10)
                        else:
                            completed = _run_assertion_query(('authored_assertion', identities, 'check', command(identities)),
                                timings=timings, timeout_seconds=10)
                    self.assertEqual([identity for query, _ in completed for identity in query[1]], identities)
                    self.assertEqual([result['status'] for _, result in completed],
                                     ['satisfied', 'satisfied', 'violated' if negative else 'satisfied'])
                    self.assertEqual((evidence.reused, evidence.executed), (3, 0))
            # A missing child still needs execution. Exercise a fresh singleton
            # and a fresh pair, including a counterexample in either retained
            # or freshly executed evidence. All four properties remain covered.
            for missing in (0, 2):
                directory = next(path for path in seed.output.iterdir()
                    if (path / 'query.json').is_file() and json.loads(
                        (path / 'query.json').read_text())['binding']['arguments'][-1] == groups[missing][-1])
                parked = directory.with_name('parked-' + directory.name)
                directory.rename(parked)
                try:
                    for safety in (False, True):
                        with self.subTest(negative=negative, missing=missing, safety=safety):
                            partial = self.evidence(f'partition-partial-{negative}-{missing}-{safety}', previous)
                            timings = ProofQueryTimings(self.model, {}, query_evidence=partial)
                            with patch.object(partial, '_binding', wraps=partial._binding) as bind:
                                partition = _cached_query_partition(identities, command(identities), timings)
                            self.assertEqual([ids for ids, _ in partition], groups)
                            self.assertEqual(bind.call_count, 1)
                            self.assertEqual((partial.reused, partial.executed), (0, 0))
                            if safety:
                                completed = _run_safety_query(('pointer', identities, command(identities)),
                                    timings=timings, timeout_seconds=10)
                            else:
                                completed = _run_assertion_query(('authored_assertion', identities,
                                    'check', command(identities)), timings=timings, timeout_seconds=10)
                            self.assertEqual([query[1] for query, _ in completed], groups)
                            self.assertEqual([result['status'] for _, result in completed],
                                ['satisfied', 'satisfied', 'violated' if negative else 'satisfied'])
                            self.assertEqual((partial.reused, partial.executed), (2, 1))
                finally:
                    parked.rename(directory)

    def test_external_solver_bytes_participate_in_query_reuse(self):
        solver = self.root / "z3"
        solver.write_text("first solver bytes")
        command = [*self.command, "--smt2", "--z3", "--external-smt2-solver", str(solver)]
        success = subprocess.CompletedProcess(command, 0,
            '[{"result":[{"property":"check.assertion.1","status":"SUCCESS"}]}]', '')
        fresh = self.evidence("solver-first")
        with patch("spaghetti_extractor.components.bisimulation_query_evidence.run_cbmc_process",
                   return_value=success) as process:
            result = run_cbmc_properties(command=command, timeout_seconds=10, query_evidence=fresh)
            self.assertEqual(process.call_count, 1)
        previous = {**self.previous, "directory": fresh.output, "outputs": {result["output_sha256"]}}
        same = self.evidence("solver-same", previous)
        with patch("spaghetti_extractor.components.bisimulation_query_evidence.run_cbmc_process",
                   side_effect=AssertionError("identical solver query must reuse")):
            self.assertEqual(run_cbmc_properties(command=command, timeout_seconds=10,
                                                query_evidence=same)["status"], "satisfied")
        self.assertEqual(same.reused, 1)
        encoding = self.evidence("solver-array-encoding", previous)
        with patch("spaghetti_extractor.components.bisimulation_query_evidence.run_cbmc_process",
                   return_value=success) as process:
            run_cbmc_properties(command=[*command, "--no-array-field-sensitivity"],
                                timeout_seconds=10, query_evidence=encoding)
            self.assertEqual(process.call_count, 1)
        self.assertEqual(encoding.reused, 0)
        solver.write_text("changed solver bytes")
        changed = self.evidence("solver-changed", previous)
        with patch("spaghetti_extractor.components.bisimulation_query_evidence.run_cbmc_process",
                   return_value=success) as process:
            run_cbmc_properties(command=command, timeout_seconds=10, query_evidence=changed)
            self.assertEqual(process.call_count, 1)
        self.assertEqual(changed.reused, 0)
        pinned = CbmcQueryEvidence(model=self.model, checker=self.cbmc, compiler=self.compiler,
            output=self.root / "solver-stale-pin", smt_solver={"id": "z3", "version": "Z3 version test",
            "executable": str(solver), "sha256": hashlib.sha256(b"first solver bytes").hexdigest()})
        with self.assertRaisesRegex(ValueError, "differs from the pinned checker"):
            run_cbmc_properties(command=command, timeout_seconds=10, query_evidence=pinned)

    def test_external_solver_timeout_kills_descendants_and_retains_failure(self):
        helper = self.root / "external-checker.py"
        child_pid = self.root / "solver-child.pid"
        helper.write_text('''import pathlib, subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
pathlib.Path(sys.argv[1]).write_text(str(child.pid))
print("partial checker output", flush=True)
time.sleep(120)
''')
        command = [sys.executable, str(helper), str(child_pid),
                   "--external-smt2-solver", sys.executable]
        for retain in (False, True):
            with self.subTest(retain=retain):
                child_pid.unlink(missing_ok=True)
                evidence = (CbmcQueryEvidence(model=helper, checker=Path(sys.executable),
                    compiler=self.compiler, output=self.root / "external-failure") if retain else None)
                result = run_cbmc_properties(command=command, timeout_seconds=1,
                                             query_evidence=evidence)
                self.assertEqual(result["code"], "cbmc_timeout", result)
                pid = int(child_pid.read_text())
                status = Path(f"/proc/{pid}/status")
                if status.exists():
                    self.assertIn("State:\tZ", status.read_text())
                if evidence is not None:
                    attempts = list((evidence.output / "failed-attempts").glob("*/attempt.json"))
                    self.assertEqual(len(attempts), 1)
                    record = json.loads(attempts[0].read_text())
                    self.assertEqual(record["termination"]["kind"], "timeout")
                    self.assertEqual(record["binding"]["tools"]["external_smt2_solver_sha256"],
                                     hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest())
                    self.assertEqual((attempts[0].parent / "stdout").read_text(), "partial checker output\n")
                    self.assertEqual(list(evidence.output.glob("*/query.json")), [])

    def test_failed_attempts_preserve_bytes_but_never_supply_reuse(self):
        evidence = self.evidence("failed")
        timeout = subprocess.TimeoutExpired(self.command, 1, output=b"partial\xff", stderr=b"deadline")
        failure = subprocess.CompletedProcess(self.command, 6, "[]", "std::bad_alloc")
        with patch("spaghetti_extractor.components.bisimulation_query_evidence.subprocess.run",
                   side_effect=[timeout, failure, failure]) as process:
            results = [run_cbmc_properties(command=self.command, timeout_seconds=1,
                                           query_evidence=evidence) for _ in range(3)]
        self.assertEqual(process.call_count, 3)
        self.assertEqual([r['status'] for r in results], ['incomplete'] * 3)
        attempts = list((evidence.output / "failed-attempts").iterdir())
        self.assertEqual(len(attempts), 3)
        outputs = []
        for attempt in attempts:
            record = json.loads((attempt / "attempt.json").read_text())
            stdout, stderr = (attempt / "stdout").read_bytes(), (attempt / "stderr").read_bytes()
            self.assertIs(record['authorizing'], False)
            self.assertIs(record['reusable'], False)
            self.assertEqual(record['stdout_sha256'], hashlib.sha256(stdout).hexdigest())
            self.assertEqual(record['stderr_sha256'], hashlib.sha256(stderr).hexdigest())
            self.assertEqual(record['binding']['goto_model_sha256'], self.previous['goto_model_sha256'])
            outputs.append((stdout, stderr))
        self.assertIn((b"partial\xff", b"deadline"), outputs)
        self.assertEqual(outputs.count((b"[]", b"std::bad_alloc")), 2)
        previous = {**self.previous, 'directory': evidence.output,
                    'outputs': {r['output_sha256'] for r in results}}
        retry = self.evidence("retry-failed", previous)
        success = subprocess.CompletedProcess(self.command, 0,
            '[{"result":[{"property":"check.assertion.1","status":"SUCCESS"}]}]', '')
        with patch("spaghetti_extractor.components.bisimulation_query_evidence.subprocess.run",
                   return_value=success) as process:
            result = run_cbmc_properties(command=self.command, timeout_seconds=1, query_evidence=retry)
        self.assertEqual(result['status'], 'satisfied')
        self.assertEqual(process.call_count, 1)
        self.assertEqual((retry.executed, retry.reused), (1, 0))

    def setUp(self):
        if not all(shutil.which(tool) for tool in ("cbmc", "goto-cc")):
            self.skipTest("CBMC tools required")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cbmc, self.compiler = (Path(shutil.which(tool)) for tool in ("cbmc", "goto-cc"))
        self.model = self.root / "model.goto"
        self.compile("x == x")
        self.command = [str(self.cbmc), str(self.model), "--json-ui", "--function", "check"]
        self.fresh = self.evidence("fresh")
        self.result = run_cbmc_properties(command=self.command, timeout_seconds=10, query_evidence=self.fresh)
        self.assertEqual(self.result["status"], "satisfied")
        self.previous = {"directory": self.root / "fresh", "outputs": {self.result["output_sha256"]},
            "goto_model_sha256": hashlib.sha256(self.model.read_bytes()).hexdigest(),
            "checker": {"cbmc_sha256": self.fresh.tools["checker_sha256"], "goto_cc_sha256": self.fresh.tools["compiler_sha256"]}}

    def compile(self, predicate):
        source = self.root / "model.c"
        (self.root / "predicate.h").write_text(f"#define predicate(x) ({predicate})\n")
        source.write_text('''#include "predicate.h"
void check(void) { unsigned x; __CPROVER_assert(predicate(x), "wanted"); }
void other(void) { __CPROVER_assert(0, "other"); }
''')
        subprocess.run([str(self.compiler), "--i386-win32", str(source), "-o", str(self.model)],
                       capture_output=True, text=True, check=True)

    def evidence(self, name, previous=None):
        return CbmcQueryEvidence(model=self.model, checker=self.cbmc, compiler=self.compiler,
                                 output=self.root / name, previous=previous)

    def test_identical_query_reuses_raw_output_through_the_current_parser(self):
        evidence = self.evidence("reused", self.previous)
        self.assertTrue(evidence.can_reuse(self.command))
        self.assertEqual((evidence.executed, evidence.reused), (0, 0))
        with patch("spaghetti_extractor.components.cbmc_backend.subprocess.run", side_effect=AssertionError("unexpected query")):
            result = run_cbmc_properties(command=self.command, timeout_seconds=10, query_evidence=evidence)
        self.assertEqual(result, self.result)
        self.assertEqual((evidence.executed, evidence.reused), (0, 1))

    def test_changed_include_or_query_function_runs_and_rejects(self):
        evidence = self.evidence("changed-function", self.previous)
        self.assertFalse(evidence.can_reuse([*self.command[:-1], "other"]))
        result = run_cbmc_properties(command=[*self.command[:-1], "other"], timeout_seconds=10, query_evidence=evidence)
        self.assertEqual(result["status"], "violated")
        self.assertEqual((evidence.executed, evidence.reused), (1, 0))

        source_before = (self.root / "model.c").read_bytes()
        self.compile("0")
        self.assertEqual((self.root / "model.c").read_bytes(), source_before)
        evidence = self.evidence("changed-model", self.previous)
        self.assertFalse(evidence.can_reuse(self.command))
        result = run_cbmc_properties(command=self.command, timeout_seconds=10, query_evidence=evidence)
        self.assertEqual(result["status"], "violated")
        self.assertEqual((evidence.executed, evidence.reused), (1, 0))

    def test_partition_probe_cannot_authorize_changed_execution_inputs(self):
        evidence = self.evidence('partition-probe', self.previous)
        probe = evidence.property_reuse_probe(self.command)
        self.assertTrue(probe(self.command))
        for changed in ([*self.command[:-1], 'other'], [*self.command, '--no-assertions']):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, 'more than its properties'):
                probe(changed)
        # The scheduling snapshot can become stale. Execution must bind the
        # changed compiled bytes and reject instead of consuming its old hit.
        self.compile('0')
        self.assertTrue(probe(self.command))
        self.assertIsNone(evidence.property_reuse_probe(self.command))
        result = run_cbmc_properties(command=self.command, timeout_seconds=10, query_evidence=evidence)
        self.assertEqual(result['status'], 'violated', result)
        self.assertEqual((evidence.reused, evidence.executed), (0, 1))

    def test_corrupt_or_unbound_evidence_is_rejected_without_fresh_execution(self):
        for mutation in ("stdout", "rehashed-output", "command", "checker", "authorizing-type", "missing", "symlink", "unbound"):
            with self.subTest(mutation=mutation):
                previous = self.root / ("previous-" + mutation)
                shutil.copytree(self.previous["directory"], previous)
                entry = next(path for path in previous.iterdir() if path.is_dir())
                record = json.loads((entry / "query.json").read_text())
                if mutation in ("stdout", "rehashed-output"):
                    (entry / "stdout").write_text("[]")
                    if mutation == "rehashed-output": record["stdout_sha256"] = hashlib.sha256(b"[]").hexdigest()
                elif mutation == "command": record["binding"]["arguments"].append("--no-assertions")
                elif mutation == "checker": record["binding"]["tools"]["checker_sha256"] = "a" * 64
                elif mutation == "authorizing-type": record["binding"]["authorizing"] = 0
                elif mutation == "missing": (entry / "stderr").unlink()
                elif mutation == "symlink":
                    (entry / "stdout").rename(previous / "outside")
                    (entry / "stdout").symlink_to(previous / "outside")
                (entry / "query.json").write_text(json.dumps(record))
                evidence = self.evidence("output-" + mutation, {**self.previous, "directory": previous,
                    "outputs": set() if mutation == "unbound" else self.previous["outputs"]})
                with patch("spaghetti_extractor.components.cbmc_backend.subprocess.run", side_effect=AssertionError("unexpected query")):
                    with self.assertRaises(ValueError):
                        evidence.can_reuse(self.command)
                    with self.assertRaises(ValueError):
                        run_cbmc_properties(command=self.command, timeout_seconds=10, query_evidence=evidence)

    def test_reuse_does_not_bypass_the_current_result_parser(self):
        # Even a retained, integrity-bound output cannot manufacture a property
        # result if the current parser finds it malformed or inconclusive.
        entry = next(path for path in self.previous["directory"].iterdir() if path.is_dir())
        (entry / "stdout").write_bytes(b"[]")
        record = json.loads((entry / "query.json").read_text())
        record["stdout_sha256"] = hashlib.sha256(b"[]").hexdigest()
        (entry / "query.json").write_text(json.dumps(record))
        self.previous["outputs"] = {_output_sha256(b"[]", (entry / "stderr").read_bytes())}
        evidence = self.evidence("parser", self.previous)
        self.assertTrue(evidence.can_reuse(self.command))
        with patch("spaghetti_extractor.components.cbmc_backend.subprocess.run", side_effect=AssertionError("unexpected query")):
            result = run_cbmc_properties(command=self.command, timeout_seconds=10, query_evidence=evidence)
        self.assertEqual(result["status"], "incomplete")


class ProofWorkspaceTests(unittest.TestCase):
    def test_incomplete_nonvacuity_reruns_unpublished_property_processes(self):
        from spaghetti_extractor.components.bisimulation_refinement import check_bisimulation_refinement
        from spaghetti_extractor.components.bisimulation_query_evidence import previous_proof_queries
        from tests.unit.components import test_bisimulation_normal_exits as fixture

        captured = {}
        def check(**kwargs):
            captured.update(kwargs)
            return check_bisimulation_refinement(**kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            # Compile and check real properties, but model a coverage timeout.
            # The ordinary receipt publishes coverage only in this case.
            with patch.object(fixture, 'check_bisimulation_refinement', side_effect=check), patch(
                    'spaghetti_extractor.components.bisimulation_execution.run_cbmc_cover',
                    return_value={'status': 'incomplete', 'code': 'cbmc_nonvacuity_timeout',
                                  'output_sha256': 'a' * 64}):
                result = fixture.check_normal_exit(root, cbmc=Path(shutil.which('cbmc')))
            self.assertEqual(result['status'], 'incomplete')
            previous = previous_proof_queries(root)
            self.assertTrue(previous)
            self.assertTrue(all(row['coverage_only'] for row in previous.values()))
            retained = list((root / 'diagnostics').rglob('query.json'))
            self.assertTrue(retained, 'completed but unpublished processes must exist')

            rerun = check_bisimulation_refinement(**{**captured,
                'previous_query_evidence': root, 'diagnostic_root': root / 'retried'})
            self.assertEqual(rerun['status'], 'satisfied', rerun['issues'])
            counters = [json.loads(p.read_text()) for p in (root / 'retried').rglob('reuse.json')]
            self.assertTrue(counters)
            self.assertTrue(all(row['reused_queries'] == 0 and row['executed_queries'] > 0
                                for row in counters))

    def test_high_level_generation_binds_contracts_and_all_auxiliary_compilation(self):
        cbmc = shutil.which("cbmc")
        if cbmc is None or shutil.which("goto-cc") is None:
            self.skipTest("CBMC tools required")
        from spaghetti_extractor.components.bisimulation_refinement import check_bisimulation_refinement
        from spaghetti_extractor.components.bisimulation_assurance import runtime_assurance_defines
        from spaghetti_extractor.components.bisimulation_issued_access import issued_access_assurance
        from spaghetti_extractor.components.bisimulation_world_memory import allocation_byte_projection_assurance
        from spaghetti_extractor.components.bisimulation_world_namespace import world_reference_assurance
        from spaghetti_extractor.components.bisimulation_execution import run_readable_entry_probe
        from tests.unit.components.test_bisimulation_reference_authority import authority_payload
        from tests.unit.components.test_bisimulation_normal_exits import check_normal_exit
        assurance = allocation_byte_projection_assurance()
        assurance['contracts'] += issued_access_assurance()['contracts'] + world_reference_assurance()['contracts']
        observed, probes = [], []

        def conditional(**kwargs):
            result = check_bisimulation_refinement(**kwargs, runtime_assurance=assurance)
            observed.append(result)
            return result

        def probe(**kwargs):
            task = kwargs['task']
            self.assertEqual(task['assurance'], assurance)
            self.assertTrue(set(runtime_assurance_defines(assurance)) <= set(task['compile_command']))
            result = run_readable_entry_probe(**kwargs)
            probes.append(result)
            return result

        with tempfile.TemporaryDirectory() as temporary, patch(
                "tests.unit.components.test_bisimulation_normal_exits.check_bisimulation_refinement", side_effect=conditional), patch(
                "spaghetti_extractor.components.bisimulation_execution.run_readable_entry_probe", side_effect=probe):
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, "conditional runtime-contract evidence"):
                check_normal_exit(root, cbmc=Path(cbmc), reference_view=True, read_buffer=True,
                                  return_to_caller=True, private_write=True, reference_authority=authority_payload())
            self.assertEqual(len(observed), 1)
            result = observed[0]
            self.assertEqual(result['status'], 'satisfied', result['issues'])
            self.assertFalse(result['activation_authorized'])
            self.assertFalse(result['authorizing'])
            self.assertEqual(result['assurance'], assurance)
            self.assertEqual(result['bindings']['assurance'], assurance)
            self.assertEqual(json.loads((root/'diagnostics/runtime-assurance.json').read_text()), assurance)
            digest = hashlib.sha256((root/'diagnostics/runtime-assurance.json').read_bytes()).hexdigest()
            for operation in result['bindings']['operation_models']:
                self.assertEqual(operation['assurance'], assurance)
                for model in operation['obligation_models']:
                    self.assertEqual(model['assurance'], assurance)
                    self.assertIn({'role': 'runtime_assurance', 'sha256': digest}, model['proof_inputs'])
            for shard in result['checks']:
                self.assertEqual(shard['assurance'], assurance)
                for value in shard.values():
                    if isinstance(value, dict) and 'receipt_sha256' in value:
                        self.assertEqual(value['assurance'], assurance)
            self.assertTrue(any(probes), 'expected a real auxiliary entry probe')

    def test_conditional_shard_is_not_accepted_by_strong_qualification(self):
        cbmc = shutil.which("cbmc")
        if cbmc is None or shutil.which("goto-cc") is None:
            self.skipTest("CBMC tools required")
        from spaghetti_extractor.components.bisimulation_execution import _run_bisimulation_obligation, _run_compile
        from tests.unit.components.test_bisimulation_normal_exits import check_normal_exit
        assurance = {"kind": "conditional-runtime-contracts", "contracts": [
            {"id": "runtime.frame", "revision": 1, "contract_sha256": "a" * 64},
        ]}
        observed = []

        def conditional(task, *, timeout_seconds):
            guarded = task['goto_model'].with_name('conditional-guard.c')
            guarded.write_text('#ifndef SPX_CONDITIONAL_RUNTIME_CONTRACT_' + 'a'*64 +
                               '\n#error "conditional contract selection missing"\n#endif\n')
            task = {**task, 'compile_command': [*task['compile_command'], str(guarded)]}
            unmarked = _run_compile(task['compile_command'], timeout_seconds,
                                    workspace=task.get('compile_workspace'))
            self.assertIsNotNone(unmarked)
            self.assertIn('conditional contract selection missing', str(unmarked))
            result = _run_bisimulation_obligation({**task, "assurance": assurance},
                                                  timeout_seconds=timeout_seconds)
            observed.append(result)
            return result

        with tempfile.TemporaryDirectory() as temporary, patch(
                "spaghetti_extractor.components.bisimulation_refinement._run_bisimulation_obligation",
                side_effect=conditional):
            with self.assertRaisesRegex(ValueError, "conditional runtime-contract evidence"):
                check_normal_exit(Path(temporary), cbmc=Path(cbmc))
        self.assertTrue(observed)
        self.assertTrue(all(row["status"] == "satisfied" for row in observed))
        for row in observed:
            self.assertEqual(row["assurance"], assurance)
            self.assertIs(row["authorizing"], False)
            for value in row.values():
                if isinstance(value, dict) and "receipt_sha256" in value:
                    self.assertEqual(value["assurance"], assurance)

    def test_engine_exception_before_diagnostic_copy_keeps_compiled_model(self):
        cbmc = shutil.which("cbmc")
        if cbmc is None or shutil.which("goto-cc") is None:
            self.skipTest("CBMC tools required")
        from tests.unit.components.test_bisimulation_normal_exits import check_normal_exit
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate, workspace = root / "candidate", root / "workspace"
            candidate.mkdir()
            models = []
            failure = RuntimeError("mandatory query incomplete")

            def interrupted(task, *, timeout_seconds):
                subprocess.run(task["compile_command"], check=True, capture_output=True)
                model = Path(task["goto_model"])
                models.append((model, model.read_bytes()))
                raise failure

            with patch("spaghetti_extractor.components.bisimulation_refinement._proof_workspace",
                       side_effect=lambda _: proof_workspace(workspace)), patch(
                       "spaghetti_extractor.components.bisimulation_refinement._run_bisimulation_obligation",
                       side_effect=interrupted), self.assertRaises(RuntimeError) as raised:
                check_normal_exit(candidate, cbmc=Path(cbmc))
            self.assertIs(raised.exception, failure)
            self.assertEqual(len(models), 1)
            model, data = models[0]
            self.assertTrue(data)
            self.assertEqual(model.read_bytes(), data)
            self.assertTrue((model.parent / "bisimulation.c").is_file())
            self.assertFalse((candidate / "diagnostics").exists())
            self.assertFalse((candidate / "contextual-refinement-result.json").exists())

    def test_existing_work_is_preserved_and_completed_staging_is_cleaned(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "keep").write_text("operator work")
            with self.assertRaisesRegex(ValueError, "already exists"):
                with proof_workspace(root):
                    self.fail("existing directory admitted")
            self.assertEqual((root / "keep").read_text(), "operator work")
            with proof_workspace(root / "model-work") as workspace:
                (workspace / "generated.c").write_text("temporary input")
            self.assertFalse((root / "model-work").exists())

    def test_exception_retains_exact_inputs_and_outputs_without_admitting_restart(self):
        for exception in (RuntimeError, KeyboardInterrupt):
            with self.subTest(exception=exception), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "model-work"
                files = {"generated.c": b"source", "model.goto": b"compiled\x00input",
                         "query-evidence/complete/stdout": b"completed\xffoutput",
                         "query-evidence/failed-attempts/stderr": b"timeout"}
                failure = exception("interrupted proof")
                with self.assertRaises(exception) as raised:
                    with proof_workspace(root) as workspace:
                        for name, data in files.items():
                            path = workspace / name
                            path.parent.mkdir(parents=True, exist_ok=True)
                            path.write_bytes(data)
                        raise failure
                self.assertIs(raised.exception, failure)
                self.assertEqual({str(p.relative_to(root)): p.read_bytes()
                    for p in root.rglob("*") if p.is_file()}, files)
                self.assertFalse((root / "contextual-refinement-result.json").exists())
                with self.assertRaisesRegex(ValueError, "already exists"):
                    with proof_workspace(root):
                        self.fail("interrupted directory admitted")
                self.assertEqual((root / "model.goto").read_bytes(), files["model.goto"])
