"""Pinned SMT execution retains complete proof, rejection and reader obligations."""

import copy
import hashlib
import json
from .jq_reader import run as run_jq_reader
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_refinement import check_bisimulation_refinement
from spaghetti_extractor.components.cbmc_backend import bind_smt_solver, run_cbmc_properties, solver_arguments, validate_smt_solver_binding
from spaghetti_extractor.components.contextual_bisimulation import validate_contextual_refinement_v2
from spaghetti_extractor.components.bisimulation_support import PACKED_SINGLE_STRATEGY
from . import test_bisimulation_normal_exits as fixture

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq", "z3"),
           "resources": ("nix/jq/strong-contextual-proof.jq",)}


class SmtProofTests(unittest.TestCase):
    def test_complete_proof_and_wrong_source_with_independent_readers(self):
        cbmc = shutil.which("cbmc")
        z3, jq = shutil.which("z3"), shutil.which("jq")
        self.assertTrue(cbmc and z3 and jq, "declared proof tools must be available")
        reader = (Path(__file__).parents[3] / TESTKIT["resources"][0]).read_text()
        binding = bind_smt_solver(Path(z3))
        for value, expected, legacy_arrays in ((7, "satisfied", False), (8, "violated", False),
                                               (7, "satisfied", True)):
            with self.subTest(value=value, legacy_arrays=legacy_arrays), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                captured = {}
                def check(**kwargs):
                    captured.update(kwargs, smt_solver=Path(z3), proof_workspace=root / "staging")
                    with patch("spaghetti_extractor.components.cbmc_backend.solver_arguments",
                               side_effect=lambda binding=None: solver_arguments(
                                   binding, array_field_sensitive=legacy_arrays)):
                        return check_bisimulation_refinement(**captured)
                with patch.object(fixture, "check_bisimulation_refinement", side_effect=check):
                    result = fixture.check_normal_exit(root, cbmc=Path(cbmc), source_value=value)
                self.assertEqual(result["status"], expected, result["issues"])
                packet = json.loads((root / "contextual-refinement-result.json").read_text())
                proof = packet["proof"]
                self.assertEqual(proof["checker"]["smt_solver"], binding)
                self.assertEqual({model["property_checker_command"]["strategy"]
                    for operation in proof["models"]["operation_models"]
                    for model in operation["obligation_models"]}, {PACKED_SINGLE_STRATEGY})
                for predicate, code in (("spx_contextual_proof_system", 0),
                                        ("spx_strong_contextual_proof", 0 if value == 7 else 1)):
                    checked = run_jq_reader([jq, "-e", reader + "\n" + predicate],
                        input=json.dumps(packet), text=True, capture_output=True)
                    self.assertEqual(checked.returncode, code, checked.stderr + checked.stdout)
                for path in (root / "diagnostics").rglob("query.json"):
                    record = json.loads(path.read_text())
                    if "--external-smt2-solver" in record["binding"]["arguments"]:
                        self.assertEqual(record["binding"]["tools"]["external_smt2_solver_sha256"], binding["sha256"])
                        self.assertEqual("--no-array-field-sensitivity" in record["binding"]["arguments"],
                                         not legacy_arrays)
                if value != 7 or legacy_arrays:
                    continue
                with patch("spaghetti_extractor.components.bisimulation_query_evidence.run_cbmc_process",
                           side_effect=AssertionError("unchanged qualified SMT queries must reuse")), \
                     patch("spaghetti_extractor.components.bisimulation_refinement._render_harness",
                           side_effect=AssertionError("unchanged local proof must not render models")), \
                     patch("spaghetti_extractor.components.bisimulation_execution._run_compile",
                           side_effect=AssertionError("unchanged local proof must not compile models")):
                    reused = check_bisimulation_refinement(**{**captured,
                        "previous_query_evidence": root, "diagnostic_root": root / "reused-diagnostics"})
                self.assertEqual(reused["status"], "satisfied", reused["issues"])
                reuse = json.loads((root / "proof-reuse.json").read_text())
                self.assertEqual([reuse[k] for k in ("model_generation", "compiler_runs", "solver_runs")], [0, 0, 0])
                self.assertEqual(reused['bindings'], result['bindings'])
                self.assertEqual(reused['checks'], result['checks'])
                headers = dict(captured['c_headers'])
                name = next(iter(headers))
                headers[name] += '\n/* changed caller header */\n'
                with patch('spaghetti_extractor.components.bisimulation_refinement._render_harness',
                           side_effect=RuntimeError('caller header requires model recheck')):
                    with self.assertRaisesRegex(RuntimeError, 'requires model recheck'):
                        check_bisimulation_refinement(**{**captured, 'c_headers': headers,
                            'previous_query_evidence': root, 'diagnostic_root': root / 'changed-header'})
                for field in ('headers', 'artifacts', 'caller-binding', 'input-inventory'):
                    forged = copy.deepcopy(packet)
                    changed = forged['proof']['models']
                    record = changed['reusable_inputs']
                    if field == 'headers':
                        record['inputs']['extra']['headers']['foreign.h'] = 'different header'
                    elif field == 'artifacts':
                        record['artifacts']['../outside'] = '0' * 64
                    elif field == 'caller-binding':
                        record['inputs']['caller']['machine_overlay_sha256'] = '0' * 64
                        record['input_sha256'] = canonical_sha256_v3(record['inputs'])
                    else:
                        changed['operation_models'][0]['obligation_models'][0]['proof_inputs'] = [
                            row for row in changed['operation_models'][0]['obligation_models'][0]['proof_inputs']
                            if row['role'] != 'proof_reuse_inputs']
                    forged['proof']['receipt_sha256'] = canonical_sha256_v3({
                        k: v for k, v in forged['proof'].items() if k != 'receipt_sha256'})
                    with self.subTest(reuse_mutation=field), self.assertRaises(ValueError):
                        validate_contextual_refinement_v2(forged['proof'], proof_plan=forged['proof_plan'],
                                                         exact_c_slice=forged['exact_c_slice'])
                # A valid old theorem with modified retained files cannot be used.
                retained_header = root / 'diagnostics' / 'stdint.h'
                original_header = retained_header.read_bytes()
                retained_header.write_bytes(original_header + b'\n/* changed */\n')
                with self.assertRaisesRegex(ValueError, 'bound inventory'):
                    check_bisimulation_refinement(**{**captured,
                        'previous_query_evidence': root, 'diagnostic_root': root / 'corrupted-diagnostics'})
                retained_header.write_bytes(original_header)
                for mutation in ("missing-pin", "null-pin", "wrong-id", "wrong-hash", "wrong-path", "mixed-command",
                                 "mixed-array-encoding", "missing-array-option", "downgraded-option"):
                    forged = copy.deepcopy(packet)
                    changed = forged["proof"]
                    solver = changed["checker"]["smt_solver"]
                    if mutation == "missing-pin":
                        del changed["checker"]["smt_solver"]
                    elif mutation == "null-pin":
                        changed["checker"]["smt_solver"] = None
                    elif mutation == "wrong-id":
                        solver["id"] = "unchecked"
                    elif mutation == "wrong-hash":
                        solver["sha256"] = "0" * 64
                    elif mutation == "wrong-path":
                        solver["executable"] += "-changed"
                    elif mutation in ("mixed-command", "mixed-array-encoding", "missing-array-option"):
                        model = changed["models"]["operation_models"][0]["obligation_models"][0]
                        if mutation == "missing-array-option":
                            model["property_checker_command"]["entry_assertion_arguments"].remove("--no-array-field-sensitivity")
                        else:
                            model["property_checker_command"]["assertion_arguments"] += (
                                ["--sat-solver", "cadical"] if mutation == "mixed-command"
                                else ["--max-field-sensitivity-array-size", "64"])
                        model["property_checker_command_sha256"] = canonical_sha256_v3(model["property_checker_command"])
                    else:
                        changed["checker"]["options"][3] = "sat-solver=cadical"
                    changed["receipt_sha256"] = canonical_sha256_v3({k: v for k, v in changed.items() if k != "receipt_sha256"})
                    with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                        validate_contextual_refinement_v2(changed, proof_plan=forged["proof_plan"], exact_c_slice=forged["exact_c_slice"])
                    checked = run_jq_reader([jq, "-e", reader + "\nspx_contextual_proof_system"],
                        input=json.dumps(forged), text=True, capture_output=True)
                    self.assertEqual(checked.returncode, 1, (mutation, checked.stderr, checked.stdout))

    def test_solver_identity_is_explicit_and_command_safe(self):
        executable = Path(shutil.which("z3"))
        binding = bind_smt_solver(executable)
        self.assertEqual(binding["sha256"], hashlib.sha256(executable.resolve().read_bytes()).hexdigest())
        self.assertEqual(solver_arguments(), ["--sat-solver", "cadical"])
        self.assertEqual(solver_arguments(binding), ["--smt2", "--z3", "--external-smt2-solver",
                                                    str(executable.resolve()), "--no-array-field-sensitivity"])
        self.assertEqual(solver_arguments(binding, array_field_sensitive=True),
                         ["--smt2", "--z3", "--external-smt2-solver", str(executable.resolve())])
        for changed in (None, {}, {**binding, "sha256": "not-a-digest"},
                        {**binding, "executable": "z3"}, {**binding, "executable": "/tmp/z3;false"},
                        {**binding, "executable": "/tmp/z3 with args"}, {**binding, "version": "unknown"}):
            with self.subTest(binding=changed), self.assertRaises(RuntimeError):
                validate_smt_solver_binding(changed)

    def test_array_encoding_preserves_symbolic_aliases_and_bounds_checks(self):
        binding = bind_smt_solver(Path(shutil.which("z3")))
        source = '''
unsigned nondet(void) { unsigned value; __CPROVER_havoc_object(&value); return value; }
int main(void) {
  unsigned a[4] = {nondet(), nondet(), nondet(), nondet()};
  unsigned i = nondet(), j = nondet();
  __CPROVER_assume(i < 4 && j < 4);
  unsigned before = a[j];
  unsigned *alias = &a[i];
  *alias = 42;
#if defined(INVALID_ALIAS)
  __CPROVER_assert(a[j] == before, "aliased writes change the current value");
#elif defined(INVALID_BOUNDS)
  a[i + 4] = 9;
#else
  __CPROVER_assert(a[j] == (i == j ? 42 : before), "current aliased memory and frame");
#endif
  return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "arrays.c"
            path.write_text(source)
            for macro, expected in ((None, "satisfied"), ("INVALID_ALIAS", "violated"),
                                    ("INVALID_BOUNDS", "violated")):
                with self.subTest(macro=macro):
                    model = root / (str(macro) + ".goto")
                    subprocess.run([shutil.which("goto-cc"), "--i386-win32",
                                    *(["-D" + macro] if macro else []), str(path), "-o", str(model)],
                                   capture_output=True, text=True, check=True)
                    result = run_cbmc_properties(command=[shutil.which("cbmc"), str(model),
                        "--json-ui", "--trace", "--unwinding-assertions", *solver_arguments(binding)],
                        timeout_seconds=30)
                    self.assertEqual(result["status"], expected, result)
                    if macro == "INVALID_BOUNDS":
                        self.assertIn("bound", result["detail"])
