"""Resume a real interrupted proof without treating its partial result as a theorem."""

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_query_evidence import CbmcQueryEvidence, previous_proof_queries
from spaghetti_extractor.components.bisimulation_refinement import check_bisimulation_refinement
from spaghetti_extractor.components.contextual_bisimulation import build_contextual_refinement_v2
from . import test_bisimulation_normal_exits as fixture

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"),
           "resources": ("nix/jq/strong-contextual-proof.jq",)}


class PartialQueryReuseTests(unittest.TestCase):
    def test_completed_queries_resume_but_the_timeout_must_be_checked(self):
        self.check_resume('assertion')

    def test_safety_exhaustion_returns_a_reusable_incomplete_receipt(self):
        self.check_resume('safety')

    def check_resume(self, phase):
        cbmc = shutil.which("cbmc")
        self.assertIsNotNone(cbmc)
        original_run = CbmcQueryEvidence.run
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            captured = {}
            interrupted = []

            def check(**kwargs):
                captured.update(kwargs, proof_workspace=root / "staging")
                return check_bisimulation_refinement(**captured)

            def interrupt(evidence, command, **kwargs):
                if "--property" in command and not interrupted:
                    selected = command[command.index("--property") + 1]
                    if phase == 'safety' and '--no-assertions' in command and '.array_bounds.' in selected:
                        if command.count('--property') == 1:
                            interrupted.append(selected)
                        raise subprocess.TimeoutExpired(command, 1, output=b"exhausted test safety query")
                    if phase == 'assertion' and selected.startswith("spx_bisimulation_check_0000.assertion."):
                        interrupted.append(selected)
                        raise subprocess.TimeoutExpired(command, 1, output=b"interrupted test query")
                return original_run(evidence, command, **kwargs)

            with patch.object(fixture, "check_bisimulation_refinement", side_effect=check), patch.object(
                    CbmcQueryEvidence, "run", interrupt):
                first = fixture.check_normal_exit(root, cbmc=Path(cbmc))
            self.assertEqual(first["status"], "incomplete", first["issues"])
            self.assertEqual(len(interrupted), 1)
            old_path = root / "contextual-refinement-result.json"
            previous_bytes = old_path.read_bytes()
            old = json.loads(previous_bytes)
            self.assertFalse(old["proof"]["activation_authorized"])
            self.assertTrue(previous_proof_queries(root))
            if phase == 'safety':
                partitioned = old['proof']['shards'][0]['partitioned_evidence']
                self.assertTrue(any(row['status'] == 'incomplete' for row in partitioned['queries']))
                self.assertFalse(any(row['kind'] == 'authored_assertion' for row in partitioned['queries']))
                reader = Path(__file__).resolve().parents[3] / TESTKIT['resources'][0]
                for predicate, expected in [('spx_contextual_proof_system', 0), ('spx_strong_contextual_proof', 1)]:
                    run = subprocess.run([shutil.which('jq'), '-e', reader.read_text() + '\n' + predicate, str(old_path)],
                                         capture_output=True, text=True)
                    self.assertEqual(run.returncode, expected, run.stderr)
                # Rehashing all statuses cannot turn the unexecuted inventory
                # into a proof, even when each retained query is painted green.
                forged = json.loads(previous_bytes)
                shard = forged['proof']['shards'][0]
                shard.update(status='satisfied', code='cbmc_properties_satisfied')
                for query in shard['partitioned_evidence']['queries']:
                    query.update(status='satisfied', code='cbmc_properties_satisfied')
                    if query['kind'] == 'language_safety':
                        query['property_ids'] = query['expected_property_ids']
                        query['properties'] = len(query['property_ids'])
                shard['output_sha256'] = canonical_sha256_v3(shard['partitioned_evidence'])
                proof = forged['proof']
                with self.assertRaisesRegex(ValueError, 'partition|property'):
                    build_contextual_refinement_v2(proof_plan=forged['proof_plan'], exact_c_slice=forged['exact_c_slice'],
                        implementation_sha256=proof['bindings']['implementation_sha256'],
                        source_profile_sha256=proof['bindings']['source_profile_sha256'],
                        checker=proof['checker'], models=proof['models'], shard_results=proof['shards'], world=proof['world'])
                proof.update(status='satisfied', activation_authorized=True)
                proof['receipt_sha256'] = canonical_sha256_v3({k: v for k, v in proof.items() if k != 'receipt_sha256'})
                run = subprocess.run([shutil.which('jq'), '-e', reader.read_text() + '\nspx_contextual_proof_system'],
                                     input=json.dumps(forged), capture_output=True, text=True)
                self.assertEqual(run.returncode, 1, run.stderr)
                # A forged root activation flag must also reject when the
                # shard remains explicitly incomplete, even with green leaves.
                shard['status'] = 'incomplete'
                run = subprocess.run([shutil.which('jq'), '-e', reader.read_text() + '\nspx_strong_contextual_proof'],
                                     input=json.dumps(forged), capture_output=True, text=True)
                self.assertEqual(run.returncode, 1, run.stderr)
            promoted = json.loads(previous_bytes)
            promoted["proof"]["activation_authorized"] = True
            promoted["proof"]["receipt_sha256"] = canonical_sha256_v3({
                key: value for key, value in promoted["proof"].items() if key != "receipt_sha256"})
            old_path.write_text(json.dumps(promoted))
            with self.assertRaisesRegex(ValueError, "previous query proof"):
                previous_proof_queries(root)
            old_path.write_bytes(previous_bytes)

            # Compilation and current parsing still run. The timeout and queries
            # skipped after it must execute; completed queries must be reused.
            completed = {tuple(json.loads(path.read_text())["binding"]["arguments"][1:])
                         for path in (root / "diagnostics").rglob("query.json")}
            process_run = subprocess.run
            fresh = []

            def restricted(command, **kwargs):
                if Path(command[0]).name == "cbmc" and "--version" not in command:
                    self.assertNotIn(tuple(command[2:]), completed)
                    fresh.append(command)
                return process_run(command, **kwargs)

            with patch("spaghetti_extractor.components.bisimulation_query_evidence.subprocess.run", side_effect=restricted):
                result = check_bisimulation_refinement(**{**captured,
                    "diagnostic_root": root / "resumed", "previous_query_evidence": root})
            self.assertEqual(result["status"], "satisfied", result["issues"])
            self.assertTrue(any("--property" in command and
                command[command.index("--property") + 1] == interrupted[0] for command in fresh))
            reuse = json.loads(next((root / "resumed").rglob("reuse.json")).read_text())
            self.assertGreater(reuse["reused_queries"], 0)
            self.assertEqual(reuse["executed_queries"], len(fresh))
            self.assertFalse(reuse["authorizing"])
            self.assertEqual(old_path.read_bytes(), previous_bytes)

            # Incomplete receipts receive the same validation as completed ones.
            old["proof"]["receipt_sha256"] = "f" * 64
            old_path.write_text(json.dumps(old))
            with self.assertRaisesRegex(ValueError, "previous query proof"):
                previous_proof_queries(root)
