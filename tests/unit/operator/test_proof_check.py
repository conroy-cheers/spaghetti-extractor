"""Ordinary regional diagnostics preserve coverage and exact query reuse."""
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
from spaghetti_extractor.components.bisimulation_refinement import check_bisimulation_refinement
from spaghetti_extractor.components.bisimulation_query_evidence import previous_proof_queries
from spaghetti_extractor.components.contextual_bisimulation import build_contextual_refinement_v2, validate_contextual_refinement_v2
from spaghetti_extractor.operator.proof_check import retain_component_proof
from tests.unit.components.jq_reader import run as run_jq
from tests.unit.components.test_bisimulation_normal_exits import check_normal_exit
from tests.unit.components.test_bisimulation_reference_authority import authority_payload

TESTKIT = {'fixtures': ('cbmc', 'compiler', 'jq'), 'commands': ('component check',),
           'resources': ('nix/jq/strong-contextual-proof.jq',)}


class OrdinaryProofCheckTests(unittest.TestCase):
    def test_public_focus_negatives_and_complete_check_reuse(self):
        cbmc, jq = shutil.which('cbmc'), shutil.which('jq')
        if cbmc is None or jq is None: self.skipTest('CBMC and JQ required')
        selection = [{'operation_id': 'run', 'obligation_id': 'sync:cut'}]
        reader = Path('nix/jq/strong-contextual-proof.jq').read_text() + '\nspx_strong_contextual_proof\n'
        def strong(packet):
            return run_jq([jq, '-e', reader], input=json.dumps(packet), text=True, capture_output=True).returncode == 0
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); focused = root/'focused'; focused.mkdir(); inputs = {}
            def execute(**kwargs):
                inputs.update(kwargs)
                return check_bisimulation_refinement(**kwargs, selected_obligations=selection)
            with patch('tests.unit.components.test_bisimulation_normal_exits.check_bisimulation_refinement', side_effect=execute):
                result = check_normal_exit(focused, cbmc=Path(cbmc), reference_view=True, reference_authority=authority_payload())
            self.assertEqual(result['status'], 'incomplete')
            packet = json.loads((focused/'contextual-refinement-result.json').read_text())
            proof = packet['proof']
            self.assertFalse(proof['activation_authorized']); self.assertFalse(strong(packet))
            self.assertEqual(len(proof['shards']), 2)
            deferred, checked = proof['shards']
            self.assertEqual(deferred['code'], 'proof_region_deferred')
            self.assertIsNone(deferred['goto_model_sha256'])
            self.assertEqual(checked['status'], 'satisfied')
            self.assertFalse((focused/'diagnostics/operation-0000-obligation-0000/query-timings.jsonl').exists())
            self.assertEqual(set(previous_proof_queries(focused)), {('run', 'sync:cut')})
            path = focused/'contextual-proof-diagnostic.json'; path.write_text(json.dumps(proof))
            # Local packages are snapshotted with member bytes, including links,
            # before Nix imports them. A foreign or stale proof never reaches import.
            member = root/'external-member'; member.write_text('retained bytes')
            (focused/'linked-member').symlink_to(member)
            def inspect_import(command):
                snapshot = Path(command[-1])
                self.assertEqual((snapshot/'linked-member').read_text(), 'retained bytes')
                self.assertFalse((snapshot/'linked-member').is_symlink())
                self.assertEqual(json.loads((snapshot/'contextual-refinement-result.json').read_text()), packet)
                raise LookupError('import inspected')
            with self.assertRaisesRegex(LookupError, 'import inspected'):
                retain_component_proof(path=focused, component_id='counter', capture=inspect_import)
            (focused/'linked-member').unlink()
            with self.assertRaisesRegex(ValueError, 'another component'):
                retain_component_proof(path=focused, component_id='foreign', capture=inspect_import)
            index = {'components': {'units': {'counter': {'products': ['proofCheckFor']}}}}
            with patch('spaghetti_extractor.commands.workflows._operator_index', return_value=index), patch(
                    'spaghetti_extractor.commands.workflows._realize_artifact', return_value=(path, proof)) as realize:
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(main(['component', 'check', 'fixture', 'counter', '--region', 'run/sync:cut',
                                           '--query-timeout', '25']), 1)
                self.assertIn('activation=no', output.getvalue())
                self.assertEqual(realize.call_args.kwargs['apply_arguments'],
                                 {'obligations': selection, 'queryTimeoutSeconds': 25})
            for mutation in ('missing-region', 'missing-selection', 'unknown-selection', 'deferred-success',
                             'deferred-evidence', 'stale-model', 'activate'):
                changed = copy.deepcopy(packet); value = changed['proof']; shard = value['shards'][0]
                if mutation == 'missing-region': value['shards'].pop(0)
                elif mutation == 'missing-selection': del value['models']['diagnostic_selection']
                elif mutation == 'unknown-selection': value['models']['diagnostic_selection'][0]['obligation_id'] = 'unknown'
                elif mutation == 'deferred-success': shard['status'] = 'satisfied'
                elif mutation == 'deferred-evidence': shard['partitioned_evidence'] = checked['partitioned_evidence']
                elif mutation == 'stale-model': shard['proof_model_sha256'] = '0'*64
                else: value.update(status='satisfied', activation_authorized=True)
                value['receipt_sha256'] = canonical_sha256_v3({k:v for k,v in value.items() if k != 'receipt_sha256'})
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    validate_contextual_refinement_v2(value, proof_plan=changed['proof_plan'], exact_c_slice=changed['exact_c_slice'])
                self.assertFalse(strong(changed), mutation)
            damaged = copy.deepcopy(packet)
            damaged['proof']['receipt_sha256'] = '0'*64
            (focused/'contextual-refinement-result.json').write_text(json.dumps(damaged))
            with self.assertRaisesRegex(ValueError, 'cannot reuse component proof'):
                retain_component_proof(path=focused, component_id='counter', capture=inspect_import)
            (focused/'contextual-refinement-result.json').write_text(json.dumps(packet))

            full = root/'full'; full.mkdir()
            complete = check_bisimulation_refinement(**{**inputs, 'diagnostic_root': full/'diagnostics'},
                                                    previous_query_evidence=focused)
            self.assertEqual(complete['status'], 'satisfied')
            complete_proof = build_contextual_refinement_v2(proof_plan=packet['proof_plan'], exact_c_slice=packet['exact_c_slice'],
                implementation_sha256=proof['bindings']['implementation_sha256'],
                source_profile_sha256=proof['bindings']['source_profile_sha256'], checker=complete['checker'],
                models=complete['bindings'], shard_results=complete['checks'], world=proof['world'])
            complete_packet = {**packet, 'proof': complete_proof}
            self.assertTrue(strong(complete_packet))
            (full/'contextual-refinement-result.json').write_text(json.dumps(complete_packet))
            reused = json.loads((full/'diagnostics/operation-0000-obligation-0001/query-evidence/reuse.json').read_text())
            self.assertEqual(reused['executed_queries'], 0)
            self.assertGreater(reused['reused_queries'], 0)
            # Selecting every region still produces diagnostics, even with a
            # complete reusable predecessor available.
            all_selected = [{'operation_id': row['operation_id'], 'obligation_id': row['obligation_id']}
                            for row in complete['checks']]
            all_result = check_bisimulation_refinement(**{**inputs, 'diagnostic_root': root/'all-diagnostics'},
                previous_query_evidence=full, selected_obligations=all_selected)
            self.assertEqual(all_result['status'], 'incomplete')
            self.assertFalse(all_result['activation_authorized'])
            self.assertTrue(all(row['status'] == 'satisfied' for row in all_result['checks']))


if __name__ == '__main__': unittest.main()
