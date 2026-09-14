"""External lifetime contracts survive lowering and cannot use a scalar oracle."""

import copy
import json
import shutil
import subprocess
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
from spaghetti_extractor.components.bisimulation_typed_services import _proof_call_specs, _trusted_adapter_lowering_receipt
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.contextual_bisimulation import _trusted_adapter_lowering_used
from spaghetti_extractor.components.bisimulation import ComponentBisimulationError
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from . import test_bisimulation_service_preconditions as preconditions_fixture

TESTKIT = {"fixtures": ("jq",), "resources": (
    "targets/gnu-hello/intent/interfaces-v5/program-name-selection.json",
    "tests/fixtures/hand-defined-boundaries/resource-text",
    "nix/jq/strong-contextual-proof.jq",)}


def typed_model():
    fixture = preconditions_fixture.ServicePreconditionTests()
    fixture.setUp()
    selected = {**fixture.binding, "abi_sha256": "a" * 64}
    receipt = _trusted_adapter_lowering_receipt(interface=fixture.interface,
        service_bindings=[selected], production_overlay_source="production fixture",
        proof_overlay_source="proof fixture")
    return {"interface_sha256": fixture.interface.sha256,
            "machine_overlay_sha256": receipt["production_overlay_sha256"],
            "proof_overlay_sha256": receipt["proof_overlay_sha256"],
            "trusted_adapter_lowering": receipt}


def rehash_model(model):
    receipt = model['trusted_adapter_lowering']
    for adapter in receipt['adapter_plan']:
        adapter['checked_binding_sha256'] = canonical_sha256_v3(adapter['checked_binding'])
        adapter['proof_call_specs_sha256'] = canonical_sha256_v3(adapter['proof_call_specs'])
        adapter['adapter_sha256'] = canonical_sha256_v3({k: v for k, v in adapter.items() if k != 'adapter_sha256'})
    receipt['adapter_plan_sha256'] = canonical_sha256_v3(receipt['adapter_plan'])
    receipt['receipt_sha256'] = canonical_sha256_v3({k: v for k, v in receipt.items() if k != 'receipt_sha256'})


def binding(payload):
    return {"service_id": "operation", "provider_kind": "external_call",
            "abi_template": "pe32-cdecl-v1", "abi_sha256": "a" * 64,
            "argument_offsets": [0], "external_effect_contract": payload,
            "external_contract_identity_sha256": "b" * 64,
            "events": [{"instruction_rva": 100, "event_index": 0, "return_rva": 105}]}


class ProofServiceEffectTests(unittest.TestCase):
    def test_unused_termination_inventory_is_absent_and_exact_legacy_superset_is_accepted(self):
        import hashlib
        from spaghetti_extractor.components.bisimulation_terminated_reads import terminated_read_implementation_paths
        model = typed_model()
        renderer = model['trusted_adapter_lowering']['renderer']
        self.assertNotIn('terminated_reads.py', [row['path'] for row in renderer['implementation_files']])
        for legacy in (False, True):
            if legacy:
                paths = {row['path']: row for row in renderer['implementation_files']}
                paths.update({path.name: {'path': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                              for path in terminated_read_implementation_paths()})
                renderer['implementation_files'] = [paths[name] for name in sorted(paths)]
                renderer['implementation_closure_sha256'] = canonical_sha256_v3(renderer['implementation_files'])
                rehash_model(model)
            self.assertTrue(_trusted_adapter_lowering_used(model))
            checked = subprocess.run([shutil.which('jq'), '-L', 'nix/jq',
                'include "strong-contextual-proof"; spx_typed_adapter_renderer_inventory'],
                input=json.dumps(model['trusted_adapter_lowering']), capture_output=True, text=True, check=True)
            self.assertIs(json.loads(checked.stdout), True)

    def test_written_termination_requires_its_complete_inventory_in_both_readers(self):
        from .test_bisimulation_terminated_writes import binding as written_binding
        from .test_hand_defined_boundaries import shared_buffer_bundle
        from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
        from spaghetti_extractor.components.refinement_v5 import _logical_projection
        interface = ProofKernelComponentInterface.parse(_logical_projection(shared_buffer_bundle()))
        receipt = _trusted_adapter_lowering_receipt(interface=interface,
            service_bindings=[{**written_binding(), 'symbol': 'load_string'}],
            production_overlay_source='native output adapter', proof_overlay_source='typed output adapter')
        for omitted in (None, 'terminated_reads.py', 'bisimulation_terminated_reads.py', 'bisimulation_image_frame.py'):
            altered = copy.deepcopy(receipt)
            model = {'interface_sha256': interface.sha256, 'trusted_adapter_lowering': altered,
                'machine_overlay_sha256': altered['production_overlay_sha256'],
                'proof_overlay_sha256': altered['proof_overlay_sha256']}
            if omitted:
                renderer = altered['renderer']
                self.assertIn(omitted, [row['path'] for row in renderer['implementation_files']])
                renderer['implementation_files'] = [row for row in renderer['implementation_files'] if row['path'] != omitted]
                renderer['implementation_closure_sha256'] = canonical_sha256_v3(renderer['implementation_files'])
                rehash_model(model)
                with self.assertRaisesRegex(ComponentBisimulationError, 'renderer closure'):
                    _trusted_adapter_lowering_used(model)
            else:
                self.assertTrue(_trusted_adapter_lowering_used(model))
            checked = subprocess.run([shutil.which('jq'), '-L', 'nix/jq',
                'include "strong-contextual-proof"; spx_typed_adapter_renderer_inventory'],
                input=json.dumps(altered), capture_output=True, text=True, check=True)
            self.assertIs(json.loads(checked.stdout), omitted is None)

    def test_explicit_read_ranges_require_all_consumer_guards_in_both_readers(self):
        from .test_bisimulation_call_ranges import buffer_binding
        from .test_hand_defined_boundaries import shared_buffer_bundle
        from spaghetti_extractor.components.bisimulation_call_ranges import readable_range_descriptions
        from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
        from spaghetti_extractor.components.refinement_v5 import _logical_projection
        bundle = shared_buffer_bundle()
        interface = ProofKernelComponentInterface.parse(_logical_projection(bundle))
        selected = {**buffer_binding(), 'symbol': 'scan_buffer'}
        effect = selected['external_effect_contract']
        effect['memory_effect'] = 'readOnly'
        effect['memory_footprints'][0]['access'] = 'read'
        receipt = _trusted_adapter_lowering_receipt(interface=interface, service_bindings=[selected],
            production_overlay_source='native read-range adapter', proof_overlay_source='typed read-range adapter')
        required = readable_range_descriptions(_proof_call_specs([selected]))
        self.assertEqual(len(required), 1)
        model = {'interface_sha256': interface.sha256, 'trusted_adapter_lowering': receipt,
            'machine_overlay_sha256': receipt['production_overlay_sha256'],
            'proof_overlay_sha256': receipt['proof_overlay_sha256'],
            'operation_models': [{'obligation_models': [
                {'required_assertion_descriptions': required},
                {'required_assertion_descriptions': required}]}]}
        for mutation in ('none', 'no-operations', 'no-segments', 'missing-guard', 'generic-guard', 'missing-closure'):
            altered = copy.deepcopy(model)
            if mutation == 'no-operations':
                altered['operation_models'] = []
            elif mutation == 'no-segments':
                altered['operation_models'][0]['obligation_models'] = []
            elif mutation in ('missing-guard', 'generic-guard'):
                altered['operation_models'][0]['obligation_models'][1]['required_assertion_descriptions'] = (
                    ['spx-bisimulation-call-buffer-authority'] if mutation == 'generic-guard' else [])
            elif mutation == 'missing-closure':
                renderer = altered['trusted_adapter_lowering']['renderer']
                renderer['implementation_files'] = [row for row in renderer['implementation_files']
                    if row['path'] != 'bisimulation_call_ranges.py']
                renderer['implementation_closure_sha256'] = canonical_sha256_v3(renderer['implementation_files'])
                rehash_model(altered)
            with self.subTest(mutation=mutation):
                if mutation == 'none':
                    self.assertTrue(_trusted_adapter_lowering_used(altered))
                else:
                    with self.assertRaises(ComponentBisimulationError):
                        _trusted_adapter_lowering_used(altered)
                query = 'include "strong-contextual-proof"; . as $models | '
                query += '(.trusted_adapter_lowering | spx_typed_adapter_renderer_inventory) and '
                query += 'all(.trusted_adapter_lowering.adapter_plan[]; spx_declared_external_range_effects($models))'
                checked = subprocess.run([shutil.which('jq'), '-L', 'nix/jq', query],
                    input=json.dumps(altered), text=True, capture_output=True, timeout=10)
                self.assertEqual(checked.returncode, 0, checked.stderr)
                self.assertIs(json.loads(checked.stdout), mutation == 'none')

    def test_both_readers_require_shared_view_adapter_implementation_closure(self):
        jq = shutil.which("jq")
        self.assertIsNotNone(jq)
        for omitted in (None, "bisimulation_world_memory.py",
                        "bisimulation_reference_origins.py", "machine_overlay_boundaries_v5.py", "machine_overlay_result_views.py",
                        "machine_overlay_state_views.py"):
            model = typed_model()
            if omitted is not None:
                renderer = model["trusted_adapter_lowering"]["renderer"]
                renderer["implementation_files"] = [row for row in renderer["implementation_files"] if row["path"] != omitted]
                renderer["implementation_closure_sha256"] = canonical_sha256_v3(renderer["implementation_files"])
                rehash_model(model)
                with self.assertRaises(ComponentBisimulationError):
                    _trusted_adapter_lowering_used(model)
            else:
                self.assertTrue(_trusted_adapter_lowering_used(model))
            checked = subprocess.run([jq, "-L", str(Path(__file__).parents[3] / "nix/jq"),
                'include "strong-contextual-proof"; spx_typed_adapter_renderer_inventory'],
                input=json.dumps(model["trusted_adapter_lowering"]), capture_output=True, text=True, timeout=10)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertEqual(json.loads(checked.stdout), omitted is None)

    def test_adapter_receipt_binds_borrowed_input_realization_implementation(self):
        for path in ('bisimulation_service_preconditions.py',
                     'bisimulation_world_memory.py', 'bisimulation_reference_origins.py',
                     'machine_overlay_boundaries_v5.py',
                     'machine_overlay_result_views.py', 'machine_overlay_state_views.py'):
            model = typed_model()
            self.assertTrue(_trusted_adapter_lowering_used(model))
            renderer = model['trusted_adapter_lowering']['renderer']
            self.assertIn(path, [row['path'] for row in renderer['implementation_files']])
            renderer['implementation_files'] = [row for row in renderer['implementation_files'] if row['path'] != path]
            renderer['implementation_closure_sha256'] = canonical_sha256_v3(renderer['implementation_files'])
            rehash_model(model)
            with self.subTest(path=path), self.assertRaisesRegex(ComponentBisimulationError, 'renderer closure'):
                _trusted_adapter_lowering_used(model)

    def test_typed_receipt_accepts_new_shape_and_rejects_rehashed_effect_loss(self):
        model = typed_model()
        self.assertTrue(_trusted_adapter_lowering_used(model))
        for mutation in ('missing-binding', 'missing-spec', 'changed-contract', 'release', 'missing-identity', 'changed-identity', 'missing-spec-identity'):
            altered = copy.deepcopy(model)
            adapter = altered['trusted_adapter_lowering']['adapter_plan'][0]
            if mutation == 'missing-identity':
                del adapter['checked_binding']['external_contract_identity_sha256']
            elif mutation == 'changed-identity':
                adapter['checked_binding']['external_contract_identity_sha256'] = 'c' * 64
            elif mutation == 'missing-spec-identity':
                del adapter['proof_call_specs'][0]['external_contract_identity_sha256']
            elif mutation == 'missing-binding':
                del adapter['checked_binding']['external_effect_contract']
            elif mutation == 'missing-spec':
                del adapter['proof_call_specs'][0]['external_effect_contract']
            else:
                adapter['checked_binding']['external_effect_contract']['world_effect'] = (
                    'dynamicRangeRelease' if mutation == 'release' else 'changed-fixture')
            rehash_model(altered)
            with self.subTest(mutation=mutation), self.assertRaises(ComponentBisimulationError):
                _trusted_adapter_lowering_used(altered)

    def test_missing_effect_contract_and_malformed_categories_fail_before_rendering(self):
        payload = {"memory_effect": "readOnly", "world_effect": "none"}
        missing = binding(payload)
        del missing["external_effect_contract"]
        with self.assertRaisesRegex(BisimulationRefinementError, "selected external effect contract"):
            _proof_call_specs([missing])
        for bad in (None, {}, {"memory_effect": "none"}, {"world_effect": "none"},
                    {**payload, "result_register_relations": None},
                    {**payload, "out_pointer_relations": None}):
            with self.subTest(payload=bad), self.assertRaises(BisimulationRefinementError):
                _proof_call_specs([binding(bad)])

    def test_selected_effect_contract_changes_behavior_identity_and_is_retained(self):
        payload = {"memory_effect": "readOnly", "world_effect": "none",
                   "memory_footprints": [{"argument": 0, "extent": 4}]}
        original = _proof_call_specs([binding(payload)])[0]
        self.assertEqual(original["external_effect_contract"], payload)
        changed = copy.deepcopy(payload)
        changed["memory_footprints"][0]["extent"] = 8
        altered = _proof_call_specs([binding(changed)])[0]
        self.assertNotEqual(original["behavior_sha256"], altered["behavior_sha256"])
        self.assertNotEqual(original["spec_id"], altered["spec_id"])
        # Physical call-site movement remains independent of the selected effect.
        relocated = binding(payload)
        relocated["events"][0].update(instruction_rva=200, return_rva=205)
        self.assertEqual(original["spec_id"], _proof_call_specs([relocated])[0]["spec_id"])

    def test_lifetime_effects_cannot_become_scalar_response_world_calls(self):
        pure = {"memory_effect": "none", "world_effect": "none"}
        release = {"success": "always", "argument_equals": [],
                   "ownership": {"family": "fixture.heap", "owner_argument": None}}
        for update in ({"world_effect": "dynamicRanges"},
                       {"world_effect": "dynamicRangeRelease", "world_effect_argument": 0,
                        "world_effect_release": release},
                       {"world_effect_release": release},
                       {"result_register_relations": [{"relation": "dynamic_range_base"}]},
                       {"out_pointer_relations": [{"relation": "nullable_dynamic_pointer"}]}):
            with self.subTest(update=update), self.assertRaisesRegex(
                    BisimulationRefinementError, "proof_service_lifetime_effect_unsupported"):
                _world_source(max_writes=1, max_private_writes=1, max_calls=1,
                    max_atomics=1, max_shadow_bytes=1, max_nul_views=1,
                    service_bindings=[binding({**pure, **update})], private_ranges=())

    def test_connected_provider_has_no_external_contract_to_invent(self):
        self.assertEqual(_proof_call_specs([{"provider_kind": "component_operation"}]), [])

    def test_native_contract_identity_is_required_and_separates_call_behaviors(self):
        selected = binding({"memory_effect": "none", "world_effect": "none"})
        original = _proof_call_specs([selected])[0]
        self.assertEqual(original["external_contract_identity_sha256"], "b" * 64)
        for identity in (None, "", "b" * 63, "B" * 64, 123):
            altered = {**selected, "external_contract_identity_sha256": identity}
            with self.subTest(identity=identity), self.assertRaisesRegex(
                    BisimulationRefinementError, "canonical external contract identity"):
                _proof_call_specs([altered])
        altered = _proof_call_specs([{**selected, "external_contract_identity_sha256": "c" * 64}])[0]
        self.assertNotEqual(original["behavior_sha256"], altered["behavior_sha256"])
        self.assertNotEqual(original["spec_id"], altered["spec_id"])
