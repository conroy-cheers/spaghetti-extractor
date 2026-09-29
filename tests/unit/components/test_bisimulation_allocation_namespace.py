"""Conditional local classes reach the normal proof context without native ordinals."""

import copy
import json
from .jq_reader import run as run_jq_reader
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_allocation_classes import checked_allocation_requirements
from spaghetti_extractor.components.bisimulation_allocation_namespace import allocation_namespace_producers
from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
from spaghetti_extractor.components.bisimulation_typed_services import _proof_call_specs
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_cover, run_cbmc_properties
from spaghetti_extractor.components.contextual_bisimulation import validate_contextual_refinement_v2
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.semantic_objects.object_authority import MachineObjectAuthorityV2
from spaghetti_extractor.semantic_providers.allocation_inputs import allocation_producer_inputs
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.semantic_providers.test_allocation_inputs import inputs as preparation_inputs
from .test_bisimulation_allocation_calls import inputs as native_inputs
from .test_bisimulation_normal_exits import check_normal_exit
from .test_bisimulation_reference_authority import authority_payload

TESTKIT = {'fixtures': ('cbmc', 'compiler', 'jq'), 'resources': ('profiles/pe32-kernel32-runtime-v1.json',
    'nix/jq/strong-contextual-proof.jq')}


def inputs(*, image=False):
    prepared = preparation_inputs()
    requirements = [row['class_requirement'] for row in allocation_producer_inputs(**prepared)['classes']]
    authority = prepared['authority']
    if image:
        payload = authority_payload()
        authority = MachineObjectAuthorityV2(machine_backend='x86-pe32', bindings=payload['bindings'],
            rules=[*payload['rules'], *authority.to_payload()['rules']])
    return authority, requirements


class AllocationNamespaceTests(unittest.TestCase):
    def test_entry_history_checks_locally_and_cannot_authorize_activation(self):
        authority, requirements = inputs()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = check_normal_exit(root, cbmc=Path(shutil.which("cbmc")),
                reference_authority=authority.to_payload(), reference_allocation_requirements=requirements,
                entry_allocation_history={"maximum_instances": 2, "classes": ["text"]})
            self.assertEqual(result["status"], "satisfied", result.get("issues"))
            self.assertFalse(result["activation_authorized"])
            self.assertIn("bisimulation_entry_allocation_admission_required", str(result["issues"]))
            system = json.loads((root / "contextual-refinement-result.json").read_text())
            proof = system["proof"]
            self.assertEqual(proof["status"], "satisfied")
            self.assertFalse(proof["activation_authorized"])
            model = proof["models"]["operation_models"][0]
            self.assertEqual(model["maximum_input_allocations"], 2)
            for region in model["obligation_models"]:
                self.assertIn("spx-bisimulation-allocation-entry-input:run", region["required_assertion_descriptions"])
                self.assertIn("spx-bisimulation-allocation-entry-admission:run", region["required_assertion_descriptions"])
            forged = copy.deepcopy(proof)
            forged["activation_authorized"] = True
            forged["receipt_sha256"] = canonical_sha256_v3({k: v for k, v in forged.items() if k != "receipt_sha256"})
            with self.assertRaisesRegex(ValueError, "aggregate status"):
                validate_contextual_refinement_v2(forged, proof_plan=system["proof_plan"],
                                                  exact_c_slice=system["exact_c_slice"])
            module = Path(__file__).resolve().parents[3] / 'nix/jq/strong-contextual-proof.jq'
            for query, expected in (("spx_cut_capture_codecs", 0), ("spx_unconditional_operation_entries", 1)):
                checked = run_jq_reader([shutil.which('jq'), '-e', module.read_text() + '\n' + query],
                    input=json.dumps(system), capture_output=True, text=True, timeout=30)
                self.assertEqual(checked.returncode, expected, checked.stderr)
            for kind in ('input', 'admission'):
                missing = copy.deepcopy(system)
                row = missing['proof']['models']['operation_models'][0]['obligation_models'][0]
                row['required_assertion_descriptions'].remove(f'spx-bisimulation-allocation-entry-{kind}:run')
                checked = run_jq_reader([shutil.which('jq'), '-e', module.read_text() + '\nspx_cut_capture_codecs'],
                    input=json.dumps(missing), capture_output=True, text=True, timeout=30)
                self.assertEqual(checked.returncode, 1, checked.stderr)

    def test_local_namespace_is_explicit_and_cannot_mix_with_native_inventory(self):
        authority, requirements = inputs()
        _payload, inventory, _bindings = native_inputs()
        native = allocation_namespace_producers(authority, inventory=inventory)
        local = allocation_namespace_producers(authority, requirements=requirements)
        self.assertEqual(local, [{'selector': 1, 'family': 1, 'proof_family': 1}])
        self.assertEqual(native[0]['selector'], 2)
        with self.assertRaisesRegex(BisimulationRefinementError, 'cannot mix'):
            allocation_namespace_producers(authority, inventory=inventory, requirements=requirements)
        with self.assertRaisesRegex(BisimulationRefinementError, 'canonical object authority'):
            checked_allocation_requirements(None, requirements)

    def test_local_requirements_still_need_checked_sites_and_normal_admission(self):
        authority, requirements = inputs()
        _payload, _inventory, bindings = native_inputs()
        with self.assertRaisesRegex(BisimulationRefinementError, 'proof_service_lifetime_effect_unsupported'):
            _proof_call_specs(bindings)
        for binding in bindings:
            del binding['events'][0]['checked_external_contract']
        with self.assertRaisesRegex(BisimulationRefinementError, 'checked external site contract'):
            _world_source(max_writes=1, max_private_writes=1, max_calls=1, max_atomics=1,
                max_shadow_bytes=1, max_nul_views=1, service_bindings=bindings, private_ranges=(), image_size=131072,
                reference_authority=authority.to_payload(), reference_allocation_requirements=requirements)

    def test_rehashed_invalid_effects_stale_authority_and_duplicate_requirements_are_rejected(self):
        authority, original = inputs()
        for kind in ('authority', 'arity', 'owner', 'size', 'initialization', 'unused_size', 'extra', 'duplicate'):
            values = copy.deepcopy(original)
            row = values[0]
            if kind == 'authority': row['authority']['object'] += 1
            if kind == 'arity': row['argument_words'] = True
            if kind == 'owner': row['effect']['ownership']['owner_argument'] = 2
            if kind == 'size': row['effect']['size_value'] = True
            if kind == 'initialization': row['effect']['allocation'] = None
            if kind == 'unused_size': row['effect']['size_right_argument'] = 0
            if kind == 'extra': row['unqualified'] = True
            row['class_sha256'] = canonical_sha256_v3({key: value for key, value in row.items() if key != 'class_sha256'})
            if kind == 'duplicate': values.append(copy.deepcopy(row))
            with self.subTest(kind=kind), self.assertRaises(BisimulationRefinementError):
                checked_allocation_requirements(authority, values)

    def check_namespace(self, *, consult_runtime=False):
        cbmc = shutil.which('cbmc')
        if cbmc is None: self.skipTest('CBMC unavailable')
        authority, requirements = inputs()
        world = _world_source(max_writes=1, max_private_writes=1, max_calls=1, max_atomics=1,
            max_shadow_bytes=1, max_nul_views=1, service_bindings=(), private_ranges=(), image_size=131072,
            reference_authority=authority.to_payload(), reference_allocation_requirements=requirements)
        self.assertIn('Local allocation class namespace:', world)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / 'stdint.h')
            (root / 'state-machine-runtime.h').write_text(exact_runtime_header())
            path = root / 'namespace.c'
            path.write_text('''#include "state-machine-runtime.h"
#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)
#ifndef SPX_TEST_COVER
#define __CPROVER_cover(condition) ((void)0)
#endif
''' + world + '''
int main(void) {
  spx_proof_reset_worlds(8388608U, 256U);
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4096U, 16U, 1U, 0U, 1U) == SPX_BOUNDARY_OK,
      "diagnostic instance allocated");
  __CPROVER_assert(spx_proof_bind_allocation_authority(&spx_source_world, 4096U, 16U, 1U, 0U,
      2U, 55U, 17U) == SPX_BOUNDARY_TYPE_MISMATCH, "native ordinal cannot replace local class");
  __CPROVER_assert(spx_proof_bind_allocation_authority(&spx_source_world, 4096U, 16U, 1U, 0U,
      1U, 55U, 17U) == SPX_BOUNDARY_OK, "bind explicitly local namespace");
  spx_proof_authority_context context;
  __CPROVER_assert(spx_proof_allocation_authority_context(&spx_source_world, &context) == SPX_BOUNDARY_OK,
      "project local namespace");
  spx_machine_reference_v1 reference = {0};
  __CPROVER_assert(spx_proof_authority_resolve_reference(&context, 4099U, 1U, 1U, "text", 0U, 0U,
      &reference) == SPX_BOUNDARY_OK, "resolve conditional instance");
  __CPROVER_assert(reference.domain == 3U && reference.object == 55U && reference.generation == 17U &&
      reference.offset == 3U && reference.extent == 16U && reference.permissions == 3U, "full logical tuple");
''' + ('''
  spx_runtime runtime = spx_proof_runtime(&spx_source_world);
  (void)runtime.resolve_reference(runtime.context, 4099U, 1U, 1U, "text", 0U, 0U, &reference);
''' if consult_runtime else '') + '__CPROVER_cover(1);\n}\n')
            command = [cbmc, str(path), '--json-ui', '--unwind', '7', '--sat-solver', 'cadical']
            result = run_cbmc_properties(command=[*command, '--trace', '--unwinding-assertions', '--bounds-check',
                '--pointer-check', '--signed-overflow-check'], timeout_seconds=30)
            self.assertEqual(result['status'], 'violated' if consult_runtime else 'satisfied', result.get('detail'))
            if consult_runtime:
                self.assertIn('spx-bisimulation-reference-locator-qualified', result.get('detail', ''))
            else:
                cover = run_cbmc_cover(command=[*command, '-DSPX_TEST_COVER', '--cover', 'cover'],
                                       expected_functions=['main'], timeout_seconds=30)
                self.assertEqual(cover['status'], 'satisfied', cover)

    def test_local_instance_projection_uses_shared_resolver(self):
        self.check_namespace()

    def test_conditional_class_and_instance_do_not_open_runtime_admission(self):
        self.check_namespace(consult_runtime=True)

    def test_normal_checker_binds_classes_and_rejects_missing_evidence(self):
        cbmc = shutil.which('cbmc')
        if cbmc is None: self.skipTest('CBMC unavailable')
        authority, requirements = inputs(image=True)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = check_normal_exit(root, cbmc=Path(cbmc), reference_authority=authority.to_payload(),
                reference_allocation_requirements=requirements, reference_view=True)
            self.assertEqual(result['status'], 'satisfied', result.get('issues'))
            artifact = json.loads((root / 'contextual-refinement-result.json').read_text())
            proof = artifact['proof']
            self.assertEqual(proof['models']['reference_allocation_requirements'], requirements)
            self.assertEqual(proof['models']['reference_allocation_requirements_sha256'], canonical_sha256_v3(requirements))
            for model in proof['models']['operation_models'][0]['obligation_models']:
                self.assertEqual([row for row in model['proof_inputs'] if row['role'] == 'allocation_class_requirements'],
                    [{'role': 'allocation_class_requirements', 'sha256': canonical_sha256_v3(requirements)}])
                for field in ('proof_inputs', 'nonvacuity_proof_inputs'):
                    model[field] = [row for row in model[field] if row['role'] != 'allocation_class_requirements']
                model['proof_model_sha256'] = canonical_sha256_v3(model['proof_inputs'])
                model['nonvacuity_proof_model_sha256'] = model['proof_model_sha256']
            proof['receipt_sha256'] = canonical_sha256_v3({k: v for k, v in proof.items() if k != 'receipt_sha256'})
            with self.assertRaisesRegex(ValueError, 'allocation class requirement input'):
                validate_contextual_refinement_v2(proof, proof_plan=artifact['proof_plan'], exact_c_slice=artifact['exact_c_slice'])
