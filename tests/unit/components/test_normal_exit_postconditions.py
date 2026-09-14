"""An authored alias fact requires the matching checked exit guards and proof."""

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.binding_intent import ComponentMachineBindingIntentV1
from spaghetti_extractor.components.normalized_component import NormalizedMachineBinding
from spaghetti_extractor.components.relation_v5 import ComponentRelationIntentV1
from spaghetti_extractor.semantic_providers.portable_c_work_package import _checked_relation_boundary_operations
from spaghetti_extractor.semantic_providers.portable_c_postconditions import (
    checked_provider_postconditions, validate_provider_postconditions,
    validate_provider_postcondition_request,
)
from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
from spaghetti_extractor.components.refinement_v5 import _logical_projection
from . import borrowed_state_fixture as fixture
from .test_hand_defined_boundaries import FIXTURE

TESTKIT = {"fixtures": ("cbmc", "compiler"), "resources": (
    "tests/fixtures/hand-defined-boundaries/resource-text",)}


class NormalExitPostconditionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cbmc = shutil.which("cbmc")
        if cbmc is None:
            raise unittest.SkipTest("CBMC is unavailable")
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        result, cls.proof = fixture.check_borrowed_state(cls.root, cbmc=Path(cbmc))
        if result['status'] != 'satisfied':
            raise AssertionError(result['issues'])
        cls.bundle, cls.binding, contract, _, transfer, _, _ = fixture.prepare_borrowed_state()
        cls.machine = NormalizedMachineBinding.create(bundle=cls.bundle, contract=contract,
            artifacts={key: 'a' * 64 for key in ('pe_sha256', 'machine_ir_sha256', 'machine_ir_manifest_sha256',
                'structural_units_sha256', 'unit_inventory_sha256', 'component_unit_inventory_sha256')},
            operation_authority={'get': {**dict(cls.binding.operations[0].authority),
                'service_ids': [], 'callback_ids': [], 'outcome_protocol_ids': []}})
        cls.transfers = [transfer]
        cls.intent = ComponentRelationIntentV1.parse(json.loads((FIXTURE/'relation.json').read_text()))

    def derive(self, **changes):
        arguments = dict(intent=self.intent, bundle=self.bundle, binding=self.binding,
            proof_system=self.proof, transfers=self.transfers, machine_binding=self.machine,
            operation_symbols={'get': 'borrowed_get'})
        arguments.update(changes)
        return arguments.pop("intent").checked_normal_exit_views(**arguments)

    def test_real_boundary_fact_follows_from_paired_fixture_exit_guards(self):
        facts = self.derive()
        self.assertEqual(len(facts), 1)
        self.assertTrue(facts[0]['normal_exit_only'])
        self.assertEqual(facts[0]['proof_receipt_sha256'], self.proof['proof']['receipt_sha256'])
        self.assertEqual(facts[0]['expression'], self.intent.operations[0]['requirements'][0]['expression'])
        self.assertEqual(ComponentRelationIntentV1.parse(self.intent.to_payload()), self.intent)
        self.assertFalse(self.intent.to_payload()['policy']['intent_authorizes'])

    def test_same_signature_does_not_prove_a_different_alias_or_invented_fact(self):
        for mutation in ('wrong-state', 'foreign-result', 'wrong-type', 'stronger-predicate'):
            operations = copy.deepcopy(list(self.intent.operations))
            expression = operations[0]['requirements'][0]['expression']
            if mutation == 'wrong-state': expression['args'][1]['attributes']['path']['id'] = 'module'
            elif mutation == 'foreign-result': expression['args'][0]['attributes']['path']['id'] = 'other'
            elif mutation == 'wrong-type':
                for term in expression['args']: term['sort']['type_id'] = 'foreign'
            else:
                operations[0]['requirements'][0]['expression'] = {'op': 'not', 'sort': {'kind': 'bool'},
                    'args': [expression], 'attributes': {}}
            altered = ComponentRelationIntentV1.create(component_id='resource-text', operations=operations, blockers=[])
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.derive(intent=altered)

    def test_postcondition_authoring_requires_a_logical_boolean_expression(self):
        operations = copy.deepcopy(list(self.intent.operations))
        requirement = operations[0]['requirements'][0]
        view = requirement['expression']['args'][0]
        machine = {'op': 'machine', 'sort': {'kind': 'bitvector', 'width': 32}, 'args': [],
            'attributes': {'place': {'kind': 'register', 'phase': 'exit', 'width': 32,
                                    'selector': {'register': 'eax'}}}}
        for expression in (view, {'op': 'eq', 'sort': {'kind': 'bool'},
                                 'args': [machine, machine], 'attributes': {}}):
            requirement['expression'] = expression
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                ComponentRelationIntentV1.create(component_id='resource-text', operations=operations, blockers=[])

    def test_changed_binding_or_overlay_cannot_reuse_the_fact(self):
        payload = self.binding.to_payload()
        operations = copy.deepcopy(payload['operations'])
        operations[0]['entry_rvas'] = [0x1285]
        changed = ComponentMachineBindingIntentV1.create(component_id='resource-text', operations=operations, blockers=[])
        with self.assertRaisesRegex(ValueError, 'binding is stale'):
            self.derive(binding=changed)
        with self.assertRaisesRegex(ValueError, 'overlay differs'):
            self.derive(operation_symbols={'get': 'different_implementation'})

    def test_a_missing_or_corrupt_local_proof_cannot_supply_the_fact(self):
        altered = copy.deepcopy(self.proof)
        altered['proof']['receipt_sha256'] = 'f' * 64
        with self.assertRaises(ValueError):
            self.derive(proof_system=altered)

    def test_alias_guards_cannot_export_current_memory_without_bound_source_evidence(self):
        from .test_shared_current_memory_postcondition import current_memory_intent
        intent = ComponentRelationIntentV1.parse(current_memory_intent())
        with self.assertRaisesRegex(ValueError, 'bound shared source evidence'):
            self.derive(intent=intent)

    def test_public_provider_preflight_does_not_treat_requests_as_checked_facts(self):
        path = self.root/'relation.json'
        path.write_text(json.dumps(self.intent.to_payload()))
        result = _checked_relation_boundary_operations(component_id='resource-text', bundle=self.bundle,
            portable=ProofKernelComponentInterface.parse(_logical_projection(self.bundle)),
            semantic_contract={}, relation_intent=path, interaction_contract_catalog=None)
        self.assertEqual(result, ({}, []))

    def test_provider_fact_reader_rederives_alias_and_exact_evidence_bindings(self):
        inputs = dict(bundle=self.bundle, binding=self.binding, proof_system=self.proof,
            transfers=self.transfers, machine_binding=self.machine, operation_symbols={'get': 'borrowed_get'})
        result = checked_provider_postconditions(intent=self.intent, **inputs)
        validate_provider_postconditions(result, **inputs)
        validate_provider_postcondition_request(result, requested_sha256=self.intent.intent_sha256)
        self.assertFalse(result['authorizing'])
        for value, requested in ((None, self.intent.intent_sha256), (result, 'f' * 64), (result, None)):
            with self.subTest(requested=requested), self.assertRaises(ValueError):
                validate_provider_postcondition_request(value, requested_sha256=requested)
        for mutation in ('missing-fact', 'wrong-proof', 'activation', 'wrong-alias'):
            changed = copy.deepcopy(result)
            if mutation == 'missing-fact': changed['facts'] = []
            elif mutation == 'wrong-proof': changed['facts'][0]['proof_receipt_sha256'] = 'f' * 64
            elif mutation == 'activation': changed['authorizing'] = True
            else:
                operations = copy.deepcopy(list(self.intent.operations))
                operations[0]['requirements'][0]['expression']['args'][1]['attributes']['path']['id'] = 'module'
                altered = ComponentRelationIntentV1.create(component_id='resource-text', operations=operations, blockers=[])
                changed['intent'] = altered.to_payload()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_provider_postconditions(changed, **inputs)
