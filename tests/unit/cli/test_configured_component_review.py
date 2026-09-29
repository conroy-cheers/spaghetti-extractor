"""Configured component contracts can be edited without manufacturing evidence."""

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.cli import main
from spaghetti_extractor.commands.component_review import write_reviewed_configured_component_inputs
from spaghetti_extractor.components.binding_intent import ComponentMachineBindingIntentV1
from spaghetti_extractor.components.bisimulation import ComponentBisimulationIntentV1
from spaghetti_extractor.components.indexes_v5 import load_component_intent_index_v5
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.work_package_v6 import ComponentWorkPackageV6
from spaghetti_extractor.components.work_package_editing import editing_input_texts
from spaghetti_extractor.util import sha256_text
from tests.unit.cli.test_component_review import review_fixture
from tests.unit.components.test_work_package_v6 import _payload

TESTKIT = {'commands': ('boundary propose', 'boundary adopt', 'boundary inspect')}


def package_fixture(root):
    review_fixture(root)
    (root / 'component-proposal-inspection.json').unlink()
    interface = ComponentInterfaceIntentV1.parse(json.loads((root / 'interface.json').read_text()))
    binding = ComponentMachineBindingIntentV1.parse(json.loads((root / 'binding.json').read_text()))
    compiled = compile_component_interface_v5(interface)
    package = _payload()
    package['component_id'] = 'leaf'
    package['bindings'].update(interface_sha256=compiled.interface.interface_sha256,
        schema_sha256=compiled.interface.schema_sha256, binding_intent_sha256=binding.intent_sha256)
    semantics = binding.operations[0].semantics
    package['operations'][0].update(signature_id='run', semantic_sha256=semantics.semantic_sha256,
        unit_ids=list(semantics.unit_ids), context_transfer_ids=list(semantics.proof_context_transfer_ids),
        entry_rvas=list(semantics.entry_rvas), entry_unit_ids=['u'], exit_unit_ids=['u'],
        machine_projection=dict(semantics.machine_projection))
    package['faithful_c_slices'][0].update(unit_id='u', rva_start=4096, rva_end=4112)
    package['requirements']['editing_inputs'] = {'interface': interface.to_payload(), 'binding': binding.to_payload()}
    return materialize(root, package)


def materialize(root, package):
    files = {'include/component.h': 'void fixture_run(void);\n',
        'src/component.c': '#include "component.h"\n#error "implement me"\n',
        **editing_input_texts(package)}
    package['generated_files'] = [{'path': name, 'sha256': sha256_text(text)} for name, text in files.items()]
    # V6 has a canonical list: C skeleton first, then sorted editing inputs.
    package['generated_files'][2:] = sorted(package['generated_files'][2:], key=lambda row: row['path'])
    for name, text in files.items():
        path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text)
    for row in package['faithful_c_slices']:
        path = root / row['source_path']; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('/* original fixture slice */\n'); row['source_sha256'] = sha256_text(path.read_text())
    package['work_package_sha256'] = canonical_sha256_v3({k:v for k,v in package.items() if k != 'work_package_sha256'})
    ComponentWorkPackageV6.parse(package)
    (root / 'component-work-package-v6.json').write_text(json.dumps(package))
    (root / 'semantic-slice-v2.json').write_text(json.dumps(package['semantic_slice']))
    return package


def cut_intent():
    return ComponentBisimulationIntentV1.create(component_id='leaf', operations=[{
        'operation_id': 'run', 'syncs': [{'id': 'scan', 'exact_unit_id': 'u',
            'captures': [{'kind': 'source_state', 'id': 'current', 'mode': 'logical_definition',
                'projection': None, 'encoding': {'op': 'const', 'width': 32, 'value': 0}, 'decoding': None}],
            'derived': [], 'invariant': {'op': 'false'}}]}]).to_payload()


class ConfiguredComponentReviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.original = self.root / 'package'; self.original.mkdir()
        self.package = package_fixture(self.original)

    def test_public_propose_edit_adopt_normalizes_inputs_without_proving_them(self):
        index = {'boundaries': {'subjects': {'component:leaf': {'kind': 'component', 'products': ['source']}}}}
        artifact = self.original / 'component-work-package-v6.json'
        draft = self.root / 'draft'; output = self.root / 'adopted'
        with patch('spaghetti_extractor.commands.workflows._operator_index', return_value=index), patch(
                'spaghetti_extractor.commands.workflows._realize_artifact', return_value=(artifact, self.package)):
            display = io.StringIO()
            with contextlib.redirect_stdout(display):
                self.assertEqual(main(['boundary', 'inspect', 'fixture', 'component:leaf']), 0)
                self.assertEqual(main(['boundary', 'propose', 'fixture', 'component:leaf', '--output', str(draft)]), 0)
            self.assertIn('editable canonical inputs:', display.getvalue())
            interface = json.loads((draft / 'interface.json').read_text())
            interface.pop('intent_sha256'); interface['schema'].pop('schema_sha256')
            interface['schema']['schema_id'] = 'operator-reviewed'
            (draft / 'interface.json').write_text(json.dumps(interface))
            cuts = cut_intent(); cuts.pop('intent_sha256')
            (draft / 'bisimulation.json').write_text(json.dumps(cuts))
            with contextlib.redirect_stdout(display):
                self.assertEqual(main(['boundary', 'adopt', 'fixture', 'component:leaf',
                                      '--input', str(draft), '--output', str(output)]), 0)
            self.assertIn('authority=no', display.getvalue())
        reviewed = load_component_intent_index_v5(output / 'interfaces-v5/index.json', kind='interface')
        self.assertEqual(reviewed.status, 'complete')  # Declaration well-formedness only.
        binding = load_component_intent_index_v5(output / 'bindings-v5/index.json', kind='machine_binding')
        self.assertEqual(binding.status, 'incomplete')
        proof = ComponentBisimulationIntentV1.parse(json.loads((output / 'bisimulation/leaf.json').read_text()))
        self.assertEqual(proof.operations[0].syncs[0].invariant, {'op': 'false'})
        self.assertEqual(json.loads((output / 'components.json').read_text())['configurations'][0]['selections'][0]['activation'], 'draft')
        self.assertFalse((output / 'semantic-provider-qualification.json').exists())
        self.assertEqual(json.loads((draft / 'interface.json').read_text()), interface)

    def test_changed_scope_or_foreign_projection_rejects_without_output(self):
        original = json.loads((self.original / 'binding.json').read_text())
        for field in ('unit_ids', 'transfer_ids', 'entry_rvas', 'exit_unit_ids', 'operation_id'):
            value = copy.deepcopy(original); op = value['operations'][0]
            if field in ('unit_ids', 'transfer_ids'): op[field] = ['v']
            elif field == 'entry_rvas': op[field] = [4112]
            elif field == 'operation_id': op['machine_projection']['operation'][field] = 'foreign'
            else: op['machine_projection']['operation'][field] = ['v']
            (self.original / 'binding.json').write_text(json.dumps(value))
            output = self.root / field
            with self.subTest(field=field), self.assertRaises(ValueError):
                write_reviewed_configured_component_inputs(draft=self.original, package=self.package,
                    program_id='fixture', output=output)
            self.assertFalse(output.exists())

    def test_stale_package_or_missing_original_cut_input_rejects(self):
        self.package['requirements']['editing_inputs']['bisimulation'] = cut_intent()
        self.package = materialize(self.original, self.package)
        (self.original / 'bisimulation.json').unlink()
        with self.assertRaisesRegex(ValueError, 'absent or not regular'):
            write_reviewed_configured_component_inputs(draft=self.original, package=self.package,
                program_id='fixture', output=self.root / 'missing')
        changed = copy.deepcopy(self.package); changed['blockers'].append({'code': 'new-frontier'})
        changed['work_package_sha256'] = canonical_sha256_v3({k:v for k,v in changed.items() if k != 'work_package_sha256'})
        with self.assertRaisesRegex(ValueError, 'baseline is stale'):
            write_reviewed_configured_component_inputs(draft=self.original, package=changed,
                program_id='fixture', output=self.root / 'stale')

    def test_embedded_or_materialized_input_mismatch_rejects(self):
        for mutation in ('binding', 'scope', 'materialized'):
            candidate = copy.deepcopy(self.package)
            if mutation == 'binding': candidate['bindings']['binding_intent_sha256'] = '0' * 64
            elif mutation == 'scope': candidate['operations'][0]['unit_ids'] = ['foreign']
            else: candidate['generated_files'][-1]['sha256'] = '0' * 64
            candidate['work_package_sha256'] = canonical_sha256_v3({k:v for k,v in candidate.items() if k != 'work_package_sha256'})
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                ComponentWorkPackageV6.parse(candidate)

    def test_outside_cut_and_nonempty_output_are_not_adopted(self):
        cuts = cut_intent(); cuts['operations'][0]['syncs'][0]['exact_unit_id'] = 'outside'
        (self.original / 'bisimulation.json').write_text(json.dumps(cuts))
        with self.assertRaisesRegex(ValueError, 'outside the owned'):
            write_reviewed_configured_component_inputs(draft=self.original, package=self.package,
                program_id='fixture', output=self.root / 'outside')
        (self.original / 'bisimulation.json').write_text(json.dumps(cut_intent()))
        output = self.root / 'occupied'; output.mkdir(); (output / 'keep').write_text('unrelated')
        with self.assertRaisesRegex(ValueError, 'new or empty'):
            write_reviewed_configured_component_inputs(draft=self.original, package=self.package,
                program_id='fixture', output=output)
        self.assertEqual((output / 'keep').read_text(), 'unrelated')

    def test_each_operation_keeps_its_own_scope_during_multi_operation_review(self):
        interface = copy.deepcopy(self.package['requirements']['editing_inputs']['interface'])
        interface['operations'].append({**interface['operations'][0], 'id': 'other'})
        interface['operations'].sort(key=lambda row: row['id'])
        from spaghetti_extractor.commands.component_review import _interface
        interface = _interface(interface)
        original = self.package['requirements']['editing_inputs']['binding']
        second = copy.deepcopy(original['operations'][0]); second['id'] = 'other'
        second.update(unit_ids=['v'], transfer_ids=['v'], entry_rvas=[4112])
        second['machine_projection']['operation'].update(operation_id='other', entry_unit_ids=['v'], exit_unit_ids=['v'])
        binding = ComponentMachineBindingIntentV1.create(component_id='leaf',
            operations=[*original['operations'], second], blockers=original['blockers'])
        bundle = compile_component_interface_v5(interface)
        self.package['bindings'].update(interface_sha256=bundle.interface.interface_sha256,
            schema_sha256=bundle.interface.schema_sha256, binding_intent_sha256=binding.intent_sha256)
        self.package['requirements']['editing_inputs'] = {'interface': interface.to_payload(), 'binding': binding.to_payload()}
        old_row = self.package['operations'][0]
        self.package['operations'] = []
        for op in binding.operations:
            semantics = op.semantics
            row = copy.deepcopy(old_row)
            row.update(operation_id=semantics.operation_id, semantic_sha256=semantics.semantic_sha256,
                unit_ids=list(semantics.unit_ids), context_transfer_ids=list(semantics.proof_context_transfer_ids),
                entry_rvas=list(semantics.entry_rvas), machine_projection=dict(semantics.machine_projection))
            if semantics.operation_id == 'other':
                definition = copy.deepcopy(self.package['semantic_slice']['definitions'][0])
                definition.update(definition_id='semantic-definition-v2:' + 'a' * 64, symbol_id='original:function:v')
                self.package['semantic_slice']['definitions'].append(definition)
                row.update(definition_ids=[definition['definition_id']], entry_unit_ids=['v'], exit_unit_ids=['v'])
            self.package['operations'].append(row)
        sliced = self.package['semantic_slice']
        sliced['definitions'].sort(key=lambda row: row['definition_id'])
        sliced['semantic_slice_sha256'] = canonical_sha256_v3({k:v for k,v in sliced.items() if k != 'semantic_slice_sha256'})
        self.package['bindings']['semantic_slice_sha256'] = sliced['semantic_slice_sha256']
        self.package = materialize(self.original, self.package)
        cuts = cut_intent()
        other = copy.deepcopy(cuts['operations'][0]); other['operation_id'] = 'other'; other['syncs'][0]['exact_unit_id'] = 'v'
        cuts['operations'].append(other)
        cuts['operations'].sort(key=lambda row: row['operation_id'])
        (self.original / 'bisimulation.json').write_text(json.dumps(cuts))
        output = self.root / 'multi'
        write_reviewed_configured_component_inputs(draft=self.original, package=self.package,
            program_id='fixture', output=output)
        parsed = ComponentBisimulationIntentV1.parse(json.loads((output / 'bisimulation/leaf.json').read_text()))
        self.assertEqual({op.operation_id for op in parsed.operations}, {'run', 'other'})
        other['syncs'][0]['exact_unit_id'] = 'u'
        (self.original / 'bisimulation.json').write_text(json.dumps(cuts))
        with self.assertRaisesRegex(ValueError, 'outside the owned operation'):
            write_reviewed_configured_component_inputs(draft=self.original, package=self.package,
                program_id='fixture', output=self.root / 'foreign-cut')
