"""Configured declaration application preserves neighbors and rejects stale edits."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.cli import main
from spaghetti_extractor.commands.component_apply import apply_reviewed_component_inputs
from spaghetti_extractor.commands.component_review import _binding, _interface, write_reviewed_configured_component_inputs
from spaghetti_extractor.components.indexes_v5 import ComponentIntentIndexV5, load_component_intent_index_v5
from spaghetti_extractor.components.lifting_intent import ComponentLiftingIntentV1
from spaghetti_extractor.components.relation_v5 import ComponentRelationIntentV1
from tests.unit.cli.test_configured_component_review import package_fixture, cut_intent, materialize

TESTKIT = {'commands': ('boundary adopt',)}


class ComponentApplyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.draft = self.root / 'draft'; self.draft.mkdir()
        self.package = package_fixture(self.draft)
        self.bundle = self.root / 'target'; self.bundle.mkdir()
        self.intent = self.bundle / 'intent'
        write_reviewed_configured_component_inputs(draft=self.draft, package=self.package,
                                                   program_id='fixture', output=self.intent)
        # The SDK allows the operator root and component intent to differ.
        self.inputs = self.bundle / 'contracts'; self.inputs.mkdir()
        for directory, kind, field, normalizer in (
            ('interfaces-v5', 'interface', 'interface_intent', _interface),
            ('bindings-v5', 'machine_binding', 'binding_intent', _binding),
        ):
            (self.intent / directory).rename(self.inputs / directory)
            folder = self.inputs / directory
            value = json.loads((folder / 'leaf.json').read_text())
            value['id' if kind == 'interface' else 'component_id'] = 'neighbor'
            neighbor = normalizer(value)
            (folder / 'neighbor.json').write_text(json.dumps(neighbor.to_payload()))
            index = ComponentIntentIndexV5.parse(json.loads((folder / 'index.json').read_text()), kind=kind)
            # Non-default filenames must survive application.
            (folder / 'leaf.json').rename(folder / 'custom.json')
            rows = [{**row, field: 'custom.json'} for row in index.components]
            rows.append({'component_id': 'neighbor', field: 'neighbor.json', 'intent_sha256': neighbor.intent_sha256})
            blockers = [*index.blockers, {'component_id': 'neighbor', 'code': 'pending-neighbor'}]
            (folder / 'index.json').write_text(json.dumps(ComponentIntentIndexV5.create(
                kind=kind, components=rows, blockers=blockers).to_payload()))
        lifting = ComponentLiftingIntentV1.parse(json.loads((self.intent / 'components.json').read_text()))
        self.lifting = ComponentLiftingIntentV1.create(program_id='fixture-program', components=[
            {**lifting.components[0], 'source': {'files': ['components/leaf.c'],
                'operation_symbols': {'run': 'fixture_run'}, 'shared_inputs': []}},
            {'id': 'neighbor', 'label': 'Unrelated dirty work'}],
            groups=[{'id': 'pair', 'label': 'Pair', 'members': ['leaf', 'neighbor']}],
            configurations=lifting.configurations)
        (self.intent / 'components.json').write_text(json.dumps(self.lifting.to_payload()))
        (self.bundle / 'target.json').write_text(json.dumps({
            'format': 'spaghetti-extractor-target-bundle-v3', 'id': 'fixture', 'display_name': 'Fixture',
            'input': {'kind': 'pe32', 'expected_sha256': 'b' * 64},
            'paths': {'nix': 'default.nix', 'components': 'intent/components.json', 'component_sources': 'source'},
            'workflow': {'default_configuration': 'draft'}}))
        source = self.bundle / 'source/components/leaf.c'; source.parent.mkdir(parents=True)
        source.write_text('/* authored C must survive */\n')
        self.paths = {'intent': 'intent/components.json',
                      'interface_index': 'contracts/interfaces-v5/index.json',
                      'binding_index': 'contracts/bindings-v5/index.json'}

    def apply(self):
        return apply_reviewed_component_inputs(draft=self.draft, package=self.package, target='fixture',
                                               bundle=self.bundle, authoring_paths=self.paths)

    def edit(self):
        value = json.loads((self.draft / 'interface.json').read_text())
        value['schema']['schema_id'] = 'reviewed-schema'
        (self.draft / 'interface.json').write_text(json.dumps(value))
        (self.draft / 'bisimulation.json').write_text(json.dumps(cut_intent()))

    def snapshot(self):
        return {str(path.relative_to(self.bundle)): path.read_bytes()
                for path in self.bundle.rglob('*') if path.is_file()}

    def test_relation_export_and_cut_apply_together_without_manual_digests(self):
        before = self.snapshot()
        self.edit()
        relation = ComponentRelationIntentV1.create(component_id='leaf', blockers=[], operations=[{
            'operation_id': 'run', 'requirements': [{'id': 'normal-return',
                'relation': 'normal_exit_postcondition', 'expression': {
                    'op': 'true', 'sort': {'kind': 'bool'}, 'args': [], 'attributes': {}}}]}]).to_payload()
        editable = dict(relation); editable.pop('intent_sha256')
        (self.draft / 'relation.json').write_text(json.dumps(editable))
        report = self.apply()
        self.assertFalse(report['authority'])
        self.assertEqual(json.loads((self.intent / 'relations/leaf.json').read_text()), relation)
        current = ComponentLiftingIntentV1.parse(json.loads((self.intent / 'components.json').read_text()))
        component = next(row for row in current.components if row['id'] == 'leaf')
        self.assertEqual(component['relation_intent'], 'relations/leaf.json')
        self.assertEqual(component['bisimulation_intent'], 'bisimulation/leaf.json')
        after = self.snapshot()
        for path, contents in before.items():
            if path not in report['changed_files']:
                self.assertEqual(after[path], contents, path)

    def test_missing_relation_fields_report_a_diagnostic_without_writes(self):
        (self.draft / 'relation.json').write_text('{"component_id": "leaf"}')
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'incomplete relation input'):
            self.apply()
        self.assertEqual(self.snapshot(), before)

    def test_relation_baseline_is_retained_and_intervening_edit_rejects_atomically(self):
        relation = ComponentRelationIntentV1.create(component_id='leaf', blockers=[], operations=[{
            'operation_id': 'run', 'requirements': [{'id': 'normal-return',
                'relation': 'normal_exit_postcondition', 'expression': {
                    'op': 'true', 'sort': {'kind': 'bool'}, 'args': [], 'attributes': {}}}]}]).to_payload()
        self.package['requirements']['editing_inputs']['relation'] = relation
        self.package = materialize(self.draft, self.package)
        declarations = [dict(row) for row in self.lifting.components]
        next(row for row in declarations if row['id'] == 'leaf')['relation_intent'] = 'relations/leaf.json'
        updated = ComponentLiftingIntentV1.create(program_id=self.lifting.program_id, components=declarations,
            groups=self.lifting.groups, configurations=self.lifting.configurations)
        (self.intent / 'components.json').write_text(json.dumps(updated.to_payload()))
        (self.intent / 'relations').mkdir()
        altered = ComponentRelationIntentV1.create(component_id='leaf', operations=relation['operations'],
            blockers=[{'code': 'intervening-edit', 'detail': 'A concurrent operator changed this contract.'}])
        (self.intent / 'relations/leaf.json').write_text(json.dumps(altered.to_payload()))
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'relation baseline is stale'):
            self.apply()
        self.assertEqual(self.snapshot(), before)

    def test_public_apply_updates_actual_indexes_preserving_sources_neighbors_and_selection(self):
        before = self.snapshot(); self.edit()
        index = {'components': {'authoringPaths': self.paths},
                 'boundaries': {'subjects': {'component:leaf': {'kind': 'component', 'products': ['source']}}}}
        with patch('spaghetti_extractor.commands.workflows._operator_index', return_value=index), patch(
                'spaghetti_extractor.commands.workflows._realize_artifact',
                return_value=(self.draft / 'component-work-package-v6.json', self.package)), patch(
                'spaghetti_extractor.commands.workflows._component_start_work_package', return_value=(self.draft, self.package)):
            display = io.StringIO()
            with contextlib.redirect_stdout(display):
                self.assertEqual(main(['boundary', 'adopt', 'fixture', 'component:leaf', '--input', str(self.draft),
                                      '--apply', '--target-flake', str(self.bundle)]), 0)
        report = json.loads(display.getvalue())
        self.assertFalse(report['authority']); self.assertFalse(report['source_installed'])
        self.assertEqual(report['configured_source_files'], ['source/components/leaf.c'])
        self.assertEqual(set(report['changed_files']), {'contracts/interfaces-v5/custom.json',
            'contracts/interfaces-v5/index.json', 'intent/components.json', 'intent/bisimulation/leaf.json'})
        after = self.snapshot()
        for path, contents in before.items():
            if path not in report['changed_files']: self.assertEqual(after[path], contents, path)
        current = ComponentLiftingIntentV1.parse(json.loads((self.intent / 'components.json').read_text()))
        self.assertEqual(current.groups, self.lifting.groups)
        self.assertEqual(current.program_id, self.lifting.program_id)
        self.assertEqual(current.configurations, self.lifting.configurations)
        for kind, directory in [('interface', 'interfaces-v5'), ('machine_binding', 'bindings-v5')]:
            parsed = load_component_intent_index_v5(self.inputs / directory / 'index.json', kind=kind)
            self.assertIn({'component_id': 'neighbor', 'code': 'pending-neighbor'}, parsed.blockers)
        with self.assertRaisesRegex(ValueError, 'baseline is stale'):
            self.apply()  # Even a cached old package cannot overwrite newly adopted contracts.

    def test_stale_target_cut_rejects_even_with_cached_package(self):
        self.package['requirements']['editing_inputs']['bisimulation'] = cut_intent()
        self.package = materialize(self.draft, self.package)
        self.edit(); before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'cutpoint baseline is stale'):
            self.apply()
        self.assertEqual(self.snapshot(), before)

    def test_binding_edit_replaces_only_its_index_blockers_and_noop_preserves_bytes(self):
        before = self.snapshot()
        self.assertEqual(self.apply()['changed_files'], [])
        self.assertEqual(self.snapshot(), before)
        path = self.draft / 'binding.json'
        value = json.loads(path.read_text())
        value['blockers'] = [{'code': 'new-required-premise'}]
        path.write_text(json.dumps(value))
        report = self.apply()
        self.assertEqual(report['changed_files'], ['contracts/bindings-v5/custom.json', 'contracts/bindings-v5/index.json'])
        index = load_component_intent_index_v5(self.inputs / 'bindings-v5/index.json', kind='machine_binding')
        self.assertEqual(list(index.blockers), [{'component_id': 'leaf', 'code': 'new-required-premise'},
                                              {'component_id': 'neighbor', 'code': 'pending-neighbor'}])

    def test_all_write_failures_and_keyboard_interrupt_restore_exact_bytes(self):
        self.edit(); before = self.snapshot()
        replace = os.replace
        for fail_at in range(1, 5):
            for failure, after_replace in ((OSError, False), (KeyboardInterrupt, False), (KeyboardInterrupt, True)):
                calls = 0
                def interrupted(source, destination):
                    nonlocal calls
                    calls += 1
                    if calls == fail_at:
                        if after_replace: replace(source, destination)
                        raise failure('injected write interruption')
                    return replace(source, destination)
                with self.subTest(fail_at=fail_at, failure=failure, after_replace=after_replace), patch(
                        'spaghetti_extractor.commands.component_apply.os.replace', side_effect=interrupted):
                    with self.assertRaises(failure): self.apply()
                self.assertEqual(self.snapshot(), before)
                self.assertFalse(list(self.bundle.glob('.component-review-*')))
                self.assertFalse((self.intent / 'bisimulation').exists())

    def test_symlink_and_occupied_cut_destinations_reject_before_writes(self):
        self.edit()
        cuts = self.intent / 'bisimulation'; cuts.mkdir()
        foreign = self.root / 'foreign.json'; foreign.write_text('do not change')
        (cuts / 'leaf.json').symlink_to(foreign)
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'symbolic link'): self.apply()
        self.assertEqual(self.snapshot(), before)
        (cuts / 'leaf.json').unlink(); (cuts / 'leaf.json').write_text('occupied')
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'occupied'): self.apply()
        self.assertEqual(self.snapshot(), before)

    def test_missing_discovery_paths_and_disagreeing_metadata_reject(self):
        before = self.snapshot(); paths = self.paths
        for candidate in (None, {**paths, 'intent': 'contracts/interfaces-v5/custom.json'},
                          {**paths, 'intent': '../outside.json'}):
            self.paths = candidate
            with self.subTest(paths=candidate), self.assertRaises(ValueError): self.apply()
            self.assertEqual(self.snapshot(), before)

    def test_stale_binding_and_cooperating_writer_lock_reject(self):
        import fcntl
        from spaghetti_extractor.commands.component_start import _component_start_lock_path
        with _component_start_lock_path(self.intent / 'components.json').open('a+') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ValueError, 'transaction is active'): self.apply()
        path = self.inputs / 'bindings-v5/custom.json'
        value = json.loads(path.read_text())
        value['blockers'].append({'code': 'additional-premise'})
        value['blockers'].sort(key=lambda row: row['code'])
        changed = _binding(value)
        path.write_text(json.dumps(changed.to_payload()))
        index_path = path.parent / 'index.json'
        index = ComponentIntentIndexV5.parse(json.loads(index_path.read_text()), kind='machine_binding')
        index_path.write_text(json.dumps(ComponentIntentIndexV5.create(kind='machine_binding', components=[
            {**row, 'intent_sha256': changed.intent_sha256} if row['component_id'] == 'leaf' else row
            for row in index.components], blockers=index.blockers).to_payload()))
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'binding baseline is stale'): self.apply()
        self.assertEqual(self.snapshot(), before)

    def test_intervening_edit_and_pending_recovery_are_not_overwritten(self):
        self.edit()
        from spaghetti_extractor.commands import component_apply
        actual_apply = component_apply._apply_files
        source = self.inputs / 'interfaces-v5/custom.json'
        def concurrent(bundle, originals, updates):
            source.write_text('external edit')
            return actual_apply(bundle, originals, updates)
        with patch.object(component_apply, '_apply_files', side_effect=concurrent):
            with self.assertRaisesRegex(ValueError, 'changed during review'): self.apply()
        self.assertEqual(source.read_text(), 'external edit')
        pending = self.bundle / '.component-review-interrupted'; pending.mkdir()
        with self.assertRaisesRegex(ValueError, 'requires recovery'): self.apply()


if __name__ == '__main__':
    unittest.main()
