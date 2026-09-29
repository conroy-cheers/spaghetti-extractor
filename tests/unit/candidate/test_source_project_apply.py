"""Public source application leaves a usable project after failed preparation."""
import contextlib
import io
import json
from pathlib import Path
import shlex
import sys
import unittest

from spaghetti_extractor.cli import main
from spaghetti_extractor.candidate.source_export import export_comparison_sources
from spaghetti_extractor.candidate.source_export_update import _inventory
from spaghetti_extractor.candidate.source_project_apply import apply_project_sources
from tests.unit.components.comparison_fixture import ComparisonFixture

TESTKIT = {'fixtures': ('compiler',), 'commands': ('candidate apply', 'component check'),
           'resources': ('tests/fixtures/jq-array-concat',)}


class ProjectApplyTests(unittest.TestCase):
    setUp = ComparisonFixture.setUp
    command = ComparisonFixture.command
    check = ComparisonFixture.check

    def project(self):
        code,text,comparison=self.check(self.package,'initial')
        self.assertEqual(code,0,text)
        project=self.root/'project';project.mkdir()
        export_comparison_sources(comparisons=[comparison],target_id='fixture',output=project/'lifted')
        (project/'operator-notes.txt').write_text('Keep this local work.\n')
        (project/'cached.o').write_bytes(b'unchanged neighboring object')
        return project,comparison

    def python(self, code):
        return shlex.join([sys.executable,'-c',code])

    def test_public_apply_stages_export_assembly_and_build_and_keeps_failed_proposals(self):
        project,comparison=self.project()
        source=self.package/'source/component.c'
        source.write_text(source.read_text().replace('a.metadata += b.metadata','a.metadata = b.metadata + a.metadata'))
        code,text,fresh=self.check(self.package,'edited');self.assertEqual(code,0,text)
        before=_inventory(project);mtime=(project/'cached.o').stat().st_mtime_ns
        assemble=self.python("from pathlib import Path; Path('assembly.txt').write_text('new entries')")
        options=dict(project=project,target_id='fixture',comparisons=[fresh],component_ids=['array-concat'])
        fail=self.python('raise SystemExit(7)')
        for assembly,checks in [(fail,[]),(assemble,[fail])]:
            with self.assertRaisesRegex(ValueError,'command failed'):
                apply_project_sources(**options,assembly_command=assembly,check_commands=checks)
            self.assertEqual(_inventory(project),before)
        proposals=list(self.root.glob('project.apply-*'))
        self.assertEqual(len(proposals),2)
        self.assertTrue(all(json.loads((p/'apply-result.json').read_text())['status']=='failed' for p in proposals))
        output=io.StringIO()
        with contextlib.redirect_stdout(output),contextlib.redirect_stderr(output):
            code=main(['candidate','apply','fixture','--project',str(project),'--comparison',str(fresh),
                '--component','array-concat','--assembly-command',assemble,'--check-command','make -C lifted'])
        self.assertEqual(code,0,output.getvalue())
        self.assertEqual((project/'assembly.txt').read_text(),'new entries')
        self.assertTrue((project/'lifted/liblifted.a').is_file())
        exported=json.loads((project/'lifted/source-export.json').read_text())
        self.assertTrue(Path(exported['update']['backup']).is_dir())
        self.assertEqual((project/'operator-notes.txt').read_text(),'Keep this local work.\n')
        self.assertEqual((project/'cached.o').stat().st_mtime_ns,mtime)
        self.assertTrue(any(_inventory(p/'previous')==before for p in self.root.glob('project.apply-*') if (p/'previous').exists()))

    def test_binding_only_apply_detects_a_concurrent_operator_edit(self):
        project,_=self.project()
        assembly=self.python("from pathlib import Path; Path("+repr(str(project/'operator-notes.txt'))+
                             ").write_text('concurrent edit'); Path('new-binding.c').write_text('staged')")
        with self.assertRaisesRegex(ValueError,'working project changed'):
            apply_project_sources(project=project,target_id='fixture',assembly_command=assembly)
        self.assertEqual((project/'operator-notes.txt').read_text(),'concurrent edit')
        self.assertFalse((project/'new-binding.c').exists())
