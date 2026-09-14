"""Real caller cuts with a conditional body-free shared transition.

The fixture declares the transition premise. The retained application driver
separately imports the actual public supplier evidence using the production
reader; this unit fixture is not supplier qualification evidence.
"""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1,compile_component_interface_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.cbmc_backend import bind_smt_solver,run_cbmc_properties,solver_arguments
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from spaghetti_extractor.transfer.behavioral_c_render import behavioral_c_support_source
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from .shared_call_region import FIXTURE,render_call_regions

TESTKIT = {'fixtures':('cbmc','compiler','z3'),'resources':('tests/fixtures/metapad-resource-callers',)}


def inputs():
    return json.loads((FIXTURE/'transition.json').read_text())


class SharedCallRegionTests(unittest.TestCase):
    def check(self, text, *, original_edit=None):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for file in FIXTURE.iterdir():
                if file.suffix in ('.c','.h'):shutil.copyfile(file,root/file.name)
            bundle=compile_component_interface_v5(ComponentInterfaceIntentV1.parse(inputs()['domain']['interface_intent']))
            for name,content in render_component_c_headers_v5(bundle,{'get':'resource_text'}).items():
                (root/name).write_text(content)
            (root/'state-machine-runtime.h').write_text(exact_runtime_header())
            _write_cbmc_stdint(root/'stdint.h')
            (root/'stddef.h').write_text('typedef unsigned int size_t;\ntypedef int ptrdiff_t;\n#define NULL ((void *)0)\n')
            if original_edit:
                original=root/'behavioral-fn-00005646.c';original.write_text(original_edit(original.read_text()))
            (root/'pair.c').write_text(text)
            compiled=subprocess.run([shutil.which('goto-cc'),'--i386-win32','-nostdinc','-I','.',
                'pair.c','behavioral-fn-00005646.c','behavioral-fn-0000570e.c','behavioral-support.c',
                '--function','check_call_regions','-o','model.goto'],cwd=root,capture_output=True,text=True,timeout=30)
            self.assertEqual(compiled.returncode,0,compiled.stderr)
            return run_cbmc_properties(command=[shutil.which('cbmc'),'model.goto','--function','check_call_regions',
                '--json-ui','--unwind','16','--unwinding-assertions','--bounds-check','--pointer-check',
                '--signed-overflow-check','--undefined-shift-check','--div-by-zero-check','--object-bits','12',
                '--no-self-loops-to-assumptions',*solver_arguments(bind_smt_solver(Path(shutil.which('z3')))),
                '--reachability-slice-fb','--slice-formula'],cwd=root,timeout_seconds=30)

    def test_actual_callers_and_full_shared_memory_without_supplier_bodies(self):
        source=render_call_regions(inputs())
        self.assertNotIn('spx_sub_00001284(',source)
        self.assertNotIn('resource_text(',source)
        result=self.check(source)
        self.assertEqual(result['status'],'satisfied',result.get('detail'))

    def test_wrong_argument_and_live_stack_transport_are_rejected(self):
        source=render_call_regions(inputs())
        cases=[(source.replace('which==0U ? 31U : 32U);','which==0U ? 30U : 32U);'),None,'dependency-arguments'),
               (source,lambda text:text.replace('0x0040e3a4U','0x0040e3a5U'),'live-stack-transport')]
        for text,edit,diagnostic in cases:
            with self.subTest(diagnostic=diagnostic):
                result=self.check(text,original_edit=edit)
                self.assertEqual(result['status'],'violated',result.get('detail'))
                self.assertIn(diagnostic,result['detail'])

    def test_restoring_memory_after_a_call_does_not_repair_its_wrong_input(self):
        replacement='''
  struct caller_environment *env=opaque;
  uint8_t old=spx_mutable_byte(env->world,TEMPORARY_ADDRESS);
  spx_mutable_event(env->world,TEMPORARY_ADDRESS,1U,old^1U,0U,0U);
  spx_view_v5 result=shared_transition(opaque,which==0U ? 31U : 32U);
  spx_mutable_event(env->world,TEMPORARY_ADDRESS,1U,old,0U,0U);
  return result;'''
        for address,expected in (('0x410150U','violated'),('0x410154U','satisfied')):
            with self.subTest(temporary_address=address):
                source=render_call_regions(inputs()).replace('return shared_transition(opaque,which==0U ? 31U : 32U);',
                    replacement.replace('TEMPORARY_ADDRESS',address))
                result=self.check(source)
                self.assertEqual(result['status'],expected,result.get('detail'))
                if expected=='violated':self.assertIn('current-input-memory',result['detail'])

    def test_changed_contract_requires_new_caller_admission(self):
        transition=inputs()
        original=render_call_regions(transition)
        other=copy.deepcopy(transition);other['supplier_receipt_sha256']='f'*64
        self.assertEqual(original,render_call_regions(other))
        for field,value in (('clobbers',['cf','df','eax','ecx','edx','eflags','of','pf','sf','zf']),
                            ('private_writes',[{'offset':-28,'bytes':36}])):
            changed=copy.deepcopy(transition);changed['domain']['machine_domain'][field]=value
            changed['domain_sha256']=canonical_sha256_v3(changed['domain'])
            with self.assertRaisesRegex(ValueError,'caller'):
                render_call_regions(changed)

    def test_retained_original_and_support_hashes(self):
        boundary=json.loads((FIXTURE/'boundary.json').read_text())
        for name,digest in boundary['files'].items():
            self.assertEqual(hashlib.sha256((FIXTURE/name).read_bytes()).hexdigest(),digest,name)
        self.assertEqual((FIXTURE/'behavioral-support.c').read_text(),behavioral_c_support_source())
