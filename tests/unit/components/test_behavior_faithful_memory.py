"""An expired machine allocation can be modeled without host C undefined behavior."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.comparison_run import run_comparison,load_comparison_result
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.util import sha256_file

TESTKIT={'fixtures':('compiler',),'commands':('component check',),
         'resources':('tests/fixtures/behavior-faithful-memory',
                      'targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json')}


class BehaviorFaithfulMemoryTests(unittest.TestCase):
    def test_expired_bytes_reuse_and_faults_preserved_without_host_ub(self):
        root=Path(__file__).resolve().parents[3]
        fixture=root/'tests/fixtures/behavior-faithful-memory'
        with tempfile.TemporaryDirectory() as temporary:
            out=Path(temporary)
            build_component_source_package(lift_unit_id='memory-regions-equal',
                files={'compare.c':fixture/'compare.c'},shared_inputs={},
                operation_symbols={'compare':'regions_equal'},out_dir=out/'source')
            package=out/'package'
            prepare_comparison_package(interface_package=root/'targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json',
                source_package=out/'source',target_id='semantic-fixture',component_id='memory-regions-equal',
                adapter_files={'driver.c':fixture/'driver.c'},include_files={},link_files={},runtime_files={},
                original_files=['adapters/driver.c'],oracle_kind='fixture',
                cases=[{'id':name,'arguments':[name]} for name in ('live','freed','reused','unmapped')],
                observation_fields=['equal','expired_reads','faults'],
                assumptions=['explicit flat memory: expired logical allocation bytes remain readable until unmapping',
                             'host arrays remain alive; no native allocator or heap-safety claim'],
                scope='labelled semantic fixture of expired reads, allocation reuse and faults',
                compiler=Path(shutil.which('cc')),runner=None,server=None,output=package)
            def check(name):
                run_comparison(package=package,output=out/name,target_id='semantic-fixture',component_id='memory-regions-equal')
                return load_comparison_result(out/name)
            result=check('preserved')
            self.assertEqual(result['status'],'match')
            observations={r['id']:r['observations']['source'] for r in result['cases']}
            self.assertEqual(observations['freed'],{'equal':1,'expired_reads':4,'faults':0})
            self.assertEqual(observations['reused'],{'equal':0,'expired_reads':1,'faults':0})
            self.assertEqual(observations['unmapped'],{'equal':0,'expired_reads':0,'faults':1})
            # A blanket safety repair is a semantic change, not a faithful lift.
            driver=package/'adapters/driver.c'
            driver.write_text(driver.read_text().replace('enforce_source_lifetime=0','enforce_source_lifetime=1'))
            plan=json.loads((package/'comparison-plan.json').read_text())
            plan['original']['files']['adapters/driver.c']=sha256_file(driver)
            (package/'comparison-plan.json').write_text(json.dumps(plan))
            result=check('safety-change')
            self.assertEqual(result['status'],'mismatch')
            self.assertEqual(result['cases'][1]['first_difference']['path'],'$.equal')
