"""Public caller partitions retain complete obligations without rerunning tools."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_execution import property_checker_command
from spaghetti_extractor.components.bisimulation_query_evidence import CbmcQueryEvidence
from spaghetti_extractor.operator.source_caller_partition import check_partitioned_caller, validate_partitioned_caller
from spaghetti_extractor.util import sha256_file

TESTKIT={'fixtures':('compiler','cbmc')}


class SourceCallerPartitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.temp.cleanup)
        cls.root=Path(cls.temp.name);cls.proof=cls.root/'proof';cls.proof.mkdir()
        cls.cbmc=Path(shutil.which('cbmc'));cls.compiler=Path(shutil.which('goto-cc'))
        source='''static void helper(unsigned x){__CPROVER_assert(x<3U,"repeated-helper");}
void check(void){unsigned bytes[2]={0U,1U},i,n;__CPROVER_assume(i<2U && n<=2U);
 helper(bytes[0]);helper(bytes[1]);
 for(unsigned j=0;j<n;j++)bytes[j]++;
 __CPROVER_assert(bytes[i]==i+(i<n),"current-byte");
 __CPROVER_assert(bytes[0]+bytes[1]==1U+n,"complete-result");}
'''
        (cls.proof/'pair.c').write_text(source)
        p=subprocess.run([str(cls.compiler),'--i386-win32','pair.c','--function','check','-o','model.goto'],
            cwd=cls.proof,capture_output=True,text=True,timeout=30)
        if p.returncode:raise AssertionError(p.stderr)
        command=property_checker_command([],source_unwind_limit=4,smt_solver=None)
        evidence=CbmcQueryEvidence(model=cls.proof/'model.goto',checker=cls.cbmc,compiler=cls.compiler,
            output=cls.proof/'query-evidence')
        query,model=check_partitioned_caller(proof=cls.proof,entry='check',command=command,
            cbmc=cls.cbmc,evidence=evidence,timeout_seconds=30)
        if query['status']!='satisfied':raise AssertionError(query)
        cls.result={'query':query,'property_model':model,'proof_key':{'unwind':4,'property_checker_command':command,
            'bindings':{'boundary':{'proof_entry':'check'}},'tools':{'cbmc':sha256_file(cls.cbmc),'goto_cc':sha256_file(cls.compiler)}},
            'proof_files':{'model.goto':sha256_file(cls.proof/'model.goto')}}

    def test_complete_replay_has_no_process_or_model_work(self):
        with patch('subprocess.run',side_effect=AssertionError('replay must not execute a tool')):
            validate_partitioned_caller(self.result,self.proof)

    def test_missing_query_or_weaker_query_options_cannot_supply_coverage(self):
        for changed_options in (False,True):
            with self.subTest(changed_options=changed_options):
                root=self.root/('changed' if changed_options else 'missing')
                shutil.copytree(self.proof,root)
                records=list((root/'query-evidence').glob('*/query.json'))
                record_path=next(p for p in records if '--show-properties' in json.loads(p.read_text())['binding']['arguments'])
                if changed_options:
                    record=json.loads(record_path.read_text());record['binding']['arguments'].append('--no-pointer-check')
                    record_path.write_text(json.dumps(record))
                    record_path.parent.rename(record_path.parent.parent/canonical_sha256_v3(record['binding']))
                else:shutil.rmtree(record_path.parent)
                with patch('subprocess.run',side_effect=AssertionError('missing evidence must not rerun tools')):
                    with self.assertRaises(ValueError):validate_partitioned_caller(self.result,root)

    def test_omitted_assertion_site_and_changed_policy_reject(self):
        for change in ('site','policy'):
            result=deepcopy(self.result)
            if change=='site':result['property_model']['required_assertion_sites'].pop()
            else:result['proof_key']['property_checker_command']['maximum_parallel_queries']+=1
            with self.subTest(change=change),self.assertRaises(ValueError):
                validate_partitioned_caller(result,self.proof)
