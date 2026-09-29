"""Normal program observations retain state differences and observer failures."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from spaghetti_extractor.components.comparison_program import program_case
from spaghetti_extractor.components.comparison_capture import CAPTURE, LEGACY_CAPTURE, instrumentation_path
from spaghetti_extractor.components.comparison_files import (
    checked_mutable_files, check_program_files, retain_program_files,
)
from spaghetti_extractor.util import sha256_file

TESTKIT = {}


class ProgramObservationTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);(self.root/'cases').mkdir()
        self.plan=dict(component_id='program',program_driver=dict(process=dict(exit_codes=[0,1])),
            observation_fields=['exit_code','stdout','stderr','state'])
        self.case=dict(id='error-path',arguments=['--unknown'])
        self.executions={side:dict(returncode=1,timed_out=False) for side in ('plain','original','source')}
        for side in self.executions:
            prefix=self.root/'cases'/('0000-'+side)
            prefix.with_suffix('.stdout').write_bytes(b'bytes\0unchanged\n')
            prefix.with_suffix('.stderr').write_bytes(b'argument error\n')
            if side!='plain':
                self.report(side,dict(live_bytes=[7,9]))

    def report(self,side,state):
        (self.root/'cases'/('0000-'+side+'.report.json')).write_text(json.dumps(dict(
            side=side,exit_code=1,observations=state,diagnostics=dict(selected_calls=int(side=='source')))))

    def case_result(self,root=None):
        return program_case(self.plan,root or self.root,0,self.case,self.executions)

    def test_memory_difference_survives_equal_output_and_expected_nonzero_exit(self):
        row=self.case_result()
        self.assertEqual(row['status'],'match')
        self.assertEqual(row['observations']['source']['exit_code'],1)
        self.assertEqual(row['program_diagnostics']['source']['selected_calls'],1)
        self.report('source',dict(live_bytes=[7,10]))
        changed=self.case_result()
        self.assertEqual(changed['status'],'mismatch')
        self.assertEqual(changed['first_difference'],dict(path='$.state.live_bytes[1]',kind='value',original=9,source=10))

    def test_equal_instrumented_outputs_cannot_hide_observer_interference(self):
        for side in ('original','source'):
            (self.root/'cases'/('0000-'+side+'.stdout')).write_bytes(b'changed by observer\n')
        row=self.case_result()
        self.assertEqual(row['status'],'invalid-observation')
        self.assertIn('instrumentation changes original program behavior',row['diagnostic'])

    def test_missing_report_is_a_replayable_failure(self):
        (self.root/'cases/0000-source.report.json').unlink()
        row=self.case_result()
        self.assertEqual(row['status'],'invalid-observation')
        self.assertEqual(row['failed_side'],'source')
        self.assertIn('did not produce its report',row['diagnostic'])
        retained=self.root/'retained';retained.mkdir()
        shutil.copytree(self.root/'cases',retained/'cases')
        self.assertEqual(self.case_result(retained),row)

    def test_separate_host_diagnostics_do_not_hide_application_errors(self):
        warning=b'WARNING: radv is not a conformant Vulkan implementation, testing use only.\n'
        for count,side in enumerate(self.executions,1):
            prefix=self.root/'cases'/('0000-'+side)
            self.executions[side]['output_capture']=LEGACY_CAPTURE
            prefix.with_suffix('.capture.json').write_text(json.dumps(dict(status=0,error=0,exit_code=1)))
            prefix.with_suffix('.host.stderr').write_bytes(warning*count)
            prefix.with_suffix('.host.stdout').write_bytes(b'')
        self.assertEqual(self.case_result()['status'],'match')
        # Identical text written by the application remains a real difference.
        (self.root/'cases/0000-source.stderr').write_bytes(b'argument error\n'+warning)
        row=self.case_result()
        self.assertEqual(row['status'],'mismatch')
        self.assertTrue(row['first_difference']['path'].startswith('$.stderr'))

    def test_missing_or_failed_capture_cannot_be_a_match(self):
        self.executions['plain']['output_capture']=LEGACY_CAPTURE
        self.assertEqual(self.case_result()['status'],'invalid-observation')
        (self.root/'cases/0000-plain.capture.json').write_text(json.dumps(dict(status=2,error=2,exit_code=0)))
        row=self.case_result()
        self.assertEqual(row['status'],'invalid-observation')
        self.assertIn('program capture failed',row['diagnostic'])

    def capture_trace(self,side,data,status=0):
        prefix=self.root/'cases'/('0000-'+side)
        self.executions[side]['output_capture']=CAPTURE
        prefix.with_suffix('.trace').write_bytes(data)
        prefix.with_suffix('.capture.json').write_text(json.dumps(dict(status=status,error=0,exit_code=1,
            trace_status=status,trace_bytes=len(data))))
        return prefix

    def test_separate_trace_is_checked_and_cannot_fall_back_to_application_stderr(self):
        from spaghetti_extractor.components.service_authoring import ServiceDefinition,service_catalog
        definition=ServiceDefinition.create(identity='fixture.call',types=[dict(id='unit',kind='void')],
            parameters=[],result='unit',resources=[],effects=[],outcomes=['return'],unobserved=[])
        catalog=service_catalog({'call':definition}).to_payload();self.plan['service_catalog']=catalog
        scope=catalog['catalog_sha256'];contract=definition.contract.contract_sha256
        lines=[('SPX_SERVICE_SCOPE ',dict(catalog_sha256=scope,event='begin')),
            ('SPX_SERVICE ',dict(contract_sha256=contract,event='call',outcome='')),
            ('SPX_SERVICE ',dict(contract_sha256=contract,event='return',outcome='return')),
            ('SPX_SERVICE_SCOPE ',dict(catalog_sha256=scope,event='end'))]
        trace=''.join(prefix+json.dumps(row)+'\n' for prefix,row in lines).encode()
        for side in ('plain','original'):self.capture_trace(side,b'')
        prefix=self.capture_trace('source',trace)
        row=self.case_result();self.assertEqual(row['status'],'match')
        self.assertEqual(row['resources']['services']['coverage']['fixture.call']['calls'],1)
        self.assertEqual(instrumentation_path(prefix,self.executions['source']),prefix.with_suffix('.trace'))
        prefix.with_suffix('.trace').unlink()
        # A valid-looking old trace in stderr must not rescue missing new evidence.
        prefix.with_suffix('.stderr').write_bytes(trace)
        self.assertEqual(self.case_result()['status'],'invalid-observation')
        prefix.with_suffix('.stderr').write_bytes(b'argument error\n')
        self.capture_trace('source',trace[:-len(lines[-1][0])-1])
        self.assertEqual(self.case_result()['resources']['status'],'incomplete')
        self.capture_trace('source',trace)
        self.capture_trace('original',trace)
        self.assertIn('non-source',self.case_result()['diagnostic'])

    def test_trace_completion_overflow_and_unclassified_bytes_are_rejected(self):
        for side in self.executions:self.capture_trace(side,b'')
        prefix=self.capture_trace('source',b'SPX_SERVICE_SCOPE {}\n',4)
        self.assertIn('instrumentation output limit',self.case_result()['diagnostic'])
        self.capture_trace('source',b'ordinary application data\n')
        self.assertIn('unclassified',self.case_result()['diagnostic'])
        self.capture_trace('source',b'')
        prefix.with_suffix('.trace').write_bytes(b'SPX_SERVICE {}\n')
        self.assertEqual(self.case_result()['status'],'invalid-observation')

    def test_mutable_file_bytes_creation_deletion_and_retained_tampering(self):
        driver=self.plan['program_driver']
        driver['process']['mutable_files']=['save.dat','created.bin','deleted.dat']
        runtime=self.root/'runtime';runtime.mkdir()
        (runtime/'tmp').mkdir()
        seed=runtime/'save.dat';seed.write_bytes(b'initial')
        immutable=runtime/'library.dll';immutable.write_bytes(b'unchanged library')
        bindings={p.name:sha256_file(p) for p in (seed,immutable)}
        seed.write_bytes(b'\x00saved\xff')
        (runtime/'created.bin').write_bytes(b'')
        check_program_files(runtime,driver,bindings)
        for side in self.executions:
            retain_program_files(runtime,driver,self.root/'cases'/('0000-'+side))
        row=self.case_result()
        self.assertEqual(row['status'],'match')
        files=row['observations']['source']['files']
        self.assertEqual(files['deleted.dat'],{'status':'absent'})
        self.assertEqual(files['created.bin']['size'],0)
        prefix=self.root/'cases/0000-source'
        (prefix.with_suffix('.files')/'save.dat').write_bytes(b'tampered snapshot')
        self.assertEqual(self.case_result()['status'],'invalid-observation')
        shutil.rmtree(prefix.with_suffix('.files'))
        seed.write_bytes(b'\x00wrong\xff')
        retain_program_files(runtime,driver,prefix)
        row=self.case_result()
        self.assertEqual(row['status'],'mismatch')
        self.assertEqual(row['first_difference']['path'],'$.files.save.dat.sha256')
        immutable.write_bytes(b'changed library')
        with self.assertRaisesRegex(ValueError,'runtime input changed: library.dll'):
            check_program_files(runtime,driver,bindings)

    def test_mutable_file_declarations_do_not_exempt_program_inputs_or_paths(self):
        driver=dict(image='runtime/original.exe',library='observer.dll',process=dict(exit_codes=[0]))
        for names in [['../outside'],['dir/file'],['tmp'],['original.exe'],['observer.dll'],
                      ['helper.dll'],['a.dat','A.dat'],['NUL'],['data.']]:
            with self.subTest(names=names), self.assertRaises(ValueError):
                driver['process']['mutable_files']=names
                checked_mutable_files(driver,['runtime/original.exe','runtime/helper.dll'])
        driver['process']['mutable_files']=['save.dat','new.dat']
        checked_mutable_files(driver,['runtime/original.exe','runtime/save.dat'])

    def test_all_absent_file_snapshots_reuse_without_empty_directories(self):
        driver=self.plan['program_driver']
        driver['process']['mutable_files']=['deleted.dat']
        runtime=self.root/'runtime';runtime.mkdir()
        for side in self.executions:
            prefix=self.root/'cases'/('0000-'+side)
            retain_program_files(runtime,driver,prefix)
            prefix.with_suffix('.files').rmdir()
        self.assertEqual(self.case_result()['status'],'match')

    def test_failed_runtime_validation_retains_not_run_sides(self):
        self.executions['plain']['observation_error']='comparison runtime input changed: original.exe'
        for side in ('original','source'):
            self.executions[side]=dict(returncode=None,timed_out=False,not_run=True,
                observation_error='not run after plain: changed original.exe')
        row=self.case_result()
        self.assertEqual(row['status'],'invalid-observation')
        self.assertEqual(row['failed_side'],'plain')
        from spaghetti_extractor.operator.comparison import _runtime_feedback
        feedback='\n'.join(_runtime_feedback(row,output=self.root,index=0))
        self.assertIn('original not run; source not run',feedback)
