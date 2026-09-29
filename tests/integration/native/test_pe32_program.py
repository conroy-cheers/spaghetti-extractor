"""Program drivers retain startup/TLS; isolated routine drivers omit both."""
import os
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import pefile

from spaghetti_extractor.testkit import fixture
from spaghetti_extractor.components.comparison_pe32_program import add_experimental_import, prepare_routine_image
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.comparison_run import run_comparison, load_comparison_result
from spaghetti_extractor.components.service_authoring import component_interface
from spaghetti_extractor.candidate.experimental_build import build_experimental_execution
from spaghetti_extractor.candidate.experimental_run import run_experimental_suite
from spaghetti_extractor.candidate.experimental_manifest import load_experimental_manifest
from spaghetti_extractor.candidate.formats import EXPERIMENTAL_COMPONENT_POLICY_V1_FORMAT
from spaghetti_extractor.util import write_json, sha256_file

TESTKIT = {'fixtures': ('compiler', 'headless-wine')}

PROGRAM = r'''
#include <windows.h>
#include <stdio.h>
static unsigned tls_calls;
__declspec(dllexport) unsigned program_tls_count(void) { return tls_calls; }
static void NTAPI callback(void *module,DWORD reason,void *reserved) {
  (void)module;(void)reserved;if(reason==DLL_PROCESS_ATTACH)++tls_calls;
}
__attribute__((section(".CRT$XLB"),used)) PIMAGE_TLS_CALLBACK callback_pointer=callback;
int main(int argc,char **argv) {
  char value[16];DWORD length=GetEnvironmentVariableA("SPX_PROGRAM_LIBRARY",value,sizeof(value));
  if(argc!=2 || (length && length>=sizeof(value)))return 91;
  printf("main tls=%u dll=%s arg=%s\n",tls_calls,length?value:"absent",argv[1]);
  return 7;
}
'''
LIBRARY = r'''
#include <windows.h>
__declspec(dllexport) void experimental_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,void *reserved) {
  (void)module;(void)reserved;
  return reason!=DLL_PROCESS_ATTACH || SetEnvironmentVariableA("SPX_PROGRAM_LIBRARY","loaded");
}
'''


class Pe32ProgramTests(unittest.TestCase):
    def test_capture_streams_large_fragmented_instrumentation_separately(self):
        from spaghetti_extractor.components.comparison_capture import RESOURCES, SOURCES
        compiler=fixture('compiler')/'bin/i686-w64-mingw32-gcc'
        runner=fixture('headless-wine')/'bin/spaghetti-headless-wine'
        with tempfile.TemporaryDirectory(prefix='pe32-trace-capture-') as temporary:
            root=Path(temporary);(root/'tmp/spaghetti-capture').mkdir(parents=True)
            for name in SOURCES:shutil.copyfile(RESOURCES/name,root/name)
            (root/'producer.c').write_text(r'''
#include <windows.h>
#include <string.h>
static void put(HANDLE stream,const void *data,DWORD size) {
  DWORD done;if(!WriteFile(stream,data,size,&done,NULL) || done!=size)ExitProcess(91);
}
int main(int argc,char **argv) {
  (void)argv;HANDLE out=GetStdHandle(STD_OUTPUT_HANDLE),err=GetStdHandle(STD_ERROR_HANDLE);
  const char line[]="SPX_SERVICE {\"payload\":\"retained-exactly\"}\n";
  const unsigned char binary[]={0,255,'\n'};
  put(out,line,sizeof(line)-1);put(err,binary,sizeof(binary));
  const char fragment[]="X_SERVICE {\"fragmented\":true}\n";
  put(err,"SP",2);Sleep(20);put(err,fragment,sizeof(fragment)-1);
  unsigned char block[sizeof(line)*256];DWORD used=0;
  for(unsigned i=0;i<256;++i){memcpy(block+used,line,sizeof(line)-1);used+=sizeof(line)-1;}
  DWORD limit=(argc>1 ? 17U : 9U)*1024U*1024U;
  for(DWORD written=0;written<limit;written+=used)put(err,block,used);
  const char trailing[]="SPX_SERVX stays application\nSPX_SER";
  put(err,trailing,sizeof(trailing)-1);return 7;
}
''')
            # Exercise the same bounded sink with a smaller test budget.
            for command in ([str(compiler),'-std=c11','-Wall','-Wextra','-Werror','-municode',
                             '-DSPX_CAPTURE_TRACE_CAPACITY=(16U*1024U*1024U)','pe32-output-capture.c','-o','capture.exe'],
                            [str(compiler),'-std=c11','-Wall','-Wextra','-Werror','producer.c','-o','producer.exe']):
                built=subprocess.run(command,cwd=root,capture_output=True,text=True,timeout=60)
                self.assertEqual(built.returncode,0,built.stderr)
            env=dict(os.environ,WINEPREFIX=str(root/'wine'),WINEDEBUG='-all',SPX_CAPTURE_TIMEOUT_MS='60000',
                WINEDLLOVERRIDES='mscoree,mshtml,winemenubuilder.exe=')
            ran=subprocess.run([str(runner),str(root/'capture.exe'),'.\\producer.exe'],cwd=root,env=env,capture_output=True,timeout=90)
            self.assertEqual(ran.returncode,7,ran.stderr)
            captured=root/'tmp/spaghetti-capture';report=json.loads((captured/'result.json').read_text())
            self.assertEqual(report['status'],0);self.assertEqual(report['trace_status'],0)
            trace=(captured/'trace').read_bytes();self.assertEqual(report['trace_bytes'],len(trace));self.assertGreater(len(trace),9*1024*1024)
            self.assertTrue(trace.startswith(b'SPX_SERVICE {"fragmented":true}\n'))
            line=b'SPX_SERVICE {"payload":"retained-exactly"}\n'
            self.assertEqual((captured/'stdout').read_bytes(),line)
            self.assertEqual((captured/'stderr').read_bytes(),b'\0\xff\nSPX_SERVX stays application\nSPX_SER')
            self.assertTrue(all(row in (b'SPX_SERVICE {"fragmented":true}',line.rstrip(b'\n')) for row in trace.splitlines()))
            ran=subprocess.run([str(runner),str(root/'capture.exe'),'.\\producer.exe','overflow'],cwd=root,env=env,capture_output=True,timeout=90)
            self.assertNotEqual(ran.returncode,7)
            report=json.loads((captured/'result.json').read_text());self.assertEqual(report['status'],4);self.assertEqual(report['trace_status'],4)

    def experimental(self,root,comparison):
        plan=json.loads((comparison/'inputs/comparison-plan.json').read_text())
        policy=root/'experimental-policy.json'
        write_json(policy,dict(format=EXPERIMENTAL_COMPONENT_POLICY_V1_FORMAT,target_id='fixture',
            configuration_id='program',scope='component-network',required_components=['increment'],
            accepted_assumptions={'increment':plan['assumptions']},allowed_formal_statuses=['not-requested'],
            allow_original_runtime_dependencies=True))
        output=root/'experimental'
        manifest=build_experimental_execution(comparison=comparison,component_checks={},policy_path=policy,
            output=output,target_id='fixture')
        self.assertEqual(manifest['symbols']['binary_sha256'],sha256_file(output/'comparison/build/observer.dll'))
        self.assertEqual(set(manifest['symbols']['definitions']),{'increment'})
        self.assertEqual(manifest['authority'],'experimental-execution-only')
        return output

    def test_component_check_launches_original_program_with_selected_c(self):
        compiler=fixture('compiler')/'bin/i686-w64-mingw32-gcc'
        fixture('headless-wine')
        if not os.environ.get('WAYLAND_DISPLAY'):
            # Keep one desktop alive around the same managed Wine lifecycle as
            # production component checks, including boot and prefix disposal.
            ran=subprocess.run([shutil.which('spaghetti-headless-wayland'),sys.executable,
                '-m','unittest',self.id()],capture_output=True,text=True,timeout=120,
                env=dict(os.environ,WINEDLLOVERRIDES='mscoree,mshtml,winemenubuilder.exe='))
            self.assertEqual(ran.returncode,0,ran.stdout+'\n'+ran.stderr)
            return
        runner=Path(shutil.which('wine'));server=Path(shutil.which('wineserver'))
        with tempfile.TemporaryDirectory(prefix='component-program-') as temporary:
            root=Path(temporary)
            (root/'program.c').write_text(r'''
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
typedef unsigned (*observe_fn)(const char *, unsigned, unsigned);
int main(int argc,char **argv) {
  if(argc!=3)return 2;
  unsigned input=(unsigned)strtoul(argv[2],0,10), original=input+1U;
  observe_fn observe=(observe_fn)(void *)GetProcAddress(GetModuleHandleA("observer.dll"),"observe");
  if(!observe)return 3;
  printf("{\"value\":%u}\n",observe(argv[1],original,input));return 0;
}
''')
            built=subprocess.run([str(compiler),str(root/'program.c'),'-o',str(root/'original.exe')],
                capture_output=True,text=True,timeout=60)
            self.assertEqual(built.returncode,0,built.stderr)
            (root/'observer.c').write_text(r'''
#include <windows.h>
#include <string.h>
#include "portable-component-implementation.h"
__declspec(dllexport) unsigned observe(const char *side,unsigned original,unsigned input) {
  return !strcmp(side,"original") ? original : increment(0,input);
}
''')
            source=root/'increment.c'
            source.write_text('#include "portable-component-implementation.h"\n'
                'uint32_t increment(spx_increment_context_v5 *ctx,uint32_t value) {\n'
                '(void)ctx;return value+1U;}\n')
            boundary=component_interface(component_id='increment',
                types=[dict(id='u32',kind='integer',signed=False,width_bits=32)],
                parameters=[('value','u32')],result='u32',services={})
            package=root/'package'
            prepare_comparison_package(interface_package=boundary,
                source_files={'increment.c':source},operation_symbols={'run':'increment'},
                target_id='fixture',component_id='increment',adapter_files={'observer.c':root/'observer.c'},
                include_files={},link_files={},runtime_files={'original.exe':root/'original.exe'},
                original_files=['runtime/original.exe'],oracle_kind='fixture',
                cases=[dict(id='three',arguments=['3'])],observation_fields=['value'],
                assumptions=['Synthetic program supplies its own original arithmetic and startup.'],
                scope='Program-driven component comparison',compiler=compiler,runner=runner,server=server,
                program_driver=dict(kind='pe32-import',image='runtime/original.exe',library='observer.dll',symbol='observe'),
                output=package)
            baseline=root/'baseline'
            run_comparison(package=package,output=baseline,target_id='fixture',component_id='increment')
            self.assertEqual(load_comparison_result(baseline)['status'],'match')
            self.assertTrue((baseline/'build/observer.dll').is_file())
            self.assertTrue((baseline/'build/comparison.preparation.json').is_file())
            experiment=self.experimental(root,baseline)
            executed=run_experimental_suite(package=experiment,output=root/'executed',target_id='fixture')
            self.assertEqual(executed['status'],'pass')
            self.assertTrue((root/'executed/runtime/observer.dll').is_file())
            authored=package/'source/increment.c'
            authored.write_text(authored.read_text().replace('value+1U','value+2U'))
            changed=root/'changed'
            run_comparison(package=package,output=changed,target_id='fixture',component_id='increment',reuse_previous=baseline)
            result=load_comparison_result(changed)
            self.assertEqual(result['status'],'mismatch')
            self.assertEqual(result['cases'][0]['first_difference'],
                dict(path='$.value',kind='value',original=4,source=5))

    def test_normal_program_package_checks_state_even_when_output_and_exit_match(self):
        compiler=fixture('compiler')/'bin/i686-w64-mingw32-gcc'
        fixture('headless-wine')
        if not os.environ.get('WAYLAND_DISPLAY'):
            ran=subprocess.run([shutil.which('spaghetti-headless-wayland'),sys.executable,
                '-m','unittest',self.id()],capture_output=True,text=True,timeout=180,
                env=dict(os.environ,WINEDLLOVERRIDES='mscoree,mshtml,winemenubuilder.exe='))
            self.assertEqual(ran.returncode,0,ran.stdout+'\n'+ran.stderr)
            return
        with tempfile.TemporaryDirectory(prefix='normal-program-package-') as temporary:
            root=Path(temporary)
            (root/'program.c').write_text(r'''
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
typedef void (*observe_fn)(unsigned,unsigned);
int main(int argc,char **argv) {
  if(argc!=4)return 91;
  unsigned value=(unsigned)strtoul(argv[1],0,10);
  observe_fn observe=(observe_fn)(void *)GetProcAddress(GetModuleHandleA("observer.dll"),"observe");
  if(observe)observe(value+1U,value);
  FILE *file=fopen("state.dat","rb");
  if(!file || fgetc(file)!=(int)value)return 95;
  fclose(file);
  file=fopen("state.dat","wb");if(!file)return 96;
  fputc((int)value+1+(getenv("SPX_PROGRAM_FILE_DELTA")!=NULL),file);
  fputc(0,file);fputc(255,file);fclose(file);
  if(value==3) {
    file=fopen("created.bin","wb");if(!file)return 97;fclose(file);
    if(remove("delete.dat"))return 98;
  } else if(remove("created.bin"))return 99;
  if(getenv("SPX_UNDECLARED_FILE")) {
    file=fopen("unexpected.dat","wb");if(!file)return 100;fclose(file);
  }
  char image[MAX_PATH];if(!GetModuleFileNameA(0,image,sizeof(image)))return 94;
  printf("image=%s args=[%s][%s]\n",image,argv[2],argv[3]);
  fputs("host-like warning\n",stderr);return 1;
}
''')
            built=subprocess.run([str(compiler),str(root/'program.c'),'-o',str(root/'original.exe')],
                capture_output=True,text=True,timeout=60)
            self.assertEqual(built.returncode,0,built.stderr)
            (root/'observer.c').write_text(r'''
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "portable-component-implementation.h"
__declspec(dllexport) void observe(unsigned original,unsigned input) {
  const char *side=getenv("SPX_COMPARISON_SIDE"), *path=getenv("SPX_COMPARISON_REPORT");
  if(!side || !path)ExitProcess(92);
  unsigned value=!strcmp(side,"source")?increment(0,input):original;
  if(getenv("SPX_PROGRAM_STATE_DELTA"))++value;
  FILE *report=fopen(path,"w");if(!report)ExitProcess(93);
  fprintf(report,"{\"side\":\"%s\",\"exit_code\":1,\"observations\":{\"value\":%u},\"diagnostics\":{}}",side,value);
  fclose(report);
}
''')
            (root/'increment.c').write_text('#include "portable-component-implementation.h"\n'
                'uint32_t increment(spx_increment_context_v5 *ctx,uint32_t value) {(void)ctx;return value+1U;}\n')
            boundary=component_interface(component_id='increment',
                types=[dict(id='u32',kind='integer',signed=False,width_bits=32)],
                parameters=[('value','u32')],result='u32',services={})
            package=root/'package'
            noisy_runner=root/'noisy-wine'
            noisy_runner.write_text('#!'+sys.executable+'\n'+
                'import os,sys\n'+
                'side=os.environ.get("SPX_COMPARISON_SIDE", "")\n'+
                'os.write(2,b"host-like warning\\n"*(2 if side=="plain" else 1))\n'+
                f'os.execv({shutil.which("wine")!r},[{shutil.which("wine")!r},*sys.argv[1:]])\n')
            noisy_runner.chmod(0o755)
            (root/'state.dat').write_bytes(b'\x03\x00\xff')
            (root/'delete.dat').write_bytes(b'delete this seed')
            prepare_comparison_package(interface_package=boundary,source_files={'increment.c':root/'increment.c'},
                operation_symbols={'run':'increment'},target_id='fixture',component_id='increment',
                adapter_files={'observer.c':root/'observer.c'},include_files={},link_files={},
                runtime_files={name:root/name for name in ('original.exe','state.dat','delete.dat')},original_files=['runtime/original.exe'],
                oracle_kind='fixture',cases=[dict(id=name,arguments=[value,'','space " quote\\'])
                    for name,value in [('three','3'),('four','4')]],
                observation_fields=['exit_code','stdout','stderr','state'],
                assumptions=['Synthetic normal entry with explicit state observation and a controllable state discrepancy.'],
                scope='Normal-entry experimental packaging',compiler=compiler,runner=noisy_runner,
                server=Path(shutil.which('wineserver')),program_driver=dict(kind='pe32-import',
                    image='runtime/original.exe',library='observer.dll',symbol='observe',process=dict(exit_codes=[1],drive='P',
                        mutable_files=['state.dat','created.bin','delete.dat'])),output=package)
            baseline=root/'baseline'
            run_comparison(package=package,output=baseline,target_id='fixture',component_id='increment')
            compared=load_comparison_result(baseline)
            self.assertEqual(compared['status'],'match')
            self.assertEqual((package/'runtime/state.dat').read_bytes(),b'\x03\x00\xff')
            self.assertEqual(compared['cases'][0]['observations']['source']['files']['created.bin']['size'],0)
            self.assertEqual(compared['cases'][1]['observations']['source']['files']['created.bin'],{'status':'absent'})
            run_comparison(package=package,output=root/'reused',target_id='fixture',component_id='increment',reuse_previous=baseline)
            reused=load_comparison_result(root/'reused')
            self.assertEqual(reused['reuse']['status'],'reused')
            self.assertEqual(reused['cases'],compared['cases'])
            self.assertEqual(reused['work_counts']['execution'],0)
            for side,count in [('plain',2),('original',1),('source',1)]:
                prefix=baseline/'cases'/('0000-'+side)
                self.assertEqual(prefix.with_suffix('.stderr').read_bytes(),b'host-like warning\r\n')
                self.assertEqual(prefix.with_suffix('.host.stderr').read_bytes().count(b'host-like warning\n'),count)
                self.assertIn(b'args=[][space " quote\\]',prefix.with_suffix('.stdout').read_bytes())
                self.assertEqual((prefix.with_suffix('.files')/'state.dat').read_bytes(),b'\x04\x00\xff')
                self.assertEqual((baseline/('runtime-'+side)/'state.dat').read_bytes(),b'\x05\x00\xff')
            experiment=self.experimental(root,baseline)
            suite=json.loads((experiment/'candidate-suite.json').read_text())
            self.assertEqual(suite['cases'][0]['args'],['3','','space " quote\\'])
            self.assertEqual(suite['cases'][0]['expected_returncode'],1)
            executed=run_experimental_suite(package=experiment,output=root/'executed',target_id='fixture')
            self.assertEqual(executed['status'],'pass')
            self.assertEqual(executed['programs']['three']['observations']['state'],{'value':4})
            self.assertIn(b'P:\\original.exe',bytes(executed['programs']['three']['observations']['stdout']))
            with patch.dict(os.environ,SPX_PROGRAM_STATE_DELTA='1'):
                run=subprocess.run([sys.executable,'-m','spaghetti_extractor','candidate','test','fixture',
                    '--experimental-package',str(experiment),'--output',str(root/'wrong')],
                    capture_output=True,text=True,timeout=60)
            self.assertEqual(run.returncode,2,run.stdout+'\n'+run.stderr)
            self.assertIn('$.state.value',run.stdout)
            wrong=json.loads((root/'wrong/experimental-run.json').read_text())
            self.assertEqual(wrong['behavioral_status'],'pass')
            self.assertEqual(wrong['status'],'fail')
            self.assertEqual(wrong['programs']['three']['first_difference'],
                dict(path='$.state.value',kind='value',original=4,source=5))
            with patch.dict(os.environ,SPX_PROGRAM_FILE_DELTA='1'):
                wrong_files=run_experimental_suite(package=experiment,output=root/'wrong-files',target_id='fixture')
            self.assertEqual(wrong_files['status'],'fail')
            self.assertEqual(wrong_files['programs']['three']['first_difference']['path'],'$.files.state.dat.sha256')
            self.assertEqual(wrong_files['programs']['three']['observations']['state'],{'value':4})
            with patch.dict(os.environ,SPX_UNDECLARED_FILE='1'):
                run_comparison(package=package,output=root/'undeclared',target_id='fixture',component_id='increment',
                    reuse_previous=baseline)
            rejected=load_comparison_result(root/'undeclared')
            self.assertEqual(rejected['status'],'incomplete')
            self.assertIn('unexpected.dat',rejected['cases'][0]['diagnostic'])
            self.assertTrue(rejected['cases'][0]['executions']['source']['not_run'])
            self.assertEqual(rejected['cases'][1]['status'],'not-run')
            library=experiment/'comparison/build/observer.dll'
            library.write_bytes(library.read_bytes()+b'changed')
            with self.assertRaisesRegex(ValueError,'artifact|stale'):
                load_experimental_manifest(experiment)

    def test_import_preserves_startup_tls_and_rejects_unsupported_inputs(self):
        compiler=fixture('compiler')/'bin/i686-w64-mingw32-gcc'
        runner=fixture('headless-wine')/'bin/spaghetti-headless-wine'
        with tempfile.TemporaryDirectory(prefix='pe32-program-') as temporary:
            root=Path(temporary)
            (root/'program.c').write_text(PROGRAM)
            (root/'library.c').write_text(LIBRARY)
            for command in [('program.c','-o','original.exe'),('-shared','library.c','-o','observer.dll')]:
                built=subprocess.run([str(compiler),'-std=c11','-Wall','-Wextra','-Werror',*command],
                    cwd=root,capture_output=True,text=True,timeout=60)
                self.assertEqual(built.returncode,0,built.stderr)
            report=add_experimental_import(root/'original.exe',root/'observer.dll','experimental_anchor',root/'selected.exe')
            self.assertTrue(report['original_sections_unchanged'])
            self.assertTrue(report['original_entry_unchanged'])
            self.assertTrue(report['original_tls_unchanged'])
            environment=dict(os.environ,WINEPREFIX=str(root/'wine'),WINEDEBUG='-all',
                WINEDLLOVERRIDES='mscoree,mshtml,winemenubuilder.exe=')
            environment.pop('SPX_PROGRAM_LIBRARY',None)
            for name,expected in [('original.exe','absent'),('selected.exe','loaded')]:
                ran=subprocess.run([str(runner),str(root/name),'actual argument'],cwd=root,
                    env=environment,capture_output=True,text=True,timeout=60)
                self.assertEqual(ran.returncode,7,ran.stderr)
                self.assertEqual(ran.stdout.strip(),f'main tls=1 dll={expected} arg=actual argument')
            routine=prepare_routine_image(root/'original.exe',root/'routines.dll')
            self.assertTrue(routine['sections_unchanged'])
            self.assertFalse(routine['startup_executed'])
            self.assertFalse(routine['tls_callbacks_executed'])
            (root/'load.c').write_text(r'''
#include <windows.h>
#include <stdio.h>
typedef unsigned (*count_fn)(void);
int main(void) {
  HMODULE image=LoadLibraryA("routines.dll");if(!image)return 81;
  count_fn count=(count_fn)(void *)GetProcAddress(image,"program_tls_count");
  if(!count)return 82;
  printf("routine tls=%u\n",count());FreeLibrary(image);return 0;
}
''')
            built=subprocess.run([str(compiler),'-std=c11','load.c','-o','load.exe'],
                cwd=root,capture_output=True,text=True,timeout=60)
            self.assertEqual(built.returncode,0,built.stderr)
            ran=subprocess.run([str(runner),str(root/'load.exe')],cwd=root,env=environment,
                capture_output=True,text=True,timeout=60)
            self.assertEqual(ran.returncode,0,ran.stderr)
            self.assertEqual(ran.stdout.strip(),'routine tls=0')
            with self.assertRaisesRegex(ValueError,'differ from the original'):
                prepare_routine_image(root/'original.exe',root/'original.exe')
            for original,symbol,diagnostic in [('original.exe','absent','export is absent'),
                                               ('selected.exe','experimental_anchor','already exists')]:
                with self.assertRaisesRegex(ValueError,diagnostic):
                    add_experimental_import(root/original,root/'observer.dll',symbol,root/'bad.exe')
                self.assertFalse((root/'bad.exe').exists())
            invalid=pefile.PE(str(root/'original.exe'))
            invalid.OPTIONAL_HEADER.AddressOfEntryPoint=0
            invalid.write(str(root/'no-entry.exe'))
            with self.assertRaisesRegex(ValueError,'requires an entry point'):
                add_experimental_import(root/'no-entry.exe',root/'observer.dll','experimental_anchor',root/'bad.exe')
            self.assertFalse((root/'bad.exe').exists())
